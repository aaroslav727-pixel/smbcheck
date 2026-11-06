"""Мониторинг двойников бренда (DRP-lite): похожие домены и сертификаты с названием компании.

Проверка пассивная: мы только спрашиваем публичный DNS, журналы сертификатов (Certificate
Transparency) и RDAP/WHOIS. На сами домены-двойники не заходим и порты не сканируем —
это чужие ресурсы.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..dnsclient import DNSError, Resolver
from ..models import HIGH, INFO, LOW, MEDIUM, OK, Finding
from ..net import fetch
from .domain import _whois, parse_date, registrable

CAT = "brand"

MAX_CANDIDATES = 400
MAX_REPORTED = 25          # больше в отчёт не выводим, остальное — одной строкой
WORKERS = 8                # больше — и слабые сети/резолверы начинают терять запросы
RETRY_WORKERS = 3
NEW_DAYS = 30              # «свежая» регистрация — самый частый признак фишинга

# Зоны, которые чаще всего берут под фишинг в СНГ и Центральной Азии
TLDS = ["uz", "kz", "kg", "com", "net", "org", "info", "online", "site", "xyz", "top", "app", "pro",
        "ru", "co", "store", "click", "live"]
# Слова, которые мошенники добавляют к названию финансовой компании
AFFIXES = ["online", "pay", "login", "lk", "kabinet", "cabinet", "app", "bank", "card", "credit",
           "kredit", "zaim", "bonus", "support", "help", "secure", "my", "uz", "kz", "24"]
PREFIX_ONLY = {"my", "secure", "lk"}

HOMOGLYPHS = {
    "o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"], "e": ["3"], "s": ["5"],
    "a": ["4"], "g": ["q"], "q": ["g"], "m": ["rn", "nn"], "w": ["vv"], "rn": ["m"], "vv": ["w"],
    "d": ["cl"], "cl": ["d"], "u": ["v"], "v": ["u"],
}
_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
PARKING_NS = ("sedoparking", "bodis", "parkingcrew", "above.com", "dan.com", "afternic", "hugedomains",
              "parklogic", "domainparking", "parking")

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _neighbors() -> dict[str, set[str]]:
    pos = {ch: (r, c) for r, row in enumerate(_ROWS) for c, ch in enumerate(row)}
    out: dict[str, set[str]] = {}
    for ch, (r, c) in pos.items():
        cand = [(r, c - 1), (r, c + 1), (r - 1, c), (r - 1, c + 1), (r + 1, c), (r + 1, c - 1)]
        out[ch] = {_ROWS[rr][cc] for rr, cc in cand if 0 <= rr < len(_ROWS) and 0 <= cc < len(_ROWS[rr])}
    return out


KEYBOARD = _neighbors()


def split_domain(domain: str) -> tuple[str, str]:
    """'anorbank.uz' → ('anorbank', 'uz'); 'shop.com.kz' → ('shop', 'com.kz')."""
    reg = registrable(domain)
    label, _, suffix = reg.partition(".")
    return label, suffix


def label_variants(label: str) -> list[tuple[str, str]]:
    """Варианты метки с типом искажения. Порядок — от самых вероятных к экзотическим."""
    out: list[tuple[str, str]] = []
    n = len(label)
    for i in range(n):                                    # пропущена буква
        out.append((label[:i] + label[i + 1:], "пропущена буква"))
    for i in range(n - 1):                                # переставлены соседние
        if label[i] != label[i + 1]:
            out.append((label[:i] + label[i + 1] + label[i] + label[i + 2:], "переставлены буквы"))
    for key, subs in HOMOGLYPHS.items():                  # похожие символы
        start = label.find(key)
        while start != -1:
            for s in subs:
                out.append((label[:start] + s + label[start + len(key):], "похожие символы"))
            start = label.find(key, start + 1)
    for i in range(n):                                    # удвоена буква
        out.append((label[:i + 1] + label[i] + label[i + 1:], "удвоена буква"))
    for i in range(1, n):                                 # вставлен дефис
        out.append((label[:i] + "-" + label[i:], "вставлен дефис"))
    for w in AFFIXES:                                     # приставки и окончания
        out.append((f"{w}-{label}", "добавлено слово"))
        if w in PREFIX_ONLY:
            out.append((f"{w}{label}", "добавлено слово"))
        else:
            out.append((f"{label}-{w}", "добавлено слово"))
            out.append((f"{label}{w}", "добавлено слово"))
    for i, ch in enumerate(label):                        # соседняя клавиша
        for nb in sorted(KEYBOARD.get(ch, ())):
            out.append((label[:i] + nb + label[i + 1:], "опечатка (соседняя клавиша)"))
    return out


def generate_lookalikes(domain: str, trusted: list[str] | None = None,
                        limit: int = MAX_CANDIDATES) -> list[tuple[str, str]]:
    """Список (домен-кандидат, как получен). Свой домен и доверенные домены исключены."""
    label, suffix = split_domain(domain)
    own = registrable(domain)
    skip = {own} | {registrable(t.strip().lower()) for t in (trusted or []) if t.strip()}
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(name: str, how: str) -> None:
        if name in seen or name in skip:
            return
        lbl = name.split(".")[0]
        if not LABEL_RE.match(lbl) or (lbl[2:4] == "--" and not lbl.startswith("xn--")) or len(lbl) < 2:
            return
        seen.add(name)
        out.append((name, how))

    for t in TLDS:                                        # то же имя в другой зоне — самое частое
        if t != suffix:
            add(f"{label}.{t}", f"другая зона .{t}")
    if not label.startswith("xn--"):                      # кириллические домены — только смена зоны
        for v, how in label_variants(label):
            add(f"{v}.{suffix}", how)
    return out[:limit]


# ----------------------------------------------------------------------- DNS

@dataclass
class Hit:
    name: str
    how: str
    ips: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    created: dt.datetime | None = None
    registrar: str = ""
    abuse: str = ""
    mx_known: bool = True

    @property
    def parked(self) -> bool:
        return any(p in n.lower() for n in self.ns for p in PARKING_NS)


def probe(name: str, how: str, resolver: Resolver) -> Hit | None:
    """None — домен свободен. DNSError пробрасывается."""
    a = resolver.query(name, "A")
    if a.nxdomain:
        return None
    h = Hit(name, how, ips=[str(x) for x in a.of("A")])
    try:
        h.mx = [str(m[1]) for m in resolver.query(name, "MX").of("MX") if isinstance(m, tuple) and m[1]]
    except DNSError:
        h.mx_known = False          # домен точно существует; про почту скажем «не удалось проверить»
    try:
        h.ns = [str(x) for x in resolver.query(name, "NS").of("NS")]
    except DNSError:
        pass
    return h


def scan_lookalikes(candidates: list[tuple[str, str]], resolver: Resolver,
                    log=lambda m: None) -> tuple[list[Hit], int]:
    """Возвращает (зарегистрированные двойники, число ошибок DNS)."""
    hits: list[Hit] = []
    failed: list[tuple[str, str]] = []

    def one(item: tuple[str, str]):
        try:
            return item, probe(item[0], item[1], resolver), False
        except DNSError:
            return item, None, True

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for i, (item, hit, err) in enumerate(ex.map(one, candidates), 1):
            if err:
                failed.append(item)
            elif hit:
                hits.append(hit)
            if i % 100 == 0:
                log(f"Двойники: проверено {i} из {len(candidates)}…")
    if failed:  # второй, медленный проход: на перегруженной сети большая часть отвечает со второго раза
        log(f"Двойники: повторяю {len(failed)} вариантов, на которые DNS не ответил…")
        retry, failed = failed, []
        with ThreadPoolExecutor(max_workers=RETRY_WORKERS) as ex:
            for item, hit, err in ex.map(one, retry):
                if err:
                    failed.append(item)
                elif hit:
                    hits.append(hit)
    order = {name: i for i, (name, _) in enumerate(candidates)}
    hits.sort(key=lambda h: order.get(h.name, 0))
    return hits, len(failed)


# ----------------------------------------------------------------------- регистрация (RDAP/WHOIS)

CREATED_PATTERNS = [r"Creation Date:\s*(\S+)", r"created:\s*(\S+)", r"Created On:\s*(\S+)",
                    r"Registration Time:\s*(\S+)", r"Domain created:\s*(\S+)", r"Registered on:\s*(\S+)",
                    r"Created:\s*(\S+)"]
REGISTRAR_PATTERNS = [r"Registrar:\s*(.+)", r"registrar:\s*(.+)", r"Current Registrar:\s*(.+)"]
ABUSE_PATTERNS = [r"Registrar Abuse Contact Email:\s*(\S+)", r"abuse-mailbox:\s*(\S+)"]


def parse_rdap_registration(data: dict) -> tuple[dt.datetime | None, str, str]:
    created = None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            created = parse_date(ev.get("eventDate", ""))
    registrar = abuse = ""
    for ent in data.get("entities", []) or []:
        if "registrar" not in (ent.get("roles") or []):
            continue
        registrar = _vcard(ent, "fn") or registrar
        for sub in ent.get("entities", []) or []:
            if "abuse" in (sub.get("roles") or []):
                abuse = _vcard(sub, "email") or abuse
    return created, registrar, abuse


def _vcard(ent: dict, key: str) -> str:
    va = ent.get("vcardArray")
    if not (isinstance(va, list) and len(va) == 2):
        return ""
    for item in va[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == key:
            return str(item[3])
    return ""


def parse_whois_registration(text: str) -> tuple[dt.datetime | None, str, str]:
    def first(pats: list[str]) -> str:
        for p in pats:
            m = re.search(p, text)
            if m:
                return m.group(1).strip()
        return ""
    raw = first(CREATED_PATTERNS)
    return (parse_date(raw) if raw else None), first(REGISTRAR_PATTERNS)[:80], first(ABUSE_PATTERNS)


def registration(name: str) -> tuple[dt.datetime | None, str, str]:
    """Дата регистрации, регистратор и адрес для жалоб. Всё, что не нашлось, — пусто."""
    try:
        r = fetch(f"https://rdap.org/domain/{name}", follow=3, timeout=10)
        if r.status == 200:
            got = parse_rdap_registration(json.loads(r.text))
            if got[0]:
                return got
    except Exception:  # noqa: BLE001
        pass
    try:
        tld = name.rsplit(".", 1)[-1]
        m = re.search(r"^whois:\s*(\S+)", _whois("whois.iana.org", tld), re.M)
        if m:
            return parse_whois_registration(_whois(m.group(1), name))
    except Exception:  # noqa: BLE001
        pass
    return None, "", ""


# ----------------------------------------------------------------------- Certificate Transparency

def ct_entries(keyword: str, timeout: float = 60) -> list[dict]:
    q = urllib.parse.quote(f"%{keyword}%")
    r = fetch(f"https://crt.sh/?q={q}&output=json&exclude=expired", timeout=timeout, max_body=8 * 1024 * 1024,
              retries=1)
    if r.status != 200:
        raise RuntimeError(f"crt.sh ответил {r.status}")
    data = json.loads(r.text or "[]")
    return data if isinstance(data, list) else []


def analyze_ct(entries: list[dict], keywords: list[str], own: list[str], trusted: list[str],
               lookalike_names: set[str] | None = None) -> list[Finding]:
    """Сертификаты, где в имени есть название компании, но домен не ваш."""
    mine = {registrable(d) for d in own + trusted if d}
    found: dict[str, dict] = {}
    for e in entries:
        for raw in str(e.get("name_value", "")).lower().split("\n"):
            name = raw.strip().lstrip("*.").strip(".")
            if not name or "." not in name or not any(k in name for k in keywords):
                continue
            reg = registrable(name)
            if reg in mine or (lookalike_names and reg in lookalike_names):
                continue  # свои домены и уже найденные через DNS не дублируем
            cur = found.setdefault(reg, {"names": set(), "first": None, "issuer": ""})
            cur["names"].add(name)
            nb = parse_date(str(e.get("not_before", "")).replace(" ", "T").split(".")[0])
            if nb and (cur["first"] is None or nb > cur["first"]):
                cur["first"] = nb
                cur["issuer"] = _issuer_org(str(e.get("issuer_name", "")))
    out: list[Finding] = []
    for reg, info in sorted(found.items(), key=lambda kv: kv[1]["first"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
                            reverse=True):
        names = sorted(info["names"])
        when = info["first"].strftime("%d.%m.%Y") if info["first"] else "дата неизвестна"
        out.append(Finding(
            f"brand.ct.{reg}", CAT, MEDIUM, f"Выпущен сертификат для похожего имени: {reg}",
            detail=f"Имена в сертификате: {', '.join(names[:4])}{' …' if len(names) > 4 else ''}. Выпущен {when}.",
            why="Мошенники получают бесплатный сертификат, чтобы фишинговый сайт показывал «замочек» как настоящий.",
            fix="Откройте имя в браузере в изолированной среде. Если это подделка — уведомление регулятору "
                "(для финорганизаций Узбекистана — в течение 24 часов), жалоба регистратору и предупреждение клиентам. "
                "Если домен ваш или партнёрский — добавьте его в «Свои и проверенные домены».",
            tech=f"crt.sh · {info['issuer']}" if info["issuer"] else "crt.sh"))
    return out


def _issuer_org(issuer: str) -> str:
    m = re.search(r"O=([^,]+)", issuer)
    return m.group(1).strip('"') if m else issuer[:60]


# ----------------------------------------------------------------------- анализ

def analyze_hits(hits: list[Hit], checked: int, now: dt.datetime | None = None) -> list[Finding]:
    now = now or dt.datetime.now(dt.timezone.utc)
    out: list[Finding] = []
    ranked: list[tuple[int, Finding]] = []
    for h in hits:
        age = (now - h.created).days if h.created else None
        fresh = age is not None and age <= NEW_DAYS
        if h.parked and not h.mx:
            sev, what = LOW, "припаркован (выставлен на продажу или не используется)"
        elif h.ips and h.mx:
            sev, what = HIGH, "работает сайт и настроена почта — можно и показывать поддельную страницу, и рассылать письма"
        elif h.mx:
            sev, what = HIGH, "настроена почта — с него можно рассылать письма от вашего имени"
        elif h.ips:
            sev, what = MEDIUM, "на нём работает сайт"
        else:
            sev, what = LOW, "зарегистрирован, но сайта и почты пока нет"
        if fresh and sev in (MEDIUM, LOW):
            sev = HIGH if h.ips or h.mx else MEDIUM
        title = f"Домен-двойник: {h.name}"
        if fresh:
            title += f" (зарегистрирован {age} дн. назад)"
        if not h.mx_known:
            what += "; почту проверить не удалось"
        tech = []
        if h.ips:
            tech.append("A: " + ", ".join(h.ips[:3]))
        if h.mx:
            tech.append("MX: " + ", ".join(h.mx[:2]))
        if h.ns:
            tech.append("NS: " + ", ".join(h.ns[:2]))
        if h.registrar:
            tech.append("регистратор: " + h.registrar)
        if h.abuse:
            tech.append("жалобы: " + h.abuse)
        if h.created:
            tech.append("создан: " + h.created.strftime("%d.%m.%Y"))
        f = Finding(
            f"brand.lookalike.{h.name}", CAT, sev, title,
            detail=f"Как получен: {h.how}. Состояние: {what}.",
            why="Похожие домены используют для фишинга: клиенты вводят логин, данные карты или код из SMS на чужом сайте.",
            fix="Проверьте домен (в изолированной среде, не вводя данных). Если это подделка — уведомление регулятору "
                "(финорганизации Узбекистана — в течение 24 часов), жалоба регистратору/хостингу и предупреждение клиентов "
                "в официальных каналах. Если домен ваш или безобидный — добавьте в «Свои и проверенные домены».",
            tech="; ".join(tech))
        rank = (0 if sev == HIGH else 1 if sev == MEDIUM else 2) * 10_000 + (age if age is not None else 9_999)
        ranked.append((rank, f))
    ranked.sort(key=lambda x: x[0])
    out += [f for _, f in ranked[:MAX_REPORTED]]
    if len(ranked) > MAX_REPORTED:
        rest = [f.title.split(": ", 1)[-1] for _, f in ranked[MAX_REPORTED:]]
        out.append(Finding("brand.lookalike.more", CAT, INFO, f"Ещё зарегистрированных похожих доменов: {len(rest)}",
                           tech=", ".join(rest)))
    if not hits:
        out.append(Finding("brand.lookalike.ok", CAT, OK, f"Зарегистрированных двойников не найдено ({checked} вариантов)"))
    return out


SUMMARY_ID = "brand.summary"


def summary(checked: int, unresolved: int, registered: int, ct_state: str, ct_found: int, keywords: list[str]) -> Finding:
    """Служебная сводка для раздела отчёта «Двойники и фишинг». ct_state: ok / error / skipped / off."""
    return Finding(SUMMARY_ID, CAT, INFO, f"Проверено похожих доменов: {checked - unresolved} из {checked}",
                   tech=f"checked={checked};unresolved={unresolved};registered={registered};ct={ct_state};"
                        f"ct_found={ct_found};keywords={','.join(keywords)}")


def parse_summary(f: Finding) -> dict:
    out: dict = {}
    for part in f.tech.split(";"):
        k, _, v = part.partition("=")
        out[k] = v
    for k in ("checked", "unresolved", "registered", "ct_found"):
        try:
            out[k] = int(out.get(k, 0))
        except ValueError:
            out[k] = 0
    out["keywords"] = [x for x in str(out.get("keywords", "")).split(",") if x]
    return out


def keywords_for(domain: str, extra: list[str]) -> list[str]:
    label, _ = split_domain(domain)
    kws = [] if label.startswith("xn--") else [label]
    kws += [k.strip().lower() for k in extra if k.strip()]
    return [k for k in dict.fromkeys(kws) if len(k) >= 5]


def run(domain: str, resolver: Resolver, keywords: list[str] | None = None, trusted: list[str] | None = None,
        log=lambda m: None, ct: bool = True, whois: bool = True) -> list[Finding]:
    trusted = trusted or []
    cands = generate_lookalikes(domain, trusted)
    log(f"Двойники: проверяю {len(cands)} похожих доменов…")
    hits, errors = scan_lookalikes(cands, resolver, log)
    if cands and errors > len(cands) // 2:
        raise DNSError(f"не ответили {errors} из {len(cands)} DNS-запросов")
    if len(cands) > 20 and len(hits) > len(cands) * 0.6:
        # так бывает, когда провайдер или Wi-Fi подменяет ответы на несуществующие имена
        raise DNSError(f"«существуют» {len(hits)} из {len(cands)} вариантов — похоже, DNS подменяет ответы; "
                       "повторите из другой сети")
    if whois:
        for h in [h for h in hits if not h.parked][:15]:   # только для подозрительных, чтобы не перегружать реестры
            h.created, h.registrar, h.abuse = registration(h.name)
    out = analyze_hits(hits, len(cands))
    if errors:
        for f in out:
            if f.id == "brand.lookalike.ok":   # «не найдено» — только среди тех, что удалось проверить
                f.title = f"Среди проверенных {len(cands) - errors} из {len(cands)} вариантов двойников не найдено"
        out.append(Finding("brand.lookalike.error.dns", CAT, INFO,
                           f"Часть вариантов не проверена: DNS не ответил на {errors} из {len(cands)}",
                           detail="Обычно это перегруженная или фильтрующая сеть (университет, гостиница, гостевой Wi-Fi). "
                                  "Повторите «Только двойники» из другой сети."))

    kws = keywords_for(domain, keywords or [])
    ct_state, ct_found = ("off" if not ct else "skipped" if not kws else "ok"), 0
    if ct and not kws:
        out.append(Finding("brand.ct.skipped", CAT, INFO, "Поиск по журналам сертификатов пропущен",
                           detail="Название слишком короткое (меньше 5 символов) — было бы много ложных совпадений. "
                                  "Добавьте ключевые слова бренда в карточке клиента."))
    for kw in (kws if ct else []):
        log(f"Двойники: журналы сертификатов по «{kw}» (crt.sh, до 2 минут)…")
        try:
            entries = ct_entries(kw)
        except Exception as e:  # noqa: BLE001 — crt.sh часто перегружен
            ct_state = "error"
            out.append(Finding("brand.ct.error", CAT, INFO, f"Журналы сертификатов (crt.sh) не ответили по «{kw}»",
                               detail="Повторите позже — сервис бесплатный и иногда перегружен.", tech=str(e)[:200]))
            continue
        cts = analyze_ct(entries, [kw], [domain], trusted, {h.name for h in hits})
        ct_found += len(cts)
        out += cts[:MAX_REPORTED]
        if not cts:
            out.append(Finding(f"brand.ct.ok.{kw}", CAT, OK, f"Чужих сертификатов с «{kw}» не найдено"))
    out.insert(0, summary(len(cands), errors, len(hits), ct_state, ct_found, kws))
    return out
