"""Почта: MX, SPF, DKIM, DMARC — защищают от писем «от имени» компании."""
from __future__ import annotations

import base64
import re

from ..dnsclient import DNSError, Resolver
from ..models import CRITICAL, HIGH, INFO, LOW, MEDIUM, OK, Finding

CAT = "email"

# Селекторы DKIM популярных провайдеров (в т.ч. российских)
DKIM_SELECTORS = [
    "mail",                     # Яндекс 360
    "mailru",                   # VK WorkSpace / Mail.ru
    "google",                   # Google Workspace
    "selector1", "selector2",   # Microsoft 365
    "default", "dkim", "k1", "k2", "k3", "s1", "s2", "smtp", "mx", "key1", "key2",
    "zoho", "protonmail", "protonmail2", "protonmail3", "us", "sendpulse", "unisender",
    "mandrill", "mailjet", "sig1", "everlytickey1", "beget", "timeweb", "reg1", "x",
]

PROVIDERS = [
    (r"(^|\.)mx\.yandex\.(net|ru)$|yandex", "Яндекс 360"),
    (r"mail\.ru$|mxs\.mail\.ru", "VK WorkSpace (Mail.ru)"),
    (r"google\.com$|googlemail\.com$", "Google Workspace"),
    (r"protection\.outlook\.com$|outlook\.com$", "Microsoft 365"),
    (r"zoho\.(com|eu|in)$", "Zoho Mail"),
    (r"beget\.(com|ru)$", "Beget"),
    (r"timeweb\.(ru|cloud)$", "Timeweb"),
    (r"reg\.ru$|hosting\.reg\.ru", "REG.RU"),
    (r"protonmail\.ch$", "Proton Mail"),
]

DKIM_HINTS = {
    "Яндекс 360": "В админке Яндекс 360 → Почта → DKIM-подписи включите подпись и добавьте показанную TXT-запись mail._domainkey.",
    "Google Workspace": "Admin Console → Приложения → Gmail → Проверка подлинности (DKIM): создайте ключ 2048 бит и добавьте TXT google._domainkey.",
    "Microsoft 365": "Defender → Email authentication → DKIM: включите подпись и добавьте CNAME selector1/selector2._domainkey.",
    "VK WorkSpace (Mail.ru)": "В панели VK WorkSpace откройте настройки домена и добавьте DKIM-запись mailru._domainkey.",
}


def detect_provider(mx_hosts: list[str]) -> str:
    for host in mx_hosts:
        h = host.lower().rstrip(".")
        for pattern, name in PROVIDERS:
            if re.search(pattern, h):
                return name
    return ""


# ------------------------------------------------------------------ SPF

SPF_LOOKUP_MECHS = re.compile(r"^[+\-~?]?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr|exists:|redirect=)", re.I)


def find_spf(txts: list[str]) -> list[str]:
    return [t for t in txts if t.lower().strip().startswith("v=spf1")]


def count_spf_lookups(resolver: Resolver, record: str, depth: int = 0, seen: set | None = None) -> int:
    """Считает DNS-запросы, которые потребует SPF (лимит RFC 7208 — 10)."""
    seen = seen if seen is not None else set()
    total = 0
    for term in record.split()[1:]:
        if not SPF_LOOKUP_MECHS.match(term):
            continue
        total += 1
        low = term.lower().lstrip("+-~?")
        target = None
        if low.startswith("include:"):
            target = term.split(":", 1)[1]
        elif low.startswith("redirect="):
            target = term.split("=", 1)[1]
        if target and depth < 10 and target.lower() not in seen:
            seen.add(target.lower())
            try:
                sub = find_spf(resolver.txt(target))
            except DNSError:
                sub = []
            if sub:
                total += count_spf_lookups(resolver, sub[0], depth + 1, seen)
    return total


def analyze_spf(domain: str, txts: list[str], has_mx: bool, lookups: int | None) -> list[Finding]:
    recs = find_spf(txts)
    if not recs:
        if has_mx:
            return [Finding(
                "email.spf.missing", CAT, HIGH, "Нет SPF-записи",
                detail=f"У домена {domain} не опубликован список серверов, которым разрешено отправлять почту.",
                why="Любой может отправить письмо «от вашего имени» — так делают фишинг и фальшивые счета клиентам.",
                fix="Добавьте TXT-запись SPF с почтовыми серверами вашего провайдера, в конце -all или ~all.",
                tech="TXT @: v=spf1 include:<провайдер> -all")]
        return [Finding(
            "email.spf.missing", CAT, MEDIUM, "Нет SPF, хотя домен не принимает почту",
            detail="Почты на домене нет, но подделать отправителя всё равно можно.",
            why="Неиспользуемые домены тоже подделывают в рассылках мошенников.",
            fix="Добавьте запись, запрещающую любую отправку: v=spf1 -all.",
            tech="TXT @: v=spf1 -all")]
    if len(recs) > 1:
        return [Finding(
            "email.spf.multiple", CAT, HIGH, "Несколько SPF-записей — защита не работает",
            detail=f"Найдено {len(recs)} записей SPF, а должна быть одна.",
            why="Почтовые серверы считают такую настройку ошибкой и игнорируют SPF целиком.",
            fix="Объедините записи в одну строку v=spf1 ... -all.",
            tech=" | ".join(recs))]
    rec = recs[0]
    terms = [t.lower() for t in rec.split()[1:]]
    out: list[Finding] = []
    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    has_redirect = any(t.startswith("redirect=") for t in terms)
    if all_term in ("all", "+all"):
        out.append(Finding(
            "email.spf.plusall", CAT, CRITICAL, "SPF разрешает отправку кому угодно (+all)",
            detail="Запись заканчивается на +all — это значит «любой сервер может слать от нас».",
            why="SPF есть только на бумаге: подделка писем ничем не ограничена.",
            fix="Замените +all на -all (или ~all, пока проверяете).", tech=rec))
    elif all_term == "?all":
        out.append(Finding(
            "email.spf.neutral", CAT, MEDIUM, "SPF в нейтральном режиме (?all)",
            detail="Чужие серверы не помечаются как подозрительные.",
            why="Почтовики почти не используют такую запись для защиты.",
            fix="Замените ?all на ~all, а после проверки — на -all.", tech=rec))
    elif all_term is None and not has_redirect:
        out.append(Finding(
            "email.spf.noall", CAT, MEDIUM, "SPF без завершающего правила all",
            detail="Не сказано, что делать с письмами с чужих серверов.",
            why="По умолчанию такие письма считаются нейтральными, а не подозрительными.",
            fix="Добавьте в конец записи -all или ~all.", tech=rec))
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        out.append(Finding(
            "email.spf.ptr", CAT, LOW, "В SPF используется устаревший механизм ptr",
            why="Он медленный, и часть почтовых серверов его не поддерживает.",
            fix="Уберите ptr и укажите серверы явно (ip4:, include:).", tech=rec))
    if lookups is not None and lookups > 10:
        out.append(Finding(
            "email.spf.lookups", CAT, HIGH, "SPF слишком длинный — превышен лимит в 10 запросов",
            detail=f"Запись требует {lookups} DNS-запросов при лимите 10.",
            why="Почтовые серверы считают SPF ошибочным, и письма могут уходить в спам.",
            fix="Уберите лишние include: сервисов, которыми больше не пользуетесь.", tech=rec))
    if not out:
        mode = "строгий (-all)" if all_term == "-all" else "мягкий (~all)" if all_term == "~all" else "через redirect"
        out.append(Finding("email.spf.ok", CAT, OK, f"SPF настроен, режим {mode}", tech=rec))
    return out


# ------------------------------------------------------------------ DMARC

def parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def analyze_dmarc(domain: str, txts: list[str]) -> list[Finding]:
    recs = [t for t in txts if t.replace(" ", "").lower().startswith("v=dmarc1")]
    if not recs:
        return [Finding(
            "email.dmarc.missing", CAT, HIGH, "Нет DMARC — подделку писем никто не блокирует",
            detail=f"Для {domain} нет записи _dmarc.",
            why="Даже при SPF и DKIM почтовики не знают, что делать с подделкой, и часто пропускают её. "
                "Gmail и Яндекс без DMARC хуже доставляют массовые рассылки.",
            fix="Начните с мониторинга: p=none и адрес для отчётов, через 2–4 недели перейдите на quarantine.",
            tech=f"TXT _dmarc.{domain}: v=DMARC1; p=none; rua=mailto:dmarc@{domain}")]
    if len(recs) > 1:
        return [Finding(
            "email.dmarc.multiple", CAT, HIGH, "Несколько DMARC-записей — защита не работает",
            why="При двух записях почтовики игнорируют DMARC.", fix="Оставьте одну запись.",
            tech=" | ".join(recs))]
    rec = recs[0]
    tags = parse_tags(rec)
    p = tags.get("p", "").lower()
    out: list[Finding] = []
    if p == "none" or p == "":
        out.append(Finding(
            "email.dmarc.none", CAT, MEDIUM, "DMARC только наблюдает (p=none)",
            detail="Поддельные письма доставляются, вы лишь получаете отчёты о них.",
            why="Это нормальный первый шаг, но не защита.",
            fix="Проверьте по отчётам, что все ваши сервисы проходят SPF/DKIM, и смените p=none на p=quarantine, затем на p=reject.",
            tech=rec))
    else:
        pct = tags.get("pct", "100")
        if pct.isdigit() and int(pct) < 100:
            out.append(Finding(
                "email.dmarc.pct", CAT, LOW, f"DMARC применяется только к {pct}% писем",
                why="Часть подделок по-прежнему проходит.", fix="Доведите pct до 100 (или уберите тег).",
                tech=rec))
        sp = tags.get("sp", "").lower()
        if sp == "none":
            out.append(Finding(
                "email.dmarc.sp", CAT, LOW, "Поддомены не защищены (sp=none)",
                why="Мошенники могут слать письма с адресов вида pay.вашдомен.",
                fix="Уберите sp=none или поставьте sp=reject.", tech=rec))
    if "rua" not in tags:
        out.append(Finding(
            "email.dmarc.norua", CAT, LOW, "DMARC не присылает отчёты",
            detail="Не указан адрес rua= для сводных отчётов.",
            why="Вы не узнаете, кто отправляет письма от вашего имени и не сломается ли легальная рассылка.",
            fix=f"Добавьте rua=mailto:dmarc@{domain} (или адрес сервиса разбора отчётов).", tech=rec))
    if not any(f.severity in (MEDIUM, HIGH, CRITICAL) for f in out):
        out.insert(0, Finding("email.dmarc.ok", CAT, OK, f"DMARC включён в режиме {p}", tech=rec))
    return out


# ------------------------------------------------------------------ DKIM

def dkim_key_bits(record: str) -> int | None:
    p = parse_tags(record).get("p")
    if p is None:
        return None
    if p == "":
        return 0
    p = re.sub(r"\s+", "", p)
    try:
        der = base64.b64decode(p + "=" * ((4 - len(p) % 4) % 4))
    except ValueError:
        return None
    if parse_tags(record).get("k", "rsa").lower() == "ed25519":
        return 256
    # Длина DER-структуры открытого ключа RSA ≈ размер модуля + ~38 байт
    n = len(der)
    if n < 100:
        return 512
    if n < 180:
        return 1024
    if n < 330:
        return 2048
    return 4096


def probe_dkim(resolver: Resolver, domain: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for sel in DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        try:
            ans = resolver.query(name, "TXT")
        except DNSError:
            continue
        recs = [t for t in ans.of("TXT") if "p=" in t]
        if recs:
            found[sel] = recs[0]
    return found


def analyze_dkim(domain: str, found: dict[str, str], provider: str) -> list[Finding]:
    if not found:
        hint = DKIM_HINTS.get(provider, "Включите DKIM-подпись в настройках почтового провайдера и опубликуйте выданную TXT-запись.")
        return [Finding(
            "email.dkim.notfound", CAT, MEDIUM, "DKIM-подпись не найдена",
            detail="Мы проверили стандартные имена ключей популярных провайдеров и не нашли ни одного.",
            why="Без подписи письма легче подделать, и они чаще попадают в спам. "
                "Возможно, ключ есть под нестандартным именем — тогда уточните у провайдера.",
            fix=hint)]
    out = []
    weak = [s for s, r in found.items() if (dkim_key_bits(r) or 2048) < 2048 and dkim_key_bits(r) != 0]
    revoked = [s for s, r in found.items() if dkim_key_bits(r) == 0]
    if weak:
        out.append(Finding(
            "email.dkim.weak", CAT, LOW, "Короткий DKIM-ключ (1024 бит или меньше)",
            detail="Селекторы: " + ", ".join(weak),
            why="Короткие ключи считаются устаревшими; рекомендуемый размер — 2048 бит.",
            fix="Перевыпустите ключ на 2048 бит в настройках почтового провайдера."))
    if revoked and len(revoked) == len(found):
        out.append(Finding(
            "email.dkim.revoked", CAT, MEDIUM, "Все найденные DKIM-ключи отозваны",
            detail="Селекторы: " + ", ".join(revoked), fix="Включите действующий ключ у провайдера."))
    out.insert(0, Finding("email.dkim.ok", CAT, OK, "DKIM-подпись найдена",
                          detail="Селекторы: " + ", ".join(found)))
    return out


# ------------------------------------------------------------------ entry

def run(domain: str, resolver: Resolver, log=lambda m: None) -> list[Finding]:
    out: list[Finding] = []
    log("Почта: MX-записи…")
    mx = resolver.query(domain, "MX")
    if mx.nxdomain:
        return [Finding("domain.nxdomain", "domain", CRITICAL, "Домен не найден в DNS",
                        detail=f"{domain} не существует или не делегирован.",
                        fix="Проверьте написание домена и оплату регистрации.")]
    mx_hosts = [h for _, h in sorted(mx.of("MX"))]
    mx_hosts = [h for h in mx_hosts if h and h != "."]
    provider = detect_provider(mx_hosts)
    if mx_hosts:
        out.append(Finding("email.mx", CAT, INFO,
                           "Почта: " + (provider or "собственный или неизвестный сервер"),
                           tech=", ".join(mx_hosts[:5])))
    else:
        out.append(Finding("email.mx", CAT, INFO, "Домен не принимает почту (нет MX)"))

    log("Почта: SPF…")
    txts = resolver.txt(domain)
    spf = find_spf(txts)
    lookups = count_spf_lookups(resolver, spf[0]) if len(spf) == 1 else None
    out += analyze_spf(domain, txts, bool(mx_hosts), lookups)

    log("Почта: DMARC…")
    out += analyze_dmarc(domain, resolver.txt(f"_dmarc.{domain}"))

    if mx_hosts:
        log("Почта: DKIM (перебор селекторов)…")
        out += analyze_dkim(domain, probe_dkim(resolver, domain), provider)
    return out
