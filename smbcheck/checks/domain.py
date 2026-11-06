"""Домен: срок регистрации, DNS-серверы, DNSSEC, CAA."""
from __future__ import annotations

import datetime as dt
import json
import re
import socket

from ..dnsclient import DNSError, Resolver
from ..models import CRITICAL, HIGH, INFO, LOW, MEDIUM, OK, Finding
from ..net import fetch

CAT = "domain"

# Частые публичные суффиксы второго уровня (упрощённо, без полного списка PSL)
SECOND_LEVEL = {
    "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru", "msk.su", "spb.su",
    "com.ua", "kiev.ua", "com.kz", "org.kz", "co.uk", "org.uk", "com.my", "com.au",
    "com.tr", "com.br", "co.il", "com.cn", "com.ge", "co.jp",
}
WHOIS_SERVERS = {"ru": "whois.tcinet.ru", "su": "whois.tcinet.ru", "xn--p1ai": "whois.tcinet.ru"}
EXPIRY_PATTERNS = [
    r"Registry Expiry Date:\s*(\S+)",
    r"Registrar Registration Expiration Date:\s*(\S+)",
    r"paid-till:\s*(\S+)",
    r"Expiration Date:\s*(\S+)",
    r"Expiry [Dd]ate:\s*(\S+)",
    r"expires:\s*(\S+)",
    r"Expires On:\s*(\S+)",
]


def registrable(domain: str) -> str:
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parse_date(s: str) -> dt.datetime | None:
    s = s.strip().rstrip(".")
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d", "%Y.%m.%d", "%d.%m.%Y", "%d-%b-%Y", "%Y/%m/%d"):
        try:
            d = dt.datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    try:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def expiry_from_rdap(data: dict) -> dt.datetime | None:
    for ev in data.get("events", []):
        if ev.get("eventAction") == "expiration":
            return parse_date(ev.get("eventDate", ""))
    return None


def expiry_from_whois(text: str) -> dt.datetime | None:
    for pat in EXPIRY_PATTERNS:
        m = re.search(pat, text)
        if m:
            d = parse_date(m.group(1))
            if d:
                return d
    return None


def _whois(server: str, query: str, timeout: float = 10) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode("idna" if not query.isascii() else "ascii"))
        chunks = []
        while True:
            c = s.recv(4096)
            if not c:
                break
            chunks.append(c)
    return b"".join(chunks).decode("utf-8", "replace")


def lookup_expiry(domain: str) -> tuple[dt.datetime | None, str]:
    """Возвращает (дата окончания, источник). Сначала RDAP, потом WHOIS."""
    try:
        r = fetch(f"https://rdap.org/domain/{domain}", follow=3, timeout=15, retries=1)
        if r.status == 200:
            d = expiry_from_rdap(json.loads(r.text))
            if d:
                return d, "RDAP"
    except Exception:  # noqa: BLE001
        pass
    tld = domain.rsplit(".", 1)[-1]
    try:
        server = WHOIS_SERVERS.get(tld)
        if not server:
            m = re.search(r"^whois:\s*(\S+)", _whois("whois.iana.org", tld), re.M)
            server = m.group(1) if m else None
        if server:
            return expiry_from_whois(_whois(server, domain)), "WHOIS"
    except Exception:  # noqa: BLE001
        pass
    return None, ""


def analyze_expiry(domain: str, expires: dt.datetime | None, now: dt.datetime | None = None) -> list[Finding]:
    if expires is None:
        return [Finding("domain.expiry.unknown", CAT, INFO, "Срок регистрации домена не удалось узнать автоматически",
                        fix="Проверьте дату окончания в личном кабинете регистратора и включите автопродление.")]
    now = now or dt.datetime.now(dt.timezone.utc)
    days = (expires - now).days
    date = expires.strftime("%d.%m.%Y")
    why = "Если домен не продлить, перестанут работать сайт и почта, а сам домен могут перехватить."
    fix = "Продлите домен у регистратора и включите автопродление; проверьте, что контактный e-mail актуален."
    if days < 0:
        return [Finding("domain.expiry", CAT, CRITICAL, f"Регистрация домена истекла {date}", why=why, fix=fix)]
    if days < 14:
        return [Finding("domain.expiry", CAT, CRITICAL, f"Домен истекает через {days} дн. ({date})", why=why, fix=fix)]
    if days < 30:
        return [Finding("domain.expiry", CAT, HIGH, f"Домен истекает через {days} дн. ({date})", why=why, fix=fix)]
    if days < 60:
        return [Finding("domain.expiry", CAT, MEDIUM, f"Домен истекает через {days} дн. ({date})", why=why, fix=fix)]
    return [Finding("domain.expiry.ok", CAT, OK, f"Домен оплачен до {date}")]


def analyze_dns(ns: list[str], ds: list, caa: list) -> list[Finding]:
    out: list[Finding] = []
    if len(ns) < 2:
        out.append(Finding("domain.ns.single", CAT, MEDIUM, "У домена только один DNS-сервер",
                           why="Если он упадёт, перестанут работать и сайт, и почта.",
                           fix="Укажите у регистратора минимум два DNS-сервера.", tech=", ".join(ns)))
    else:
        out.append(Finding("domain.ns", CAT, INFO, f"DNS-серверы: {len(ns)}", tech=", ".join(sorted(ns)[:4])))
    if ds:
        out.append(Finding("domain.dnssec.ok", CAT, OK, "DNSSEC включён"))
    else:
        out.append(Finding("domain.dnssec.missing", CAT, LOW, "DNSSEC не включён",
                           why="DNSSEC защищает от подмены DNS-ответов: посетителя или почту нельзя тайно увести на чужой сервер.",
                           fix="Включите DNSSEC у регистратора или DNS-хостинга — обычно это одна кнопка."))
    if not caa:
        out.append(Finding("domain.caa.missing", CAT, INFO, "Не ограничено, кто может выпускать сертификаты (нет CAA)",
                           fix="Добавьте CAA-запись с вашим центром сертификации, например 0 issue \"letsencrypt.org\"."))
    return out


def run(domain: str, resolver: Resolver, log=lambda m: None) -> list[Finding]:
    base = registrable(domain)
    out: list[Finding] = []
    log(f"Домен: срок регистрации {base}…")
    exp, _src = lookup_expiry(base)
    out += analyze_expiry(base, exp)
    log("Домен: DNS-серверы и DNSSEC…")
    try:
        ns = resolver.query(base, "NS").of("NS")
        ds = resolver.query(base, "DS").of("DS")
        caa = resolver.query(domain, "CAA").of("CAA") or resolver.query(base, "CAA").of("CAA")
        out += analyze_dns(ns, ds, caa)
    except DNSError as e:
        if exp is None:
            raise  # ни DNS, ни RDAP/WHOIS не ответили — проверка домена не состоялась
        out.append(Finding("domain.dns.error", CAT, INFO, "Не удалось проверить DNS-записи домена", tech=str(e)))
    return out
