"""Сайт: сертификат, HTTPS, защитные заголовки, забытые служебные файлы."""
from __future__ import annotations

import datetime as dt
import re
import socket
import ssl

from ..dnsclient import Resolver
from ..models import CRITICAL, HIGH, INFO, LOW, MEDIUM, OK, Finding
from ..net import HttpResponse, fetch
from ..tlsctx import context as ssl_context

CAT = "web"


# ------------------------------------------------------------------ TLS

def tls_info(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Проверка сертификата с полной валидацией, как это делает браузер."""
    ctx = ssl_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                return {"ok": True, "cert": cert, "version": ss.version()}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "kind": "verify", "code": getattr(e, "verify_code", 0),
                "message": getattr(e, "verify_message", str(e))}
    except (ConnectionRefusedError, socket.timeout, TimeoutError) as e:
        return {"ok": False, "kind": "noconnect", "message": str(e) or e.__class__.__name__}
    except (ssl.SSLError, OSError) as e:
        return {"ok": False, "kind": "other", "message": str(e)}


def supports_legacy_tls(host: str, port: int = 443, timeout: float = 6.0) -> bool | None:
    """True — сервер принимает TLS 1.0/1.1; False — нет; None — проверить не смогли."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as e:
        if "NO_PROTOCOLS_AVAILABLE" in str(e).upper():
            return None
        return False
    except OSError:
        return None


def cert_days_left(cert: dict, now: dt.datetime | None = None) -> int | None:
    na = cert.get("notAfter")
    if not na:
        return None
    exp = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(na), tz=dt.timezone.utc)
    now = now or dt.datetime.now(dt.timezone.utc)
    return (exp - now).days


def cert_issuer(cert: dict) -> str:
    for rdn in cert.get("issuer", ()):
        for k, v in rdn:
            if k == "organizationName":
                return v
    return ""


def analyze_tls(host: str, info: dict, legacy: bool | None) -> list[Finding]:
    out: list[Finding] = []
    if not info.get("ok"):
        kind, code, msg = info.get("kind"), info.get("code"), info.get("message", "")
        if kind == "noconnect":
            return [Finding("web.https.none", CAT, HIGH, "Сайт не открывается по HTTPS",
                            detail=f"Порт 443 на {host} не отвечает.",
                            why="Без HTTPS пароли и данные форм передаются открытым текстом, браузеры помечают сайт как «Не защищён».",
                            fix="Подключите бесплатный сертификат Let's Encrypt в панели хостинга.",
                            tech=msg)]
        if kind == "verify":
            if code == 10:
                return [Finding("web.cert.expired", CAT, CRITICAL, "Сертификат сайта просрочен",
                                why="Браузеры показывают посетителям полноэкранное предупреждение — большинство уходит.",
                                fix="Перевыпустите сертификат и включите автопродление.", tech=msg)]
            if code in (18, 19):
                return [Finding("web.cert.selfsigned", CAT, HIGH, "Самоподписанный сертификат",
                                why="Браузеры ему не доверяют и показывают предупреждение.",
                                fix="Замените на сертификат от доверенного центра (Let's Encrypt бесплатно).", tech=msg)]
            if code == 62 or "hostname" in msg.lower():
                return [Finding("web.cert.mismatch", CAT, HIGH, "Сертификат выдан на другое имя",
                                why="Браузер считает, что посетитель попал на чужой сайт.",
                                fix=f"Выпустите сертификат, включающий {host} и www.{host}.", tech=msg)]
            return [Finding("web.cert.invalid", CAT, HIGH, "Браузеры не доверяют сертификату сайта",
                            why="Посетители видят предупреждение о небезопасном соединении.",
                            fix="Проверьте, что на сервере установлена полная цепочка сертификатов.", tech=msg)]
        return [Finding("web.tls.error", CAT, MEDIUM, "Не удалось установить защищённое соединение",
                        fix="Проверьте настройки HTTPS на хостинге.", tech=msg)]

    cert = info["cert"]
    days = cert_days_left(cert)
    issuer = cert_issuer(cert)
    if days is not None:
        if days < 7:
            out.append(Finding("web.cert.expiring", CAT, CRITICAL, f"Сертификат истекает через {days} дн.",
                               why="После истечения сайт перестанет открываться без предупреждения.",
                               fix="Срочно продлите сертификат и проверьте автопродление.", tech=issuer))
        elif days < 14:
            out.append(Finding("web.cert.expiring", CAT, HIGH, f"Сертификат истекает через {days} дн.",
                               why="Если автопродление сломано, через пару недель сайт покажет ошибку.",
                               fix="Проверьте, что автопродление работает.", tech=issuer))
        else:
            out.append(Finding("web.cert.ok", CAT, OK, f"Сертификат действителен ещё {days} дн.",
                               tech=f"{issuer}, {info.get('version', '')}"))
    if legacy:
        out.append(Finding("web.tls.legacy", CAT, MEDIUM, "Сервер принимает устаревшие TLS 1.0/1.1",
                           why="Эти версии протокола взломаны и запрещены стандартами (в т.ч. PCI DSS для оплаты картами).",
                           fix="Отключите TLS 1.0 и 1.1 в настройках веб-сервера или хостинга."))
    return out


# ------------------------------------------------------------------ HTTP

SEC_HEADERS = {
    "strict-transport-security": "HSTS",
    "x-content-type-options": "X-Content-Type-Options",
    "content-security-policy": "Content-Security-Policy",
    "referrer-policy": "Referrer-Policy",
}
VERSION_RE = re.compile(r"\d+\.\d+")


def analyze_redirect(http_resp: HttpResponse | None) -> list[Finding]:
    if http_resp is None:
        return []
    loc = http_resp.header("Location")
    if http_resp.status in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
        return [Finding("web.redirect.ok", CAT, OK, "HTTP перенаправляет на HTTPS")]
    if http_resp.status == 200:
        return [Finding("web.redirect.missing", CAT, MEDIUM, "Сайт доступен без HTTPS",
                        detail="По адресу http:// сайт открывается без перенаправления на защищённую версию.",
                        why="Посетитель, набравший адрес без https, работает по незащищённому каналу.",
                        fix="Включите в панели хостинга «Перенаправлять на HTTPS» (301 редирект).")]
    return []


def analyze_headers(resp: HttpResponse) -> list[Finding]:
    out: list[Finding] = []
    present = {k.lower() for k in resp.headers.keys()}
    missing = [label for key, label in SEC_HEADERS.items() if key not in present]
    csp = resp.header("Content-Security-Policy").lower()
    if "x-frame-options" not in present and "frame-ancestors" not in csp:
        missing.append("X-Frame-Options")
    if "HSTS" in missing and resp.url.startswith("https://"):
        out.append(Finding("web.hsts.missing", CAT, LOW, "Браузеру не велено всегда использовать HTTPS (нет HSTS)",
                           why="Первое подключение по http:// можно перехватить в публичном Wi-Fi.",
                           fix="Добавьте заголовок Strict-Transport-Security: max-age=31536000.",
                           tech="Strict-Transport-Security"))
    minor = [m for m in missing if m != "HSTS"]
    if minor:
        out.append(Finding("web.headers.missing", CAT, LOW if len(minor) >= 3 else INFO,
                           f"Не хватает защитных заголовков ({len(minor)})",
                           detail=", ".join(minor),
                           why="Заголовки защищают посетителей от встраивания сайта в чужие страницы и подмены содержимого.",
                           fix="Попросите разработчика или хостинг добавить заголовки — это несколько строк настройки.",
                           tech=", ".join(minor)))
    leaks = []
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        v = resp.header(h)
        if v and VERSION_RE.search(v):
            leaks.append(f"{h}: {v}")
    if leaks:
        out.append(Finding("web.version.leak", CAT, LOW, "Сайт сообщает версии своего ПО",
                           detail="; ".join(leaks),
                           why="Злоумышленнику проще подобрать известную уязвимость под конкретную версию.",
                           fix="Скройте версии в настройках веб-сервера (server_tokens off, expose_php = Off).",
                           tech="; ".join(leaks)))
    insecure = []
    for c in resp.headers_all("Set-Cookie"):
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        if resp.url.startswith("https://") and "secure" not in low:
            insecure.append(name)
    if insecure:
        out.append(Finding("web.cookies", CAT, LOW, "Cookie без флага Secure",
                           detail=", ".join(sorted(set(insecure))[:6]),
                           why="Такие cookie могут уйти по незащищённому каналу и быть перехвачены.",
                           fix="Включите флаги Secure и HttpOnly для cookie сессии."))
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', resp.text, re.I)
    if gen:
        out.append(Finding("web.cms", CAT, INFO, f"Движок сайта: {gen.group(1)[:60]}",
                           why="Устаревшие версии CMS и плагинов — самая частая причина взлома небольших сайтов.",
                           fix="Включите автообновления движка и плагинов, удалите неиспользуемые плагины."))
    if re.search(r"<title>\s*Index of /", resp.text, re.I):
        out.append(Finding("web.listing", CAT, MEDIUM, "Открыт список файлов на сервере",
                           why="Любой может просмотреть и скачать файлы из папки сайта.",
                           fix="Отключите листинг каталогов (Options -Indexes) и добавьте index-файл."))
    return out


# ------------------------------------------------------------------ забытые файлы

def _is_env(body: str) -> bool:
    lines = [l for l in body.splitlines() if l.strip() and not l.startswith("#")]
    kv = [l for l in lines if re.match(r"^[A-Z][A-Z0-9_]{2,}\s*=", l)]
    return len(kv) >= 2 and len(kv) >= len(lines) * 0.6


EXPOSED = [
    # путь, проверка содержимого, важность, заголовок, пояснение
    ("/.git/HEAD", lambda b, raw: b.startswith("ref:") or bool(re.fullmatch(r"[0-9a-f]{40}\s*", b)),
     CRITICAL, "Открыта папка .git с исходным кодом сайта",
     "Из неё можно скачать весь код сайта, часто вместе с паролями от базы данных."),
    ("/.env", lambda b, raw: _is_env(b),
     CRITICAL, "Открыт файл .env с настройками и паролями",
     "В этом файле обычно хранятся пароли от базы данных, почты и ключи платёжных систем."),
    ("/wp-config.php.bak", lambda b, raw: "DB_PASSWORD" in b,
     CRITICAL, "Открыта резервная копия конфигурации WordPress",
     "В файле пароль от базы данных сайта."),
    ("/wp-config.php~", lambda b, raw: "DB_PASSWORD" in b,
     CRITICAL, "Открыта резервная копия конфигурации WordPress",
     "В файле пароль от базы данных сайта."),
    ("/phpinfo.php", lambda b, raw: "phpinfo()" in b or "PHP Version" in b and "Configuration" in b,
     MEDIUM, "Открыта страница phpinfo",
     "Она раскрывает версии ПО, пути к файлам и настройки сервера."),
    ("/server-status", lambda b, raw: "Apache Server Status" in b,
     MEDIUM, "Открыта страница статуса Apache",
     "Видны адреса посетителей и внутренние запросы к сайту."),
    ("/.DS_Store", lambda b, raw: raw[4:8] == b"Bud1",
     LOW, "Открыт служебный файл .DS_Store",
     "По нему можно узнать имена файлов и папок на сервере."),
]


def analyze_exposed(path: str, resp: HttpResponse) -> Finding | None:
    for p, check, sev, title, why in EXPOSED:
        if p != path:
            continue
        if resp.status != 200 or not resp.body:
            return None
        ctype = resp.header("Content-Type").lower()
        body = resp.text
        if "text/html" in ctype and p not in ("/phpinfo.php", "/server-status"):
            return None  # «мягкая 404» — сайт отдаёт главную страницу на любой адрес
        if check(body, resp.body):
            fid = "web.exposed." + re.sub(r"[^a-z0-9]+", "_", p.lower()).strip("_")
            return Finding(fid, CAT, sev, title, detail=f"Адрес: {resp.url}", why=why,
                           fix="Удалите файл с сервера или закройте к нему доступ, затем смените пароли, которые там были.")
    return None


# ------------------------------------------------------------------ entry

def run(domain: str, resolver: Resolver, log=lambda m: None) -> list[Finding]:
    host = domain
    if not resolver.query(host, "A").of("A") and not resolver.query(host, "AAAA").of("AAAA"):
        www = "www." + domain
        if resolver.query(www, "A").of("A"):
            host = www
        else:
            return [Finding("web.nosite", CAT, INFO, "У домена нет сайта (нет A/AAAA-записей)")]

    out: list[Finding] = []
    log(f"Сайт: сертификат {host}…")
    info = tls_info(host)
    legacy = supports_legacy_tls(host) if info.get("ok") else None
    out += analyze_tls(host, info, legacy)

    log("Сайт: перенаправление на HTTPS…")
    try:
        out += analyze_redirect(fetch(f"http://{host}/", timeout=8))
    except Exception:  # noqa: BLE001 — порт 80 может быть закрыт, это нормально
        pass

    if info.get("kind") == "noconnect":
        return out
    log("Сайт: заголовки безопасности…")
    verify = bool(info.get("ok"))
    base = f"https://{host}"
    try:
        main = fetch(base + "/", follow=5, verify=verify, timeout=12)
        out += analyze_headers(main)
        base = re.match(r"https?://[^/]+", main.url).group(0)
    except Exception as e:  # noqa: BLE001
        out.append(Finding("web.fetch.error", CAT, INFO, "Главная страница не загрузилась", tech=str(e)))

    log("Сайт: забытые служебные файлы…")
    for path, *_ in EXPOSED:
        try:
            f = analyze_exposed(path, fetch(base + path, verify=verify, timeout=8, max_body=64 * 1024))
        except Exception:  # noqa: BLE001
            continue
        if f:
            out.append(f)
    if not any(f.id.startswith("web.exposed") for f in out):
        out.append(Finding("web.exposed.none", CAT, OK, "Служебные файлы (.git, .env, бэкапы) не найдены"))
    return out
