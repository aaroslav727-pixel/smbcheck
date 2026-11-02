"""Открытые сервисы: проверка небольшого списка опасных портов (TCP connect).

Сканируются ТОЛЬКО адреса сайта клиента и IP офиса из карточки клиента,
на которые есть письменное согласие.
"""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from ..dnsclient import Resolver
from ..models import CRITICAL, HIGH, INFO, LOW, MEDIUM, OK, Finding

CAT = "network"

# порт: (сервис, важность, почему опасно)
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    3389: ("Удалённый рабочий стол Windows (RDP)", CRITICAL,
           "Самый частый вход для вирусов-шифровальщиков: пароли подбирают автоматически круглосуточно."),
    445: ("Общие папки Windows (SMB)", CRITICAL,
          "Через этот порт распространялись WannaCry и другие черви; из интернета он должен быть закрыт."),
    6379: ("База Redis", CRITICAL, "Часто работает без пароля — данные можно прочитать или стереть."),
    27017: ("База MongoDB", CRITICAL, "Открытые MongoDB массово выкачивают и шифруют с требованием выкупа."),
    9200: ("Elasticsearch", CRITICAL, "Частая причина крупных утечек баз клиентов."),
    2375: ("Docker API без шифрования", CRITICAL, "Даёт полный контроль над сервером."),
    23: ("Telnet", HIGH, "Пароли передаются открытым текстом, протокол устарел."),
    139: ("NetBIOS (Windows)", HIGH, "Раскрывает сведения о сети и открывает доступ к общим папкам."),
    5900: ("Удалённый доступ VNC", HIGH, "Часто защищён слабым паролем или вовсе без него."),
    3306: ("База MySQL", HIGH, "База данных не должна быть доступна из интернета — только с сервера сайта."),
    5432: ("База PostgreSQL", HIGH, "База данных не должна быть доступна из интернета."),
    1433: ("База Microsoft SQL", HIGH, "Постоянная цель подбора паролей."),
    11211: ("Memcached", HIGH, "Используется для DDoS-атак и утечек данных."),
    8291: ("Управление MikroTik (Winbox)", HIGH,
           "Роутеры MikroTik массово взламывают через Winbox; управление должно быть доступно только изнутри сети."),
    1541: ("Сервер 1С:Предприятие", MEDIUM, "Сервер 1С с бухгалтерией виден из интернета; доступ лучше давать через VPN."),
    1540: ("Агент сервера 1С", MEDIUM, "Служебный порт 1С не должен быть доступен из интернета."),
    21: ("FTP", MEDIUM, "Пароли передаются открытым текстом; лучше SFTP."),
    10000: ("Панель Webmin", MEDIUM, "Панель управления сервером видна всему интернету."),
    8728: ("API MikroTik", MEDIUM, "Управление роутером доступно из интернета."),
    22: ("SSH", INFO, "Нормально для сервера, если вход только по ключам и пароль отключён."),
}

FIX = "Закройте порт на роутере или в файрволе хостинга. Если доступ нужен сотрудникам — давайте его через VPN."


def check_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def scan_ip(ip: str, ports: list[int] | None = None, workers: int = 20) -> list[int]:
    ports = ports or list(RISKY_PORTS)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda p: (p, check_port(ip, p)), ports))
    return sorted(p for p, is_open in results if is_open)


def analyze_ports(target_label: str, ip: str, open_ports: list[int], shared_hint: bool) -> list[Finding]:
    out: list[Finding] = []
    for p in open_ports:
        name, sev, why = RISKY_PORTS.get(p, (f"порт {p}", LOW, ""))
        if shared_hint and sev in (CRITICAL, HIGH) and p in (3306, 21, 22, 5432):
            sev = MEDIUM  # на общем хостинге эти порты часто открывает сам хостинг
        extra = " Адрес сайта может принадлежать хостингу — уточните, ваш ли это сервер." if shared_hint else ""
        out.append(Finding(
            f"network.{p}.{ip}", CAT, sev, f"Открыт порт {p}: {name}",
            detail=f"{target_label}: {ip}.{extra}", why=why, fix=FIX if sev != INFO else
            "Убедитесь, что вход по паролю отключён (PasswordAuthentication no).",
            tech=f"{ip}:{p}/tcp open"))
    return out


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def run(domain: str, resolver: Resolver, office_ips: list[str] | None = None, log=lambda m: None) -> list[Finding]:
    targets: list[tuple[str, str, bool]] = []  # (метка, ip, сайт_ли)
    for ip in resolver.query(domain, "A").of("A")[:2]:
        targets.append((f"Сервер сайта {domain}", ip, True))
    for ip in office_ips or []:
        ip = ip.strip()
        if ip and is_public(ip):
            targets.append(("Офис", ip, False))
    if not targets:
        return [Finding("network.none", CAT, INFO, "Нет публичных адресов для проверки портов")]
    out: list[Finding] = []
    for label, ip, is_site in targets:
        if not is_public(ip):
            continue
        log(f"Порты: {label} {ip}…")
        out += analyze_ports(label, ip, scan_ip(ip), shared_hint=is_site)
    if not any(f.is_problem for f in out):
        checked = ", ".join(ip for _, ip, _ in targets)
        out.append(Finding("network.ok", CAT, OK, f"Опасные сервисы снаружи не видны ({len(RISKY_PORTS)} портов)",
                           tech=checked))
    return out
