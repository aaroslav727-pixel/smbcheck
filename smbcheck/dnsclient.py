"""Мини DNS-клиент без внешних зависимостей.

Спрашивает публичные резолверы (так мы видим домен так же, как его видит весь интернет),
по UDP, при обрезанном ответе — по TCP. Если сеть режет внешний DNS (университет, гостиница,
офис с жёстким фаерволом), по очереди пробует: DNS-сервер, который выдала сама сеть,
DNS-over-HTTPS и, для A/AAAA, системный резолвер Windows.
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import socket
import struct
import sys
import threading
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .tlsctx import context as ssl_context

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "CAA": 257}
TYPE_NAMES = {v: k for k, v in TYPES.items()}

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://1.1.1.1/dns-query",                 # без DNS-имени — если сеть не даёт разрешить cloudflare-dns.com
    "https://dns.quad9.net:5053/dns-query",
]
FAIL_LIMIT = 3          # столько провалов подряд — сервер временно пропускаем
REPROBE_EVERY = 25      # раз в столько запросов снова пробуем «упавшие» серверы

NOERROR, NXDOMAIN = 0, 3


class DNSError(Exception):
    """Не удалось получить ответ ни от одного резолвера."""


@dataclass
class DNSAnswer:
    rcode: int = NOERROR
    records: list[tuple[str, object]] = field(default_factory=list)  # (тип, данные)

    def of(self, rtype: str) -> list:
        return [d for t, d in self.records if t == rtype]

    @property
    def nxdomain(self) -> bool:
        return self.rcode == NXDOMAIN


# ---------------------------------------------------------------- wire format

def build_query(name: str, rtype: str, qid: int | None = None) -> bytes:
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)  # RD=1, 1 вопрос, 1 доп. (EDNS)
    qname = b"".join(
        bytes([len(p)]) + p for p in (lbl.encode("idna") for lbl in name.strip(".").split(".") if lbl)
    ) + b"\x00"
    question = qname + struct.pack(">HH", TYPES[rtype], 1)
    edns = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)  # OPT, буфер 1232 байта
    return header + question + edns


def _read_name(msg: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    jumped_end = None
    while True:
        if off >= len(msg) or depth > 20:
            raise ValueError("битое имя в DNS-ответе")
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:  # сжатие имени (указатель)
            ptr = struct.unpack(">H", msg[off:off + 2])[0] & 0x3FFF
            if jumped_end is None:
                jumped_end = off + 2
            off = ptr
            depth += 1
            continue
        off += 1
        labels.append(msg[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(labels), (jumped_end if jumped_end is not None else off)


def _parse_rdata(msg: bytes, rtype: int, off: int, rdlen: int):
    rd = msg[off:off + rdlen]
    if rtype == 1:
        return str(ipaddress.IPv4Address(rd))
    if rtype == 28:
        return str(ipaddress.IPv6Address(rd))
    if rtype in (2, 5):
        return _read_name(msg, off)[0]
    if rtype == 15:
        pref = struct.unpack(">H", rd[:2])[0]
        return (pref, _read_name(msg, off + 2)[0])
    if rtype == 16:
        parts, i = [], 0
        while i < len(rd):
            ln = rd[i]
            parts.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
            i += 1 + ln
        return "".join(parts)
    if rtype == 257:
        flags, tlen = rd[0], rd[1]
        return (flags, rd[2:2 + tlen].decode("ascii", "replace"), rd[2 + tlen:].decode("utf-8", "replace"))
    if rtype == 43:
        return struct.unpack(">H", rd[:2])[0]  # key tag
    return rd.hex()


def parse_response(msg: bytes, expect_id: int | None = None) -> tuple[DNSAnswer, bool]:
    """Возвращает (ответ, обрезан_ли)."""
    qid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    if expect_id is not None and qid != expect_id:
        raise ValueError("чужой ответ")
    truncated = bool(flags & 0x0200)
    rcode = flags & 0x000F
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    ans = DNSAnswer(rcode=rcode)
    for _ in range(an):
        _, off = _read_name(msg, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        if rtype in TYPE_NAMES:
            ans.records.append((TYPE_NAMES[rtype], _parse_rdata(msg, rtype, off, rdlen)))
        off += rdlen
    return ans, truncated


# ---------------------------------------------------------------- transports

def _udp(server: str, q: bytes, timeout: float) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        return s.recvfrom(4096)[0]


def _tcp(server: str, q: bytes, timeout: float) -> bytes:
    with socket.create_connection((server, 53), timeout=timeout) as s:
        s.sendall(struct.pack(">H", len(q)) + q)
        ln = struct.unpack(">H", _recv_exact(s, 2))[0]
        return _recv_exact(s, ln)


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("соединение закрыто")
        buf += chunk
    return buf


_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def parse_doh_json(data: dict, rtype: str) -> DNSAnswer:
    ans = DNSAnswer(rcode=int(data.get("Status", 0)))
    for rr in data.get("Answer", []) or []:
        t = TYPE_NAMES.get(rr.get("type"))
        if t != rtype:
            continue
        raw = str(rr.get("data", ""))
        if t == "TXT":
            chunks = _QUOTED.findall(raw)
            val = "".join(c.replace('\\"', '"') for c in chunks) if chunks else raw
        elif t == "MX":
            pref, _, host = raw.partition(" ")
            val = (int(pref), host.rstrip("."))
        elif t == "CAA":
            m = re.match(r'(\d+)\s+(\S+)\s+"?(.*?)"?$', raw)
            val = (int(m.group(1)), m.group(2), m.group(3)) if m else (0, "", raw)
        elif t == "DS":
            val = int(raw.split()[0]) if raw.split() and raw.split()[0].isdigit() else raw
        elif t in ("NS", "CNAME"):
            val = raw.rstrip(".")
        else:
            val = raw
        ans.records.append((t, val))
    return ans


def _doh(url: str, name: str, rtype: str, timeout: float) -> DNSAnswer:
    full = url + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(full, headers={"Accept": "application/dns-json", "User-Agent": "SMBCheck"})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as r:
        return parse_doh_json(json.loads(r.read().decode()), rtype)


# коды getaddrinfo: «такого имени нет» и «имя есть, но адресов этого типа нет» (POSIX и Windows)
_GAI_NONAME = {getattr(socket, "EAI_NONAME", -2), 11001}
_GAI_NODATA = {getattr(socket, "EAI_NODATA", -5), 11004}


def _system_lookup(name: str, rtype: str) -> DNSAnswer:
    """A/AAAA через резолвер операционной системы — последний запасной путь."""
    fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
    try:
        infos = socket.getaddrinfo(name, None, fam, socket.SOCK_STREAM)
    except socket.gaierror as e:
        if e.errno in _GAI_NODATA:
            return DNSAnswer()
        if e.errno in _GAI_NONAME:
            return DNSAnswer(rcode=NXDOMAIN)
        raise
    return DNSAnswer(records=[(rtype, ip) for ip in dict.fromkeys(str(i[4][0]) for i in infos)])


def _valid_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False


def system_dns_servers() -> list[str]:
    """DNS-серверы, которые выдала текущая сеть (реестр Windows или /etc/resolv.conf)."""
    found: list[str] = []
    if sys.platform == "win32":
        try:
            import winreg
            base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
                for i in range(winreg.QueryInfoKey(k)[0]):
                    try:
                        with winreg.OpenKey(k, winreg.EnumKey(k, i)) as sk:
                            for val in ("NameServer", "DhcpNameServer"):
                                try:
                                    v, _ = winreg.QueryValueEx(sk, val)
                                except OSError:
                                    continue
                                found += re.split(r"[\s,]+", str(v).strip())
                    except OSError:
                        continue
        except Exception:  # noqa: BLE001
            pass
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
                found += [m.group(1) for m in (re.match(r"\s*nameserver\s+(\S+)", ln) for ln in f) if m]
        except OSError:
            pass
    return [ip for ip in dict.fromkeys(found) if _valid_ipv4(ip) and ip not in RESOLVERS]


# ---------------------------------------------------------------- public API

class Resolver:
    """Потокобезопасен: проверка двойников делает запросы из нескольких потоков.

    Сервер, который не ответил FAIL_LIMIT раз подряд, временно пропускается, а раз в
    REPROBE_EVERY запросов снова получает шанс — так единичный сбой сети не отключает UDP
    до конца проверки (раньше одного таймаута хватало, чтобы перейти на DoH навсегда).
    """

    def __init__(self, servers: list[str] | None = None, timeout: float = 3.0, attempts: int = 2,
                 use_system: bool = True, doh: list[str] | None = None):
        self.servers = list(servers or RESOLVERS)
        if use_system and servers is None:
            self.servers += system_dns_servers()
        self.doh = list(DOH_ENDPOINTS if doh is None else doh)
        self.timeout = timeout
        self.attempts = attempts
        self.use_system = use_system
        self._cache: dict[tuple[str, str], DNSAnswer] = {}
        self._fails: dict[str, int] = {}
        self._lock = threading.Lock()
        self._n = 0

    # ---- здоровье серверов
    def _healthy(self, names: list[str]) -> list[str]:
        with self._lock:
            self._n += 1
            if self._n % REPROBE_EVERY == 0:
                return list(names)
            ok = [x for x in names if self._fails.get(x, 0) < FAIL_LIMIT]
            return sorted(ok, key=lambda x: self._fails.get(x, 0))

    def _mark(self, server: str, good: bool) -> None:
        with self._lock:
            self._fails[server] = 0 if good else self._fails.get(server, 0) + 1

    def _udp_query(self, server: str, name: str, rtype: str) -> DNSAnswer | None:
        qid = random.randint(0, 0xFFFF)
        q = build_query(name, rtype, qid)
        ans, truncated = parse_response(_udp(server, q, self.timeout), qid)
        if truncated:
            ans, _ = parse_response(_tcp(server, q, self.timeout), qid)
        return ans

    def query(self, name: str, rtype: str) -> DNSAnswer:
        key = (name.lower().strip("."), rtype)
        if key in self._cache:
            return self._cache[key]
        errors: list[str] = []
        ans = None
        servers = self._healthy(self.servers)
        for _attempt in range(self.attempts):
            for server in servers:
                try:
                    got = self._udp_query(server, key[0], rtype)
                except (OSError, ValueError, struct.error) as e:
                    self._mark(server, False)
                    errors.append(f"{server}: {e}")
                    continue
                if got.rcode in (NOERROR, NXDOMAIN):
                    self._mark(server, True)
                    ans = got
                    break
                errors.append(f"{server}: rcode {got.rcode}")   # SERVFAIL и т.п. — сервер жив, спросим другой
            if ans is not None:
                break
        if ans is None:
            for url in self._healthy(self.doh):
                try:
                    ans = _doh(url, key[0], rtype, self.timeout + 3)
                    self._mark(url, True)
                    break
                except Exception as e:  # noqa: BLE001 — сеть может падать как угодно
                    self._mark(url, False)
                    errors.append(f"DoH {url}: {e}")
        if ans is None and self.use_system and rtype in ("A", "AAAA"):
            try:
                ans = _system_lookup(key[0], rtype)
            except OSError as e:
                errors.append(f"система: {e}")
        if ans is None:
            raise DNSError(f"DNS-запрос {rtype} {name} не удался: " + "; ".join(errors[-3:] or ["нет доступных серверов"]))
        self._cache[key] = ans
        return ans

    def txt(self, name: str) -> list[str]:
        return self.query(name, "TXT").of("TXT")
