"""Мини DNS-клиент без внешних зависимостей.

Спрашивает публичные резолверы (так мы видим домен так же, как его видит весь интернет),
по UDP, при обрезанном ответе — по TCP, а если порт 53 закрыт — через DNS-over-HTTPS.
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import socket
import struct
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "CAA": 257}
TYPE_NAMES = {v: k for k, v in TYPES.items()}

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

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
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return parse_doh_json(json.loads(r.read().decode()), rtype)


# ---------------------------------------------------------------- public API

class Resolver:
    def __init__(self, servers: list[str] | None = None, timeout: float = 3.0):
        self.servers = servers or RESOLVERS
        self.timeout = timeout
        self._cache: dict[tuple[str, str], DNSAnswer] = {}
        self._udp_broken = False

    def query(self, name: str, rtype: str) -> DNSAnswer:
        key = (name.lower().strip("."), rtype)
        if key in self._cache:
            return self._cache[key]
        errors: list[str] = []
        ans = None
        if not self._udp_broken:
            for server in self.servers:
                try:
                    qid = random.randint(0, 0xFFFF)
                    q = build_query(key[0], rtype, qid)
                    ans, truncated = parse_response(_udp(server, q, self.timeout), qid)
                    if truncated:
                        ans, _ = parse_response(_tcp(server, q, self.timeout), qid)
                    if ans.rcode in (NOERROR, NXDOMAIN):
                        break
                    errors.append(f"{server}: rcode {ans.rcode}")
                    ans = None
                except (OSError, ValueError, struct.error) as e:
                    errors.append(f"{server}: {e}")
                    ans = None
            if ans is None:
                self._udp_broken = True  # дальше сразу идём через DoH
        if ans is None:
            for url in DOH_ENDPOINTS:
                try:
                    ans = _doh(url, key[0], rtype, self.timeout + 3)
                    break
                except Exception as e:  # noqa: BLE001 — сеть может падать как угодно
                    errors.append(f"DoH {url}: {e}")
        if ans is None:
            raise DNSError(f"DNS-запрос {rtype} {name} не удался: " + "; ".join(errors[-3:]))
        self._cache[key] = ans
        return ans

    def txt(self, name: str) -> list[str]:
        return self.query(name, "TXT").of("TXT")
