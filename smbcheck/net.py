"""HTTP-запросы без автоматических редиректов (стандартная библиотека)."""
from __future__ import annotations

import socket
import ssl
import time
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import Message

from .tlsctx import context as ssl_context

USER_AGENT = "Mozilla/5.0 (compatible; SMBCheck/0.1; authorized security check)"
MAX_BODY = 256 * 1024


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: Message
    body: bytes = b""
    chain: list[tuple[int, str]] = field(default_factory=list)  # (код, url) редиректов

    def header(self, name: str) -> str:
        return self.headers.get(name, "") or ""

    def headers_all(self, name: str) -> list[str]:
        return self.headers.get_all(name) or []

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _opener(verify: bool) -> urllib.request.OpenerDirector:
    if verify:
        ctx = ssl_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))


def fetch(url: str, *, follow: int = 0, verify: bool = True, timeout: float = 10.0,
          max_body: int = MAX_BODY, retries: int = 0) -> HttpResponse:
    """GET url; follow — сколько редиректов пройти. Исключения сети пробрасываются.

    retries — сколько раз повторить при таймауте/обрыве или ответе 429/5xx (для внешних API).
    """
    for attempt in range(retries + 1):
        try:
            r = _fetch_once(url, follow, verify, timeout, max_body)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ssl.SSLError) as e:
            if attempt >= retries or isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                raise
        else:
            if r.status in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(2 * (attempt + 1))
                continue
            return r
        time.sleep(1 + attempt)
    raise RuntimeError("unreachable")


def _fetch_once(url: str, follow: int, verify: bool, timeout: float, max_body: int) -> HttpResponse:
    opener = _opener(verify)
    chain: list[tuple[int, str]] = []
    current = url
    for _ in range(follow + 1):
        req = urllib.request.Request(current, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        try:
            resp = opener.open(req, timeout=timeout)
            status, headers = resp.status, resp.headers
            body = resp.read(max_body)
            resp.close()
        except urllib.error.HTTPError as e:  # 3xx/4xx/5xx приходят сюда
            status, headers = e.code, e.headers
            try:
                body = e.read(max_body)
            except Exception:  # noqa: BLE001
                body = b""
        loc = headers.get("Location") if headers else None
        if status in (301, 302, 303, 307, 308) and loc and len(chain) < follow:
            chain.append((status, current))
            current = urllib.parse.urljoin(current, loc)
            continue
        return HttpResponse(current, status, headers, body, chain)
    return HttpResponse(current, status, headers, body, chain)
