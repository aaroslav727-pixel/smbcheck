import socket

import pytest

from smbcheck import dnsclient
from smbcheck.checks import brand
from smbcheck.dnsclient import DNSAnswer, DNSError, NXDOMAIN, Resolver
from smbcheck.models import INFO, MEDIUM, OK, Finding, ScanResult
from smbcheck.report import render_html
from smbcheck.storage import Client, Consent, Settings


def _resolver(monkeypatch, udp, doh=None, system=None, **kw):
    monkeypatch.setattr(Resolver, "_udp_query", lambda self, server, name, rtype: udp(server, name, rtype))
    monkeypatch.setattr(dnsclient, "_doh", doh or (lambda url, name, rtype, t: (_ for _ in ()).throw(OSError("doh off"))))
    monkeypatch.setattr(dnsclient, "_system_lookup", system or (lambda n, t: (_ for _ in ()).throw(OSError("sys off"))))
    return Resolver(servers=["s1", "s2"], doh=["https://doh"], **kw)


def test_single_timeout_does_not_disable_udp(monkeypatch):
    calls = []

    def udp(server, name, rtype):
        calls.append((server, name))
        if name == "bad.example" or (name == "a.example" and len(calls) <= 2):
            raise socket.timeout("timed out")
        return DNSAnswer(records=[("A", "1.2.3.4")])

    r = _resolver(monkeypatch, udp, doh=lambda *a: DNSAnswer(records=[("A", "9.9.9.9")]))
    assert r.query("a.example", "A").of("A") == ["1.2.3.4"]      # второй круг попыток
    assert r.query("bad.example", "A").of("A") == ["9.9.9.9"]    # ушёл в DoH
    assert r.query("c.example", "A").of("A") == ["1.2.3.4"]      # но UDP после этого не выключен


def test_dead_server_is_skipped(monkeypatch):
    seen = []

    def udp(server, name, rtype):
        seen.append(server)
        if server == "s1":
            raise socket.timeout("timed out")
        return DNSAnswer()

    r = _resolver(monkeypatch, udp)
    for i in range(6):
        r.query(f"n{i}.example", "A")
    assert seen[-3:] == ["s2", "s2", "s2"]   # после FAIL_LIMIT провалов s1 не тормозит каждый запрос


def test_system_fallback_and_total_failure(monkeypatch):
    def udp(*a):
        raise socket.timeout("timed out")

    r = _resolver(monkeypatch, udp, system=lambda n, t: DNSAnswer(rcode=NXDOMAIN))
    assert r.query("nope.example", "A").nxdomain
    with pytest.raises(DNSError):
        r.query("nope.example", "MX")        # MX системный резолвер не умеет


def test_system_dns_servers_parsing(monkeypatch, tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 10.0.0.1\nnameserver 1.1.1.1\nnameserver fe80::1\n# x\n")
    real_open = open
    monkeypatch.setattr(dnsclient.sys, "platform", "linux")
    monkeypatch.setattr("builtins.open", lambda p, *a, **k: real_open(conf if p == "/etc/resolv.conf" else p, *a, **k))
    assert dnsclient.system_dns_servers() == ["10.0.0.1"]


def test_ssl_context_has_certifi_roots():
    from smbcheck import tlsctx
    ctx = tlsctx.context()
    assert ctx.verify_mode.name == "CERT_REQUIRED" and ctx.check_hostname
    if tlsctx.has_certifi():
        assert ctx.cert_store_stats()["x509_ca"] > 50


class Flaky:
    """Первый запрос к каждому имени падает, второй отвечает."""
    def __init__(self, zone):
        self.zone, self.seen = zone, set()

    def query(self, name, rtype):
        if (name, rtype) not in self.seen and rtype == "A":
            self.seen.add((name, rtype))
            raise DNSError("timeout")
        return DNSAnswer(records=[("A", "1.2.3.4")]) if name in self.zone else DNSAnswer(rcode=NXDOMAIN)


def test_brand_retry_pass_and_summary():
    r = Flaky({"izdeplus.kz"})
    out = brand.run("izdeplus.com", r, ct=False, whois=False)
    ids = [f.id for f in out]
    assert "brand.lookalike.izdeplus.kz" in ids and "brand.lookalike.error.dns" not in ids
    sm = brand.parse_summary(out[0])
    assert out[0].id == brand.SUMMARY_ID and sm["unresolved"] == 0 and sm["registered"] == 1 and sm["ct"] == "off"


def test_brand_partial_is_honest():
    class Half:
        def query(self, name, rtype):
            if hash(name) % 3 == 0:
                raise DNSError("timeout")
            return DNSAnswer(rcode=NXDOMAIN)
    out = brand.run("izdeplus.com", Half(), ct=False, whois=False)
    ok = next(f for f in out if f.id == "brand.lookalike.ok")
    assert ok.title.startswith("Среди проверенных")
    assert brand.parse_summary(out[0])["unresolved"] > 0


def test_report_phishing_section_partial():
    c = Client("test3", "izdeplus.com", consent=Consent(True, "06.11.2026", "", "3"))
    fs = [Finding("email.dmarc.none", "email", MEDIUM, "DMARC только наблюдает (p=none)"),
          brand.summary(150, 69, 0, "error", 0, ["izdeplus"]),
          Finding("brand.lookalike.ok", "brand", OK, "Среди проверенных 81 из 150 вариантов двойников не найдено"),
          Finding("brand.ct.error", "brand", INFO, "Журналы сертификатов (crt.sh) не ответили по «izdeplus»")]
    html = render_html(ScanResult("izdeplus.com", findings=fs, checks_run=["email", "brand"]), c, Settings())
    for text in ("Фишинг от вашего имени", "Можно подделать", "Проверено частично", "81 из 150",
                 "Сервис не ответил", "Что мы искали", "izdeplus.uz"):
        assert text in html, text
    assert "Двойников бренда не найдено." not in html


def test_report_phishing_section_found():
    from smbcheck.demo import demo_client, demo_results
    cur, _ = demo_results()
    html = render_html(cur, demo_client(), Settings())
    assert "romashka-demo-online.ru (зарегистрирован 4 дн. назад)" in html and "Что делать с найденным" in html
    details = html.split("<h2>Подробности</h2>", 1)[1]
    assert "romashka-demo-online" not in details      # двойники не дублируются в «Подробностях»


def test_old_and_for_sale_lookalikes_are_low():
    import datetime as dt
    from smbcheck.models import HIGH, LOW, MEDIUM
    now = dt.datetime(2026, 11, 6, tzinfo=dt.timezone.utc)
    old = now - dt.timedelta(days=365 * 9)
    hits = [
        brand.Hit("ideplus.com", "пропущена буква", ips=["1.2.3.4"], created=old),                    # продаётся/чужой
        brand.Hit("izdepluss.com", "удвоена буква", ips=["1.2.3.4"], mx=["mx.x"], created=old),       # давний, с почтой
        brand.Hit("izdeplus.net", "другая зона", ips=["1.2.3.4"], ns=["ns1.afternic.com"]),           # на площадке продажи
        brand.Hit("izdeplus-pay.com", "добавлено слово", ips=["1.2.3.4"], created=now - dt.timedelta(days=3)),
    ]
    fs = {f.id.split(".", 2)[2]: f for f in brand.analyze_hits(hits, 150, now)}
    assert fs["ideplus.com"].severity == LOW and fs["ideplus.com"].title == "Похожий домен: ideplus.com"
    assert "9 лет" in fs["ideplus.com"].detail and "продажу" in fs["ideplus.com"].detail
    assert fs["izdepluss.com"].severity == MEDIUM and "другая компания" in fs["izdepluss.com"].detail
    assert fs["izdeplus.net"].severity == LOW and "припаркован" in fs["izdeplus.net"].detail
    assert fs["izdeplus-pay.com"].severity == HIGH and fs["izdeplus-pay.com"].title.startswith("Домен-двойник")
    assert brand._years(1) == "год" and brand._years(3) == "года" and brand._years(11) == "лет"


def test_diff_marks_lookalike_after_partial_scan():
    from smbcheck.models import LOW
    from smbcheck.scoring import diff
    prev = ScanResult("izdeplus.com", checks_run=["brand"],
                      findings=[brand.summary(150, 69, 0, "error", 0, ["izdeplus"])])
    cur = ScanResult("izdeplus.com", checks_run=["brand"],
                     findings=[brand.summary(150, 0, 1, "ok", 0, ["izdeplus"]),
                               Finding("brand.lookalike.ideplus.com", "brand", LOW, "Похожий домен: ideplus.com")])
    [f] = diff(cur, prev).new
    assert "впервые удалось проверить" in f.title
    prev_full = ScanResult("izdeplus.com", checks_run=["brand"], findings=[brand.summary(150, 0, 0, "ok", 0, [])])
    assert diff(cur, prev_full).new[0].title == "Похожий домен: ideplus.com"
