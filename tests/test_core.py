import base64
import datetime as dt
import struct
from email.message import Message

import pytest

from smbcheck import dnsclient
from smbcheck.checks import domain as dom
from smbcheck.checks import email as em
from smbcheck.checks import leaks, network, web
from smbcheck.dnsclient import DNSAnswer
from smbcheck.models import CRITICAL, HIGH, INFO, LOW, MEDIUM, OK, Finding, ScanResult
from smbcheck.net import HttpResponse
from smbcheck.report import render_html, summary_text
from smbcheck.scanner import ConsentError, run_scan
from smbcheck.scoring import diff, score, top_actions
from smbcheck.storage import Client, Consent, Settings, Store, normalize_domain


# ------------------------------------------------------------- DNS

def _name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"


def test_dns_wire_roundtrip():
    q = dnsclient.build_query("example.ru", "TXT", qid=0x1234)
    assert q[:2] == b"\x12\x34"
    # ответ: заголовок + вопрос + 2 записи (TXT из двух строк и MX со сжатием имени)
    hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
    question = _name("example.ru") + struct.pack(">HH", 16, 1)
    txt = b"\x0bv=spf1 -all" + b"\x03 ok"
    rr1 = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(txt)) + txt
    mx = struct.pack(">H", 10) + b"\x02mx\xc0\x0c"
    rr2 = b"\xc0\x0c" + struct.pack(">HHIH", 15, 1, 60, len(mx)) + mx
    ans, tc = dnsclient.parse_response(hdr + question + rr1 + rr2, 0x1234)
    assert not tc and ans.rcode == 0
    assert ans.of("TXT") == ["v=spf1 -all ok"]
    assert ans.of("MX") == [(10, "mx.example.ru")]


def test_doh_json():
    data = {"Status": 0, "Answer": [
        {"type": 16, "data": '"v=spf1 include:_spf.yandex.net " "-all"'},
        {"type": 15, "data": "10 mx.yandex.net."},
        {"type": 257, "data": '0 issue "letsencrypt.org"'},
    ]}
    assert dnsclient.parse_doh_json(data, "TXT").of("TXT") == ["v=spf1 include:_spf.yandex.net -all"]
    assert dnsclient.parse_doh_json(data, "MX").of("MX") == [(10, "mx.yandex.net")]
    assert dnsclient.parse_doh_json(data, "CAA").of("CAA") == [(0, "issue", "letsencrypt.org")]


class FakeResolver:
    def __init__(self, zone):
        self.zone = zone  # {(name, type): [data]}

    def query(self, name, rtype):
        recs = self.zone.get((name, rtype), [])
        return DNSAnswer(records=[(rtype, r) for r in recs])

    def txt(self, name):
        return self.query(name, "TXT").of("TXT")


# ------------------------------------------------------------- почта

def ids(fs):
    return {f.id: f.severity for f in fs}


def test_spf_cases():
    assert ids(em.analyze_spf("a.ru", [], True, None)) == {"email.spf.missing": HIGH}
    assert ids(em.analyze_spf("a.ru", [], False, None)) == {"email.spf.missing": MEDIUM}
    assert ids(em.analyze_spf("a.ru", ["v=spf1 +all"], True, 0))["email.spf.plusall"] == CRITICAL
    assert ids(em.analyze_spf("a.ru", ["v=spf1 a ?all"], True, 1))["email.spf.neutral"] == MEDIUM
    assert ids(em.analyze_spf("a.ru", ["v=spf1 a", "v=spf1 mx"], True, None)) == {"email.spf.multiple": HIGH}
    assert ids(em.analyze_spf("a.ru", ["v=spf1 include:x -all"], True, 11))["email.spf.lookups"] == HIGH
    assert ids(em.analyze_spf("a.ru", ["v=spf1 include:_spf.yandex.net -all"], True, 2)) == {"email.spf.ok": OK}


def test_spf_lookup_count_recursive():
    r = FakeResolver({
        ("a.ru", "TXT"): ["v=spf1 include:b.ru include:c.ru mx -all"],
        ("b.ru", "TXT"): ["v=spf1 a mx include:c.ru -all"],
        ("c.ru", "TXT"): ["v=spf1 ip4:1.2.3.4 a -all"],
    })
    # a: include b, include c, mx = 3; b: a, mx, include c(уже видели) = 3; c: a = 1
    assert em.count_spf_lookups(r, "v=spf1 include:b.ru include:c.ru mx -all") == 7


def test_dmarc_cases():
    assert ids(em.analyze_dmarc("a.ru", [])) == {"email.dmarc.missing": HIGH}
    assert ids(em.analyze_dmarc("a.ru", ["v=DMARC1; p=none; rua=mailto:x@a.ru"])) == {"email.dmarc.none": MEDIUM}
    r = ids(em.analyze_dmarc("a.ru", ["v=DMARC1; p=reject; sp=none"]))
    assert r == {"email.dmarc.ok": OK, "email.dmarc.sp": LOW, "email.dmarc.norua": LOW}


def _rsa_der_len(n):
    return base64.b64encode(b"\x30" * n).decode()


def test_dkim():
    assert em.dkim_key_bits(f"v=DKIM1; k=rsa; p={_rsa_der_len(162)}") == 1024
    assert em.dkim_key_bits(f"v=DKIM1; p={_rsa_der_len(294)}") == 2048
    assert em.dkim_key_bits("v=DKIM1; p=") == 0
    fs = em.analyze_dkim("a.ru", {"mail": f"v=DKIM1; p={_rsa_der_len(162)}"}, "Яндекс 360")
    assert ids(fs) == {"email.dkim.ok": OK, "email.dkim.weak": LOW}
    nf = em.analyze_dkim("a.ru", {}, "Яндекс 360")[0]
    assert nf.severity == MEDIUM and "Яндекс 360" in nf.fix


def test_provider_detection():
    assert em.detect_provider(["mx.yandex.net"]) == "Яндекс 360"
    assert em.detect_provider(["a-ru.mail.protection.outlook.com"]) == "Microsoft 365"
    assert em.detect_provider(["aspmx.l.google.com"]) == "Google Workspace"
    assert em.detect_provider(["mx1.example.org"]) == ""


def test_email_run_full():
    der = _rsa_der_len(294)
    r = FakeResolver({
        ("shop.ru", "MX"): [(10, "mx.yandex.net")],
        ("shop.ru", "TXT"): ["v=spf1 include:_spf.yandex.net ~all", "google-site-verification=x"],
        ("_spf.yandex.net", "TXT"): ["v=spf1 ip4:1.1.1.1 -all"],
        ("_dmarc.shop.ru", "TXT"): [],
        ("mail._domainkey.shop.ru", "TXT"): [f"v=DKIM1; k=rsa; p={der}"],
    })
    got = ids(em.run("shop.ru", r))
    assert got["email.dmarc.missing"] == HIGH
    assert got["email.spf.ok"] == OK and got["email.dkim.ok"] == OK


# ------------------------------------------------------------- сайт

def resp(status=200, headers=None, body=b"", url="https://a.ru/"):
    m = Message()
    for k, v in (headers or {}).items():
        if isinstance(v, list):
            for x in v:
                m[k] = x
        else:
            m[k] = v
    return HttpResponse(url, status, m, body)


def test_headers():
    fs = ids(web.analyze_headers(resp(headers={
        "Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3",
        "Set-Cookie": ["PHPSESSID=abc; path=/", "x=1; Secure; HttpOnly"],
    }, body=b'<meta name="generator" content="WordPress 6.1">')))
    assert fs["web.hsts.missing"] == LOW
    assert fs["web.headers.missing"] == LOW
    assert fs["web.version.leak"] == LOW
    assert fs["web.cookies"] == LOW
    assert fs["web.cms"] == INFO
    good = web.analyze_headers(resp(headers={
        "Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'", "Referrer-Policy": "no-referrer",
        "Server": "nginx"}))
    assert good == []


def test_redirect():
    assert ids(web.analyze_redirect(resp(301, {"Location": "https://a.ru/"}, url="http://a.ru/"))) == {"web.redirect.ok": OK}
    assert ids(web.analyze_redirect(resp(200, url="http://a.ru/"))) == {"web.redirect.missing": MEDIUM}


def test_exposed_files_and_soft404():
    git = web.analyze_exposed("/.git/HEAD", resp(body=b"ref: refs/heads/master\n",
                                                headers={"Content-Type": "text/plain"}, url="https://a.ru/.git/HEAD"))
    assert git and git.severity == CRITICAL
    env = web.analyze_exposed("/.env", resp(body=b"APP_KEY=base64:xx\nDB_PASSWORD=secret\nDB_HOST=localhost\n",
                                            headers={"Content-Type": "application/octet-stream"}))
    assert env and env.severity == CRITICAL
    # сайт отдаёт HTML на любой адрес — не находка
    soft = web.analyze_exposed("/.env", resp(body=b"<html>APP_KEY=1\nDB_X=2</html>",
                                             headers={"Content-Type": "text/html"}))
    assert soft is None
    assert web.analyze_exposed("/.git/HEAD", resp(404, body=b"ref: x")) is None


def test_tls_analysis():
    assert ids(web.analyze_tls("a.ru", {"ok": False, "kind": "verify", "code": 10, "message": "expired"}, None)) \
        == {"web.cert.expired": CRITICAL}
    assert ids(web.analyze_tls("a.ru", {"ok": False, "kind": "noconnect", "message": "refused"}, None)) \
        == {"web.https.none": HIGH}
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=60)).strftime("%b %d %H:%M:%S %Y GMT")
    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5, hours=1)).strftime("%b %d %H:%M:%S %Y GMT")
    cert = {"notAfter": future, "issuer": ((("organizationName", "Let's Encrypt"),),)}
    assert ids(web.analyze_tls("a.ru", {"ok": True, "cert": cert}, True)) == {"web.cert.ok": OK, "web.tls.legacy": MEDIUM}
    assert ids(web.analyze_tls("a.ru", {"ok": True, "cert": {"notAfter": soon}}, False)) == {"web.cert.expiring": CRITICAL}


# ------------------------------------------------------------- домен

def test_domain_helpers():
    assert dom.registrable("shop.example.ru") == "example.ru"
    assert dom.registrable("www.firma.msk.ru") == "firma.msk.ru"
    w = "domain: EXAMPLE.RU\nstate: REGISTERED\npaid-till: 2027-03-01T21:00:00Z\n"
    assert dom.expiry_from_whois(w) == dt.datetime(2027, 3, 1, 21, tzinfo=dt.timezone.utc)
    rdap = {"events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
                       {"eventAction": "expiration", "eventDate": "2026-12-01T00:00:00Z"}]}
    exp = dom.expiry_from_rdap(rdap)
    now = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
    assert ids(dom.analyze_expiry("a.ru", exp, now)) == {"domain.expiry": CRITICAL}
    assert ids(dom.analyze_expiry("a.ru", exp, now - dt.timedelta(days=40))) == {"domain.expiry": MEDIUM}
    assert ids(dom.analyze_expiry("a.ru", None)) == {"domain.expiry.unknown": INFO}
    assert ids(dom.analyze_dns(["ns1.x"], [], [])) == {
        "domain.ns.single": MEDIUM, "domain.dnssec.missing": LOW, "domain.caa.missing": INFO}


# ------------------------------------------------------------- порты и утечки

def test_ports():
    fs = network.analyze_ports("Офис", "203.0.113.5", [3389, 8291, 1541], shared_hint=False)
    assert [f.severity for f in fs] == [CRITICAL, HIGH, MEDIUM]
    shared = network.analyze_ports("Сайт", "203.0.113.6", [3306], shared_hint=True)
    assert shared[0].severity == MEDIUM and "хостинг" in shared[0].detail
    assert not network.is_public("192.168.1.1") and network.is_public("8.8.8.8")


def test_leaks():
    assert leaks.analyze_site_breaches("a.ru", [])[0].severity == OK
    res = leaks.analyze_account_breaches({
        "boss@a.ru": [{"Title": "Fresh", "BreachDate": "2025-06-01", "DataClasses": ["Passwords"]}],
        "hr@a.ru": [],
    }, now=dt.date(2026, 11, 1))
    assert ids(res) == {"leaks.account.boss@a.ru": HIGH}


# ------------------------------------------------------------- оценка, отчёт, согласие

def F(i, sev, cat="email"):
    return Finding(i, cat, sev, i, fix="fix " + i)


def test_score_and_actions():
    fs = [F("a", CRITICAL, "network"), F("b", HIGH), F("c", LOW, "web"), F("d", OK)]
    pts, grade = score(fs)
    assert pts == 53 and grade == "D"
    assert score([F("x", LOW)]) == (98, "A")
    assert score([F("x", CRITICAL)]) == (70, "D")
    assert score([F("x", MEDIUM), F("y", MEDIUM), F("z", MEDIUM)]) == (88, "B")  # критичное не даёт оценку выше D
    assert [f.id for f in top_actions(fs)] == ["a", "b", "c"]


def test_diff():
    prev = ScanResult("a.ru", checks_run=["email", "web"], score=60, finished="2026-10-01T10:00:00",
                      findings=[F("old", HIGH), F("stay", LOW, "web")])
    cur = ScanResult("a.ru", checks_run=["email", "web"], score=80,
                     findings=[F("stay", LOW, "web"), F("new", MEDIUM, "web")])
    d = diff(cur, prev)
    assert [f.id for f in d.fixed] == ["old"] and [f.id for f in d.new] == ["new"] and d.score_delta == 20
    # missing → none у DMARC: это улучшение, а не «исправлено + новое»
    p2 = ScanResult("a.ru", checks_run=["email"], findings=[Finding("email.dmarc.missing", "email", HIGH, "нет")])
    c2 = ScanResult("a.ru", checks_run=["email"], findings=[Finding("email.dmarc.none", "email", MEDIUM, "p=none")])
    d2 = diff(c2, p2)
    assert d2.new == [] and [f.title for f in d2.fixed] == ["Улучшено: p=none"]


def test_consent():
    assert "согласии" in Consent().problem()
    c = Consent(has=True, date="01.11.2026", document="Договор №7")
    assert c.problem() == ""
    c.valid_until = "01.01.2026"
    assert "истёк" in c.problem(dt.date(2026, 11, 1))
    with pytest.raises(ConsentError):
        run_scan(Client("X", "a.ru"), Settings())


def test_normalize_domain():
    assert normalize_domain("https://www.Example.RU/page?x=1") == "example.ru"
    assert normalize_domain("пример.рф") == "xn--e1afmkfd.xn--p1ai"
    assert normalize_domain("not a domain") == ""
    assert normalize_domain("localhost") == ""


def test_scan_pipeline_and_report(tmp_path, monkeypatch):
    der = _rsa_der_len(294)
    r = FakeResolver({
        ("shop.ru", "MX"): [(10, "mx.yandex.net")],
        ("shop.ru", "TXT"): ["v=spf1 include:_spf.yandex.net +all"],
        ("_dmarc.shop.ru", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@shop.ru"],
        ("mail._domainkey.shop.ru", "TXT"): [f"v=DKIM1; p={der}"],
        ("shop.ru", "NS"): ["ns1.reg.ru", "ns2.reg.ru"],
        ("shop.ru", "A"): ["81.200.10.21"],
    })
    monkeypatch.setattr(dom, "lookup_expiry", lambda d: (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=20), "RDAP"))
    monkeypatch.setattr(network, "scan_ip", lambda ip, ports=None: [3389] if ip == "81.200.10.20" else [])
    client = Client("ООО «Ромашка»", "shop.ru", office_ips=["81.200.10.20"],
                    consent=Consent(True, "01.11.2026", "", "Договор №12"))
    res = run_scan(client, Settings(), ["email", "domain", "network"], resolver=r)
    got = ids(res.findings)
    assert got["email.spf.plusall"] == CRITICAL
    assert got["network.3389.81.200.10.20"] == CRITICAL
    assert got["domain.expiry"] == HIGH
    assert res.grade == "F" and res.errors == []

    store = Store(tmp_path)
    store.save_scan(client.id, res)
    assert store.last_scan(client.id).score == res.score

    html = render_html(res, client, Settings(company_name="Иван Петров"), diff(res, None))
    assert "Удалённый рабочий стол" in html and "Договор №12" in html and "<script" not in html
    txt = summary_text(res, client)
    assert "Оценка: F" in txt and "1." in txt


def test_offline_scan_not_graded_a(monkeypatch):
    class Dead:
        def query(self, *a):
            raise dnsclient.DNSError("нет сети")
        txt = query
    monkeypatch.setattr(leaks, "_get", lambda *a, **k: (0, None))
    c = Client("X", "a.ru", consent=Consent(True, "01.11.2026", "", "Д1"))
    res = run_scan(c, Settings(), ["email", "domain"], resolver=Dead())
    assert res.grade == "?" and res.errors
    assert "неполная" in render_html(res, c, Settings())


def test_leaks_partial_status(monkeypatch):
    from smbcheck.scoring import PARTIAL, category_status
    monkeypatch.setattr(leaks, "_get", lambda *a, **k: (200, []))
    # ящики указаны, ключа нет — «Проверено частично», а не «В порядке»
    fs = leaks.run("a.ru", ["boss@a.ru"], api_key="")
    assert category_status(fs, ["leaks"])["leaks"] == PARTIAL
    # ящики не указаны — тоже частично
    fs2 = leaks.run("a.ru", [], api_key="")
    assert category_status(fs2, ["leaks"])["leaks"] == PARTIAL
    # с ключом и чистыми ящиками — в порядке
    monkeypatch.setattr(leaks, "_get", lambda path, key="", **k: (200, []) if "breaches?" in path else (404, None))
    fs3 = leaks.run("a.ru", ["boss@a.ru"], api_key="KEY")
    assert category_status(fs3, ["leaks"])["leaks"] == OK
    # отчёт объясняет, что не проверено, и не дублирует это в «К сведению»
    r = ScanResult("a.ru", checks_run=["leaks"], findings=fs, finished="2026-11-02T10:00:00")
    c = Client("X", "a.ru", consent=Consent(True, "01.11.2026", "", "Д1"))
    html = render_html(r, c, Settings())
    assert "Проверено частично" in html and "Что проверено не полностью" in html
    assert html.count("на утечки не проверялись") == 1
