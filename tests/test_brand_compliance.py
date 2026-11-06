import datetime as dt

from smbcheck.checks import brand
from smbcheck.compliance import (CLIENT, ISSUES, NOT_CHECKED, OK_ST, STALE, brand_cases, controls_for, evaluate,
                                 open_issues, render_evidence, render_notices)
from smbcheck.demo import demo_fin
from smbcheck.dnsclient import DNSAnswer, DNSError
from smbcheck.models import HIGH, LOW, MEDIUM, OK, Finding, ScanResult
from smbcheck.scoring import diff, score, top_actions
from smbcheck.storage import Client, Consent, Settings, Store

UTC = dt.timezone.utc


# ------------------------------------------------------------- генерация двойников

def test_generate_lookalikes():
    c = dict(brand.generate_lookalikes("tezkredit.uz", trusted=["tezkredit.com"]))
    assert "tezkredit.uz" not in c and "tezkredit.com" not in c          # свой и доверенный
    assert "tezkredit.kz" in c and "tezkredit.top" in c                 # смена зоны
    assert "tezkredt.uz" in c                                            # пропущена буква
    assert "tezkredit-online.uz" in c and "mytezkredit.uz" in c          # добавлено слово
    assert "tezkred1t.uz" in c                                           # похожий символ
    assert "etzkredit.uz" in c                                           # перестановка
    assert all(not n.split(".")[0].startswith("-") and not n.split(".")[0].endswith("-") for n in c)
    assert len(c) <= brand.MAX_CANDIDATES


def test_generate_idn_and_second_level():
    idn = brand.generate_lookalikes("xn--80aswg.xn--p1ai")
    assert idn and all(n.startswith("xn--80aswg.") for n, _ in idn)     # только смена зоны
    sl = dict(brand.generate_lookalikes("shop1.com.kz"))
    assert "shop1.uz" in sl and "shpo1.com.kz" in sl


class Zone:
    def __init__(self, zone):
        self.zone = zone

    def query(self, name, rtype):
        if name not in self.zone:
            return DNSAnswer(rcode=3)
        return DNSAnswer(records=[(rtype, r) for r in self.zone[name].get(rtype, [])])


def test_scan_and_analyze_hits():
    zone = {"tezkredit-online.uz": {"A": ["45.12.88.10"], "MX": [(10, "mx.tezkredit-online.uz")]},
            "tezkredit.top": {"A": ["1.2.3.4"]},
            "tezkredit.kz": {"NS": ["ns1.sedoparking.com"], "A": ["5.6.7.8"]},
            "tezkredt.uz": {}}
    cands = brand.generate_lookalikes("tezkredit.uz")
    hits, errors = brand.scan_lookalikes(cands, Zone(zone))
    assert errors == 0 and {h.name for h in hits} == set(zone)
    now = dt.datetime(2026, 11, 4, tzinfo=UTC)
    for h in hits:
        if h.name == "tezkredit.top":
            h.created = now - dt.timedelta(days=5)   # свежая регистрация поднимает важность
    fs = {f.id: f for f in brand.analyze_hits(hits, len(cands), now)}
    assert fs["brand.lookalike.tezkredit-online.uz"].severity == HIGH
    assert fs["brand.lookalike.tezkredit.top"].severity == HIGH and "5 дн." in fs["brand.lookalike.tezkredit.top"].title
    assert fs["brand.lookalike.tezkredit.kz"].severity == LOW              # припаркован
    assert fs["brand.lookalike.tezkredt.uz"].severity == LOW
    assert brand.analyze_hits([], 100)[0].severity == OK


def test_brand_run_detects_dns_hijack():
    class Everything:
        def query(self, name, rtype):
            return DNSAnswer(records=[("A", "10.0.0.1")] if rtype == "A" else [])
    try:
        brand.run("tezkredit.uz", Everything(), ct=False, whois=False)
        assert False, "ожидали DNSError"
    except DNSError as e:
        assert "подменяет" in str(e)


def test_ct_and_registration_parsers():
    entries = [
        {"name_value": "tezkredit.uz\nwww.tezkredit.uz", "not_before": "2026-10-01T00:00:00", "issuer_name": "C=US, O=Let's Encrypt, CN=R11"},
        {"name_value": "*.tezkredit-pay.com", "not_before": "2026-11-01T10:00:00", "issuer_name": "C=US, O=Let's Encrypt, CN=R10"},
        {"name_value": "login.tezkredit-pay.com", "not_before": "2026-10-20T10:00:00", "issuer_name": "O=Other"},
        {"name_value": "partner-tezkredit.net", "not_before": "2026-10-20T10:00:00", "issuer_name": ""},
        {"name_value": "tezkredit-online.uz", "not_before": "2026-10-20T10:00:00", "issuer_name": ""},
    ]
    fs = brand.analyze_ct(entries, ["tezkredit"], ["tezkredit.uz"], ["partner-tezkredit.net"], {"tezkredit-online.uz"})
    assert [f.id for f in fs] == ["brand.ct.tezkredit-pay.com"]
    assert "01.11.2026" in fs[0].detail and "Let's Encrypt" in fs[0].tech
    rdap = {"events": [{"eventAction": "registration", "eventDate": "2026-10-30T08:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Reg"]]],
                          "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@reg.example"]]]}]}]}
    created, reg, abuse = brand.parse_rdap_registration(rdap)
    assert created.date() == dt.date(2026, 10, 30) and reg == "Example Reg" and abuse == "abuse@reg.example"
    w = "Domain Name: X.UZ\nCreation Date: 2026-10-29T00:00:00Z\nRegistrar: Some Registrar LLC\n"
    assert brand.parse_whois_registration(w)[0].date() == dt.date(2026, 10, 29)
    assert brand.keywords_for("ab.uz", ["  TezKredit "]) == ["tezkredit"]


# ------------------------------------------------------------- оценка и история

def test_brand_not_in_score_and_actions():
    base = [Finding("email.dmarc.missing", "email", HIGH, "Нет DMARC", fix="добавить DMARC")]
    with_brand = base + [Finding("brand.lookalike.x.uz", "brand", HIGH, "Домен-двойник: x.uz", fix="жалоба")]
    assert score(base) == score(with_brand)
    assert all(f.category != "brand" for f in top_actions(with_brand))


def test_brand_history_kept_separately(tmp_path):
    st = Store(tmp_path)
    full = ScanResult("a.uz", finished="2026-10-01T10:00:00", checks_run=["email", "brand"])
    daily = ScanResult("a.uz", finished="2026-10-02T10:00:00", checks_run=["brand"])
    st.save_scan("c1", full)
    st.save_scan("c1", daily, "brand")
    assert st.last_scan("c1").finished == full.finished          # месячное сравнение не ломается
    assert st.last_with("c1", "brand").finished == daily.finished
    assert [s.finished for s in st.all_scans("c1")] == [full.finished, daily.finished]
    c = Client("X", "a.uz", profile="uz_fin", accepts_cards=True, brand_keywords=["abc"], trusted_domains=["b.uz"])
    st.save_clients([c])
    back = st.load_clients()[0]
    assert (back.profile, back.accepts_cards, back.brand_keywords, back.trusted_domains) == ("uz_fin", True, ["abc"], ["b.uz"])


def test_diff_reports_new_lookalikes():
    prev = ScanResult("a.uz", checks_run=["brand"], findings=[Finding("brand.lookalike.ok", "brand", OK, "нет")])
    cur = ScanResult("a.uz", checks_run=["brand"], findings=[Finding("brand.lookalike.b.uz", "brand", MEDIUM, "Домен-двойник: b.uz")])
    assert [f.id for f in diff(cur, prev).new] == ["brand.lookalike.b.uz"]


# ------------------------------------------------------------- пакет доказательств

def test_controls_by_profile():
    general = {c.id for c in controls_for(Client("X", "x.ru"))}
    uz = {c.id for c in controls_for(Client("X", "x.uz", profile="uz_fin", accepts_cards=True))}
    kz = {c.id for c in controls_for(Client("X", "x.kz", profile="kz_fin"))}
    assert "uz_biometry" in uz and "pci_tests" in uz and "kz_pd_local" not in uz
    assert "kz_pd_local" in kz and "uz_biometry" not in kz and "pci_tests" not in kz
    assert "uz_biometry" not in general and "perimeter" in general


def test_evaluate_statuses():
    c = Client("X", "x.uz", profile="uz_fin", consent=Consent(True, "01.01.2026", "", "Д1"))
    now = dt.datetime(2026, 11, 4, 12, 0)
    full = ScanResult("x.uz", finished="2026-11-01T10:00:00", checks_run=["email", "web", "domain", "network", "leaks"],
                      findings=[Finding("network.ok", "network", OK, "Опасные сервисы не видны"),
                                Finding("email.dmarc.none", "email", MEDIUM, "DMARC p=none")])
    brand_run = ScanResult("x.uz", finished="2026-10-25T10:00:00", checks_run=["brand"],
                           findings=[Finding("brand.lookalike.ok", "brand", OK, "нет")])
    st = {s.control.id: s for s in evaluate(c, [brand_run, full], now)}
    assert st["perimeter"].status == OK_ST
    assert st["antiphishing_mail"].status == ISSUES and st["antiphishing_mail"].worst == MEDIUM
    assert st["brand"].status == STALE and "ежедневный" in st["brand"].note    # 24 часа требуют ежедневного запуска
    assert st["uz_biometry"].status == CLIENT
    st2 = {s.control.id: s for s in evaluate(c, [full], now)}
    assert st2["brand"].status == NOT_CHECKED


def test_open_issues_since():
    def scan(day, findings):
        return ScanResult("x.uz", finished=f"2026-{day}T10:00:00", checks_run=["network"], findings=findings)
    rdp = Finding("network.3389.1.2.3.4", "network", HIGH, "RDP")
    scans = [scan("08-01", [rdp]), scan("09-01", []), scan("10-01", [rdp]), scan("11-01", [rdp])]
    [i] = open_issues(scans)
    assert i.since.date() == dt.date(2026, 10, 1)   # непрерывно с октября, августовский эпизод был закрыт


def test_render_evidence_and_notices():
    c, scans = demo_fin()
    s = Settings(company_name="Исполнитель")
    html = render_evidence(c, s, scans)
    for text in ("Карта соответствия", "PCI DSS v4.0.1, 4.2.1", "Журнал проверок", "tezkredit-online.uz", "сверить",
                 "не является юридическим"):
        assert text in html
    assert "romashka" not in html
    cases = brand_cases(scans)
    assert {x.finding.id for x in cases if x.active} == {"brand.lookalike.tezkredit-online.uz", "brand.lookalike.tezkredit.top"}
    n = render_notices(c, s, cases)
    assert "Центральный банк" in n and "срок прошёл" in n and "tezkredit.top" in n
    kz = Client("Y", "y.kz", profile="kz_fin")
    assert "Центральный банк" not in render_notices(kz, s, cases)
