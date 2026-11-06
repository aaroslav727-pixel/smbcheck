"""Пакет доказательств для регулятора и банка-партнёра.

Карта соответствия связывает находки проверок с темами требований (ЦБ РУз, АРРФР/НБРК, PCI DSS).
Это ориентир для подготовки к проверке, а не юридическое заключение: ответственность перед
регулятором остаётся у финансовой организации. Пункты с пометкой «сверить» взяты из вторичных
источников — перед продажей их нужно сверить с официальным текстом.
"""
from __future__ import annotations

import datetime as dt
import html
from dataclasses import dataclass, field
from pathlib import Path

from .models import CRITICAL, HIGH, LOW, MEDIUM, OK, SEVERITY_ORDER, SEVERITY_RU, Finding, ScanResult
from .scoring import family, sort_key
from .storage import PROFILES, Client, Settings, display_domain

e = html.escape


@dataclass
class Control:
    id: str
    title: str
    refs: dict[str, str]                  # тег профиля → ссылка на требование
    families: list[str] = field(default_factory=list)   # префиксы id находок, которые служат доказательством
    checks: list[str] = field(default_factory=list)     # какие проверки должны были выполняться
    covers: str = ""                       # что закрывает программа
    client_side: str = ""                  # что остаётся за клиентом
    verify: bool = False                   # ссылка из вторичного источника — сверить с первоисточником
    regular_days: int = 0                  # если >0 — контроль регулярности (последняя проверка не старше N дней)


CONTROLS: list[Control] = [
    Control(
        "monitoring", "Регулярная внешняя проверка периметра",
        {"all": "Ежемесячный контроль с историей изменений",
         "pci": "PCI DSS v4.0.1, 11.3.2 — ежеквартальный внешний скан ASV",
         "uz_fin": "ЦБ РУз: минимальные требования к ИБ (для МФО — отдельное положение)",
         "kz_fin": "Требования АРРФР к ИБ финансовых организаций"},
        families=["network.", "web."], checks=["network", "web"], regular_days=35,
        covers="Ежемесячная проверка сайта и внешних адресов, журнал проверок с датами и изменениями.",
        client_side="Наш скан не является ASV-сканом PCI DSS и не заменяет пентест: ASV и QSA — аккредитованные компании.",
        verify=True),
    Control(
        "perimeter", "Нет опасных сервисов, открытых в интернет",
        {"all": "Базовая защита периметра",
         "pci": "PCI DSS v4.0.1, требования 1 и 2.2 — сетевые средства защиты, безопасная конфигурация",
         "uz_fin": "ЦБ РУз: защита периметра информационных систем",
         "kz_fin": "АРРФР: защита периметра"},
        families=["network."], checks=["network"],
        covers="RDP, общие папки, базы данных, Docker, 1С, управление MikroTik и др. — на сайте и внешнем IP офиса.",
        client_side="Внутреннюю сеть, рабочие станции и VPN снаружи не видно — это зона вашего администратора.",
        verify=True),
    Control(
        "crypto", "Шифрование каналов: действующий сертификат, HTTPS, без TLS 1.0/1.1",
        {"all": "Защита данных при передаче",
         "pci": "PCI DSS v4.0.1, 4.2.1 — стойкая криптография при передаче",
         "uz_fin": "ЦБ РУз, требования к дистанционным услугам: поддерживаемая версия TLS (поправки от 14.08.2026)",
         "kz_fin": "АРРФР: обязательное шифрование внешних соединений (постановление от 20.04.2026)"},
        families=["web.cert", "web.tls", "web.https", "web.redirect", "web.hsts"], checks=["web"],
        covers="Срок и корректность сертификата, переадресация на HTTPS, HSTS, отказ от TLS 1.0/1.1.",
        client_side="Шифрование мобильного приложения и внутренних каналов проверяется отдельно.", verify=True),
    Control(
        "webconfig", "Безопасная конфигурация сайта",
        {"all": "Нет открытых служебных файлов и лишних сведений о ПО",
         "pci": "PCI DSS v4.0.1, 2.2 и 6.4 — безопасная конфигурация, защита публичных веб-приложений"},
        families=["web.exposed", "web.listing", "web.version", "web.headers", "web.cookies"], checks=["web"],
        covers=".git, .env, бэкапы, phpinfo, листинг каталогов, версии ПО в заголовках, заголовки безопасности, cookie.",
        client_side="Уязвимости логики (обход лимита займа, подмена суммы) находит только пентест. PCI DSS 6.4.2 требует "
                    "автоматической защиты веб-приложений (WAF) — сканер её не заменяет."),
    Control(
        "antiphishing_mail", "Защита почты от подделки (SPF, DKIM, DMARC)",
        {"all": "Письма от вашего имени нельзя подделать",
         "pci": "PCI DSS v4.0.1, 5.4.1 — механизмы защиты от фишинга"},
        families=["email.spf", "email.dkim", "email.dmarc"], checks=["email"],
        covers="Записи SPF, DKIM, DMARC и их режимы.",
        client_side="Обучение сотрудников и фильтрация входящей почты — на вашей стороне."),
    Control(
        "brand", "Мониторинг фишинговых доменов и двойников бренда",
        {"all": "Раннее обнаружение фишинга против ваших клиентов",
         "uz_fin": "ЦБ РУз (авг. 2025): непрерывный мониторинг внешних источников, уведомление ЦБ и профильной "
                   "инспекции в течение 24 часов, публикация в официальных каналах"},
        families=["brand."], checks=["brand"], regular_days=2,
        covers="Похожие домены (опечатки, другие зоны, добавленные слова) и сертификаты с названием компании.",
        client_side="Соцсети, мессенджеры, поддельные приложения и SMS-рассылки автоматически не проверяются. "
                    "Уведомление регулятору направляете вы — программа готовит черновик."),
    Control(
        "domain", "Непрерывность домена",
        {"all": "Сайт и почта не остановятся из-за домена"},
        families=["domain."], checks=["domain"],
        covers="Срок регистрации, количество DNS-серверов, DNSSEC, CAA."),
    Control(
        "leaks", "Контроль утечек учётных данных",
        {"all": "Ящики сотрудников в публичных утечках"},
        families=["leaks."], checks=["leaks"],
        covers="Взлом сайта в базе HIBP; ящики сотрудников — с ключом HIBP.",
        client_side="Смена паролей и двухфакторный вход — на вашей стороне."),
    # --- только на стороне клиента: показываем, чтобы граница ответственности была видна
    Control(
        "kz_pd_local", "Хранение персональных данных граждан РК в Казахстане",
        {"kz_fin": "Закон РК №94-V «О персональных данных», ст. 12 п. 2"},
        client_side="Мы не видим, где лежат ваши базы. Базы с ПДн, их копии и логи с ПДн — в ЦОД на территории РК."),
    Control(
        "kz_pd_breach", "Уведомление об утечке персональных данных в течение 1 рабочего дня",
        {"kz_fin": "Закон РК №94-V, ст. 25"},
        client_side="Нужен регламент реагирования. Проверка утечек помогает узнать о компрометации раньше."),
    Control(
        "kz_logs", "Журналы: не менее 3 месяцев в оперативном доступе и 1 года в архиве",
        {"kz_fin": "Постановление АРРФР от 20.04.2026"},
        client_side="Журналы ваших систем — ваша зона. История наших проверок хранится и прикладывается как "
                    "доказательство мониторинга периметра.", verify=True),
    Control(
        "kz_mfa", "Два разных способа подтверждения при входе в мобильный банк / кабинет",
        {"kz_fin": "Постановление АРРФР от 20.04.2026, с 12.07.2026"},
        client_side="Настраивается в вашем приложении и личном кабинете.", verify=True),
    Control(
        "uz_biometry", "Хранение биометрических данных клиентов в Узбекистане",
        {"uz_fin": "Постановление ЦБ РУз от 22.07.2026 (в силе с 06.08.2026)"},
        client_side="Биометрия для идентификации — только в ЦОД на территории Узбекистана.", verify=True),
    Control(
        "pci_tests", "Ежегодный пентест и ежеквартальный ASV-скан",
        {"pci": "PCI DSS v4.0.1, 11.3.2 и 11.4"},
        client_side="Выполняют аккредитованные ASV/пентестеры. Наша ежемесячная проверка помогает прийти на них без сюрпризов."),
    Control(
        "ir_plan", "План реагирования на инциденты",
        {"pci": "PCI DSS v4.0.1, 12.10.1", "uz_fin": "ЦБ РУз: уведомление о признаках атак",
         "kz_fin": "АРРФР: немедленное уведомление о серьёзных инцидентах"},
        client_side="Регламент, ответственные, контакты регулятора. Программа даёт черновики уведомлений по двойникам.",
        verify=True),
]


def client_tags(client: Client) -> set[str]:
    tags = {"all", client.profile}
    if client.accepts_cards:
        tags.add("pci")
    return tags


def refs_for(ctrl: Control, tags: set[str]) -> list[str]:
    specific = [v for k, v in ctrl.refs.items() if k != "all" and k in tags]
    return specific or ([ctrl.refs["all"]] if "all" in ctrl.refs and "all" in tags else [])


def controls_for(client: Client) -> list[Control]:
    tags = client_tags(client)
    return [c for c in CONTROLS if any(k in tags for k in c.refs)]


# ----------------------------------------------------------------------- оценка

OK_ST, ISSUES, STALE, NOT_CHECKED, CLIENT = "ok", "issues", "stale", "not_checked", "client"
STATUS_RU = {OK_ST: "Подтверждено проверкой", ISSUES: "Есть замечания", STALE: "Проверка нерегулярна",
             NOT_CHECKED: "Не проверялось", CLIENT: "На стороне организации"}
STATUS_COLOR = {OK_ST: "#1f7a4d", ISSUES: "#b42318", STALE: "#b7791f", NOT_CHECKED: "#6b7280", CLIENT: "#1e3a5f"}


@dataclass
class ControlStatus:
    control: Control
    status: str
    worst: str = ""
    note: str = ""
    evidence: list[str] = field(default_factory=list)


def _match(f: Finding, families: list[str]) -> bool:
    return any(f.id.startswith(p) for p in families)


def _dt(iso: str) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(iso)
    except ValueError:
        return dt.datetime.min


def evaluate(client: Client, scans: list[ScanResult], now: dt.datetime | None = None) -> list[ControlStatus]:
    """scans — все проверки клиента (полные и ежедневные) в хронологическом порядке."""
    now = now or dt.datetime.now()
    out: list[ControlStatus] = []
    for c in controls_for(client):
        if not c.families:
            out.append(ControlStatus(c, CLIENT))
            continue
        relevant = [s for s in scans if all(ch in s.checks_run for ch in c.checks)]
        if not relevant:
            out.append(ControlStatus(c, NOT_CHECKED, note="Нужно запустить соответствующую проверку."))
            continue
        last = relevant[-1]
        found = [f for f in last.findings if _match(f, c.families)]
        problems = sorted([f for f in found if f.is_problem], key=sort_key)
        when = _dt(last.finished).strftime("%d.%m.%Y")
        age = (now - _dt(last.finished)).days
        st = ControlStatus(c, ISSUES if problems else OK_ST)
        if problems:
            st.worst = problems[0].severity
            st.evidence = [f"{SEVERITY_RU[f.severity]}: {f.title}" for f in problems[:4]]
            if len(problems) > 4:
                st.evidence.append(f"… и ещё {len(problems) - 4}")
        else:
            st.evidence = [f.title for f in found if f.severity == OK][:3] or ["Замечаний нет"]
        st.note = f"Последняя проверка {when}"
        if c.regular_days:
            n = sum(1 for s in relevant if (now - _dt(s.finished)).days <= 365)
            st.note += f"; за 12 мес. — {n}"
            need = c.regular_days if (c.id != "brand" or client.profile == "uz_fin") else 35
            if age > need and not problems:
                st.status = STALE
                st.note += (f". Последней проверке {age} дн. — для 24-часового срока уведомления ЦБ нужен ежедневный запуск."
                            if c.id == "brand" and client.profile == "uz_fin" else
                            f". Последней проверке {age} дн., ожидалось не реже раза в {need} дн.")
        out.append(st)
    return out


@dataclass
class OpenIssue:
    finding: Finding
    since: dt.datetime


def open_issues(scans: list[ScanResult]) -> list[OpenIssue]:
    """Замечания последней полной проверки и дата, с которой они висят непрерывно."""
    full = [s for s in scans if s.checks_run and s.checks_run != ["brand"]]
    if not full:
        return []
    last = full[-1]
    out: list[OpenIssue] = []
    for f in sorted((f for f in last.findings if f.is_problem and f.category != "brand"), key=sort_key):
        fam = family(f)
        since = _dt(last.finished)
        for s in reversed(full[:-1]):
            if f.category not in s.checks_run:
                continue
            if any(family(x) == fam and x.is_problem for x in s.findings):
                since = _dt(s.finished)
            else:
                break
        out.append(OpenIssue(f, since))
    return out


@dataclass
class BrandCase:
    finding: Finding
    first_seen: dt.datetime
    last_seen: dt.datetime
    active: bool


def brand_cases(scans: list[ScanResult]) -> list[BrandCase]:
    runs = [s for s in scans if "brand" in s.checks_run]
    if not runs:
        return []
    cases: dict[str, BrandCase] = {}
    for s in runs:
        t = _dt(s.finished)
        for f in s.findings:
            if f.category != "brand" or not f.is_problem:
                continue
            if f.id in cases:
                cases[f.id].last_seen = t
                cases[f.id].finding = f
            else:
                cases[f.id] = BrandCase(f, t, t, False)
    latest = {f.id for f in runs[-1].findings if f.category == "brand" and f.is_problem}
    for k, c in cases.items():
        c.active = k in latest
    return sorted(cases.values(), key=lambda c: (not c.active, SEVERITY_ORDER.index(c.finding.severity), -c.first_seen.timestamp()))


# ----------------------------------------------------------------------- HTML

CSS = """
:root{--ink:#1d2433;--muted:#5d6678;--line:#e3e6ec;--soft:#f5f6f9;--accent:#1e3a5f}
*{box-sizing:border-box}
body{margin:0;background:#eceef2;color:var(--ink);font:13.5px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
.page{background:#fff;max-width:900px;margin:24px auto;padding:40px 48px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:21px;margin:0 0 4px}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--accent);margin:28px 0 8px}
.meta{color:var(--muted);font-size:12.5px}
.top{border-bottom:2px solid var(--ink);padding-bottom:14px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:16px}
.kpi{background:var(--soft);border-radius:6px;padding:10px 12px}
.kpi b{display:block;font-size:20px} .kpi span{font-size:12px;color:var(--muted)}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:6px;border-bottom:2px solid var(--line)}
td{padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
tr{break-inside:avoid}
.st{font-weight:700;white-space:nowrap}
.ref{font-size:12px;color:var(--muted)}
.ver{display:inline-block;font-size:10px;font-weight:700;text-transform:uppercase;color:#9a6b12;background:#fdf3d7;border-radius:8px;padding:0 6px;margin-left:4px}
.ev{font-size:12px;margin:3px 0 0;padding-left:16px}
.cs{font-size:12px;color:var(--muted);margin-top:3px}
.box{background:var(--soft);border-radius:6px;padding:10px 14px;font-size:12.5px;margin:10px 0}
.foot{margin-top:26px;padding-top:10px;border-top:1px solid var(--line);font-size:11.5px;color:var(--muted)}
.screen-only{font-size:12px;color:var(--muted);text-align:center;margin:10px}
.mono{font:11.5px Consolas,"Courier New",monospace}
@media print{body{background:#fff}.page{box-shadow:none;margin:0;padding:0;max-width:none}.screen-only{display:none}
@page{size:A4;margin:12mm}}
"""


CHECK_SHORT = {"email": "почта", "web": "сайт", "domain": "домен", "network": "порты", "leaks": "утечки",
               "brand": "двойники"}


def _d(t: dt.datetime) -> str:
    return t.strftime("%d.%m.%Y") if t != dt.datetime.min else "—"


def render_evidence(client: Client, settings: Settings, scans: list[ScanResult], months: int = 12,
                    now: dt.datetime | None = None) -> str:
    now = now or dt.datetime.now()
    start = now - dt.timedelta(days=round(months * 30.5))
    scans = sorted(scans, key=lambda s: s.finished)
    period = [s for s in scans if _dt(s.finished) >= start]
    full = [s for s in period if s.checks_run and s.checks_run != ["brand"]]
    brand_runs = [s for s in period if "brand" in s.checks_run]
    statuses = evaluate(client, scans, now)
    issues = open_issues(scans)
    cases = [c for c in brand_cases(scans) if c.last_seen >= start]
    dom = display_domain(client.domain)
    tags = client_tags(client)

    p: list[str] = []
    a = p.append
    a(f"<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
      f"<title>Пакет доказательств — {e(dom)} — {now:%d.%m.%Y}</title><style>{CSS}</style></head><body>")
    a("<div class='screen-only'>Чтобы сохранить в PDF: Ctrl+P → «Сохранить как PDF»</div><div class='page'>")
    a("<div class='top'>")
    a(f"<h1>Пакет доказательств: мониторинг внешнего периметра</h1>")
    a(f"<div class='meta'>{e(client.name)} · {e(dom)} · {e(PROFILES.get(client.profile, ''))}"
      + (" · принимает банковские карты" if client.accepts_cards else "")
      + f"<br>Период: {start:%d.%m.%Y} — {now:%d.%m.%Y}"
      + (f" · подготовил: {e(settings.company_name)}" if settings.company_name else "") + "</div>")
    ok_n = sum(1 for s in statuses if s.status == OK_ST)
    checked_n = sum(1 for s in statuses if s.status != CLIENT)
    a("<div class='kpis'>"
      f"<div class='kpi'><b>{len(full)}</b><span>полных проверок за период</span></div>"
      f"<div class='kpi'><b>{len(brand_runs)}</b><span>проверок двойников бренда</span></div>"
      f"<div class='kpi'><b>{ok_n} из {checked_n}</b><span>тем подтверждено без замечаний</span></div>"
      f"<div class='kpi'><b>{sum(1 for c in cases if c.active)}</b><span>активных двойников сейчас</span></div>"
      "</div></div>")

    a("<h2>1. Карта соответствия</h2>")
    a("<p class='ref'>Для каждой темы: что подтверждает внешняя проверка, её статус на дату последней проверки "
      "и что остаётся за организацией. Пометка <span class='ver'>сверить</span> — ссылка взята из вторичных "
      "источников и должна быть сверена с официальным текстом до предъявления.</p>")
    a("<table><thead><tr><th style='width:34%'>Требование</th><th>Что подтверждено</th><th style='width:17%'>Статус</th></tr></thead><tbody>")
    for s in statuses:
        c = s.control
        refs = refs_for(c, tags)
        color = STATUS_COLOR[s.status] if s.status != ISSUES else {CRITICAL: "#b42318", HIGH: "#d9480f",
                                                                     MEDIUM: "#b7791f", LOW: "#4b6b8a"}.get(s.worst, "#b42318")
        a(f"<tr><td><b>{e(c.title)}</b>"
          + "".join(f"<div class='ref'>{e(r)}</div>" for r in refs)
          + ("<span class='ver'>сверить</span>" if c.verify else "") + "</td><td>")
        if c.covers:
            a(f"<div>{e(c.covers)}</div>")
        if s.evidence:
            a("<ul class='ev'>" + "".join(f"<li>{e(x)}</li>" for x in s.evidence) + "</ul>")
        if c.client_side:
            a(f"<div class='cs'><b>За организацией:</b> {e(c.client_side)}</div>")
        a(f"</td><td><div class='st' style='color:{color}'>{STATUS_RU[s.status]}</div>"
          + (f"<div class='ref'>{e(s.note)}</div>" if s.note else "") + "</td></tr>")
    a("</tbody></table>")

    a("<h2>2. Журнал проверок</h2>")
    if full:
        a("<table><thead><tr><th>Дата</th><th>Оценка</th><th>Замечаний</th><th>Что проверялось</th></tr></thead><tbody>")
        for s in reversed(full[-24:]):
            n = sum(1 for f in s.findings if f.is_problem and f.category != "brand")
            a(f"<tr><td>{_d(_dt(s.finished))}</td><td><b>{e(s.grade)}</b> ({s.score}/100)</td><td>{n}</td>"
              f"<td class='ref'>{e(', '.join(CHECK_SHORT.get(x, x) for x in s.checks_run))}</td></tr>")
        a("</tbody></table>")
    else:
        a("<p>За период полных проверок нет.</p>")
    if brand_runs:
        first, last = _dt(brand_runs[0].finished), _dt(brand_runs[-1].finished)
        a(f"<div class='box'>Мониторинг двойников: {len(brand_runs)} запусков с {_d(first)} по {_d(last)}.</div>")

    a("<h2>3. Открытые замечания и с какого времени</h2>")
    if issues:
        a("<table><thead><tr><th>Важность</th><th>Замечание</th><th>Открыто с</th><th>Что сделать</th></tr></thead><tbody>")
        for i in issues:
            days = (now - i.since).days
            a(f"<tr><td class='st'>{SEVERITY_RU[i.finding.severity]}</td><td>{e(i.finding.title)}</td>"
              f"<td>{_d(i.since)}<div class='ref'>{days} дн.</div></td><td class='ref'>{e(i.finding.fix)}</td></tr>")
        a("</tbody></table>")
    else:
        a("<p>Открытых замечаний нет.</p>")

    a("<h2>4. Двойники бренда</h2>")
    if cases:
        a("<table><thead><tr><th>Домен / сертификат</th><th>Важность</th><th>Обнаружен</th><th>Состояние</th></tr></thead><tbody>")
        for c in cases[:40]:
            a(f"<tr><td>{e(c.finding.title)}<div class='ref mono'>{e(c.finding.tech)}</div></td>"
              f"<td class='st'>{SEVERITY_RU[c.finding.severity]}</td><td>{_d(c.first_seen)}</td>"
              f"<td>{'активен' if c.active else 'больше не обнаруживается с ' + _d(c.last_seen)}</td></tr>")
        a("</tbody></table>")
    elif brand_runs:
        a("<p>За период двойников не обнаружено.</p>")
    else:
        a("<p>Мониторинг двойников не проводился.</p>")

    c = client.consent
    a("<div class='foot'>Документ подготовлен по результатам внешних проверок с письменного согласия владельца ресурсов "
      f"({e(c.document)} от {e(c.date)}). Проверялись только публично доступные сведения. Документ не является юридическим "
      "заключением о соответствии, ASV-сканом PCI DSS или тестом на проникновение; ответственность перед регулятором "
      "остаётся у организации. Темы требований приведены для ориентира и должны сверяться с действующими текстами актов."
      + (f"<br>Контакт исполнителя: {e(settings.company_contact)}" if settings.company_contact else "")
      + "</div></div></body></html>")
    return "".join(p)


def _safe(domain: str) -> str:
    return "".join(ch for ch in display_domain(domain) if ch.isalnum() or ch in "-._") or "client"


def save_evidence(client: Client, settings: Settings, scans: list[ScanResult], months: int = 12) -> Path:
    folder = settings.reports_path() / "пакеты"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{dt.date.today().isoformat()}_пакет_{_safe(client.domain)}.html"
    path.write_text(render_evidence(client, settings, scans, months), "utf-8")
    return path


# ----------------------------------------------------------------------- черновики уведомлений

NOTICE_CSS = CSS + """
.letter{border:1px solid var(--line);border-radius:6px;padding:16px 20px;margin:12px 0;white-space:pre-wrap;font:13px/1.55 "Segoe UI",system-ui,sans-serif;break-inside:avoid}
.dl{display:inline-block;background:#fdecea;color:#b42318;font-weight:700;border-radius:6px;padding:2px 8px}
"""


def render_notices(client: Client, settings: Settings, cases: list[BrandCase], now: dt.datetime | None = None) -> str:
    now = now or dt.datetime.now()
    dom = display_domain(client.domain)
    active = [c for c in cases if c.active]
    lines, lines_en = [], []
    for c in active:
        name = c.finding.id.split(".", 2)[-1]
        lines.append(f"— {name}: {c.finding.detail} Обнаружен {c.first_seen:%d.%m.%Y %H:%M}. {c.finding.tech}")
        lines_en.append(f"— {name} (first seen {c.first_seen:%Y-%m-%d %H:%M}; {c.finding.tech})")
    listing = "\n".join(lines) or "— (заполните)"
    listing_en = "\n".join(lines_en) or "— (fill in)"
    who = settings.company_name or "[исполнитель мониторинга]"
    first = min((c.first_seen for c in active), default=now)

    p: list[str] = []
    a = p.append
    a(f"<!doctype html><html lang='ru'><head><meta charset='utf-8'><title>Уведомления по двойникам — {e(dom)}</title>"
      f"<style>{NOTICE_CSS}</style></head><body><div class='screen-only'>Черновики. Проверьте адресатов и форму "
      "по действующим актам перед отправкой.</div><div class='page'>")
    a(f"<h1>Черновики уведомлений: домены-двойники {e(dom)}</h1>")
    a(f"<div class='meta'>{e(client.name)} · подготовлено {now:%d.%m.%Y %H:%M} · активных двойников: {len(active)}</div>")
    a("<div class='box'><b>Прежде чем отправлять:</b> убедитесь, что домен действительно поддельный (откройте его в "
      "изолированной среде, ничего не вводя), сделайте скриншоты и сохраните дату обнаружения. Домены, которые "
      "принадлежат вам или партнёрам, добавьте в «Свои и проверенные домены» в карточке клиента.</div>")

    if client.profile == "uz_fin":
        a("<h2>1. Уведомление в Центральный банк и профильную инспекцию</h2>"
          "<p>Срок — 24 часа с момента обнаружения каждого ресурса. Форму и канал направления сверьте "
          "с действующим положением ЦБ.</p><ul>")
        for c in active:
            deadline = c.first_seen + dt.timedelta(hours=24)
            late = " — срок прошёл, отправляйте немедленно" if deadline < now else ""
            a(f"<li>{e(c.finding.id.split('.', 2)[-1])}: <span class='dl'>до {deadline:%d.%m.%Y %H:%M}{late}</span></li>")
        a("</ul>")
        a(f"<div class='letter'>В Центральный банк Республики Узбекистан\nВ [профильная инспекция]\n\n"
          f"От: {e(client.name)}\n\nУведомление о выявлении ресурсов, использующих бренд организации\n\n"
          f"В ходе мониторинга внешних источников {first:%d.%m.%Y} выявлены ресурсы, имитирующие официальный "
          f"домен {e(dom)}:\n{e(listing)}\n\nПринятые меры: направлены обращения регистратору и хостинг-провайдеру "
          "о блокировке, клиенты предупреждены через официальные каналы [перечислить].\n\n"
          "Контактное лицо: [ФИО, должность, телефон]\nДата: [дата]</div>")
        n = 2
    else:
        n = 1
        if client.profile == "kz_fin":
            a("<p class='ref'>Для финорганизаций Казахстана отдельного срока уведомления о двойниках в исследованных "
              "источниках не найдено; при признаках атаки на клиентов действуйте по вашему регламенту инцидентов и "
              "требованиям АРРФР.</p>")

    a(f"<h2>{n}. Жалоба регистратору / хостинг-провайдеру</h2>"
      "<p>Адрес для жалоб (abuse) указан в технических деталях домена, если его удалось узнать из RDAP/WHOIS.</p>")
    a(f"<div class='letter'>Subject: Phishing / brand impersonation — request for suspension\n\n"
      f"Hello,\n\nThe following domain(s) impersonate {e(dom)}, owned by {e(client.name)}, and may be used for "
      f"phishing against our customers:\n{e(listing_en)}\n\nWe did not authorise this registration. Please investigate "
      "and suspend the domain(s) under your abuse policy. Screenshots and evidence are attached.\n\n"
      f"Contact: [name, phone, e-mail]\n\n— — —\n\nЗдравствуйте!\n\nДомены выше имитируют {e(dom)} ({e(client.name)}) "
      "и могут использоваться для фишинга против наших клиентов. Регистрацию мы не разрешали. Просим проверить и "
      "приостановить делегирование по вашей политике злоупотреблений. Скриншоты прилагаем.\n\nКонтакт: [ФИО, телефон, e-mail]</div>")

    a(f"<h2>{n + 1}. Предупреждение клиентам (сайт, Telegram, приложение)</h2>")
    names = ", ".join(c.finding.id.split(".", 2)[-1] for c in active) or "[домены]"
    a(f"<div class='letter'>⚠ Осторожно, мошенники!\n\nОбнаружены сайты, которые выдают себя за {e(client.name)}: "
      f"{e(names)}.\nНаш единственный официальный сайт — {e(dom)}. Мы никогда не просим сообщать код из SMS, "
      "CVV-код или пароль по телефону и в мессенджерах.\nЕсли вы ввели данные на подозрительном сайте — срочно "
      "позвоните нам: [телефон].</div>")
    a(f"<div class='foot'>Подготовлено программой мониторинга · {e(who)}. Это черновики, не юридическая консультация.</div>")
    a("</div></body></html>")
    return "".join(p)


def save_notices(client: Client, settings: Settings, cases: list[BrandCase]) -> Path:
    folder = settings.reports_path() / "уведомления"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{dt.datetime.now():%Y-%m-%d_%H%M}_двойники_{_safe(client.domain)}.html"
    path.write_text(render_notices(client, settings, cases), "utf-8")
    return path
