"""Отчёт для клиента: HTML (печатается в PDF из браузера) и короткий текст для мессенджера."""
from __future__ import annotations

import datetime as dt
import html
from pathlib import Path

from .checks import brand as brand_chk
from .models import CATEGORIES, CRITICAL, HIGH, INFO, LOW, MEDIUM, OK, SEVERITY_ORDER, SEVERITY_RU, Finding, ScanResult
from .scoring import PARTIAL, Diff, category_status, is_gap, sort_key, top_actions
from .storage import Client, Settings, display_domain

VERDICT = {
    "A": "Серьёзных проблем не найдено. Продолжаем следить каждый месяц.",
    "B": "В целом хорошо, но есть что улучшить.",
    "C": "Есть заметные риски — их стоит закрыть в течение месяца.",
    "D": "Найдены серьёзные риски — действовать нужно в ближайшие дни.",
    "F": "Критическое состояние — исправлять нужно сегодня.",
    "?": "Проверка не выполнилась (нет доступа к сети или DNS). Повторите позже.",
}
STATUS_TEXT = {
    OK: "В порядке", LOW: "Мелкие замечания", MEDIUM: "Есть риск", HIGH: "Серьёзный риск",
    CRITICAL: "Критично", "": "Не проверялось", PARTIAL: "Проверено частично",
}
COLORS = {
    CRITICAL: "#b42318", HIGH: "#d9480f", MEDIUM: "#b7791f", LOW: "#4b6b8a", INFO: "#6b7280", OK: "#1f7a4d", "": "#9ca3af", PARTIAL: "#8a6d3b",
}
GRADE_COLORS = {"A": "#1f7a4d", "B": "#3f7d3a", "C": "#b7791f", "D": "#d9480f", "F": "#b42318"}

e = html.escape


def _date(iso: str) -> str:
    try:
        return dt.datetime.fromisoformat(iso).strftime("%d.%m.%Y")
    except ValueError:
        return iso[:10]


def _plural(n: int, one: str, few: str, many: str) -> str:
    n10, n100 = n % 10, n % 100
    if n10 == 1 and n100 != 11:
        return one
    if 2 <= n10 <= 4 and not 12 <= n100 <= 14:
        return few
    return many


CSS = """
:root{--ink:#1d2433;--muted:#5d6678;--line:#e3e6ec;--soft:#f5f6f9;--accent:#1e3a5f}
*{box-sizing:border-box}
body{margin:0;background:#eceef2;color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
.page{background:#fff;max-width:820px;margin:24px auto;padding:40px 48px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:22px;margin:0 0 2px;letter-spacing:-.01em}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--accent);margin:28px 0 10px}
.meta{color:var(--muted);font-size:13px}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;border-bottom:2px solid var(--ink);padding-bottom:16px}
.grade{display:flex;align-items:center;gap:16px}
.badge{width:76px;height:76px;border-radius:50%;color:#fff;display:flex;align-items:center;justify-content:center;font-size:40px;font-weight:700}
.score{font-size:13px;color:var(--muted)} .score b{font-size:22px;color:var(--ink)}
.verdict{font-size:16px;margin:18px 0 0;font-weight:600}
ol.actions{list-style:none;padding:0;margin:0;counter-reset:a}
ol.actions li{counter-increment:a;position:relative;padding:12px 14px 12px 52px;border:1px solid var(--line);border-left:4px solid var(--c);border-radius:6px;margin-bottom:8px;break-inside:avoid}
ol.actions li:before{content:counter(a);position:absolute;left:14px;top:11px;width:26px;height:26px;border-radius:50%;background:var(--c);color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center}
.at{font-weight:600} .aw{color:var(--muted);font-size:13px;margin:2px 0 4px} .af{font-size:13.5px}
.af:before{content:"Что сделать: ";font-weight:600}
table{width:100%;border-collapse:collapse}
.areas td{padding:7px 4px;border-bottom:1px solid var(--line)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;vertical-align:middle}
.st{text-align:right;font-weight:600;white-space:nowrap}
.changes{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.box{background:var(--soft);border-radius:6px;padding:10px 14px;font-size:13px}
.box b{display:block;margin-bottom:4px}
.box ul{margin:0;padding-left:18px}
.det h3{font-size:14px;margin:20px 0 6px;padding-bottom:4px;border-bottom:1px solid var(--line)}
.f{display:grid;grid-template-columns:118px 1fr;gap:4px 12px;padding:8px 0;border-bottom:1px dashed var(--line);break-inside:avoid}
.sev{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;color:var(--c)}
.ft{font-weight:600} .fd{color:var(--muted);font-size:13px} .ff{font-size:13px}
.tech{font:11.5px/1.4 Consolas,"Courier New",monospace;color:#6b7280;word-break:break-all}
.oklist{columns:2;font-size:13px;color:var(--muted);padding-left:18px}
.foot{margin-top:28px;padding-top:12px;border-top:1px solid var(--line);font-size:11.5px;color:var(--muted)}
.break{break-before:page}
.lead{font-size:13.5px;color:var(--muted);margin:0 0 12px}
.ph{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.pc{border:1px solid var(--line);border-top:4px solid var(--c);border-radius:6px;padding:10px 12px;break-inside:avoid}
.pc .pk{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.pc .pv{font-weight:700;color:var(--c);margin:2px 0 4px;font-size:15px}
.pc .pd{font-size:12.5px}
.tw{margin-top:12px}
.tw th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:6px 4px;border-bottom:2px solid var(--line)}
.tw td{padding:7px 4px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}
.tw tr{break-inside:avoid}
.ex{font:12px/1.6 Consolas,"Courier New",monospace;color:var(--ink)}
.cols2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
@media (max-width:640px){.ph,.cols2,.changes{grid-template-columns:1fr}.page{padding:24px 16px}}
.screen-only{font-size:12px;color:var(--muted);text-align:center;margin:10px}
@media print{body{background:#fff}.page{box-shadow:none;margin:0;padding:0;max-width:none}.screen-only{display:none}
@page{size:A4;margin:14mm}}
"""


# ---------------------------------------------------------------- фишинг

def _brand_summary(result: ScanResult) -> dict | None:
    for f in result.findings:
        if f.id == brand_chk.SUMMARY_ID:
            return brand_chk.parse_summary(f)
    return None


def _mail_spoofing(result: ScanResult, domain: str) -> tuple[str, str, str]:
    """(цвет, вывод, пояснение) — можно ли отправить письмо от имени домена."""
    if "email" not in result.checks_run:
        return COLORS[""], "Не проверялось", "Проверка почты в этот раз не запускалась."
    ids = {f.id: f for f in result.findings if f.category == "email"}
    if "email.dmarc.missing" in ids or "email.dmarc.multiple" in ids:
        return (COLORS[HIGH], "Можно подделать",
                f"DMARC не работает: письмо мошенника с адресом @{domain} дойдёт до ваших клиентов как настоящее.")
    if "email.dmarc.none" in ids:
        return (COLORS[MEDIUM], "Можно подделать",
                "DMARC только наблюдает (p=none): поддельные письма от вашего имени доставляются. "
                "Нужен режим quarantine или reject.")
    ok = ids.get("email.dmarc.ok")
    if ok and "reject" in ok.title:
        return COLORS[OK], "Защищено", "DMARC в режиме reject: почтовые сервисы отклоняют письма-подделки."
    if ok and "quarantine" in ok.title:
        return (COLORS[LOW], "Частично защищено",
                "DMARC в режиме quarantine: подделки уходят в спам. Следующий шаг — reject.")
    return COLORS[""], "Нет данных", "Запись DMARC прочитать не удалось."


def _what_on(f: Finding) -> str:
    m = f.detail.split("Состояние: ", 1)
    return m[1].rstrip(".") if len(m) == 2 else f.detail


def _examples(domain: str, trusted: list[str]) -> list[tuple[str, str]]:
    """По одному примеру каждого вида искажения — чтобы клиенту было понятно, что искали."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for name, how in brand_chk.generate_lookalikes(domain, trusted):
        kind = "другая зона" if how.startswith("другая зона") else how
        if kind in seen:
            continue
        seen.add(kind)
        out.append((name, kind))
    return out[:8]


def phishing_section(result: ScanResult, client: Client) -> str:
    dom = display_domain(result.domain)
    sm = _brand_summary(result)
    brand_run = "brand" in result.checks_run
    found = sorted([f for f in result.findings if f.category == "brand" and f.is_problem and f.id != brand_chk.SUMMARY_ID],
                   key=sort_key)
    lookalikes = [f for f in found if f.id.startswith("brand.lookalike.")]
    certs = [f for f in found if f.id.startswith("brand.ct.")]
    more = next((f for f in result.findings if f.id == "brand.lookalike.more"), None)

    p: list[str] = []
    a = p.append
    a("<h2>Фишинг от вашего имени</h2>")
    a("<p class='lead'>Мошенники обманывают клиентов двумя путями: присылают письма, будто бы от вас, и создают сайты "
      "с похожими адресами, где просят ввести пароль, данные карты или код из SMS. Ниже — насколько вы защищены "
      "от обоих путей.</p><div class='ph'>")

    c, v, d = _mail_spoofing(result, dom)
    a(f"<div class='pc' style='--c:{c}'><div class='pk'>Письма от вашего имени</div><div class='pv'>{e(v)}</div>"
      f"<div class='pd'>{e(d)}</div></div>")

    if not brand_run or not sm:
        c, v, d = COLORS[""], "Не проверялось", "Проверка двойников в этот раз не запускалась."
    else:
        n_ok = sm["checked"] - sm["unresolved"]
        hot = [f for f in lookalikes if f.severity in (CRITICAL, HIGH, MEDIUM)]
        if hot:
            c, v = COLORS[HIGH], f"Найдено: {len(lookalikes)}"
            d = f"Из них с сайтом или почтой — {len(hot)}. Список ниже."
        elif lookalikes:
            c, v = COLORS[LOW], f"Заняты: {len(lookalikes)}, признаков фишинга нет"
            d = ("Похожие адреса кем-то зарегистрированы, но они пустые, продаются или давно принадлежат "
                 "другим. Сообщим, если на них появится почта или сменится владелец.")
        elif sm["unresolved"]:
            c, v = COLORS[PARTIAL], "Проверено частично"
            d = (f"Проверено {n_ok} из {sm['checked']} вариантов, двойников среди них нет. "
                 f"Остальные {sm['unresolved']} не удалось проверить из-за сети — повторим.")
        else:
            c, v = COLORS[OK], "Не найдено"
            d = f"Проверено {sm['checked']} похожих адресов — ни один не зарегистрирован."
    a(f"<div class='pc' style='--c:{c}'><div class='pk'>Похожие домены</div><div class='pv'>{e(v)}</div>"
      f"<div class='pd'>{e(d)}</div></div>")

    kws = ", ".join(f"«{k}»" for k in (sm or {}).get("keywords", []))
    st = (sm or {}).get("ct", "off")
    if not brand_run or not sm or st == "off":
        c, v, d = COLORS[""], "Не проверялось", "Поиск по журналам сертификатов не запускался."
    elif st == "skipped":
        c, v, d = COLORS[""], "Пропущено", "Название короче 5 символов. Добавьте слова бренда в карточке клиента."
    elif certs:
        c, v, d = COLORS[MEDIUM], f"Найдено: {len(certs)}", f"Сертификаты на чужие адреса с {kws}. Список ниже."
    elif st == "error":
        c, v, d = COLORS[PARTIAL], "Сервис не ответил", "Журналы сертификатов (crt.sh) были недоступны — повторим в следующий раз."
    else:
        c, v, d = COLORS[OK], "Не найдено", f"Чужих сертификатов с {kws} нет."
    a(f"<div class='pc' style='--c:{c}'><div class='pk'>Сертификаты с вашим названием</div><div class='pv'>{e(v)}</div>"
      f"<div class='pd'>{e(d)}</div></div></div>")

    if found:
        a("<table class='tw'><thead><tr><th>Адрес</th><th>Что на нём</th><th style='width:110px'>Важность</th></tr></thead><tbody>")
        for f in lookalikes + certs:
            name = f.title.split(": ", 1)[-1]
            what = _what_on(f) if f.id.startswith("brand.lookalike.") else f.detail
            a(f"<tr><td><b>{e(name)}</b><div class='tech'>{e(f.tech)}</div></td><td>{e(what)}</td>"
              f"<td class='sev' style='--c:{COLORS[f.severity]}'>{SEVERITY_RU[f.severity]}</td></tr>")
        if more:
            a(f"<tr><td colspan='3' class='tech'>{e(more.title)}: {e(more.tech)}</td></tr>")
        a("</tbody></table>")
        a("<div class='box' style='margin-top:10px'><b>Что делать с найденным</b><ol style='margin:0;padding-left:18px'>"
          "<li>Откройте адрес в изолированной среде (ничего не вводя) и сделайте скриншоты.</li>"
          "<li>Если это подделка — жалоба регистратору и хостингу (черновик готовим мы), предупреждение клиентам "
          "на сайте и в соцсетях, для финорганизаций — уведомление регулятору.</li>"
          "<li>Если адрес ваш или партнёрский — сообщите нам, и мы перестанем считать его двойником.</li></ol></div>")

    if brand_run and sm:
        ex = _examples(result.domain, client.trusted_domains)
        a("<div class='cols2'><div class='box'><b>Что мы искали</b>"
          f"{sm['checked']} вариантов вашего адреса, например:<div class='ex'>"
          + "<br>".join(f"{e(n)} <span style='color:#6b7280'>— {e(k)}</span>" for n, k in ex) + "</div>"
          + (f"<div style='margin-top:6px'>И сертификаты, где встречается {kws}.</div>" if kws else "") + "</div>")
        a("<div class='box'><b>Что не проверяется автоматически</b><ul>"
          "<li>Страницы и аккаунты в соцсетях и мессенджерах от вашего имени</li>"
          "<li>Поддельные мобильные приложения</li><li>SMS и звонки мошенников</li>"
          "<li>Адреса, совсем не похожие на ваш (найдутся, только если в сертификате есть ваше название)</li>"
          "</ul></div></div>")
    return "".join(p)


def render_html(result: ScanResult, client: Client, settings: Settings, d: Diff | None = None) -> str:
    d = d or Diff()
    dom = display_domain(result.domain)
    gc = GRADE_COLORS.get(result.grade, "#6b7280")
    actions = top_actions(result.findings, 3)
    status = category_status(result.findings, result.checks_run)
    problems = sorted([f for f in result.findings if f.is_problem], key=sort_key)
    oks = [f for f in result.findings if f.severity == OK and f.category != "brand"]
    infos = [f for f in result.findings if f.severity == INFO and not is_gap(f) and f.category != "brand"]

    p: list[str] = []
    a = p.append
    a(f"<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
      f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
      f"<title>Отчёт о безопасности — {e(dom)} — {_date(result.finished)}</title><style>{CSS}</style></head><body>")
    a("<div class='screen-only'>Чтобы сохранить в PDF: Ctrl+P → «Сохранить как PDF»</div>")
    a("<div class='page'>")
    a("<div class='top'><div>")
    a(f"<h1>Отчёт о безопасности: {e(dom)}</h1>")
    a(f"<div class='meta'>{e(client.name)} · проверка от {_date(result.finished)}")
    if settings.company_name:
        a(f" · подготовил: {e(settings.company_name)}")
    a("</div></div>")
    a(f"<div class='grade'><div class='badge' style='background:{gc}'>{e(result.grade)}</div>"
      f"<div class='score'><b>{result.score}</b>/100<br>итоговая оценка</div></div></div>")
    a(f"<p class='verdict'>{e(VERDICT.get(result.grade, ''))}</p>")
    if result.errors:
        a("<p class='box' style='margin-top:10px'><b>Проверка неполная.</b> Не выполнились: "
          + e("; ".join(x.split(":")[0] for x in result.errors)) + ". Оценка учитывает только выполненные проверки.</p>")

    brand = [f for f in problems if f.category == "brand"]
    if "brand" in result.checks_run:
        if brand:
            hi = sum(1 for f in brand if f.severity in (CRITICAL, HIGH))
            a(f"<p class='box' style='margin-top:10px;border-left:4px solid {COLORS[HIGH]}'><b>Найдены двойники бренда: "
              f"{len(brand)}</b>" + (f", из них с сайтом или почтой — {hi}" if hi else "") +
              ". Это не ваши настройки, поэтому на оценку не влияет, но через такие домены обманывают ваших клиентов. "
              "Список — в разделе «Фишинг от вашего имени», черновики жалоб и уведомлений — отдельным документом.</p>")
        else:
            sm = _brand_summary(result)
            part = f" среди проверенных {sm['checked'] - sm['unresolved']} из {sm['checked']}" if sm and sm["unresolved"] else ""
            a(f"<p class='box' style='margin-top:10px'>Двойников бренда не найдено{part}. Подробнее — в разделе «Фишинг от вашего имени».</p>")

    a("<h2>Что сделать в этом месяце</h2>")
    if actions:
        a("<ol class='actions'>")
        for f in actions:
            a(f"<li style='--c:{COLORS[f.severity]}'><div class='at'>{e(f.title)}</div>")
            if f.why:
                a(f"<div class='aw'>{e(f.why)}</div>")
            a(f"<div class='af'>{e(f.fix)}</div></li>")
        a("</ol>")
    else:
        a("<p>Срочных действий нет. 👍</p>")

    a("<h2>Состояние по направлениям</h2><table class='areas'>")
    for cat, label in CATEGORIES.items():
        st = status.get(cat, "")
        a(f"<tr><td><span class='dot' style='background:{COLORS[st]}'></span>{e(label)}</td>"
          f"<td class='st' style='color:{COLORS[st]}'>{STATUS_TEXT[st]}</td></tr>")
    a("</table>")
    gaps = [f for f in result.findings if is_gap(f) and f.id != "scan.partial"]
    if gaps:
        a("<div class='box' style='margin-top:10px'><b>Что проверено не полностью</b><ul>")
        for f in gaps:
            a(f"<li>{e(f.title)}" + (f". {e(f.detail)}" if f.detail else "") + "</li>")
        a("</ul></div>")

    if d.score_delta is not None:
        sign = "+" if d.score_delta > 0 else ""
        a(f"<h2>Изменения с прошлой проверки ({e(_date(d.prev_date))})</h2>")
        a(f"<p>Оценка: <b>{sign}{d.score_delta}</b> {_plural(abs(d.score_delta), 'балл', 'балла', 'баллов')}.</p>")
        a("<div class='changes'>")
        a("<div class='box'><b style='color:#1f7a4d'>Исправлено</b>")
        a("<ul>" + "".join(f"<li>{e(f.title)}</li>" for f in d.fixed) + "</ul>" if d.fixed else "—")
        a("</div><div class='box'><b style='color:#b42318'>Появилось новое</b>")
        a("<ul>" + "".join(f"<li>{e(f.title)}</li>" for f in d.new) + "</ul>" if d.new else "—")
        a("</div></div>")

    if "brand" in result.checks_run or "email" in result.checks_run:
        a(phishing_section(result, client))

    # ---------- подробности (двойники подробно описаны в разделе о фишинге)
    detail_problems = [f for f in problems if f.category != "brand"]
    a("<div class='break'></div><h2>Подробности</h2><div class='det'>")
    if not detail_problems:
        a("<p>Замечаний нет.</p>")
    for cat, label in CATEGORIES.items():
        items = [f for f in detail_problems if f.category == cat]
        if not items:
            continue
        a(f"<h3>{e(label)}</h3>")
        for f in items:
            a(f"<div class='f' style='--c:{COLORS[f.severity]}'><div class='sev'>{SEVERITY_RU[f.severity]}</div><div>")
            a(f"<div class='ft'>{e(f.title)}</div>")
            if f.detail:
                a(f"<div class='fd'>{e(f.detail)}</div>")
            if f.fix:
                a(f"<div class='ff'><b>Что сделать:</b> {e(f.fix)}</div>")
            if f.tech:
                a(f"<div class='tech'>{e(f.tech)}</div>")
            a("</div></div>")
    a("</div>")
    if oks:
        a("<h2>Что в порядке</h2><ul class='oklist'>" + "".join(f"<li>{e(f.title)}</li>" for f in oks) + "</ul>")
    if infos:
        a("<h2>К сведению</h2><ul class='oklist'>" + "".join(f"<li>{e(f.title)}</li>" for f in infos) + "</ul>")

    c = client.consent
    a("<div class='foot'>")
    a(f"Проверка выполнена с письменного согласия владельца домена ({e(c.document)} от {e(c.date)}). "
      "Проверялись только публично доступные сведения: DNS-записи, сертификат, ответы сайта, "
      "небольшой список сетевых портов и публичные базы утечек. Взлом, подбор паролей и нагрузочное "
      "тестирование не проводились. Отчёт не является полноценным тестом на проникновение; "
      "отсутствие замечаний не гарантирует отсутствие уязвимостей.")
    if settings.company_contact:
        a(f"<br>Вопросы по отчёту: {e(settings.company_contact)}")
    a("</div></div></body></html>")
    return "".join(p)


def summary_text(result: ScanResult, client: Client, d: Diff | None = None) -> str:
    """Короткий текст для Telegram/WhatsApp."""
    d = d or Diff()
    lines = [f"Проверка безопасности {display_domain(result.domain)} от {_date(result.finished)}",
             f"Оценка: {result.grade} ({result.score}/100). {VERDICT.get(result.grade, '')}"]
    if d.score_delta is not None:
        sign = "+" if d.score_delta > 0 else ""
        lines.append(f"С прошлого раза: {sign}{d.score_delta}, исправлено {len(d.fixed)}, новых {len(d.new)}.")
    brand = [f for f in result.findings if f.category == "brand" and f.is_problem]
    if brand:
        lines.append(f"Найдены похожие домены (возможный фишинг): {len(brand)} — список в отчёте.")
    acts = top_actions(result.findings, 3)
    if acts:
        lines.append("")
        lines.append("Что сделать:")
        for i, f in enumerate(acts, 1):
            lines.append(f"{i}. {f.title} — {f.fix}")
    lines.append("")
    lines.append("Подробный отчёт — во вложении.")
    return "\n".join(lines)


def save_report(result: ScanResult, client: Client, settings: Settings, d: Diff | None = None) -> Path:
    folder = settings.reports_path()
    stamp = _date(result.finished).split(".")
    stamp = "-".join(reversed(stamp)) if len(stamp) == 3 else dt.date.today().isoformat()
    safe = "".join(ch for ch in display_domain(result.domain) if ch.isalnum() or ch in "-._")
    path = folder / f"{stamp}_{safe}.html"
    path.write_text(render_html(result, client, settings, d), "utf-8")
    return path
