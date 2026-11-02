"""Бланк согласия на проверку — печатается, подписывается клиентом, скан хранится у вас."""
from __future__ import annotations

import datetime as dt
import html
from pathlib import Path

from .storage import Client, Settings, display_domain

e = html.escape

CSS = """
body{font:14px/1.55 "Times New Roman",Georgia,serif;color:#111;background:#eceef2;margin:0}
.page{background:#fff;max-width:760px;margin:24px auto;padding:48px 56px}
h1{font-size:18px;text-align:center;margin:0 0 4px} .c{text-align:center;margin:0 0 20px}
ol{padding-left:20px} li{margin-bottom:6px}
.blank{display:inline-block;min-width:220px;border-bottom:1px solid #111}
.sign{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-top:40px}
.sign div{border-top:1px solid #111;padding-top:4px;font-size:12px}
.hint{font:12px system-ui,sans-serif;color:#666;text-align:center;margin:10px}
@media print{body{background:#fff}.page{margin:0;padding:0}.hint{display:none}@page{size:A4;margin:20mm}}
"""


def render_consent(client: Client, settings: Settings) -> str:
    dom = display_domain(client.domain) if client.domain else ""
    ips = ", ".join(client.office_ips) or "—"
    today = dt.date.today().strftime("%d.%m.%Y")
    executor = settings.company_name or '<span class="blank"></span>'

    def v(x: str) -> str:
        return e(x) if x else '<span class="blank"></span>'

    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>Согласие на проверку — {e(dom)}</title><style>{CSS}</style></head><body>
<div class="hint">Шаблон. Перед использованием покажите юристу. Печать: Ctrl+P</div>
<div class="page">
<h1>СОГЛАСИЕ</h1>
<p class="c">на проведение внешней проверки защищённости<br>{today}</p>
<p>{v(client.name)} (далее — Заказчик), в лице {'<span class="blank"></span>'}, действующего на основании
{'<span class="blank"></span>'}, разрешает {executor} (далее — Исполнитель) проводить проверку
защищённости перечисленных ниже ресурсов на условиях настоящего согласия.</p>
<ol>
<li><b>Ресурсы.</b> Доменное имя: <b>{v(dom)}</b> и его поддомены; IP-адреса: {e(ips)}.
Заказчик подтверждает, что является владельцем или законным администратором этих ресурсов
либо получил разрешение их владельца (в том числе хостинг-провайдера, если это требуется его правилами).</li>
<li><b>Что проверяется.</b> Публичные DNS-записи (SPF, DKIM, DMARC, MX, DNSSEC, CAA); срок регистрации домена;
сертификат и настройки HTTPS; HTTP-заголовки сайта; наличие в открытом доступе служебных файлов
(например, .git, .env, резервных копий); доступность из интернета ограниченного списка сетевых портов
(не более 30) методом установления TCP-соединения; наличие адресов электронной почты Заказчика
в публичных базах утечек: {v(", ".join(client.emails))}.</li>
<li><b>Что не проводится.</b> Подбор паролей, эксплуатация уязвимостей, получение доступа к данным,
нагрузочное тестирование и любые действия, способные нарушить работу ресурсов.</li>
<li><b>Периодичность.</b> Не чаще одного раза в неделю, плановая проверка — ежемесячно.</li>
<li><b>Конфиденциальность.</b> Результаты передаются только Заказчику и не раскрываются третьим лицам,
кроме случаев, предусмотренных законом.</li>
<li><b>Срок действия.</b> С даты подписания до {'<span class="blank"></span>'} или до письменного отзыва
согласия Заказчиком.</li>
<li><b>Контакт для экстренной остановки проверки:</b> {v(client.contact)}.</li>
</ol>
<div class="sign">
<div>Заказчик: подпись, ФИО, должность, печать (при наличии)</div>
<div>Исполнитель: подпись, ФИО</div>
</div>
</div></body></html>"""


def save_consent(client: Client, settings: Settings) -> Path:
    folder = settings.reports_path() / "согласия"
    folder.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch for ch in display_domain(client.domain) if ch.isalnum() or ch in "-._") or "client"
    p = folder / f"согласие_{safe}.html"
    p.write_text(render_consent(client, settings), "utf-8")
    return p
