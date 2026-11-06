"""Пример отчёта без сети — чтобы показать клиенту, как выглядит результат."""
from __future__ import annotations

import datetime as dt

from .models import CRITICAL, HIGH, INFO, LOW, MEDIUM, OK, Finding, ScanResult
from .scoring import score
from .storage import Client, Consent


def demo_client() -> Client:
    return Client("ООО «Ромашка» (пример)", "romashka-demo.ru", contact="Анна, +7 900 000-00-00",
                  emails=["director@romashka-demo.ru"], office_ips=["81.200.10.20"],
                  consent=Consent(True, "01.10.2026", "", "Договор № 12/2026"))


def _f(*a, **k) -> Finding:
    return Finding(*a, **k)


def demo_results() -> tuple[ScanResult, ScanResult]:
    now = dt.datetime.now().replace(microsecond=0)
    prev_findings = [
        _f("email.dmarc.missing", "email", HIGH, "Нет DMARC — подделку писем никто не блокирует"),
        _f("email.spf.neutral", "email", MEDIUM, "SPF в нейтральном режиме (?all)"),
        _f("web.exposed.env", "web", CRITICAL, "Открыт файл .env с настройками и паролями"),
        _f("network.3389.81.200.10.20", "network", CRITICAL, "Открыт порт 3389: Удалённый рабочий стол Windows (RDP)"),
        _f("network.8291.81.200.10.20", "network", HIGH, "Открыт порт 8291: Управление MikroTik (Winbox)"),
        _f("email.dkim.notfound", "email", MEDIUM, "DKIM-подпись не найдена"),
        _f("web.hsts.missing", "web", LOW, "Браузеру не велено всегда использовать HTTPS (нет HSTS)"),
        _f("web.version.leak", "web", LOW, "Сайт сообщает версии своего ПО"),
        _f("domain.dnssec.missing", "domain", LOW, "DNSSEC не включён"),
        _f("leaks.account.director@romashka-demo.ru", "leaks", MEDIUM, "Ящик director@romashka-demo.ru найден в утечках: 3"),
    ]
    prev = ScanResult("romashka-demo.ru", "ООО «Ромашка» (пример)",
                      started=(now - dt.timedelta(days=30)).isoformat(),
                      finished=(now - dt.timedelta(days=30)).isoformat(),
                      findings=prev_findings + [
                          _f("brand.summary", "brand", INFO, "Проверено похожих доменов: 141 из 141",
                             tech="checked=141;unresolved=0;registered=0;ct=ok;ct_found=0;keywords=romashka-demo"),
                          _f("brand.lookalike.ok", "brand", OK, "Зарегистрированных двойников не найдено (141 вариантов)")],
                      checks_run=["email", "web", "domain", "network", "leaks", "brand"])
    prev.score, prev.grade = score(prev.findings)

    cur_findings = [
        _f("email.mx", "email", INFO, "Почта: Яндекс 360", tech="mx.yandex.net"),
        _f("email.spf.ok", "email", OK, "SPF настроен, режим мягкий (~all)"),
        _f("email.dmarc.none", "email", MEDIUM, "DMARC только наблюдает (p=none)",
           detail="Поддельные письма доставляются, вы лишь получаете отчёты о них.",
           why="Это нормальный первый шаг, но не защита.",
           fix="Проверьте по отчётам, что все ваши сервисы проходят SPF/DKIM, и смените p=none на p=quarantine, затем на p=reject.",
           tech="v=DMARC1; p=none; rua=mailto:dmarc@romashka-demo.ru"),
        _f("email.dkim.notfound", "email", MEDIUM, "DKIM-подпись не найдена",
           detail="Мы проверили стандартные имена ключей популярных провайдеров и не нашли ни одного.",
           why="Без подписи письма легче подделать, и они чаще попадают в спам.",
           fix="В админке Яндекс 360 → Почта → DKIM-подписи включите подпись и добавьте показанную TXT-запись mail._domainkey."),
        _f("network.3389.81.200.10.20", "network", CRITICAL, "Открыт порт 3389: Удалённый рабочий стол Windows (RDP)",
           detail="Офис: 81.200.10.20.",
           why="Самый частый вход для вирусов-шифровальщиков: пароли подбирают автоматически круглосуточно.",
           fix="Закройте порт на роутере или в файрволе хостинга. Если доступ нужен сотрудникам — давайте его через VPN.",
           tech="81.200.10.20:3389/tcp open"),
        _f("network.8291.81.200.10.20", "network", HIGH, "Открыт порт 8291: Управление MikroTik (Winbox)",
           detail="Офис: 81.200.10.20.",
           why="Роутеры MikroTik массово взламывают через Winbox; управление должно быть доступно только изнутри сети.",
           fix="Закройте порт на роутере или в файрволе хостинга. Если доступ нужен сотрудникам — давайте его через VPN.",
           tech="81.200.10.20:8291/tcp open"),
        _f("web.cert.ok", "web", OK, "Сертификат действителен ещё 64 дн.", tech="Let's Encrypt, TLSv1.3"),
        _f("web.redirect.ok", "web", OK, "HTTP перенаправляет на HTTPS"),
        _f("web.hsts.missing", "web", LOW, "Браузеру не велено всегда использовать HTTPS (нет HSTS)",
           why="Первое подключение по http:// можно перехватить в публичном Wi-Fi.",
           fix="Добавьте заголовок Strict-Transport-Security: max-age=31536000."),
        _f("web.version.leak", "web", LOW, "Сайт сообщает версии своего ПО", detail="Server: nginx/1.18.0; X-Powered-By: PHP/7.4.33",
           fix="Скройте версии в настройках веб-сервера (server_tokens off, expose_php = Off)."),
        _f("web.cms", "web", INFO, "Движок сайта: WordPress 6.4.2"),
        _f("web.exposed.none", "web", OK, "Служебные файлы (.git, .env, бэкапы) не найдены"),
        _f("domain.expiry", "domain", HIGH, "Домен истекает через 23 дн. (24.11.2026)",
           why="Если домен не продлить, перестанут работать сайт и почта, а сам домен могут перехватить.",
           fix="Продлите домен у регистратора и включите автопродление; проверьте, что контактный e-mail актуален."),
        _f("domain.dnssec.missing", "domain", LOW, "DNSSEC не включён",
           fix="Включите DNSSEC у регистратора или DNS-хостинга — обычно это одна кнопка."),
        _f("leaks.site.ok", "leaks", OK, "Сайт не числится среди известных взломов (HIBP)"),
        _f("leaks.account.director@romashka-demo.ru", "leaks", MEDIUM, "Ящик director@romashka-demo.ru найден в утечках: 3",
           detail="Collection #1, Canva, LinkedIn",
           why="Если сотрудник использовал этот пароль и для рабочей почты, ящик могут взломать.",
           fix="Смените пароль от этого ящика и везде, где он повторялся; включите двухфакторный вход."),
    ]
    cur_findings += [
        _f("brand.summary", "brand", INFO, "Проверено похожих доменов: 141 из 141",
           tech="checked=141;unresolved=0;registered=2;ct=ok;ct_found=0;keywords=romashka-demo"),
        _f("brand.lookalike.romashka-demo-online.ru", "brand", HIGH,
           "Домен-двойник: romashka-demo-online.ru (зарегистрирован 4 дн. назад)",
           detail="Как получен: добавлено слово. Состояние: работает сайт и настроена почта — можно и показывать "
                  "поддельную страницу, и рассылать письма.",
           tech="A: 45.12.88.10; MX: mx.romashka-demo-online.ru; регистратор: Example Registrar; "
                "жалобы: abuse@registrar.example"),
        _f("brand.lookalike.romashka-demo.com", "brand", LOW, "Домен-двойник: romashka-demo.com",
           detail="Как получен: другая зона .com. Состояние: припаркован (выставлен на продажу или не используется).",
           tech="NS: ns1.sedoparking.com"),
        _f("brand.ct.ok.romashka-demo", "brand", OK, "Чужих сертификатов с «romashka-demo» не найдено"),
    ]
    cur = ScanResult("romashka-demo.ru", "ООО «Ромашка» (пример)", started=now.isoformat(), finished=now.isoformat(),
                     findings=cur_findings, checks_run=["email", "web", "domain", "network", "leaks", "brand"])
    cur.score, cur.grade = score(cur.findings)
    return cur, prev


# ---------------------------------------------------------------- пример для финорганизации

FIN_DOMAIN = "tezkredit-demo.uz"


def _brand(name: str, sev: str, how: str, state: str, tech: str) -> Finding:
    return _f(f"brand.lookalike.{name}", "brand", sev, f"Домен-двойник: {name}",
              detail=f"Как получен: {how}. Состояние: {state}.",
              why="Похожие домены используют для фишинга: клиенты вводят логин, данные карты или код из SMS на чужом сайте.",
              fix="Проверьте домен в изолированной среде. Если это подделка — уведомление регулятору (в течение 24 часов), "
                  "жалоба регистратору и предупреждение клиентов.",
              tech=tech)


def demo_fin() -> tuple[Client, list[ScanResult]]:
    """МФО из Узбекистана: три ежемесячные проверки и ежедневный мониторинг двойников."""
    c = Client("МФО «ТезКредит» (пример)", FIN_DOMAIN, contact="Дилшод, комплаенс, +998 90 000-00-00",
               emails=["info@tezkredit-demo.uz"], consent=Consent(True, "01.08.2026", "", "Договор № 7/2026"),
               profile="uz_fin", accepts_cards=True, brand_keywords=["tezkredit"])
    now = dt.datetime.now().replace(microsecond=0)
    base_cur, base_prev = demo_results()
    scans: list[ScanResult] = []
    for months_ago, src in ((2, base_prev), (1, base_prev), (0, base_cur)):
        t = now - dt.timedelta(days=30 * months_ago)
        fs = [Finding.from_dict({k: (v.replace("romashka-demo.ru", FIN_DOMAIN) if isinstance(v, str) else v)
                                 for k, v in f.to_dict().items()}) for f in src.findings if f.category != "brand"]
        if months_ago == 0:
            fs.append(_brand("tezkredit-online.uz", HIGH, "добавлено слово", "работает сайт и настроена почта",
                             "A: 45.12.88.10; MX: mx.tezkredit-online.uz; регистратор: Example Registrar; создан: "
                             + (now - dt.timedelta(days=3)).strftime("%d.%m.%Y")))
            fs.append(_brand("tezkredit.top", MEDIUM, "другая зона .top", "на нём работает сайт", "A: 104.21.3.7"))
        else:
            fs.append(_f("brand.lookalike.ok", "brand", OK, "Зарегистрированных двойников не найдено (180 вариантов)"))
        fs.append(_f("brand.summary", "brand", INFO, "Проверено похожих доменов: 180 из 180",
                     tech=f"checked=180;unresolved=0;registered={2 if months_ago == 0 else 0};ct=ok;ct_found=0;"
                          "keywords=tezkredit"))
        r = ScanResult(FIN_DOMAIN, c.name, started=t.isoformat(), finished=t.isoformat(), findings=fs,
                       checks_run=["email", "web", "domain", "network", "leaks", "brand"])
        r.score, r.grade = score(r.findings)
        scans.append(r)
    for days_ago in range(20, 0, -1):  # ежедневные прогоны двойников
        t = now - dt.timedelta(days=days_ago, hours=-2)
        fs = [_f("brand.lookalike.ok", "brand", OK, "Зарегистрированных двойников не найдено")]
        if days_ago <= 3:
            fs = [_brand("tezkredit-online.uz", HIGH, "добавлено слово", "работает сайт и настроена почта",
                         "A: 45.12.88.10; MX: mx.tezkredit-online.uz")]
        scans.append(ScanResult(FIN_DOMAIN, c.name, started=t.isoformat(), finished=t.isoformat(),
                                findings=fs, checks_run=["brand"]))
    scans.sort(key=lambda s: s.finished)
    return c, scans
