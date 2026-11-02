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
                      findings=prev_findings, checks_run=["email", "web", "domain", "network", "leaks"])
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
    cur = ScanResult("romashka-demo.ru", "ООО «Ромашка» (пример)", started=now.isoformat(), finished=now.isoformat(),
                     findings=cur_findings, checks_run=["email", "web", "domain", "network", "leaks"])
    cur.score, cur.grade = score(cur.findings)
    return cur, prev
