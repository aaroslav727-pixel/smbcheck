"""Запуск всех проверок для клиента. Без согласия проверка не начинается."""
from __future__ import annotations

import datetime as dt
import threading
from typing import Callable

from .checks import domain as domain_chk
from .checks import email as email_chk
from .checks import leaks as leaks_chk
from .checks import network as network_chk
from .checks import web as web_chk
from .dnsclient import DNSError, Resolver
from .models import CRITICAL, INFO, Finding, ScanResult
from .scoring import score
from .storage import Client, Settings

ALL_CHECKS = ["email", "web", "domain", "network", "leaks"]
CHECK_LABELS = {
    "email": "Почта: SPF, DKIM, DMARC",
    "web": "Сайт: сертификат, HTTPS, заголовки, забытые файлы",
    "domain": "Домен: срок регистрации, DNSSEC",
    "network": "Порты: RDP, базы данных, 1С, MikroTik",
    "leaks": "Утечки (Have I Been Pwned)",
}


class ConsentError(Exception):
    pass


class Cancelled(Exception):
    pass


def run_scan(client: Client, settings: Settings, checks: list[str] | None = None,
             log: Callable[[str], None] = lambda m: None,
             cancel: threading.Event | None = None,
             resolver: Resolver | None = None) -> ScanResult:
    problem = client.consent.problem()
    if problem:
        raise ConsentError(problem)
    checks = [c for c in (checks or ALL_CHECKS) if c in ALL_CHECKS]
    resolver = resolver or Resolver()
    d = client.domain
    res = ScanResult(domain=d, client=client.name, started=dt.datetime.now().isoformat(timespec="seconds"))

    def step(name: str, fn: Callable[[], list[Finding]]) -> None:
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        try:
            res.findings.extend(fn())
            res.checks_run.append(name)
        except DNSError as e:
            res.errors.append(f"{CHECK_LABELS[name]}: DNS недоступен ({e})")
            log(f"! {name}: {e}")
        except Exception as e:  # noqa: BLE001 — одна упавшая проверка не должна ронять всё
            res.errors.append(f"{CHECK_LABELS[name]}: {e.__class__.__name__}: {e}")
            log(f"! {name}: {e}")

    # Сначала убеждаемся, что домен вообще существует — иначе остальные проверки дают шум
    try:
        exists = not resolver.query(d, "SOA").nxdomain
    except DNSError:
        exists = True  # DNS недоступен — дальше каждая проверка сама сообщит об ошибке
    if not exists:
        res.findings.append(Finding("domain.nxdomain", "domain", CRITICAL, "Домен не найден в DNS",
                                    detail=f"{d} не существует или не делегирован.",
                                    fix="Проверьте написание домена и оплату регистрации."))
        res.checks_run.append("domain")
        checks = []
    if "email" in checks:
        step("email", lambda: email_chk.run(d, resolver, log))
    if "domain" in checks:
        step("domain", lambda: domain_chk.run(d, resolver, log))
    if "web" in checks:
        step("web", lambda: web_chk.run(d, resolver, log))
    if "network" in checks:
        step("network", lambda: network_chk.run(d, resolver, client.office_ips, log))
    if "leaks" in checks:
        step("leaks", lambda: leaks_chk.run(d, client.emails, settings.hibp_key, log))

    if res.errors:
        res.findings.append(Finding("scan.partial", "domain", INFO,
                                    "Часть проверок не выполнилась — результат неполный",
                                    detail="; ".join(res.errors)))
    res.score, res.grade = score(res.findings)
    if not res.checks_run:  # ничего не проверилось (нет сети) — «пятёрка» была бы враньём
        res.score, res.grade = 0, "?"
    res.finished = dt.datetime.now().isoformat(timespec="seconds")
    log(f"Готово: {res.score}/100, оценка {res.grade}")
    return res
