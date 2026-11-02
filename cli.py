"""Командная строка: для Планировщика заданий Windows и быстрых проверок.

  smbcheck                      — открыть окно
  smbcheck demo                 — пример отчёта
  smbcheck scan-all             — проверить всех клиентов с согласием (для ежемесячного запуска)
  smbcheck check DOMAIN --consent-doc "Договор 12" --consent-date 01.11.2026
"""
from __future__ import annotations

import argparse
import sys

from . import APP_NAME, __version__
from .report import save_report, summary_text
from .scanner import ALL_CHECKS, ConsentError, run_scan
from .scoring import diff
from .storage import Client, Consent, Store, normalize_domain


def _print(msg: str) -> None:
    if sys.stdout is None:  # запуск из оконной сборки без консоли — пишем в журнал
        from .storage import data_dir
        with open(data_dir() / "smbcheck.log", "a", encoding="utf-8") as f:
            f.write(msg + "\n")
        return
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:  # старая консоль Windows
        print(msg.encode("ascii", "replace").decode(), flush=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="smbcheck", description=f"{APP_NAME} {__version__}")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("gui", help="открыть окно (по умолчанию)")
    sub.add_parser("demo", help="сохранить пример отчёта")
    sa = sub.add_parser("scan-all", help="проверить всех клиентов с действующим согласием")
    sa.add_argument("--checks", default=",".join(ALL_CHECKS))
    ch = sub.add_parser("check", help="разовая проверка домена")
    ch.add_argument("domain")
    ch.add_argument("--client", default="")
    ch.add_argument("--consent-doc", required=True, help="номер письменного согласия/договора")
    ch.add_argument("--consent-date", required=True, help="дата согласия ДД.ММ.ГГГГ")
    ch.add_argument("--email", action="append", default=[], help="ящик для проверки утечек (можно несколько)")
    ch.add_argument("--office-ip", action="append", default=[])
    ch.add_argument("--checks", default=",".join(ALL_CHECKS))
    args = p.parse_args(argv)

    if args.cmd in (None, "gui"):
        from .gui import main as gui_main
        gui_main()
        return 0

    store = Store()
    settings = store.load_settings()

    if args.cmd == "demo":
        from .demo import demo_client, demo_results
        c = demo_client()
        cur, prev = demo_results()
        _print(str(save_report(cur, c, settings, diff(cur, prev))))
        return 0

    if args.cmd == "check":
        domain = normalize_domain(args.domain)
        if not domain:
            _print(f"Некорректный домен: {args.domain}")
            return 2
        client = Client(args.client or domain, domain, emails=args.email, office_ips=args.office_ip,
                        consent=Consent(True, args.consent_date, "", args.consent_doc))
        clients = [client]
    else:
        clients = store.load_clients()

    checks = [c.strip() for c in args.checks.split(",") if c.strip()]
    worst = 0
    for c in clients:
        _print(f"=== {c.name} ({c.domain}) ===")
        prev = store.last_scan(c.id) if args.cmd == "scan-all" else None
        try:
            res = run_scan(c, settings, checks, log=lambda m: _print("  " + m))
        except ConsentError as e:
            _print(f"  Пропущено: {e}")
            continue
        d = diff(res, prev)
        if args.cmd == "scan-all":
            store.save_scan(c.id, res)
        path = save_report(res, c, settings, d)
        _print(summary_text(res, c, d))
        _print(f"Отчёт: {path}\n")
        worst = max(worst, 1 if res.grade in "DF" else 0)
    return worst


if __name__ == "__main__":
    sys.exit(main())
