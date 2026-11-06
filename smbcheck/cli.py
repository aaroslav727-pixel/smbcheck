"""Командная строка: для Планировщика заданий Windows и быстрых проверок.

  smbcheck                      — открыть окно
  smbcheck demo                 — пример отчёта
  smbcheck scan-all             — проверить всех клиентов с согласием (для ежемесячного запуска)
  smbcheck brand-all            — только двойники бренда (для ежедневного запуска)
  smbcheck evidence [КЛИЕНТ]    — пакет доказательств для проверки (по всем или по одному клиенту)
  smbcheck check DOMAIN --consent-doc "Договор 12" --consent-date 01.11.2026
"""
from __future__ import annotations

import argparse
import sys

from . import APP_NAME, __version__
from .compliance import brand_cases, save_evidence, save_notices
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
    sub.add_parser("brand-all", help="только двойники бренда у всех клиентов с согласием (ежедневно)")
    ev = sub.add_parser("evidence", help="пакет доказательств для регулятора/банка")
    ev.add_argument("client", nargs="?", default="", help="название, домен или id; пусто — все клиенты")
    ev.add_argument("--months", type=int, default=12)
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
        from .demo import demo_client, demo_fin, demo_results
        c = demo_client()
        cur, prev = demo_results()
        _print(str(save_report(cur, c, settings, diff(cur, prev))))
        fc, scans = demo_fin()
        _print(str(save_evidence(fc, settings, scans)))
        _print(str(save_notices(fc, settings, brand_cases(scans))))
        return 0

    if args.cmd == "evidence":
        q = args.client.strip().lower()
        chosen = [c for c in store.load_clients()
                  if not q or q in (c.id, c.domain, c.name.lower(), normalize_domain(q))]
        if not chosen:
            _print(f"Клиент не найден: {args.client}")
            return 2
        for c in chosen:
            _print(f"{c.name}: {save_evidence(c, settings, store.all_scans(c.id), args.months)}")
        return 0

    if args.cmd == "brand-all":
        alerts = 0
        for c in store.load_clients():
            prev = store.last_with(c.id, "brand")
            try:
                res = run_scan(c, settings, ["brand"], log=lambda m: _print("  " + m))
            except ConsentError as e:
                _print(f"{c.name}: пропущено — {e}")
                continue
            store.save_scan(c.id, res, "brand")
            new = [f for f in diff(res, prev).new if f.category == "brand"] if prev else \
                [f for f in res.findings if f.category == "brand" and f.is_problem]
            if new:
                alerts += 1
                path = save_notices(c, settings, brand_cases(store.all_scans(c.id)))
                _print(f"⚠ {c.name}: новые двойники ({len(new)}): " + ", ".join(f.title for f in new))
                _print(f"  Черновики уведомлений: {path}")
            else:
                _print(f"{c.name}: новых двойников нет")
        return 3 if alerts else 0

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
