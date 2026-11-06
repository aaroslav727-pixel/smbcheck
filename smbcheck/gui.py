"""Окно программы (tkinter — входит в Python для Windows, ставить ничего не нужно)."""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from . import APP_NAME, __version__
from .compliance import brand_cases, save_evidence, save_notices
from .consent import save_consent
from .demo import demo_client, demo_fin, demo_results
from .report import save_report, summary_text
from .scanner import ALL_CHECKS, CHECK_LABELS, Cancelled, ConsentError, run_scan
from .scoring import diff
from .storage import PROFILES, Client, Consent, Settings, Store, display_domain, normalize_domain


def open_path(path: Path) -> None:
    """Открыть файл/папку программой по умолчанию."""
    try:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            webbrowser.open(path.resolve().as_uri())
    except Exception as e:  # noqa: BLE001
        messagebox.showerror(APP_NAME, f"Не удалось открыть {path}:\n{e}")


def _lines(text: str) -> list[str]:
    return [x.strip() for x in text.replace(",", "\n").replace(";", "\n").splitlines() if x.strip()]


# ====================================================================== диалоги

class ClientDialog:
    """Карточка клиента. self.result — Client после «Сохранить», иначе None."""

    def __init__(self, parent: tk.Misc, client: Client | None, settings: Settings):
        self.result: Client | None = None
        self.settings = settings
        self.src = client
        c = client or Client("", "")
        self.win = tk.Toplevel(parent)
        self.win.title("Клиент" if client else "Новый клиент")
        self.win.transient(parent)
        self.win.resizable(False, False)
        f = ttk.Frame(self.win, padding=14)
        f.pack(fill="both", expand=True)

        self.v_name = tk.StringVar(value=c.name)
        self.v_domain = tk.StringVar(value=display_domain(c.domain) if c.domain else "")
        self.v_contact = tk.StringVar(value=c.contact)
        row = 0
        for label, var, hint in (
            ("Название клиента*", self.v_name, "ООО «Ромашка»"),
            ("Домен*", self.v_domain, "romashka.ru"),
            ("Контакт", self.v_contact, "имя, телефон или Telegram"),
        ):
            ttk.Label(f, text=label).grid(row=row, column=0, sticky="w", pady=3)
            ttk.Entry(f, textvariable=var, width=46).grid(row=row, column=1, sticky="we", pady=3)
            ttk.Label(f, text=hint, foreground="#888").grid(row=row, column=2, sticky="w", padx=6)
            row += 1

        ttk.Label(f, text="Рабочие ящики клиента\n(проверка утечек)").grid(row=row, column=0, sticky="nw", pady=3)
        self.t_emails = tk.Text(f, width=46, height=3, font=("Segoe UI", 9))
        self.t_emails.insert("1.0", "\n".join(c.emails))
        self.t_emails.grid(row=row, column=1, sticky="we", pady=3)
        ttk.Label(f, text="почта сотрудников клиента,\nнапр. director@romashka.ru;\nнужен ключ HIBP в Настройках",
                  foreground="#888").grid(row=row, column=2, sticky="nw", padx=6)
        row += 1
        ttk.Label(f, text="Внешний IP офиса").grid(row=row, column=0, sticky="nw", pady=3)
        self.t_ips = tk.Text(f, width=46, height=2, font=("Segoe UI", 9))
        self.t_ips.insert("1.0", "\n".join(c.office_ips))
        self.t_ips.grid(row=row, column=1, sticky="we", pady=3)
        ttk.Label(f, text="адрес роутера; узнать:\n2ip.ru с компьютера офиса", foreground="#888") \
            .grid(row=row, column=2, sticky="nw", padx=6)
        row += 1
        ttk.Label(f, text="Заметки").grid(row=row, column=0, sticky="nw", pady=3)
        self.t_notes = tk.Text(f, width=46, height=2, font=("Segoe UI", 9))
        self.t_notes.insert("1.0", c.notes)
        self.t_notes.grid(row=row, column=1, sticky="we", pady=3)
        row += 1

        pf = ttk.LabelFrame(f, text=" Финорганизациям: пакет для проверки и двойники бренда ", padding=10)
        pf.grid(row=row, column=0, columnspan=3, sticky="we", pady=(12, 4))
        self.v_profile = tk.StringVar(value=PROFILES.get(c.profile, PROFILES["general"]))
        ttk.Label(pf, text="Тип клиента").grid(row=0, column=0, sticky="w", pady=3)
        ttk.Combobox(pf, textvariable=self.v_profile, values=list(PROFILES.values()), state="readonly", width=52) \
            .grid(row=0, column=1, columnspan=2, sticky="w", pady=3)
        self.v_cards = tk.BooleanVar(value=c.accepts_cards)
        ttk.Checkbutton(pf, text="Принимает банковские карты на сайте (добавить темы PCI DSS)", variable=self.v_cards) \
            .grid(row=1, column=0, columnspan=3, sticky="w")
        self.v_keywords = tk.StringVar(value=", ".join(c.brand_keywords))
        ttk.Label(pf, text="Слова бренда").grid(row=2, column=0, sticky="w", pady=3)
        ttk.Entry(pf, textvariable=self.v_keywords, width=40).grid(row=2, column=1, sticky="w", pady=3)
        ttk.Label(pf, text="латиницей, через запятую", foreground="#888").grid(row=2, column=2, sticky="w", padx=6)
        ttk.Label(pf, text="Свои и проверенные\nпохожие домены").grid(row=3, column=0, sticky="nw", pady=3)
        self.t_trusted = tk.Text(pf, width=40, height=2, font=("Segoe UI", 9))
        self.t_trusted.insert("1.0", "\n".join(c.trusted_domains))
        self.t_trusted.grid(row=3, column=1, sticky="w", pady=3)
        ttk.Label(pf, text="не считать двойниками", foreground="#888").grid(row=3, column=2, sticky="nw", padx=6)
        row += 1

        cf = ttk.LabelFrame(f, text=" Письменное согласие владельца (без него проверка не запустится) ", padding=10)
        cf.grid(row=row, column=0, columnspan=3, sticky="we", pady=(12, 4))
        self.v_has = tk.BooleanVar(value=c.consent.has)
        self.v_cdate = tk.StringVar(value=c.consent.date)
        self.v_cdoc = tk.StringVar(value=c.consent.document)
        self.v_cuntil = tk.StringVar(value=c.consent.valid_until)
        ttk.Checkbutton(cf, text="Согласие подписано и хранится у меня", variable=self.v_has) \
            .grid(row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(cf, text="Документ №").grid(row=1, column=0, sticky="w", pady=3)
        ttk.Entry(cf, textvariable=self.v_cdoc, width=22).grid(row=1, column=1, sticky="w", pady=3)
        ttk.Label(cf, text="от").grid(row=1, column=2, sticky="e", padx=4)
        ttk.Entry(cf, textvariable=self.v_cdate, width=12).grid(row=1, column=3, sticky="w")
        ttk.Label(cf, text="Действует до").grid(row=2, column=0, sticky="w", pady=3)
        ttk.Entry(cf, textvariable=self.v_cuntil, width=12).grid(row=2, column=1, sticky="w", pady=3)
        ttk.Label(cf, text="ДД.ММ.ГГГГ, можно оставить пустым", foreground="#888") \
            .grid(row=2, column=2, columnspan=2, sticky="w")
        ttk.Button(cf, text="Сформировать бланк согласия…", command=self._consent_form) \
            .grid(row=3, column=0, columnspan=4, sticky="w", pady=(8, 0))
        row += 1

        bf = ttk.Frame(f)
        bf.grid(row=row, column=0, columnspan=3, sticky="e", pady=(12, 0))
        ttk.Button(bf, text="Отмена", command=self.win.destroy).pack(side="right")
        ttk.Button(bf, text="Сохранить", command=self._save).pack(side="right", padx=6)
        self.win.bind("<Escape>", lambda _e: self.win.destroy())
        self.win.grab_set()
        self.win.wait_visibility()
        self.win.focus_set()

    def _collect(self, strict: bool) -> Client | None:
        name = self.v_name.get().strip()
        domain = normalize_domain(self.v_domain.get())
        if strict and not name:
            messagebox.showwarning(APP_NAME, "Укажите название клиента.", parent=self.win)
            return None
        if strict and not domain:
            messagebox.showwarning(APP_NAME, "Домен указан неверно. Пример: romashka.ru", parent=self.win)
            return None
        emails = _lines(self.t_emails.get("1.0", "end"))
        bad = [x for x in emails if "@" not in x]
        if strict and bad:
            messagebox.showwarning(APP_NAME, "Неверные адреса почты:\n" + "\n".join(bad), parent=self.win)
            return None
        ips = _lines(self.t_ips.get("1.0", "end"))
        bad_ips = []
        for ip in ips:
            try:
                if not ipaddress.ip_address(ip).is_global:
                    bad_ips.append(f"{ip} — это внутренний адрес, снаружи его не проверить")
            except ValueError:
                bad_ips.append(f"{ip} — не похоже на IP-адрес")
        if strict and bad_ips:
            messagebox.showwarning(APP_NAME, "\n".join(bad_ips), parent=self.win)
            return None
        for label, var in (("Дата согласия", self.v_cdate), ("Срок действия", self.v_cuntil)):
            val = var.get().strip()
            if strict and val:
                try:
                    dt.datetime.strptime(val, "%d.%m.%Y")
                except ValueError:
                    messagebox.showwarning(APP_NAME, f"{label}: формат ДД.ММ.ГГГГ", parent=self.win)
                    return None
        trusted = [normalize_domain(x) or x.lower() for x in _lines(self.t_trusted.get("1.0", "end"))]
        profile = next((k for k, v in PROFILES.items() if v == self.v_profile.get()), "general")
        c = Client(name=name, domain=domain, contact=self.v_contact.get().strip(),
                   emails=emails, office_ips=ips, notes=self.t_notes.get("1.0", "end").strip(),
                   consent=Consent(self.v_has.get(), self.v_cdate.get().strip(), self.v_cuntil.get().strip(),
                                   self.v_cdoc.get().strip()),
                   profile=profile, accepts_cards=bool(self.v_cards.get()),
                   brand_keywords=[k.lower() for k in _lines(self.v_keywords.get())],
                   trusted_domains=trusted)
        if self.src:
            c.id = self.src.id
        return c

    def _consent_form(self) -> None:
        c = self._collect(strict=False)
        if c and c.domain:
            open_path(save_consent(c, self.settings))
        else:
            messagebox.showinfo(APP_NAME, "Сначала укажите корректный домен.", parent=self.win)

    def _save(self) -> None:
        c = self._collect(strict=True)
        if c is None:
            return
        if not c.consent.has:
            if not messagebox.askyesno(APP_NAME, "Согласие не отмечено — проверять этого клиента будет нельзя.\n"
                                                 "Сохранить всё равно?", parent=self.win):
                return
        self.result = c
        self.win.destroy()


class SettingsDialog:
    def __init__(self, parent: tk.Misc, s: Settings):
        self.result: Settings | None = None
        self.win = tk.Toplevel(parent)
        self.win.title("Настройки")
        self.win.transient(parent)
        self.win.resizable(False, False)
        f = ttk.Frame(self.win, padding=14)
        f.pack(fill="both", expand=True)
        self.v_company = tk.StringVar(value=s.company_name)
        self.v_contact = tk.StringVar(value=s.company_contact)
        self.v_key = tk.StringVar(value=s.hibp_key)
        self.v_dir = tk.StringVar(value=s.reports_dir)
        rows = [
            ("Ваше имя / компания", self.v_company, "в отчёте: «подготовил: …»", None),
            ("Контакт для клиентов", self.v_contact, "Telegram, телефон или e-mail", None),
            ("Ключ HIBP", self.v_key, "haveibeenpwned.com/API/Key", "*"),
        ]
        for i, (label, var, hint, show) in enumerate(rows):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="w", pady=3)
            ttk.Entry(f, textvariable=var, width=44, show=show or "").grid(row=i, column=1, pady=3, sticky="we")
            ttk.Label(f, text=hint, foreground="#888").grid(row=i, column=2, sticky="w", padx=6)
        ttk.Label(f, text="Папка отчётов").grid(row=3, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.v_dir, width=44).grid(row=3, column=1, pady=3, sticky="we")
        ttk.Button(f, text="Выбрать…", command=self._pick).grid(row=3, column=2, sticky="w", padx=6)
        ttk.Label(f, text="Без ключа HIBP проверяется только взлом самого сайта; ящики сотрудников — с ключом.",
                  foreground="#666").grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))
        bf = ttk.Frame(f)
        bf.grid(row=5, column=0, columnspan=3, sticky="e", pady=(12, 0))
        ttk.Button(bf, text="Отмена", command=self.win.destroy).pack(side="right")
        ttk.Button(bf, text="Сохранить", command=self._save).pack(side="right", padx=6)
        self.win.grab_set()
        self.win.wait_visibility()

    def _pick(self) -> None:
        d = filedialog.askdirectory(parent=self.win)
        if d:
            self.v_dir.set(d)

    def _save(self) -> None:
        self.result = Settings(self.v_key.get().strip(), self.v_dir.get().strip(),
                               self.v_company.get().strip(), self.v_contact.get().strip())
        self.win.destroy()


# ====================================================================== главное окно

class App:
    def __init__(self, store: Store | None = None):
        if os.name == "nt":
            try:  # чёткий текст на мониторах с масштабированием
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:  # noqa: BLE001
                pass
        self.store = store or Store()
        self.settings = self.store.load_settings()
        self.clients = self.store.load_clients()
        self.q: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        self.worker: threading.Thread | None = None
        self.last_report: dict[str, Path] = {}
        self.last_text: dict[str, str] = {}

        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} {__version__} — проверка безопасности для малого бизнеса")
        self.root.geometry("1120x680")
        self.root.minsize(900, 560)
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Grade.TLabel", font=("Segoe UI", 28, "bold"))
        style.configure("H.TLabel", font=("Segoe UI", 11, "bold"))
        self._build()
        self._refresh()
        self.root.after(100, self._poll)

    # ---------------------------------------------------------------- layout
    def _build(self) -> None:
        bar = ttk.Frame(self.root, padding=(10, 8))
        bar.pack(fill="x")
        for text, cmd in (("+ Клиент", self.add_client), ("Изменить", self.edit_client),
                          ("Удалить", self.delete_client)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=(0, 6))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(bar, text="Пример отчёта", command=self.demo).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Пример пакета МФО", command=self.demo_fin).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Папка отчётов", command=lambda: open_path(self.settings.reports_path())) \
            .pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Настройки", command=self.open_settings).pack(side="right")

        pw = ttk.PanedWindow(self.root, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        left = ttk.Frame(pw)
        cols = ("domain", "consent", "last", "grade")
        self.tree = ttk.Treeview(left, columns=cols, show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="Клиент")
        self.tree.heading("domain", text="Домен")
        self.tree.heading("consent", text="Согласие")
        self.tree.heading("last", text="Проверка")
        self.tree.heading("grade", text="Оценка")
        self.tree.column("#0", width=200)
        self.tree.column("domain", width=150)
        self.tree.column("consent", width=90, anchor="center")
        self.tree.column("last", width=85, anchor="center")
        self.tree.column("grade", width=60, anchor="center")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._on_select())
        self.tree.bind("<Double-1>", lambda _e: self.edit_client())
        self.tree.tag_configure("noconsent", foreground="#a0a0a0")
        pw.add(left, weight=3)

        right = ttk.Frame(pw, padding=(12, 0, 0, 0))
        pw.add(right, weight=2)
        self.lbl_client = ttk.Label(right, text="Выберите клиента слева", style="H.TLabel")
        self.lbl_client.pack(anchor="w")
        self.lbl_consent = ttk.Label(right, text="", foreground="#a33", wraplength=380)
        self.lbl_consent.pack(anchor="w", pady=(2, 8))

        chk = ttk.LabelFrame(right, text=" Что проверять ", padding=8)
        chk.pack(fill="x")
        self.v_checks = {c: tk.BooleanVar(value=True) for c in ALL_CHECKS}
        for c in ALL_CHECKS:
            ttk.Checkbutton(chk, text=CHECK_LABELS[c], variable=self.v_checks[c]).pack(anchor="w")

        bf = ttk.Frame(right)
        bf.pack(fill="x", pady=8)
        self.btn_scan = ttk.Button(bf, text="▶ Проверить выбранных", command=self.scan_selected)
        self.btn_scan.pack(side="left")
        self.btn_all = ttk.Button(bf, text="Проверить всех", command=self.scan_all)
        self.btn_all.pack(side="left", padx=6)
        self.btn_stop = ttk.Button(bf, text="Стоп", command=self.cancel.set, state="disabled")
        self.btn_stop.pack(side="left")
        self.progress = ttk.Progressbar(right, mode="indeterminate")
        self.progress.pack(fill="x")

        res = ttk.Frame(right)
        res.pack(fill="x", pady=(10, 4))
        self.lbl_grade = ttk.Label(res, text="—", style="Grade.TLabel", width=3, anchor="center")
        self.lbl_grade.pack(side="left")
        info = ttk.Frame(res)
        info.pack(side="left", fill="x", expand=True, padx=8)
        self.lbl_score = ttk.Label(info, text="Ещё не проверялся")
        self.lbl_score.pack(anchor="w")
        rb = ttk.Frame(info)
        rb.pack(anchor="w", pady=(4, 0))
        self.btn_report = ttk.Button(rb, text="Открыть отчёт", command=self.open_report, state="disabled")
        self.btn_report.pack(side="left")
        self.btn_copy = ttk.Button(rb, text="Текст для мессенджера", command=self.copy_text, state="disabled")
        self.btn_copy.pack(side="left", padx=6)
        rb2 = ttk.Frame(info)
        rb2.pack(anchor="w", pady=(4, 0))
        self.btn_pack = ttk.Button(rb2, text="Пакет для проверки", command=self.evidence, state="disabled")
        self.btn_pack.pack(side="left")
        self.btn_notice = ttk.Button(rb2, text="Уведомления по двойникам", command=self.notices, state="disabled")
        self.btn_notice.pack(side="left", padx=6)
        self.btn_brand = ttk.Button(right, text="Только двойники (быстро, можно каждый день)", command=self.scan_brand)
        self.btn_brand.pack(anchor="w", pady=(6, 0))

        ttk.Label(right, text="Журнал").pack(anchor="w", pady=(8, 2))
        self.log = ScrolledText(right, height=10, font=("Consolas", 9), state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True)

    # ---------------------------------------------------------------- helpers
    def _selected(self) -> list[Client]:
        ids = set(self.tree.selection())
        return [c for c in self.clients if c.id in ids]

    def _refresh(self) -> None:
        sel = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        for c in sorted(self.clients, key=lambda x: x.name.lower()):
            last = self.store.last_scan(c.id)
            problem = c.consent.problem()
            self.tree.insert("", "end", iid=c.id, text=c.name,
                             values=(display_domain(c.domain), "нет" if problem else "есть",
                                     dt.datetime.fromisoformat(last.finished).strftime("%d.%m.%Y") if last else "—",
                                     f"{last.grade} ({last.score})" if last else "—"),
                             tags=("noconsent",) if problem else ())
        keep = [i for i in sel if self.tree.exists(i)]
        if keep:
            self.tree.selection_set(keep)
        self._on_select()

    def _on_select(self) -> None:
        sel = self._selected()
        if len(sel) != 1:
            self.lbl_client.configure(text=f"Выбрано клиентов: {len(sel)}" if sel else "Выберите клиента слева")
            self.lbl_consent.configure(text="")
            self.lbl_grade.configure(text="—", foreground="")
            self.lbl_score.configure(text="")
            self.btn_report.configure(state="disabled")
            self.btn_copy.configure(state="disabled")
            self.btn_pack.configure(state="disabled")
            self.btn_notice.configure(state="disabled")
            return
        c = sel[0]
        self.lbl_client.configure(text=f"{c.name} — {display_domain(c.domain)}")
        problem = c.consent.problem()
        self.lbl_consent.configure(text=("⚠ " + problem) if problem else
                                   f"Согласие: {c.consent.document} от {c.consent.date}", foreground="#a33" if problem else "#2b7a4b")
        last = self.store.last_scan(c.id)
        colors = {"A": "#1f7a4d", "B": "#3f7d3a", "C": "#b7791f", "D": "#d9480f", "F": "#b42318"}
        if last:
            self.lbl_grade.configure(text=last.grade, foreground=colors.get(last.grade, ""))
            problems = sum(1 for f in last.findings if f.is_problem)
            self.lbl_score.configure(text=f"{last.score}/100 · замечаний: {problems} · "
                                          f"{dt.datetime.fromisoformat(last.finished).strftime('%d.%m.%Y %H:%M')}")
        else:
            self.lbl_grade.configure(text="—", foreground="")
            self.lbl_score.configure(text="Ещё не проверялся")
        has_report = c.id in self.last_report or last is not None
        self.btn_report.configure(state="normal" if has_report else "disabled")
        self.btn_copy.configure(state="normal" if has_report else "disabled")
        any_scan = has_report or bool(self.store.history(c.id, "brand"))
        self.btn_pack.configure(state="normal" if any_scan else "disabled")
        self.btn_notice.configure(state="normal" if any_scan else "disabled")

    def _log(self, msg: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", f"{dt.datetime.now():%H:%M:%S}  {msg}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _busy(self, busy: bool) -> None:
        st = "disabled" if busy else "normal"
        self.btn_scan.configure(state=st)
        self.btn_all.configure(state=st)
        self.btn_brand.configure(state=st)
        self.btn_stop.configure(state="normal" if busy else "disabled")
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    # ---------------------------------------------------------------- клиенты
    def add_client(self) -> None:
        d = ClientDialog(self.root, None, self.settings)
        self.root.wait_window(d.win)
        if d.result:
            if any(c.domain == d.result.domain for c in self.clients):
                if not messagebox.askyesno(APP_NAME, "Клиент с таким доменом уже есть. Добавить ещё одного?"):
                    return
            self.clients.append(d.result)
            self.store.save_clients(self.clients)
            self._refresh()
            self.tree.selection_set(d.result.id)

    def edit_client(self) -> None:
        sel = self._selected()
        if len(sel) != 1:
            return
        d = ClientDialog(self.root, sel[0], self.settings)
        self.root.wait_window(d.win)
        if d.result:
            self.clients = [d.result if c.id == d.result.id else c for c in self.clients]
            self.store.save_clients(self.clients)
            self._refresh()

    def delete_client(self) -> None:
        sel = self._selected()
        if not sel:
            return
        names = ", ".join(c.name for c in sel)
        if messagebox.askyesno(APP_NAME, f"Удалить: {names}?\nИстория проверок останется в папке данных."):
            ids = {c.id for c in sel}
            self.clients = [c for c in self.clients if c.id not in ids]
            self.store.save_clients(self.clients)
            self._refresh()

    def open_settings(self) -> None:
        d = SettingsDialog(self.root, self.settings)
        self.root.wait_window(d.win)
        if d.result:
            self.settings = d.result
            self.store.save_settings(self.settings)

    # ---------------------------------------------------------------- проверка
    def scan_selected(self) -> None:
        sel = self._selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Выберите клиента в списке.")
            return
        self._start(sel)

    def scan_all(self) -> None:
        ok = [c for c in self.clients if not c.consent.problem()]
        skipped = len(self.clients) - len(ok)
        if not ok:
            messagebox.showinfo(APP_NAME, "Нет клиентов с действующим согласием.")
            return
        msg = f"Проверить клиентов: {len(ok)}?"
        if skipped:
            msg += f"\nБез согласия будут пропущены: {skipped}."
        if messagebox.askyesno(APP_NAME, msg):
            self._start(ok)

    def scan_brand(self) -> None:
        sel = self._selected() or [c for c in self.clients if not c.consent.problem()]
        if not sel:
            messagebox.showinfo(APP_NAME, "Нет клиентов с действующим согласием.")
            return
        self._start(sel, ["brand"])

    def _start(self, clients: list[Client], only: list[str] | None = None) -> None:
        blocked = [(c, c.consent.problem()) for c in clients if c.consent.problem()]
        if blocked:
            text = "\n".join(f"• {c.name}: {p}" for c, p in blocked)
            messagebox.showwarning(APP_NAME, "Эти клиенты не будут проверены — нет действующего согласия:\n\n"
                                   + text + "\n\nОткройте карточку клиента и заполните раздел «Согласие».")
            clients = [c for c in clients if not c.consent.problem()]
        if not clients:
            return
        checks = only or [c for c, v in self.v_checks.items() if v.get()]
        if not checks:
            messagebox.showinfo(APP_NAME, "Отметьте хотя бы одну проверку.")
            return
        self.cancel.clear()
        self._busy(True)
        settings = self.settings
        self.worker = threading.Thread(target=self._work, args=(clients, checks, settings), daemon=True)
        self.worker.start()

    def _work(self, clients: list[Client], checks: list[str], settings: Settings) -> None:
        """Фоновый поток: никаких вызовов tkinter, только очередь сообщений."""
        log = lambda m: self.q.put(("log", m))  # noqa: E731
        for c in clients:
            if self.cancel.is_set():
                break
            log(f"=== {c.name} ({display_domain(c.domain)}) ===")
            try:
                brand_only = checks == ["brand"]
                prev = self.store.last_with(c.id, "brand") if brand_only else self.store.last_scan(c.id)
                res = run_scan(c, settings, checks, log=log, cancel=self.cancel)
                d = diff(res, prev)
                self.store.save_scan(c.id, res, "brand" if brand_only else "full")
                new_brand = [f for f in d.new if f.category == "brand"] if prev else \
                    [f for f in res.findings if f.category == "brand" and f.is_problem]
                if new_brand:
                    notice = save_notices(c, settings, brand_cases(self.store.all_scans(c.id)))
                    log(f"⚠ Новые двойники: {len(new_brand)}. Черновики уведомлений: {notice}")
                if brand_only:
                    log(f"Двойники: активных {sum(1 for f in res.findings if f.category == 'brand' and f.is_problem)}")
                    self.q.put(("finished_one",))
                    continue
                path = save_report(res, c, settings, d)
                self.q.put(("done", c.id, path, summary_text(res, c, d)))
                log(f"Отчёт: {path}")
            except ConsentError as e:
                log(f"Пропущено: {e}")
            except Cancelled:
                log("Остановлено пользователем.")
                break
            except Exception as e:  # noqa: BLE001
                log(f"Ошибка: {e.__class__.__name__}: {e}")
        self.q.put(("finished",))

    def _poll(self) -> None:
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "log":
                    self._log(msg[1])
                elif kind == "done":
                    _, cid, path, text = msg
                    self.last_report[cid] = path
                    self.last_text[cid] = text
                    self._refresh()
                elif kind == "finished_one":
                    self._refresh()
                elif kind == "finished":
                    self._busy(False)
                    self._refresh()
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    # ---------------------------------------------------------------- отчёты
    def _report_for(self, c: Client) -> tuple[Path, str] | None:
        if c.id in self.last_report:
            return self.last_report[c.id], self.last_text[c.id]
        hist = self.store.history(c.id)
        if not hist:
            return None
        cur, prev = hist[-1], (hist[-2] if len(hist) > 1 else None)
        d = diff(cur, prev)
        path = save_report(cur, c, self.settings, d)  # пересобираем из истории (например, после смены настроек)
        return path, summary_text(cur, c, d)

    def open_report(self) -> None:
        sel = self._selected()
        if len(sel) == 1:
            r = self._report_for(sel[0])
            if r:
                open_path(r[0])

    def copy_text(self) -> None:
        sel = self._selected()
        if len(sel) == 1:
            r = self._report_for(sel[0])
            if r:
                self.root.clipboard_clear()
                self.root.clipboard_append(r[1])
                self._log("Текст для клиента скопирован в буфер обмена.")

    def evidence(self) -> None:
        sel = self._selected()
        if len(sel) == 1:
            path = save_evidence(sel[0], self.settings, self.store.all_scans(sel[0].id))
            self._log(f"Пакет доказательств: {path}")
            open_path(path)

    def notices(self) -> None:
        sel = self._selected()
        if len(sel) != 1:
            return
        cases = [x for x in brand_cases(self.store.all_scans(sel[0].id)) if x.active]
        if not cases:
            messagebox.showinfo(APP_NAME, "Активных двойников по последней проверке нет.")
            return
        open_path(save_notices(sel[0], self.settings, cases))

    def demo_fin(self) -> None:
        c, scans = demo_fin()
        open_path(save_evidence(c, self.settings, scans))
        open_path(save_notices(c, self.settings, brand_cases(scans)))

    def demo(self) -> None:
        c = demo_client()
        cur, prev = demo_results()
        open_path(save_report(cur, c, self.settings, diff(cur, prev)))

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    App().run()
