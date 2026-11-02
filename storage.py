"""Хранение клиентов, настроек и истории проверок в JSON (папка %APPDATA%\\SMBCheck)."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .models import ScanResult


def data_dir() -> Path:
    base = os.environ.get("SMBCHECK_HOME")
    if base:
        p = Path(base)
    elif os.name == "nt":
        p = Path(os.environ.get("APPDATA", Path.home())) / "SMBCheck"
    else:
        p = Path.home() / ".smbcheck"
    p.mkdir(parents=True, exist_ok=True)
    return p


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def normalize_domain(raw: str) -> str:
    """'https://www.Пример.рф/page' → 'xn--e1afmkfd.xn--p1ai'. Пустая строка, если домен некорректен."""
    s = raw.strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/")[0].split("?")[0].split("@")[-1].split(":")[0].strip(".")
    if s.startswith("www."):
        s = s[4:]
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return s if DOMAIN_RE.match(s) else ""


def display_domain(ascii_domain: str) -> str:
    try:
        return ascii_domain.encode("ascii").decode("idna")
    except UnicodeError:
        return ascii_domain


@dataclass
class Consent:
    has: bool = False
    date: str = ""          # дата подписания, ДД.ММ.ГГГГ
    valid_until: str = ""   # необязательно
    document: str = ""      # номер договора/согласия
    scope: str = ""         # что разрешено проверять

    def problem(self, today: dt.date | None = None) -> str:
        """Пустая строка — согласие в порядке, иначе причина отказа."""
        if not self.has:
            return "Нет отметки о письменном согласии владельца домена."
        if not self.date.strip():
            return "Не указана дата согласия."
        if not self.document.strip():
            return "Не указан номер договора или согласия."
        if self.valid_until.strip():
            try:
                until = dt.datetime.strptime(self.valid_until.strip(), "%d.%m.%Y").date()
            except ValueError:
                return "Срок действия согласия указан не в формате ДД.ММ.ГГГГ."
            if until < (today or dt.date.today()):
                return f"Срок согласия истёк {self.valid_until}."
        return ""


@dataclass
class Client:
    name: str
    domain: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    contact: str = ""
    emails: list[str] = field(default_factory=list)       # ящики для проверки утечек
    office_ips: list[str] = field(default_factory=list)   # внешний IP офиса (роутер)
    notes: str = ""
    consent: Consent = field(default_factory=Consent)

    @staticmethod
    def from_dict(d: dict) -> "Client":
        c = Client(name=d.get("name", ""), domain=d.get("domain", ""), id=d.get("id") or uuid.uuid4().hex[:10])
        c.contact = d.get("contact", "")
        c.emails = list(d.get("emails", []))
        c.office_ips = list(d.get("office_ips", []))
        c.notes = d.get("notes", "")
        c.consent = Consent(**{k: v for k, v in (d.get("consent") or {}).items() if k in Consent.__dataclass_fields__})
        return c


@dataclass
class Settings:
    hibp_key: str = ""
    reports_dir: str = ""
    company_name: str = ""     # ваше имя/компания — подпись в отчёте
    company_contact: str = ""

    def reports_path(self) -> Path:
        p = Path(self.reports_dir) if self.reports_dir else data_dir() / "reports"
        p.mkdir(parents=True, exist_ok=True)
        return p


class Store:
    def __init__(self, root: Path | None = None):
        self.root = root or data_dir()
        self.root.mkdir(parents=True, exist_ok=True)
        self.clients_file = self.root / "clients.json"
        self.settings_file = self.root / "settings.json"
        self.history_dir = self.root / "history"

    # ---- клиенты
    def load_clients(self) -> list[Client]:
        if not self.clients_file.exists():
            return []
        data = json.loads(self.clients_file.read_text("utf-8"))
        return [Client.from_dict(d) for d in data]

    def save_clients(self, clients: list[Client]) -> None:
        tmp = self.clients_file.with_suffix(".tmp")
        tmp.write_text(json.dumps([asdict(c) for c in clients], ensure_ascii=False, indent=2), "utf-8")
        tmp.replace(self.clients_file)

    # ---- настройки
    def load_settings(self) -> Settings:
        if not self.settings_file.exists():
            return Settings()
        d = json.loads(self.settings_file.read_text("utf-8"))
        return Settings(**{k: v for k, v in d.items() if k in Settings.__dataclass_fields__})

    def save_settings(self, s: Settings) -> None:
        self.settings_file.write_text(json.dumps(asdict(s), ensure_ascii=False, indent=2), "utf-8")

    # ---- история
    def _client_hist(self, client_id: str) -> Path:
        p = self.history_dir / client_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def save_scan(self, client_id: str, result: ScanResult) -> Path:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        p = self._client_hist(client_id) / f"{stamp}.json"
        p.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), "utf-8")
        return p

    def history(self, client_id: str) -> list[ScanResult]:
        d = self.history_dir / client_id
        if not d.exists():
            return []
        return [ScanResult.from_dict(json.loads(f.read_text("utf-8"))) for f in sorted(d.glob("*.json"))]

    def last_scan(self, client_id: str) -> ScanResult | None:
        h = self.history(client_id)
        return h[-1] if h else None
