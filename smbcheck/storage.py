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


# Профиль клиента определяет, на какие требования мапится пакет доказательств
PROFILES = {
    "general": "Обычный бизнес",
    "uz_fin": "Финорганизация Узбекистана (МФО, ломбард, платёжная)",
    "kz_fin": "Финорганизация Казахстана (МФО, платёжная)",
}


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
    profile: str = "general"                              # ключ из PROFILES
    accepts_cards: bool = False                           # принимает карты на сайте → PCI DSS
    brand_keywords: list[str] = field(default_factory=list)   # доп. слова для поиска двойников
    trusted_domains: list[str] = field(default_factory=list)  # свои и проверенные похожие домены

    @staticmethod
    def from_dict(d: dict) -> "Client":
        c = Client(name=d.get("name", ""), domain=d.get("domain", ""), id=d.get("id") or uuid.uuid4().hex[:10])
        c.contact = d.get("contact", "")
        c.emails = list(d.get("emails", []))
        c.office_ips = list(d.get("office_ips", []))
        c.notes = d.get("notes", "")
        c.profile = d.get("profile", "general") if d.get("profile") in PROFILES else "general"
        c.accepts_cards = bool(d.get("accepts_cards", False))
        c.brand_keywords = list(d.get("brand_keywords", []))
        c.trusted_domains = list(d.get("trusted_domains", []))
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
    # Полные проверки — history/<id>/*.json; ежедневные проверки двойников — history/<id>/brand/*.json,
    # чтобы частые короткие прогоны не ломали сравнение «месяц к месяцу».
    def _client_hist(self, client_id: str, kind: str = "full") -> Path:
        p = self.history_dir / client_id
        if kind == "brand":
            p = p / "brand"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def save_scan(self, client_id: str, result: ScanResult, kind: str = "full") -> Path:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        p = self._client_hist(client_id, kind) / f"{stamp}.json"
        p.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), "utf-8")
        return p

    def history(self, client_id: str, kind: str = "full") -> list[ScanResult]:
        d = self.history_dir / client_id
        if kind == "brand":
            d = d / "brand"
        if not d.exists():
            return []
        return [ScanResult.from_dict(json.loads(f.read_text("utf-8"))) for f in sorted(d.glob("*.json"))]

    def last_scan(self, client_id: str) -> ScanResult | None:
        h = self.history(client_id)
        return h[-1] if h else None

    def all_scans(self, client_id: str) -> list[ScanResult]:
        """Полные и ежедневные проверки вместе, по времени — для пакета доказательств."""
        return sorted(self.history(client_id) + self.history(client_id, "brand"), key=lambda r: r.finished)

    def last_with(self, client_id: str, check: str) -> ScanResult | None:
        """Самая свежая проверка (любого вида), где выполнялась проверка check."""
        h = [r for r in self.all_scans(client_id) if check in r.checks_run]
        return h[-1] if h else None
