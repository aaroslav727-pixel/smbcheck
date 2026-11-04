"""Общие структуры данных: находка (Finding) и результат проверки (ScanResult)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Уровни важности: от самого опасного к «всё хорошо».
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"
OK = "ok"

SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO, OK]
SEVERITY_RU = {
    CRITICAL: "Критично",
    HIGH: "Высокий риск",
    MEDIUM: "Средний риск",
    LOW: "Низкий риск",
    INFO: "К сведению",
    OK: "В порядке",
}

# Категории проверок (ключ → название в отчёте)
CATEGORIES = {
    "email": "Почта (защита от подделки писем)",
    "web": "Сайт и HTTPS",
    "domain": "Домен",
    "network": "Открытые сервисы",
    "leaks": "Утечки данных",
    "brand": "Двойники бренда (фишинг)",
}

# Категории, которые не влияют на оценку A–F: это не настройки клиента, а внешние угрозы
NOT_SCORED = {"brand"}


@dataclass
class Finding:
    id: str                 # стабильный ключ, по нему сравниваем месяцы, напр. "email.dmarc.missing"
    category: str           # ключ из CATEGORIES
    severity: str           # одно из SEVERITY_ORDER
    title: str              # коротко и по-человечески
    detail: str = ""        # что именно нашли
    why: str = ""           # почему это важно — простыми словами
    fix: str = ""           # что сделать
    tech: str = ""          # техническая деталь для админа

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Finding":
        return Finding(**{k: d.get(k, "") for k in Finding.__dataclass_fields__})

    @property
    def is_problem(self) -> bool:
        return self.severity in (CRITICAL, HIGH, MEDIUM, LOW)


@dataclass
class ScanResult:
    domain: str
    client: str = ""
    started: str = ""
    finished: str = ""
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)   # проверки, которые не удалось выполнить
    checks_run: list[str] = field(default_factory=list)
    score: int = 0
    grade: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ScanResult":
        r = ScanResult(domain=d.get("domain", ""))
        for k in ("client", "started", "finished", "score", "grade"):
            setattr(r, k, d.get(k, getattr(r, k)))
        r.errors = list(d.get("errors", []))
        r.checks_run = list(d.get("checks_run", []))
        r.findings = [Finding.from_dict(x) for x in d.get("findings", [])]
        return r
