"""Оценка, три главных действия и сравнение с прошлой проверкой."""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import CATEGORIES, CRITICAL, HIGH, LOW, MEDIUM, OK, SEVERITY_ORDER, Finding, ScanResult  # noqa: F401

# Первая находка уровня — полный штраф, каждая следующая — поменьше,
# чтобы оценка не упиралась в ноль и прогресс от месяца к месяцу был виден.
PENALTY = {CRITICAL: (30, 12), HIGH: (15, 6), MEDIUM: (6, 3), LOW: (2, 1)}
# При равной важности сначала то, что чаще приводит к реальным потерям
CATEGORY_PRIORITY = ["network", "leaks", "email", "domain", "web"]


def score(findings: list[Finding]) -> tuple[int, str]:
    counts: dict[str, int] = {}
    for f in findings:
        if f.severity in PENALTY:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    pts = 100 - sum(PENALTY[s][0] + PENALTY[s][1] * (n - 1) for s, n in counts.items())
    pts = max(0, min(100, pts))
    grade = "A" if pts >= 90 else "B" if pts >= 75 else "C" if pts >= 60 else "D" if pts >= 40 else "F"
    if any(f.severity == CRITICAL for f in findings) and grade in "ABC":
        grade = "D"
    return pts, grade


def sort_key(f: Finding) -> tuple[int, int]:
    cat = CATEGORY_PRIORITY.index(f.category) if f.category in CATEGORY_PRIORITY else 99
    return SEVERITY_ORDER.index(f.severity), cat


def top_actions(findings: list[Finding], n: int = 3) -> list[Finding]:
    seen_fix: set[str] = set()
    out: list[Finding] = []
    for f in sorted((f for f in findings if f.is_problem), key=sort_key):
        if f.fix in seen_fix:
            continue
        seen_fix.add(f.fix)
        out.append(f)
        if len(out) == n:
            break
    return out


def category_status(findings: list[Finding], checks_run: list[str]) -> dict[str, str]:
    """Для каждой категории — худшая важность (или '' если не проверялась)."""
    status: dict[str, str] = {}
    for cat in CATEGORIES:
        if cat not in checks_run:
            status[cat] = ""
            continue
        sevs = [f.severity for f in findings if f.category == cat and f.is_problem]
        status[cat] = min(sevs, key=SEVERITY_ORDER.index) if sevs else OK
    return status


@dataclass
class Diff:
    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    score_delta: int | None = None
    prev_date: str = ""


def family(f: Finding) -> str:
    """Одна и та же проблема в разных состояниях: email.dmarc.missing и email.dmarc.none — это «DMARC»."""
    if f.category in ("network", "leaks") or f.id.startswith("web.exposed."):
        return f.id
    return ".".join(f.id.split(".")[:2])


def diff(current: ScanResult, previous: ScanResult | None) -> Diff:
    if previous is None:
        return Diff()
    common = set(current.checks_run) & set(previous.checks_run)  # только то, что проверяли оба раза
    cur: dict[str, Finding] = {}
    prev: dict[str, Finding] = {}
    for src, dst in ((current, cur), (previous, prev)):
        for f in sorted((f for f in src.findings if f.is_problem and f.category in common), key=sort_key):
            dst.setdefault(family(f), f)  # худшая находка в семействе
    rank = SEVERITY_ORDER.index
    new, fixed = [], []
    for k, f in cur.items():
        if k not in prev:
            new.append(f)
        elif rank(f.severity) < rank(prev[k].severity):
            new.append(Finding(f.id, f.category, f.severity, f"Ухудшилось: {f.title}"))
    for k, f in prev.items():
        if k not in cur:
            fixed.append(f)
        elif rank(cur[k].severity) > rank(f.severity):
            fixed.append(Finding(f.id, f.category, f.severity, f"Улучшено: {cur[k].title}"))
    return Diff(new=sorted(new, key=sort_key), fixed=sorted(fixed, key=sort_key),
                score_delta=current.score - previous.score, prev_date=previous.finished[:10])

