"""Утечки: Have I Been Pwned.

- Без ключа: был ли взломан сам сайт клиента (публичный список утечек HIBP).
- С ключом HIBP (платный, от ~4 $/мес): в каких утечках засветились рабочие ящики сотрудников.
"""
from __future__ import annotations

import datetime as dt
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from ..models import HIGH, INFO, LOW, MEDIUM, OK, Finding

CAT = "leaks"
API = "https://haveibeenpwned.com/api/v3"
UA = "SMBCheck-security-report"


def _get(path: str, key: str = "", timeout: float = 15) -> tuple[int, object]:
    headers = {"User-Agent": UA}
    if key:
        headers["hibp-api-key"] = key
    req = urllib.request.Request(API + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e:
        return e.code, None


def analyze_site_breaches(domain: str, breaches: list[dict]) -> list[Finding]:
    if not breaches:
        return [Finding("leaks.site.ok", CAT, OK, "Сайт не числится среди известных взломов (HIBP)")]
    names = ", ".join(f"{b.get('Title', b.get('Name'))} ({b.get('BreachDate', '')[:4]})" for b in breaches)
    return [Finding("leaks.site", CAT, HIGH, "База пользователей сайта уже утекала",
                    detail=names,
                    why="Пароли и e-mail ваших клиентов есть у злоумышленников — по ним рассылают фишинг от вашего имени.",
                    fix="Принудительно смените пароли пользователей, проверьте, закрыта ли уязвимость, предупредите клиентов.")]


def analyze_account_breaches(results: dict[str, list[dict]], now: dt.date | None = None) -> list[Finding]:
    now = now or dt.date.today()
    out: list[Finding] = []
    for email, breaches in results.items():
        if not breaches:
            continue
        recent_pw = []
        for b in breaches:
            try:
                d = dt.date.fromisoformat(b.get("BreachDate", "1970-01-01"))
            except ValueError:
                d = dt.date(1970, 1, 1)
            if "Passwords" in (b.get("DataClasses") or []) and (now - d).days < 3 * 365:
                recent_pw.append(b.get("Title") or b.get("Name"))
        sev = HIGH if recent_pw else MEDIUM if len(breaches) >= 3 else LOW
        out.append(Finding(
            f"leaks.account.{email.lower()}", CAT, sev, f"Ящик {email} найден в утечках: {len(breaches)}",
            detail=", ".join((b.get("Title") or b.get("Name", "")) for b in breaches[:8]),
            why="Если сотрудник использовал этот пароль и для рабочей почты, ящик могут взломать."
                + (" Среди утечек есть свежие с паролями." if recent_pw else ""),
            fix="Смените пароль от этого ящика и везде, где он повторялся; включите двухфакторный вход."))
    if results and not out:
        out.append(Finding("leaks.accounts.ok", CAT, OK, f"Проверенные ящики ({len(results)}) в утечках не найдены"))
    return out


def run(domain: str, emails: list[str], api_key: str = "", log=lambda m: None) -> list[Finding]:
    out: list[Finding] = []
    log("Утечки: взломы сайта по базе HIBP…")
    status, data = _get("/breaches?domain=" + urllib.parse.quote(domain))
    if status == 200 and isinstance(data, list):
        out += analyze_site_breaches(domain, data)
    else:
        out.append(Finding("leaks.site.error", CAT, INFO, "Базу утечек HIBP проверить не удалось", tech=f"HTTP {status}"))

    emails = [e.strip() for e in emails if e.strip()]
    if not emails:
        return out
    if not api_key:
        out.append(Finding("leaks.accounts.skipped", CAT, INFO,
                           "Почтовые ящики на утечки не проверялись",
                           fix="Укажите ключ Have I Been Pwned в настройках программы."))
        return out
    results: dict[str, list[dict]] = {}
    for i, email in enumerate(emails):
        if i:
            time.sleep(6.5)  # лимит самого дешёвого тарифа HIBP — 10 запросов в минуту
        log(f"Утечки: {email}…")
        status, data = _get(f"/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false", api_key)
        if status == 200 and isinstance(data, list):
            results[email] = data
        elif status == 404:
            results[email] = []
        elif status == 401:
            out.append(Finding("leaks.key.invalid", CAT, INFO, "Ключ HIBP не принят — проверьте его в настройках"))
            break
        else:
            out.append(Finding(f"leaks.account.error.{email}", CAT, INFO, f"Не удалось проверить {email}",
                               tech=f"HTTP {status}"))
    return out + analyze_account_breaches(results)
