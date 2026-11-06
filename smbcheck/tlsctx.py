"""Общий SSL-контекст: корневые сертификаты Windows + набор certifi.

Python на Windows берёт корневые сертификаты из хранилища системы, но Windows докачивает
многие корни «по требованию» — только когда их просит браузер. Поэтому на свежей системе
Python иногда не доверяет даже cloudflare-dns.com («unable to get local issuer certificate»).
Набор certifi (его кладёт в .exe PyInstaller) закрывает этот пробел. Хранилище Windows
тоже остаётся: в него антивирусы и корпоративные сети добавляют свои корни.
"""
from __future__ import annotations

import ssl
import threading

_lock = threading.Lock()
_ctx: ssl.SSLContext | None = None


def has_certifi() -> bool:
    try:
        import certifi  # noqa: F401
        return True
    except ImportError:
        return False


def context() -> ssl.SSLContext:
    """Контекст с полной проверкой сертификата. Один на всю программу (потокобезопасен)."""
    global _ctx
    with _lock:
        if _ctx is None:
            ctx = ssl.create_default_context()
            try:
                import certifi
                ctx.load_verify_locations(cafile=certifi.where())
            except Exception:  # noqa: BLE001 — certifi необязателен
                pass
            _ctx = ctx
        return _ctx
