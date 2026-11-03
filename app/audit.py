"""Аудит-лог: запись действий пользователей, бота и обращений к Remnawave."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from .db import AuditLog, BotEvent, session_factory

logger = logging.getLogger("rwadmin.audit")


def _safe_detail(detail) -> str:
    if detail is None:
        return ""
    if isinstance(detail, str):
        return detail[:4000]
    try:
        return json.dumps(detail, ensure_ascii=False, default=str)[:4000]
    except Exception:  # noqa: BLE001
        return str(detail)[:4000]


def record(
    *,
    actor: str,
    role: str = "",
    ip: str = "",
    category: str,
    method: str = "",
    path: str = "",
    target: str = "",
    status: str = "ok",
    detail=None,
    duration_ms: int = 0,
) -> None:
    """Записать событие в audit_log (своя сессия БД, не блокирует запрос)."""
    try:
        db = session_factory()
        entry = AuditLog(
            ts=datetime.now(timezone.utc),
            actor=(actor or "system")[:128],
            role=(role or "")[:32],
            ip=(ip or "")[:64],
            category=category[:32],
            method=method[:16],
            path=path[:255],
            target=target[:255],
            status=status[:32],
            detail=_safe_detail(detail),
            duration_ms=int(duration_ms or 0),
        )
        db.add(entry)
        db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("audit record failed")


def record_bot(
    *,
    huid: str = "",
    username: str = "",
    command: str = "",
    argument: str = "",
    status: str = "ok",
    detail=None,
) -> None:
    """Записать событие бота: и в bot_events, и в audit_log."""
    try:
        db = session_factory()
        ev = BotEvent(
            ts=datetime.now(timezone.utc),
            huid=huid[:64],
            username=username[:128],
            command=command[:64],
            argument=argument[:255],
            status=status[:32],
            detail=_safe_detail(detail),
        )
        db.add(ev)
        db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("bot event record failed")
    record(
        actor=f"bot:{huid}" if huid else "bot:unknown",
        role="bot",
        category="bot",
        method="CMD",
        path=command,
        target=argument[:255],
        status=status,
        detail=detail,
    )
