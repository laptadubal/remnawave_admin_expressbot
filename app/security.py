"""Авторизация админки: argon2-пароли, серверные сессии, роли и разрешения."""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Cookie, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import AccessSession, AccessUser, session_factory

logger = logging.getLogger("rwadmin.security")

COOKIE_NAME = "rw_session"

ROLES = ("viewer", "operator", "bot_admin", "admin")

ROLE_PERMS: dict[str, set[str]] = {
    "viewer": {"read"},
    "operator": {
        "read",
        "manage_nodes",
        "manage_users",
        "manage_hosts",
        "keygen",
    },
    "bot_admin": {"read", "manage_bot"},
    "admin": {
        "read",
        "manage_nodes",
        "manage_users",
        "manage_hosts",
        "keygen",
        "manage_profiles",
        "manage_bot",
        "manage_access",
        "view_audit",
    },
}

ROLE_TITLES = {
    "viewer": "наблюдатель",
    "operator": "оператор",
    "bot_admin": "бот-админ",
    "admin": "администратор",
}

_hasher = PasswordHasher(time_cost=3)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:  # noqa: BLE001
        return False


def role_perms(role: str) -> set[str]:
    return set(ROLE_PERMS.get(role, set()))


def has_perm(role: str, perm: str) -> bool:
    return perm in role_perms(role)


def create_session(db: Session, user: AccessUser, ip: str, user_agent: str) -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    settings = get_settings()
    sess = AccessSession(
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        user_id=user.id,
        ip=ip[:64],
        user_agent=user_agent[:255],
        created_at=now,
        expires_at=now + timedelta(hours=settings.session_hours),
    )
    user.last_login_at = now
    db.add(sess)
    db.commit()
    return token


def get_current_user(request: Request):
    """Зависимость: пользователь по куке сессии или None."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    db = session_factory()
    try:
        row = db.get(AccessSession, hashlib.sha256(token.encode()).hexdigest())
        if not row:
            return None
        now = datetime.now(timezone.utc)
        row_exp = row.expires_at
        if row_exp.tzinfo is None:
            row_exp = row_exp.replace(tzinfo=timezone.utc)
        if row_exp < now:
            db.delete(row)
            db.commit()
            return None
        # скользящее продление: если живёт менее половины срока
        created = row.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        ttl = now - created
        if ttl > timedelta(hours=get_settings().session_hours) / 2:
            row.expires_at = now + timedelta(hours=get_settings().session_hours)
            db.commit()
        user = db.get(AccessUser, row.user_id)
        if not user or not user.is_active:
            return None
        db.expunge(user)
        return user
    finally:
        db.close()


def require_user(request: Request, user=Depends(get_current_user)):
    if user is None:
        from fastapi.responses import RedirectResponse

        return None  # обработаем в роутере редиректом
    return user


def require_login(user=Depends(get_current_user)):
    """Передавать в роутер: если пользователь не авторизован — редирект на /login."""
    return user


def check_page_access(request: Request):
    """Мидлвари-помощник: для HTML-страниц без сессии — редирект на /login."""
    from fastapi.responses import RedirectResponse

    if get_current_user(request) is None:
        return RedirectResponse(url="/login", status_code=302)
    return None
