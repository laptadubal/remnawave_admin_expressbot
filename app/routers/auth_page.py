"""Вход/выход в админку (собственная авторизация, независимая от Remnawave)."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from ..audit import record
from ..config import get_settings
from ..db import AccessUser, session_factory
from ..flash import FLASH_COOKIE, pop_flash
from ..page import TEMPLATES
from ..security import (
    COOKIE_NAME,
    create_session,
    get_current_user,
    hash_password,  # noqa: F401  (используется в api.py)
    role_perms,
    verify_password,
)

logger = logging.getLogger("rwadmin.auth")
router = APIRouter(tags=["auth"])


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return request.client.host if request.client else ""


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, user=Depends(get_current_user)):
    if user is not None:
        from fastapi.responses import RedirectResponse

        return RedirectResponse("/", status_code=302)
    flash = pop_flash(request)
    return TEMPLATES.TemplateResponse(
        "login.html",
        {"request": request, "flash": flash, "error": request.query_params.get("e")},
    )


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
):
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")[:255]
    db = session_factory()
    try:
        user = (
            db.query(AccessUser).filter(AccessUser.username == username.strip()).first()
        )
    finally:
        db.close()

    if not (user and user.is_active and verify_password(password, user.password_hash)):
        record(
            actor=username.strip() or "unknown",
            category="auth",
            method="POST",
            path="/login",
            status="denied",
            detail="bad credentials or inactive",
            ip=ip,
        )
        flash = {"k": "error", "t": "Неверный логин или пароль"}
        return TEMPLATES.TemplateResponse(
            "login.html", {"request": request, "flash": flash, "error": None}, status_code=200
        )

    # новая сессия
    db = session_factory()
    try:
        token = create_session(db, user, ip, ua)
    finally:
        db.close()
    record(
        actor=user.username,
        role=user.role,
        category="auth",
        method="POST",
        path="/login",
        status="ok",
        ip=ip,
    )
    from fastapi.responses import RedirectResponse

    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(
        COOKIE_NAME,
        token,
        max_age=get_settings().session_hours * 3600,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return resp


@router.post("/logout")
async def logout(request: Request, user=Depends(get_current_user)):
    if user is not None:
        record(
            actor=user.username,
            role=user.role,
            category="auth",
            method="POST",
            path="/logout",
            status="ok",
            ip=_client_ip(request),
        )
        # удалить сессию из БД
        import hashlib

        from fastapi import Cookie

        token = request.cookies.get(COOKIE_NAME, "")
        if token:
            db = session_factory()
            try:
                from ..db import AccessSession

                db.query(AccessSession).filter(
                    AccessSession.token_hash == hashlib.sha256(token.encode()).hexdigest()
                ).delete()
                db.commit()
            finally:
                db.close()
    from fastapi.responses import RedirectResponse

    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp
