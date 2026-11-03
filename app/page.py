"""Помощники рендеринга страниц."""
from __future__ import annotations

from datetime import datetime

from fastapi import Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .flash import delete_flash_cookie, pop_flash
from .security import ROLE_TITLES, role_perms

TEMPLATES = Jinja2Templates(directory="app/templates")
TEMPLATES.env.globals["range"] = range


def human_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def pdate(v) -> str:
    """ISO-строка панели -> 'ГГГГ-ММ-ДД ЧЧ:ММ' (UTC->как есть)."""
    if not v:
        return ""
    s = str(v).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return str(v)[:19]
    return dt.strftime("%Y-%m-%d %H:%M")


def short_uuid(v) -> str:
    return str(v)[:8] if v else ""


TEMPLATES.env.filters["human_bytes"] = human_bytes
TEMPLATES.env.filters["pdate"] = pdate
TEMPLATES.env.filters["short_uuid"] = short_uuid
TEMPLATES.env.tests["nodekey"] = lambda key: str(key).startswith("node:")


def require_user_or_redirect(request: Request, user):
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return None


def page_context(request: Request, user, active: str, **extra) -> dict:
    ctx = {
        "request": request,
        "user": user,
        "perms": sorted(role_perms(user.role)),
        "role_titles": ROLE_TITLES,
        "active": active,
        "flash": pop_flash(request),
    }
    ctx.update(extra)
    return ctx


def render(name: str, request: Request, user, active: str, **extra):
    from .flash import delete_flash_cookie as _dfc

    resp = TEMPLATES.TemplateResponse(name, page_context(request, user, active, **extra))
    _dfc(resp)
    return resp
