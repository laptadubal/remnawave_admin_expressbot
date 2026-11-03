"""HTML-страницы админки: ноды, пользователи, хосты, профили, ключи,
бот eXpress, аудит, доступы, настройки."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from ..import flash  # noqa: F401  (используется внутри)
from ..db import AccessUser, AuditLog, BotConfig, BotEvent, session_factory
from ..page import TEMPLATES, render, require_user_or_redirect
from ..remna.client import RemnaError, RemnawaveClient
from ..security import ROLE_TITLES, ROLES, get_current_user, has_perm
from .auth_page import _client_ip

logger = logging.getLogger("rwadmin.web")
router = APIRouter(tags=["web"])

USERS_PAGE_SIZE = 100


def get_remna(request: Request) -> RemnawaveClient:
    return request.app.state.remna  # type: ignore[no-any-return]


def _nodes_items(data) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("list", "nodes", "result", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def _users_items(data) -> tuple[list, int | None]:
    if isinstance(data, list):
        return data, len(data)
    if isinstance(data, dict):
        total = data.get("total")
        for key in ("list", "nodes", "result", "data"):
            if isinstance(data.get(key), list):
                return data[key], total
    return [], None


def _node_conn_label(nd: dict) -> tuple[str, str]:  # (текст, css-class)
    if nd.get("isConnected") or nd.get("is_connected"):
        return "в сети", "ok"
    if nd.get("isDisabled") or nd.get("is_disabled"):
        return "выключена", "off"
    return "не в сети", "down"


async def users_fragments(request: Request, search: str, user, page: int = 1):
    """Тело таблицы пользователей (для страницы /users и htmx-обновлений)."""
    ctx = await _users_fragment_ctx(request, search, user)
    return TEMPLATES.TemplateResponse("fragments/users_table.html", ctx)


async def _users_fragment_ctx(request: Request, search: str, user) -> dict:
    remna = get_remna(request)
    if not remna.configured:
        return {"request": request, "state": "not_configured", "users": [], "search": search}
    try:
        data = await remna.users(start=0, size=USERS_PAGE_SIZE)
    except RemnaError as e:
        return {"request": request, "state": "error", "users": [], "search": search,
                "error": e.message[:300]}
    items, total = _users_items(data)
    q = search.strip().lower()
    if q:
        items = [u for u in items if
                 q in str(u.get("username", "")).lower() or q in str(u.get("uuid", "")).lower()]
    can_sub = has_perm(user.role, "manage_users")
    return {"request": request, "state": "ok", "users": items, "total": total,
            "search": search, "can_sub": can_sub}


@router.get("/", response_class=None)
async def dashboard(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    remna = get_remna(request)
    context: dict = {}
    if not remna.configured:
        context.update(nodes=[], state="not_configured", error="", users_total=None, mode="none")
    else:
        mode = "token" if remna.s.remnawave_api_token else "login"
        try:
            nodes = await remna.nodes()
            try:
                users_data = await remna.users(start=0, size=1)
                items, total = _users_items(users_data)
            except RemnaError:
                items, total = [], None
            context.update(nodes=_nodes_items(nodes), state="ok", error="", users_total=total, mode=mode)
        except RemnaError as e:
            context.update(nodes=[], state="error", error=e.message[:500], users_total=None, mode=mode)
    return render("dashboard.html", request, user, "dash", **context)


@router.get("/nodes/{node_uuid}")
async def node_detail(request: Request, node_uuid: str, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    remna = get_remna(request)
    if not remna.configured:
        return render("node_detail.html", request, user, "dash", state="not_configured", node={})
    try:
        node = await remna.node(node_uuid)
        if not isinstance(node, dict):
            node = {}
    except RemnaError as e:
        return render("node_detail.html", request, user, "dash", state="error",
                      node={}, error=e.message[:500])
    can = has_perm(user.role, "manage_nodes")
    conn_label, conn_cls = _node_conn_label(node)
    return render("node_detail.html", request, user, "dash", state="ok", node=node,
                  conn_label=conn_label, conn_cls=conn_cls, can=can)


@router.get("/users")
async def users_page(request: Request, user=Depends(get_current_user),
                     search: str = "", can_create: bool | None = None):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    fragment = TEMPLATES.get_template("fragments/users_table.html").render(
        await _users_fragment_ctx(request, search, user))
    can_create = has_perm(user.role, "manage_users")
    return render("users.html", request, user, "users", fragment=fragment,
                  can_create=can_create)


@router.get("/users/new")
async def user_new_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "manage_users"):
        return render("forbidden.html", request, user, "users")
    return render("user_form.html", request, user, "users", is_new=True, data={})


@router.get("/users/{user_uuid}")
async def user_detail(request: Request, user_uuid: str, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    remna = get_remna(request)
    if not remna.configured:
        return render("user_detail.html", request, user, "users", state="not_configured", data={})
    try:
        data = await remna.user(user_uuid)
        if not isinstance(data, dict):
            data = {}
    except RemnaError as e:
        return render("user_detail.html", request, user, "users", state="error",
                      data={}, error=e.message[:500])
    try:
        sub = await remna.subscription(user_uuid)
    except RemnaError:
        sub = None
    if isinstance(sub, dict):
        sub = sub.get("sub") or sub.get("subscription") or sub.get("url") or sub.get("link")
    can = has_perm(user.role, "manage_users")
    return render("user_detail.html", request, user, "users", state="ok", data=data,
                  sub=(sub if can else None), can=can)


@router.get("/hosts")
async def hosts_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    remna = get_remna(request)
    context: dict = {}
    if not remna.configured:
        context.update(hosts=[], state="not_configured", error="")
    else:
        try:
            hosts = await remna.hosts()
            context.update(hosts=_nodes_items(hosts), state="ok", error="")
        except RemnaError as e:
            context.update(hosts=[], state="error", error=e.message[:500])
    can = has_perm(user.role, "manage_hosts")
    return render("hosts.html", request, user, "hosts", can=can, **context)


@router.get("/hosts/new")
async def host_new_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "manage_hosts"):
        return render("forbidden.html", request, user, "hosts")
    return render("host_form.html", request, user, "hosts", is_new=True, host={})


@router.get("/hosts/{host_uuid}")
async def host_edit_page(request: Request, host_uuid: str, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "manage_hosts"):
        return render("forbidden.html", request, user, "hosts")
    remna = get_remna(request)
    try:
        host = await remna.host(host_uuid)
        if not isinstance(host, dict):
            host = {}
    except RemnaError:
        host = {}
    return render("host_form.html", request, user, "hosts", is_new=False, host=host)


@router.get("/profiles")
async def profiles_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    remna = get_remna(request)
    context: dict = {}
    if not remna.configured:
        context.update(profiles=[], state="not_configured", error="")
    else:
        try:
            profiles = await remna.profiles()
            context.update(profiles=_nodes_items(profiles), state="ok", error="")
        except RemnaError as e:
            context.update(profiles=[], state="error", error=e.message[:500])
    can = has_perm(user.role, "manage_profiles")
    return render("profiles.html", request, user, "profiles", can=can, **context)


@router.get("/profiles/new")
async def profile_new_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "manage_profiles"):
        return render("forbidden.html", request, user, "profiles")
    return render("profile_new.html", request, user, "profiles")


@router.get("/profiles/{profile_uuid}")
async def profile_detail(request: Request, profile_uuid: str, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    remna = get_remna(request)
    if not remna.configured:
        return render("profile_detail.html", request, user, "profiles",
                      state="not_configured", profile={})
    try:
        profile = await remna.profile(profile_uuid)
        if not isinstance(profile, dict):
            profile = {}
    except RemnaError as e:
        return render("profile_detail.html", request, user, "profiles", state="error",
                      profile={}, error=e.message[:500])
    can = has_perm(user.role, "manage_profiles")
    return render("profile_detail.html", request, user, "profiles", state="ok",
                  profile=profile, can=can)


@router.get("/keys")
async def keys_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "keygen"):
        return render("forbidden.html", request, user, "keys")
    remna = get_remna(request)
    base_url = remna.base_url if remna.configured else ""
    state = "ok" if remna.configured else "not_configured"
    return render("keys.html", request, user, "keys", state=state, base_url=base_url)


@router.get("/audit")
async def audit_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "view_audit"):
        return render("forbidden.html", request, user, "audit")
    db = session_factory()
    try:
        count = db.query(AuditLog).count()
        categories = [
            r[0] for r in db.query(AuditLog.category).distinct().all() if r[0]
        ]
        rows = (
            db.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()
        )
    finally:
        db.close()
    fragment = TEMPLATES.get_template("fragments/audit_rows.html").render(
        {"request": request, "rows": rows, "limit": 100}
    )
    return render("audit.html", request, user, "audit",
                  count=count, categories=categories or ["all"], fragment=fragment)


@router.get("/access")
async def access_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "manage_access"):
        return render("forbidden.html", request, user, "access")
    db = session_factory()
    try:
        users = db.query(AccessUser).order_by(AccessUser.id).all()
    finally:
        db.close()
    return render("access.html", request, user, "access",
                  users=users, current_id=user.id, roles=list(ROLES),
                  role_titles=ROLE_TITLES)


@router.get("/bot")
async def bot_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "manage_bot"):
        return render("forbidden.html", request, user, "bot")
    db = session_factory()
    try:
        cfg = db.get(BotConfig, 1)
    finally:
        db.close()
    from ..botx.crypto import decrypt_secret

    allowed_raw = (cfg.allowed_huids if cfg else "") or ""
    secret_set = bool(cfg and cfg.secret_enc and decrypt_secret(cfg.secret_enc))
    config = {
        "enabled": bool(cfg and cfg.enabled),
        "cts_url": (cfg.cts_url if cfg else "") or "",
        "bot_id": (cfg.bot_id if cfg else "") or "",
        "secret_set": secret_set,
        "huids": [h for h in allowed_raw.splitlines() if h.strip()],
        "updated_at": (cfg.updated_at if cfg else None),
    }
    db = session_factory()
    try:
        events = db.query(BotEvent).order_by(BotEvent.id.desc()).limit(30).all()
    finally:
        db.close()
    bot_frag = TEMPLATES.get_template("fragments/bot_events.html").render(
        {"request": request, "events": events, "limit": 30}
    )
    return render("bot.html", request, user, "bot", config=config, bot_frag=bot_frag)


@router.get("/settings")
async def settings_page(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    s = request.app.state.settings  # type: ignore[attr-defined]
    from .. import __version__

    mode = "token" if s.remnawave_api_token else ("login" if (s.remnawave_username) else "none")
    return render("settings.html", request, user, "settings",
                  base_url=s.remnawave_base_url or "", mode=mode,
                  has_token=bool(s.remnawave_api_token),
                  has_login=bool(s.remnawave_username and s.remnawave_password),
                  version=__version__)
