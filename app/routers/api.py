"""htmx/API-эндпоинты: действия с нодами, пользователями, хостами, профилями,
keygen, конфиг bота, управление доступами, экспорт аудита."""
from __future__ import annotations

import csv
import io
import json
import logging
import uuid as _uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse

from ..audit import record
from ..db import AccessUser, AuditLog, BotConfig, BotEvent, session_factory
from ..flash import flash_redirect
from ..page import TEMPLATES, require_user_or_redirect
from ..remna.client import RemnaError, RemnawaveClient
from ..security import COOKIE_NAME, get_current_user, hash_password, has_perm
from .auth_page import _client_ip
from .web import users_fragments

logger = logging.getLogger("rwadmin.api")
router = APIRouter(prefix="/api", tags=["api"])


def _remna(request: Request) -> RemnawaveClient:
    return request.app.state.remna  # type: ignore[no-any-return]


def _guard(request: Request, user, perm: str):
    """Возвращает None (OK) либо ответ с отказом (редирект/403)."""
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, perm):
        record(actor=user.username, role=user.role, ip=_client_ip(request),
               category="action", method=request.method, path=request.url.path,
               status="denied", detail=f"missing perm {perm}")
        return flash_redirect(request.url.path, "error", "Недостаточно прав для этого действия")
    return None


def _audit_ok(request, user, target: str, remna_path: str, detail=None, dur_ms: int = 0):
    record(actor=user.username, role=user.role, ip=_client_ip(request),
           category="action", method=request.method, path=request.url.path,
           target=target, status="ok", detail={
               "remna": f"-> {remna_path}", **(detail or {})
           }, duration_ms=dur_ms)


def _audit_err(request, user, target: str, remna_path: str, err: Exception, dur_ms: int = 0):
    record(actor=user.username, role=user.role, ip=_client_ip(request),
           category="action", method=request.method, path=request.url.path,
           target=target, status="error", detail={"remna": f"-> {remna_path}",
                                                  "error": str(err)[:400]}, duration_ms=dur_ms)


# ---------------- фрагменты (htmx) ----------------

@router.get("/frag/users-table")
async def frag_users(request: Request, user=Depends(get_current_user),
                     search: str = "", page: int = 1):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    return await users_fragments(request, search, user, page)


@router.get("/frag/audit")
async def frag_audit(request: Request, user=Depends(get_current_user),
                     user_q: str = "", category: str = "",
                     date_from: str = "", date_to: str = "", limit: int = 200):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "view_audit"):
        return flash_redirect("/audit", "error", "Раздел «Аудит» доступен только администраторам")
    limit = max(1, min(limit, 500))
    db = session_factory()
    try:
        q = db.query(AuditLog)
        if user_q.strip():
            q = q.filter(AuditLog.actor.ilike(f"%{user_q.strip()}%"))
        if category:
            q = q.filter(AuditLog.category == category)
        if date_from:
            try:
                q = q.filter(AuditLog.ts >= datetime.fromisoformat(date_from))
            except ValueError:
                pass
        if date_to:
            try:
                q = q.filter(AuditLog.ts <= datetime.fromisoformat(date_to + "T23:59:59+00:00"))
            except ValueError:
                pass
        rows = q.order_by(AuditLog.id.desc()).limit(limit).all()
    finally:
        db.close()
    return TEMPLATES.TemplateResponse("fragments/audit_rows.html",
                                      {"request": request, "rows": rows, "limit": limit})


@router.get("/frag/bot-events")
async def frag_bot_events(request: Request, user=Depends(get_current_user), limit: int = 30):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    if not has_perm(user.role, "manage_bot"):
        return flash_redirect("/bot", "error", "Раздел «Бот» защищён ролью bot_admin/admin")
    db = session_factory()
    try:
        events = db.query(BotEvent).order_by(BotEvent.id.desc()).limit(min(limit, 100)).all()
    finally:
        db.close()
    return TEMPLATES.TemplateResponse("fragments/bot_events.html",
                                      {"request": request, "events": events})


@router.post("/keygen")
async def keygen_post(request: Request, user=Depends(get_current_user),
                      key_type: str = Form("x25519")):
    denied = _guard(request, user, "keygen")
    if denied is not None:
        return denied
    kt = (key_type or "x25519").strip()
    if kt not in ("x25519", "uuid", "curve25519"):
        kt = "x25519"
    remna = _remna(request)
    try:
        data = await remna.keygen(kt)
    except RemnaError as e:
        _audit_err(request, user, kt, f"/api/keygen?type={kt}", e)
        return TEMPLATES.TemplateResponse("fragments/keys_result.html",
                                          {"request": request, "error": e.message[:300]})
    _audit_ok(request, user, kt, f"/api/keygen?type={kt}", detail={"generated": True})
    try:
        pretty = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    except Exception:  # noqa: BLE001
        pretty = str(data)
    return TEMPLATES.TemplateResponse("fragments/keys_result.html",
                                      {"request": request, "error": "", "raw": pretty})


# ---------------- Remnawave: статус ----------------

@router.get("/remna/status-test")
async def remna_status_test(request: Request, user=Depends(get_current_user)):
    redir = require_user_or_redirect(request, user)
    if redir is not None:
        return redir
    remna = _remna(request)
    if not remna.configured:
        return JSONResponse({"ok": False, "state": "not_configured",
                             "message": "REMNAWAVE_BASE_URL пустой — заполните .env"})
    try:
        st = await remna.auth_status()
        nodes = await remna.nodes()
        n = len(nodes) if isinstance(nodes, list) else None
        return JSONResponse({"ok": True, "state": "ok",
                             "message": f"Подключение OK, нод в панели: {n if n is not None else '?'}"})
    except RemnaError as e:
        _audit_err(request, user, "", "/api/auth/status", e)
        return JSONResponse({"ok": False, "state": "error", "message": e.message[:400]})


# ---------------- Remnawave: ноды ----------------

@router.post("/node/{node_uuid}/{action}")
async def node_action(request: Request, node_uuid: str, action: str,
                      user=Depends(get_current_user)):
    denied = _guard(request, user, "manage_nodes")
    if denied is not None:
        return denied
    remna = _remna(request)
    label = {"enable": "включение", "disable": "выключение", "restart": "перезапуск",
             "reset-traffic": "сброс трафика"}.get(action, action)
    try:
        await remna.node_action(node_uuid, action)
    except RemnaError as e:
        _audit_err(request, user, node_uuid, f"/api/nodes/{node_uuid}/actions/{action}", e)
        return flash_redirect(f"/nodes/{node_uuid}", "error",
                              f"Не удалось {label}: {e.message[:200]}")
    _audit_ok(request, user, node_uuid, f"/api/nodes/{node_uuid}/actions/{action}")
    return flash_redirect(f"/nodes/{node_uuid}", "ok", f"Нода: {label} выполнен(а)")


# ---------------- Remnawave: пользователи ----------------

def _user_body_from_form(
    username: str,
    expire_at: str,
    max_active_devices: str,
    traffic_limit_gb: str,
) -> dict:
    body: dict = {"username": username.strip()}
    if expire_at.strip():
        # datetime-local: 2026-12-01T12:00 -> ISO с Z (UTC, как в панели)
        iso = expire_at.strip()
        if not iso.endswith("Z") and "+" not in iso:
            iso += ":00Z"
        body["expireAt"] = iso
    try:
        mad = int(max_active_devices or "1")
        if mad > 0:
            body["maxActiveDevices"] = mad
    except ValueError:
        pass
    try:
        gb = float(traffic_limit_gb or "0")
        if gb > 0:
            body["trafficLimit"] = int(gb * 1024 ** 3)
    except ValueError:
        pass
    return body


@router.post("/user")
async def user_create(
    request: Request,
    user=Depends(get_current_user),
    username: str = Form(""),
    expire_at: str = Form(""),
    max_active_devices: str = Form("1"),
    traffic_limit_gb: str = Form(""),
):
    denied = _guard(request, user, "manage_users")
    if denied is not None:
        return denied
    if not username.strip() or len(username.strip()) < 3:
        return flash_redirect("/users/new", "error",
                              "Имя пользователя: минимум 3 символа")
    remna = _remna(request)
    body = _user_body_from_form(username, expire_at, max_active_devices, traffic_limit_gb)
    try:
        created = await remna.create_user(body)
    except RemnaError as e:
        _audit_err(request, user, body["username"], "/api/users", e)
        return flash_redirect("/users/new", "error", f"Панель: {e.message[:250]}")
    new_uuid = ""
    if isinstance(created, dict):
        new_uuid = str(created.get("uuid") or "")
    _audit_ok(request, user, body["username"], "/api/users", detail=body)
    if new_uuid:
        return flash_redirect(f"/users/{new_uuid}", "ok", f"Пользователь «{body['username']}» создан")
    return flash_redirect("/users", "ok", f"Пользователь «{body['username']}» создан")


@router.post("/user/{user_uuid}")
async def user_update(
    request: Request, user_uuid: str,
    user=Depends(get_current_user),
    username: str = Form(""),
    expire_at: str = Form(""),
    max_active_devices: str = Form("1"),
    traffic_limit_gb: str = Form(""),
):
    denied = _guard(request, user, "manage_users")
    if denied is not None:
        return denied
    remna = _remna(request)
    body = _user_body_from_form(username, expire_at, max_active_devices, traffic_limit_gb)
    try:
        await remna.update_user(user_uuid, body)
    except RemnaError as e:
        _audit_err(request, user, user_uuid, f"/api/users/{user_uuid}", e)
        return flash_redirect(f"/users/{user_uuid}", "error", f"Панель: {e.message[:250]}")
    _audit_ok(request, user, user_uuid, f"/api/users/{user_uuid}", detail=body)
    return flash_redirect(f"/users/{user_uuid}", "ok", "Пользователь обновлён")


@router.post("/user/{user_uuid}/delete")
async def user_delete(request: Request, user_uuid: str, user=Depends(get_current_user)):
    denied = _guard(request, user, "manage_users")
    if denied is not None:
        return denied
    remna = _remna(request)
    try:
        await remna.delete_user(user_uuid)
    except RemnaError as e:
        _audit_err(request, user, user_uuid, f"/api/users/{user_uuid} DELETE", e)
        return flash_redirect("/users", "error", f"Панель: {e.message[:250]}")
    _audit_ok(request, user, user_uuid, f"/api/users/{user_uuid} DELETE")
    return flash_redirect("/users", "ok", f"Пользователь {user_uuid[:8]}… удалён")


@router.post("/user/{user_uuid}/{action}")
async def user_action(request: Request, user_uuid: str, action: str,
                      user=Depends(get_current_user)):
    denied = _guard(request, user, "manage_users")
    if denied is not None:
        return denied
    remna = _remna(request)
    labels = {"enable": "включён", "disable": "выключен",
              "reset-traffic": "трафик сброшен", "revoke": "подписка отозвана"}
    try:
        await remna.user_action(user_uuid, action)
    except (RemnaError, ValueError) as e:
        _audit_err(request, user, user_uuid, f"/api/users/{user_uuid}/actions/{action}", e)
        return flash_redirect(f"/users/{user_uuid}", "error", f"Панель: {e.message[:250] if isinstance(e, RemnaError) else e}")
    _audit_ok(request, user, user_uuid, f"/api/users/{user_uuid}/actions/{action}")
    return flash_redirect(f"/users/{user_uuid}", "ok",
                          f"Пользователь {labels.get(action, action)}")


@router.post("/user/{user_uuid}/extend")
async def user_extend(request: Request, user_uuid: str, user=Depends(get_current_user),
                      days: str = Form("1")):
    denied = _guard(request, user, "manage_users")
    if denied is not None:
        return denied
    try:
        d = max(1, min(int(days), 3650))
    except ValueError:
        return flash_redirect(f"/users/{user_uuid}", "error", "Дни: целое число")
    remna = _remna(request)
    try:
        await remna.user_action(user_uuid, "extend", {"days": d})
    except RemnaError as e:
        _audit_err(request, user, user_uuid, f"/api/users/{user_uuid}/actions/extend", e)
        return flash_redirect(f"/users/{user_uuid}", "error", f"Панель: {e.message[:250]}")
    _audit_ok(request, user, user_uuid, f"/api/users/{user_uuid}/actions/extend",
              detail={"days": d})
    return flash_redirect(f"/users/{user_uuid}", "ok", f"Срок продлён на {d} дн.")


# ---------------- Remnawave: хосты ----------------

@router.post("/host")
async def host_create(
    request: Request,
    user=Depends(get_current_user),
    name: str = Form(""),
    host: str = Form(""),
    port: str = Form("443"),
    protocol: str = Form("https"),
    is_default: str = Form("off"),
):
    denied = _guard(request, user, "manage_hosts")
    if denied is not None:
        return denied
    if not host.strip():
        return flash_redirect("/hosts/new", "error", "Host (ip/домен) обязателен")
    body = {"name": (name or host).strip(), "host": host.strip(),
            "port": int(port or 443), "protocol": protocol,
            "isDefault": is_default == "on"}
    remna = _remna(request)
    try:
        await remna.create_host(body)
    except RemnaError as e:
        _audit_err(request, user, body["host"], "/api/hosts", e)
        return flash_redirect("/hosts", "error", f"Панель: {e.message[:250]}")
    _audit_ok(request, user, body["host"], "/api/hosts", detail=body)
    return flash_redirect("/hosts", "ok", f"Хост {body['host']} создан")


@router.post("/host/{host_uuid}")
async def host_update(
    request: Request, host_uuid: str,
    user=Depends(get_current_user),
    name: str = Form(""),
    host: str = Form(""),
    port: str = Form("443"),
    protocol: str = Form("https"),
    is_default: str = Form("off"),
):
    denied = _guard(request, user, "manage_hosts")
    if denied is not None:
        return denied
    body = {"name": name.strip() or host.strip(), "host": host.strip(),
            "port": int(port or 443), "protocol": protocol,
            "isDefault": is_default == "on"}
    remna = _remna(request)
    try:
        await remna.update_host(host_uuid, body)
    except RemnaError as e:
        _audit_err(request, user, host_uuid, f"/api/hosts/{host_uuid}", e)
        return flash_redirect("/hosts", "error", f"Панель: {e.message[:250]}")
    _audit_ok(request, user, host_uuid, f"/api/hosts/{host_uuid}", detail=body)
    return flash_redirect("/hosts", "ok", f"Хост {body['host']} обновлён")


@router.post("/host/{host_uuid}/delete")
async def host_delete(request: Request, host_uuid: str, user=Depends(get_current_user)):
    denied = _guard(request, user, "manage_hosts")
    if denied is not None:
        return denied
    remna = _remna(request)
    try:
        await remna.delete_host(host_uuid)
    except RemnaError as e:
        _audit_err(request, user, host_uuid, f"/api/hosts/{host_uuid} DELETE", e)
        return flash_redirect("/hosts", "error", f"Панель: {e.message[:250]}")
    _audit_ok(request, user, host_uuid, f"/api/hosts/{host_uuid} DELETE")
    return flash_redirect("/hosts", "ok", f"Хост {host_uuid[:8]}… удалён")


# ---------------- Remnawave: профили ключей и конфигов ----------------

@router.post("/profile")
async def profile_create(
    request: Request,
    user=Depends(get_current_user),
    name: str = Form(""),
    protocol: str = Form("vless"),
    host: str = Form(""),
    port: str = Form("443"),
    pin: str = Form(""),
    config: str = Form(""),
):
    denied = _guard(request, user, "manage_profiles")
    if denied is not None:
        return denied
    if not name.strip():
        return flash_redirect("/profiles/new", "error", "Имя профиля обязательно")
    remna = _remna(request)
    body: dict = {"name": name.strip()}
    cfg: dict = {"protocol": protocol, "host": host.strip(), "port": int(port or 443)}
    if pin.strip():
        cfg["pin"] = pin.strip()
    if config.strip():
        try:
            cfg["config"] = json.loads(config)
        except Exception:  # noqa: BLE001
            return flash_redirect("/profiles/new", "error", "JSON входов некорректен")
    body["config"] = cfg
    try:
        await remna.create_profile(body)
    except RemnaError as e:
        _audit_err(request, user, name.strip(), "/api/config-profiles", e)
        return flash_redirect("/profiles/new", "error", f"Панель: {e.message[:250]}")
    _audit_ok(request, user, name.strip(), "/api/config-profiles",
              detail={"protocol": protocol, "host": host.strip()})
    return flash_redirect("/profiles", "ok", f"Профиль «{name.strip()}» создан")


@router.post("/profile/{profile_uuid}")
async def profile_update(request: Request, profile_uuid: str,
                         user=Depends(get_current_user),
                         name: str = Form(""), config: str = Form("")):
    denied = _guard(request, user, "manage_profiles")
    if denied is not None:
        return denied
    if not config.strip():
        return flash_redirect(f"/profiles/{profile_uuid}", "error",
                              "Конфиг пуст — сохранение отменено")
    try:
        json.loads(config)
    except Exception:  # noqa: BLE001
        return flash_redirect(f"/profiles/{profile_uuid}", "error",
                              "JSON некорректен — сохранение отменено")
    remna = _remna(request)
    body = {"name": name.strip(), "config": config}
    try:
        await remna.update_profile(profile_uuid, body)
    except RemnaError as e:
        _audit_err(request, user, profile_uuid, f"/api/config-profiles/{profile_uuid}", e)
        return flash_redirect(f"/profiles/{profile_uuid}", "error", f"Панель: {e.message[:250]}")
    _audit_ok(request, user, profile_uuid, f"/api/config-profiles/{profile_uuid}",
              detail={"bytes": len(config)})
    return flash_redirect(f"/profiles/{profile_uuid}", "ok", "Профиль сохранён")


# ---------------- Бот eXpress ----------------

@router.post("/bot/config")
async def bot_config_save(
    request: Request,
    user=Depends(get_current_user),
    enabled: str = Form("off"),
    cts_url: str = Form(""),
    bot_id: str = Form(""),
    secret: str = Form(""),
    allowed_huids: str = Form(""),
):
    denied = _guard(request, user, "manage_bot")
    if denied is not None:
        return denied
    cts_url = cts_url.strip()
    bot_id = bot_id.strip()
    if enabled == "on" and (not cts_url or not bot_id):
        return flash_redirect("/bot", "error",
                              "Для включения бота укажите CTS URL и Bot ID")
    try:
        _uuid.UUID(bot_id) if bot_id else None
    except ValueError:
        return flash_redirect("/bot", "error", "Bot ID должен быть UUID")
    if cts_url and not cts_url.startswith(("http://", "https://")):
        cts_url = "https://" + cts_url

    from ..botx.crypto import encrypt_secret

    db = session_factory()
    try:
        cfg = db.get(BotConfig, 1)
        if cfg is None:
            cfg = BotConfig(id=1)
            db.add(cfg)
        cfg.enabled = enabled == "on"
        cfg.cts_url = cts_url
        cfg.bot_id = bot_id
        if secret.strip():
            cfg.secret_enc = encrypt_secret(secret.strip())
        cfg.allowed_huids = "\n".join(
            h.strip() for h in allowed_huids.replace("\r", "").splitlines() if h.strip()
        )
        cfg.revision = (cfg.revision or 0) + 1
        db.commit()
    finally:
        db.close()

    provider = request.app.state.bot_provider
    provider.refresh()
    _audit_ok(request, user, "bot-config", "bot/config",
              detail={"enabled": cfg.enabled, "cts_url": cts_url,
                      "bot_id": bot_id, "secret_changed": bool(secret.strip()),
                      "huids": len(cfg.allowed_huids.splitlines()) if cfg.allowed_huids else 0})
    return flash_redirect("/bot", "ok", "Настройки бота сохранены")


# ---------------- Управление доступами (локальные пользователи) ----------------

@router.post("/access/user")
async def access_create(
    request: Request,
    user=Depends(get_current_user),
    username: str = Form(""),
    role: str = Form("viewer"),
    password: str = Form(""),
):
    denied = _guard(request, user, "manage_access")
    if denied is not None:
        return denied
    username = username.strip()
    if len(username) < 3 or len(username) > 64:
        return flash_redirect("/access", "error", "Логин: 3–64 символа")
    if len(password) < 8:
        return flash_redirect("/access", "error", "Пароль: минимум 8 символов")
    if role not in ("viewer", "operator", "bot_admin", "admin"):
        return flash_redirect("/access", "error", "Неизвестная роль")
    db = session_factory()
    try:
        if db.query(AccessUser).filter(AccessUser.username == username).first():
            return flash_redirect("/access", "error", f"Логин «{username}» уже занят")
        db.add(AccessUser(username=username, password_hash=hash_password(password), role=role))
        db.commit()
    finally:
        db.close()
    _audit_ok(request, user, username, "access/create", detail={"role": role})
    return flash_redirect("/access", "ok", f"Пользователь «{username}» создан ({role})")


@router.post("/access/user/{target_id}/password")
async def access_set_password(request: Request, target_id: int,
                              user=Depends(get_current_user),
                              new_password: str = Form("")):
    denied = _guard(request, user, "manage_access")
    if denied is not None:
        return denied
    import secrets as _secrets

    new_password = new_password.strip()
    if not new_password:
        new_password = _secrets.token_urlsafe(12)
    if len(new_password) < 8:
        return TEMPLATES.TemplateResponse(
            "fragments/access_feedback.html",
            {"request": request, "error": "Пароль: минимум 8 символов"},
        )
    db = session_factory()
    try:
        target = db.get(AccessUser, target_id)
        if not target:
            return TEMPLATES.TemplateResponse(
                "fragments/access_feedback.html",
                {"request": request, "error": "Пользователь не найден"},
            )
        target.password_hash = hash_password(new_password)
        db.commit()
        name = target.username
    finally:
        db.close()
    _audit_ok(request, user, name, "access/set-password")
    return TEMPLATES.TemplateResponse(
        "fragments/access_feedback.html",
        {"request": request, "error": "", "username": name, "password": new_password},
    )


@router.post("/access/user/{target_id}/role")
async def access_set_role(request: Request, target_id: int,
                          user=Depends(get_current_user),
                          role: str = Form("viewer"),
                          is_active: str = Form("on")):
    denied = _guard(request, user, "manage_access")
    if denied is not None:
        return denied
    if role not in ("viewer", "operator", "bot_admin", "admin"):
        return flash_redirect("/access", "error", "Неизвестная роль")
    db = session_factory()
    try:
        target = db.get(AccessUser, target_id)
        if not target:
            return flash_redirect("/access", "error", "Пользователь не найден")
        target.role = role
        target.is_active = is_active == "on"
        db.commit()
        name = target.username
    finally:
        db.close()
    _audit_ok(request, user, name, "access/role", detail={"role": role,
                                                          "is_active": is_active == "on"})
    return flash_redirect("/access", "ok", f"«{name}»: роль {role}")


@router.post("/access/user/{target_id}/toggle")
async def access_toggle(request: Request, target_id: int, user=Depends(get_current_user)):
    denied = _guard(request, user, "manage_access")
    if denied is not None:
        return denied
    db = session_factory()
    try:
        target = db.get(AccessUser, target_id)
        if not target:
            return flash_redirect("/access", "error", "Пользователь не найден")
        if target.id == user.id:
            return flash_redirect("/access", "error", "Нельзя отключить самого себя")
        target.is_active = not target.is_active
        db.commit()
        name, now_active = target.username, target.is_active
    finally:
        db.close()
    _audit_ok(request, user, name, "access/toggle", detail={"active": now_active})
    return flash_redirect("/access", "ok",
                          f"«{name}» {'включён' if now_active else 'отключён'}")


@router.post("/access/user/{target_id}/delete")
async def access_delete(request: Request, target_id: int, user=Depends(get_current_user)):
    denied = _guard(request, user, "manage_access")
    if denied is not None:
        return denied
    db = session_factory()
    try:
        target = db.get(AccessUser, target_id)
        if not target:
            return flash_redirect("/access", "error", "Пользователь не найден")
        if target.id == user.id:
            return flash_redirect("/access", "error", "Нельзя удалить самого себя")
        if target.role == "admin":
            admins = db.query(AccessUser).filter(
                AccessUser.role == "admin", AccessUser.is_active.is_(True)
            ).count()
            if admins <= 1:
                return flash_redirect("/access", "error",
                                      "Нельзя удалить последнего администратора")
        db.delete(target)
        db.commit()
        name = target.username
    finally:
        db.close()
    _audit_ok(request, user, name, "access/delete")
    return flash_redirect("/access", "ok", f"«{name}» удалён")


# ---------------- Экспорт аудита ----------------

@router.get("/export/audit.csv")
async def export_audit_csv(request: Request, user=Depends(get_current_user),
                           user_q: str = "", category: str = "",
                           date_from: str = "", date_to: str = ""):
    denied = _guard(request, user, "view_audit")
    if denied is not None:
        return denied
    db = session_factory()
    try:
        q = db.query(AuditLog)
        if user_q.strip():
            q = q.filter(AuditLog.actor.ilike(f"%{user_q.strip()}%"))
        if category:
            q = q.filter(AuditLog.category == category)
        if date_from:
            try:
                q = q.filter(AuditLog.ts >= datetime.fromisoformat(date_from))
            except ValueError:
                pass
        if date_to:
            try:
                q = q.filter(AuditLog.ts <= datetime.fromisoformat(date_to + "T23:59:59+00:00"))
            except ValueError:
                pass
        rows = q.order_by(AuditLog.id.desc()).limit(20000).all()
        data = [[
            r.ts.isoformat() if r.ts else "",
            r.actor, r.role, r.ip, r.category, r.method, r.path,
            r.target, r.status, r.duration_ms, r.detail,
        ] for r in rows]
    finally:
        db.close()

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";")
        w.writerow(["ts", "actor", "role", "ip", "category", "method", "path",
                    "target", "status", "duration_ms", "detail"])
        yield buf.getvalue()
        buf.seek(0); buf.truncate(0)
        for row in data:
            w.writerow(row)
            yield buf.getvalue()
            buf.seek(0); buf.truncate(0)

    fn = f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.csv"
    return StreamingResponse(
        gen(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={fn}"},
    )
