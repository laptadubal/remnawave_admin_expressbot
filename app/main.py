"""remnawave-admin: точка входа FastAPI.

- собственная авторизация (локальные пользователи + роли)
- полный менеджмент панели Remnawave через её REST API
- встроенный bот мессенджера eXpress (BotX, pybotx)
- аудит всех действий
"""
from __future__ import annotations

import asyncio
import logging
import secrets

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .botx.commands import BotDeps, build_collector
from .botx.provider import DbBotAccountProvider
from .config import get_settings
from .db import AccessUser, init_db, session_factory
from .page import TEMPLATES
from .routers import api as api_router
from .routers import auth_page as auth_router
from .routers import web as web_router
from .remna.client import RemnawaveClient
from .security import hash_password

logger = logging.getLogger("rwadmin")


def ensure_default_admin() -> None:
    s = get_settings()
    db = session_factory()
    try:
        existing = db.query(AccessUser).filter(
            AccessUser.username == s.admin_username
        ).first()
        if existing:
            return
        password = s.admin_password
        if not password:
            password = "Rw" + secrets.token_urlsafe(12)
            banner = "#" * 60
            logger.warning(
                banner + "\n"
                "Создан первый администратор админки:\n"
                "  логин:   %s\n"
                "  пароль:   %s\n"
                "Пароль сгенерирован автоматически и печатается ОДИН раз.\n"
                "Задайте ADMIN_PASSWORD в .env, если хотите свой.\n"
                + banner,
                s.admin_username, password,
            )
        db.add(AccessUser(
            username=s.admin_username,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        ))
        db.commit()
        logger.info("Default admin '%s' created", s.admin_username)
    finally:
        db.close()


def _create_app() -> FastAPI:
    settings = get_settings()
    init_db()
    ensure_default_admin()

    app = FastAPI(title="remnawave-admin", version=__version__, docs_url=None,
                  redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.remna = RemnawaveClient(settings)
    app.state.bot_provider = DbBotAccountProvider()

    # --- bот eXpress (pybotx) ---
    try:
        from pybotx import Bot, FastAPIBotAppConfig, setup_fastapi_bot

        deps = BotDeps(app.state.remna, app.state.bot_provider)
        collector = build_collector(deps)
        bot = Bot(collectors=[collector], account_provider=app.state.bot_provider)
        setup_fastapi_bot(
            app,
            bot=bot,
            config=FastAPIBotAppConfig(
                command_path="/botx/command",
                status_path="/botx/status",
                callback_path="/botx/notification/callback",
                healthcheck_prefix=None,  # наш healthz отдельно
            ),
        )
        app.state.bot = bot
        logger.info("eXpress bot module attached (paths: /botx/command, /botx/status, /botx/notification/callback)")
    except Exception:  # noqa: BLE001
        logger.exception("pybotx integration failed — web-админка продолжит работать без бота")
        app.state.bot = None

    app.include_router(auth_router.router)
    app.include_router(web_router.router)
    app.include_router(api_router.router)
    app.mount("/static", StaticFiles(directory="app/static"), name="static")

    @app.get("/healthz")
    async def healthz():
        return JSONResponse({"ok": True, "version": __version__})

    # --- фоновый мониторинг панели и нод (алерты в eXpress) ---
    from .monitoring import MonitorEngine

    engine = MonitorEngine(app.state.remna, app.state.bot, app.state.bot_provider)
    app.state.monitor = engine

    @app.on_event("startup")
    async def _start_monitor():
        app.state.monitor_task = asyncio.create_task(engine.run())
        logger.info("monitor: фоновая проверка панели и нод запущена")

    @app.on_event("shutdown")
    async def _shutdown():
        task = getattr(app.state, "monitor_task", None)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await app.state.remna.close()

    return app


app = _create_app()
