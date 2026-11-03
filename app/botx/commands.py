"""Команды eXpress-бота: мониторинг Remnawave через бота.

Права: бот отвечает только HUId, перечисленным в BotConfig.allowed_huids
(раздел «Бот» админки). Все команды журналируются (bot_events + audit_log).
"""
from __future__ import annotations

import logging

from pybotx import HandlerCollector, IncomingMessage

from ..audit import record_bot
from ..remna.client import RemnaError, RemnawaveClient

logger = logging.getLogger("rwadmin.botx.commands")


def _human(n: float | int | None) -> str:
    if n is None:
        return "—"
    n = float(n)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _node_lines(nodes) -> str:
    if not isinstance(nodes, list):
        return "Панель вернула неожиданный формат списка нод."
    lines = []
    for nd in nodes:
        name = nd.get("name", "?")
        addr = nd.get("address", "?")
        port = nd.get("port", "")
        cc = nd.get("countryCode") or nd.get("country_code") or ""
        conn = nd.get("isConnected") or nd.get("is_connected")
        disabled = nd.get("isDisabled") or nd.get("is_disabled")
        traffic = nd.get("trafficUsedBytes", nd.get("traffic_used_bytes"))
        mark = "в сети" if conn else ("выключена" if disabled else "НЕ в сети")
        lines.append(f"{name} ({addr}:{port} {cc}) — {mark}, {_human(traffic)}")
    return "\n".join(lines) if lines else "Ноды не найдены."


def _user_lines(users) -> str:
    if isinstance(users, dict):
        users = users.get("list") or users.get("nodes") or []
    if not isinstance(users, list):
        return "Не удалось получить список пользователей."
    lines = []
    for u in users[:20]:
        name = u.get("username", "?")
        exp = (u.get("expireAt") or u.get("expire_at") or "бессрочно")[:10]
        active = u.get("status") in (1, True)
        lines.append(f"{name} — {'активен' if active else 'выключен'} до {exp}")
    if len(users) > 20:
        lines.append(f"(показаны 20 из {len(users)})")
    return "\n".join(lines)


class BotDeps:
    """Доступ к Remnawave-клиенту из обработчиков команд."""

    def __init__(self, remna: RemnawaveClient, provider):
        self.remn = remna
        self.provider = provider

    def allowed(self, huid: str) -> bool:
        self.provider.refresh()  # взять актуальный снапшот
        from ..db import BotConfig, session_factory

        db = session_factory()
        try:
            cfg = db.get(BotConfig, 1)
        finally:
            db.close()
        if not cfg or not cfg.allowed_huids:
            return False
        allowed = {h.strip().lower() for h in cfg.allowed_huids.splitlines() if h.strip()}
        return huid.lower() in allowed


def _check_access(deps: BotDeps, message: IncomingMessage, bot, command: str) -> bool:
    """Возвращает True, если отправитель разрешён; иначе отвечает отказом + аудит."""
    huid = str(message.sender.huid)
    u_name = message.sender.username or ""
    if deps.allowed(huid):
        return True
    record_bot(
        huid=huid,
        username=u_name,
        command=command,
        argument=message.argument,
        status="denied",
        detail="HUId not in allow-list",
    )
    return False


def build_collector(deps: BotDeps) -> HandlerCollector:
    collector = HandlerCollector()

    @collector.command("/help", description="Список команд")
    async def help_cmd(message: IncomingMessage, bot) -> None:
        if not _check_access(deps, message, bot, "/help"):
            await bot.answer_message(
                "Доступ запрещён: ваш HUId не в списке разрешённых пользователей. "
                "Обратитесь к администратору."
            )
            return
        await bot.answer_message(
            "Команды:\n"
            "/status — состояние нод\n"
            "/users [поиск] — список пользователей (первые 20)\n"
            "/user <имя> — информация о пользователе\n"
            "/traffic <имя> — трафик пользователя\n"
            "/nodes <ip|имя> — детали ноды\n"
            "/help — эта справка"
        )

    @collector.command("/status", description="Состояние нод панели")
    async def status_cmd(message: IncomingMessage, bot) -> None:
        if not _check_access(deps, message, bot, "/status"):
            await bot.answer_message("Доступ запрещён: ваш HUId не в списке разрешённых.")
            return
        huid, uname = str(message.sender.huid), message.sender.username or ""
        try:
            nodes = await deps.remn.nodes()
            text = _node_lines(nodes)
            record_bot(huid=huid, username=uname, command="/status", status="ok")
        except RemnaError as e:
            text = f"Ошибка Remnawave: {e.message}"
            record_bot(huid=huid, username=uname, command="/status", status="error", detail=e.message)
        await bot.answer_message(text)

    @collector.command("/users", description="Список пользователей: /users [поиск]")
    async def users_cmd(message: IncomingMessage, bot) -> None:
        if not _check_access(deps, message, bot, "/users"):
            await bot.answer_message("Доступ запрещён: ваш HUId не в списке разрешённых.")
            return
        huid, uname = str(message.sender.huid), message.sender.username or ""
        try:
            users = await deps.remn.users(start=0, size=20)
            q = message.argument.strip().lower()
            if q and isinstance(users, list):
                users = [u for u in users if q in str(u.get("username", "")).lower()]
            text = _user_lines(users)
            record_bot(huid=huid, username=uname, command="/users", argument=message.argument, status="ok")
        except RemnaError as e:
            text = f"Ошибка Remnawave: {e.message}"
            record_bot(huid=huid, username=uname, command="/users", argument=message.argument, status="error", detail=e.message)
        await bot.answer_message(text)

    @collector.command("/user", description="Информация о пользователе: /user <имя>")
    async def user_cmd(message: IncomingMessage, bot) -> None:
        if not _check_access(deps, message, bot, "/user"):
            await bot.answer_message("Доступ запрещён: ваш HUId не в списке разрешённых.")
            return
        name = message.argument.strip()
        huid, uname = str(message.sender.huid), message.sender.username or ""
        if not name:
            await bot.answer_message("Укажите имя: /user <имя>")
            return
        try:
            u = await deps.remn.user_by_username(name)
            if isinstance(u, dict) and u:
                exp = (u.get("expireAt") or u.get("expire_at") or "бессрочно")[:19]
                tl = u.get("trafficLimit") or u.get("traffic_limit")
                act = u.get("status") in (1, True)
                text = (
                    f"{u.get('username', name)}\n"
                    f"статус: {'активен' if act else 'выключен'}\n"
                    f"действует до: {exp}\n"
                    f"лимит трафика: {_human(tl) if tl else 'безлимит'}\n"
                    f"uuid: {u.get('uuid')}"
                )
            else:
                text = f"Пользователь «{name}» не найден."
            record_bot(huid=huid, username=uname, command="/user", argument=name, status="ok")
        except RemnaError as e:
            text = f"Ошибка Remnawave: {e.message}"
            record_bot(huid=huid, username=uname, command="/user", argument=name, status="error", detail=e.message)
        await bot.answer_message(text)

    @collector.command("/traffic", description="Трафик пользователя: /traffic <имя>")
    async def traffic_cmd(message: IncomingMessage, bot) -> None:
        if not _check_access(deps, message, bot, "/traffic"):
            await bot.answer_message("Доступ запрещён: ваш HUId не в списке разрешённых.")
            return
        name = message.argument.strip()
        huid, uname = str(message.sender.huid), message.sender.username or ""
        if not name:
            await bot.answer_message("Укажите имя: /traffic <имя>")
            return
        try:
            u = await deps.remn.user_by_username(name)
            if isinstance(u, dict) and u.get("uuid"):
                stats = await deps.remn.bandwidth_users()
                matched = None
                if isinstance(stats, list):
                    for s in stats:
                        if s.get("userUuid") == u.get("uuid") or s.get("uuid") == u.get("uuid"):
                            matched = s
                            break
                if matched:
                    used = matched.get("usedBytes") or matched.get("trafficUsedBytes") or 0
                    text = f"{name}: израсходовано {_human(used)}"
                else:
                    text = f"{name}: статистика трафика недоступна"
            else:
                text = f"Пользователь «{name}» не найден."
            record_bot(huid=huid, username=uname, command="/traffic", argument=name, status="ok")
        except RemnaError as e:
            text = f"Ошибка Remnawave: {e.message}"
            record_bot(huid=huid, username=uname, command="/traffic", argument=name, status="error", detail=e.message)
        await bot.answer_message(text)

    @collector.command("/nodes", description="Детали ноды: /nodes <ip|имя>")
    async def nodes_cmd(message: IncomingMessage, bot) -> None:
        if not _check_access(deps, message, bot, "/nodes"):
            await bot.answer_message("Доступ запрещён: ваш HUId не в списке разрешённых.")
            return
        q = message.argument.strip()
        huid, uname = str(message.sender.huid), message.sender.username or ""
        if not q:
            await bot.answer_message("Укажите ip или имя: /nodes <ip|имя>")
            return
        try:
            nodes = await deps.remn.nodes()
            if not isinstance(nodes, list):
                await bot.answer_message("Не удалось получить список нод.")
                return
            found = [
                n
                for n in nodes
                if q in str(n.get("address", "")) or q.lower() in str(n.get("name", "")).lower()
            ]
            if found:
                n = found[0]
                text = (
                    f"{n.get('name')}\n"
                    f"адрес: {n.get('address')}:{n.get('port')}\n"
                    f"страна: {n.get('countryCode', '—')}\n"
                    f"подключение: {'да' if (n.get('isConnected') or n.get('is_connected')) else 'нет'}\n"
                    f"трафик: {_human(n.get('trafficUsedBytes', n.get('traffic_used_bytes')))}"
                )
            else:
                text = f"Нода «{q}» не найдена."
            record_bot(huid=huid, username=uname, command="/nodes", argument=q, status="ok")
        except RemnaError as e:
            text = f"Ошибка Remnawave: {e.message}"
            record_bot(huid=huid, username=uname, command="/nodes", argument=q, status="error", detail=e.message)
        await bot.answer_message(text)

    return collector
