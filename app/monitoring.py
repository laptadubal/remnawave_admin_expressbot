"""Мониторинг панели Remnawave и её нод.

Фоновый цикл (в пределах одного воркера):
  * опрашивает GET /api/nodes панели с настраиваемым интервалом;
  * отслеживает переходы состояний: панель up/down/auth, ноды
    up/down/disabled/«исчезла из панели»;
  * при переходе шлёт алерт в eXpress всем доверенным HUID
    (ensure_personal_chat + send_message), пишем событие в БД
    (monitor_events) независимо от того, включён ли сам бот.

Правила:
  * первичный снэшот (нет сохранённого состояния) — алерт только
    для объектов, уже находящихся в плохом состоянии;
  * повторные алерты в состояние down/auth гасятся кулдауном
    ALERT_COOLDOWN (чтобы флэпинг не спамил);
  * восстановления (down->up, auth->up) и «нода исчезла» — всегда.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid as uuid_mod
from datetime import datetime, timedelta, timezone

from .audit import record_bot
from .db import BotConfig, MonitorEvent, MonitorState, session_factory
from .remna.client import (
    RemnaAuthError,
    RemnaError,
    RemnaNotConfigured,
    RemnawaveClient,
)

logger = logging.getLogger("rwadmin.monitor")

PANEL_KEY = "panel"
PANEL_LABEL = "панель Remnawave"
ALERT_COOLDOWN = timedelta(minutes=15)
MAX_EVENTS = 300
BOOT_DELAY_S = 5
MIN_INTERVAL_S = 30


def node_key(node_uuid: str) -> str:
    return f"node:{node_uuid}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite возвращает naive — приравниваем к UTC для безопасного сравнения."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _node_identity(raw: dict) -> tuple[str, str]:
    """(uuid, display) для нода; display — «имя (addr:port)»."""
    ident = str(raw.get("uuid") or raw.get("id") or "")
    name = raw.get("name") or "?"
    addr = raw.get("address") or ""
    port = raw.get("port") or ""
    addr_s = f"{addr}:{port}" if addr and port else (addr or addr_s)
    display = f"{name} ({addr_s})" if addr_s else str(name)
    return ident, display


def node_state_of(raw: dict) -> str:
    """Нормализация состояния нода из ответа /api/nodes."""
    if raw.get("isConnected") or raw.get("is_connected"):
        return "up"
    if raw.get("isDisabled") or raw.get("is_disabled"):
        return "disabled"
    status = str(raw.get("status") or "").strip().lower()
    if status in ("online", "up", "connected", "running"):
        return "up"
    if status in ("offline", "down", "unreachable", "disconnected"):
        return "down"
    # не подключена и не выключена intentionally => «недоступна»
    return "down"


def nodes_from_api(data) -> list[dict] | None:
    """Список нод из ответа API; None — формат неожиданный."""
    if isinstance(data, list):
        return [n for n in data if isinstance(n, dict)]
    if isinstance(data, dict):
        for key in ("list", "items", "nodes"):
            inner = data.get(key)
            if isinstance(inner, list):
                return [n for n in inner if isinstance(n, dict)]
    return None


class MonitorEngine:
    def __init__(self, remna: RemnawaveClient, bot, provider):
        self.remn = remna
        self.bot = bot
        self.provider = provider
        self._chat_cache: dict[str, str] = {}

    # ---------------- конфигурация ----------------

    def _cfg(self) -> BotConfig | None:
        db = session_factory()
        try:
            return db.get(BotConfig, 1)
        finally:
            db.close()

    # ---------------- основной цикл ----------------

    async def run(self) -> None:
        """Бесконечный цикл; отменяется на shutdown приложения."""
        await asyncio.sleep(BOOT_DELAY_S)
        cycle_num = 0
        while True:
            interval_s = 300.0
            try:
                cfg = self._cfg()
                # свежая БД без строки конфига — мониторинг включён по умолчанию
                mon_enabled = True if cfg is None else bool(cfg.monitor_enabled)
                interval_min = (cfg.monitor_interval_min if cfg is not None else 5) or 5
                if mon_enabled:
                    if interval_min > 0:
                        interval_s = float(interval_min) * 60.0
                    interval_s = max(MIN_INTERVAL_S, interval_s)
                    await self.check_cycle()
                else:
                    interval_s = MIN_INTERVAL_S
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("monitor: цикл проверки упал")
            cycle_num += 1
            if cycle_num % 10 == 0:
                try:
                    self._trim_events()
                except Exception:  # noqa: BLE001
                    logger.exception("monitor: trim событий")
            await asyncio.sleep(interval_s)

    # ---------------- один цикл проверки ----------------

    async def check_cycle(self) -> None:
        if not self.remn.configured:
            return  # панель не настроена — мониторингу нечего проверять

        started = time.perf_counter()
        panel_new = "unknown"
        panel_err = ""
        nodes_raw: list[dict] | None = None
        try:
            data = await self.remn.nodes()
            panel_new = "up"
            nodes_raw = nodes_from_api(data)
            if nodes_raw is None:
                # панель отвечает, но список нод в неожиданном виде
                self._set_panel("unknown", detail="неожиданный формат списка нод")
        except RemnaAuthError as e:
            panel_new = "auth"
            panel_err = e.message
        except RemnaNotConfigured:
            return
        except RemnaError as e:
            panel_new = "down"
            panel_err = e.message
        except Exception as e:  # httpx transport, таймауты и т.п.
            panel_new = "down"
            panel_err = f"{type(e).__name__}: {e}"

        took_ms = int((time.perf_counter() - started) * 1000)
        logger.info("monitor: панель=%s (%d мс), нод: %s",
                    panel_new, took_ms,
                    "n/a" if nodes_raw is None else f"{len(nodes_raw)}")

        # состояние панели
        if panel_new == "unknown":
            self._set_panel("unknown")
            return
        if panel_new == "down":
            await self._panel_transition("down", panel_err)
        elif panel_new == "auth":
            await self._panel_transition("auth", panel_err)
        else:  # up
            await self._panel_transition("up", "")
            if nodes_raw is not None:
                await self._process_nodes(nodes_raw)

    # ---------------- панель ----------------

    def _set_panel(self, state: str, detail: str = "") -> None:
        """Без алерта: только сохранить состояние (первичный/нейтральный снэшот)."""
        db = session_factory()
        try:
            st = db.get(MonitorState, PANEL_KEY)
            if st is None:
                st = MonitorState(key=PANEL_KEY, state=state, display=PANEL_LABEL)
                db.add(st)
            else:
                st.state = state
                st.detail = detail
            db.commit()
        finally:
            db.close()

    async def _panel_transition(self, new_state: str, err: str) -> None:
        db = session_factory()
        try:
            st = db.get(MonitorState, PANEL_KEY)
            old = st.state if st else None
            if old is None:  # первичный снэшот
                self._set_panel(new_state, detail=err)
                if new_state in ("down", "auth"):
                    await self._emit(
                        PANEL_KEY,
                        "warn" if new_state == "auth" else "alert",
                        PANEL_LABEL,
                        self._panel_text(new_state, err, first=True),
                    )
                return
            if old == new_state and new_state != "down":
                return
            if old == new_state == "down":
                # кулдаун против спэма, если панель мигает по границе down/up/down
                last_alert = _aware(st.last_alert_at)
                if last_alert and _now() - last_alert < ALERT_COOLDOWN:
                    st.detail = err
                    db.commit()
                    return
                await self._emit(
                    PANEL_KEY, "alert", PANEL_LABEL,
                    self._panel_text("down", err, first=False),
                    bump=True,
                )
                st.state = new_state
                st.detail = err
                db.commit()
                return

            # переход
            if new_state == "up" and old in ("down", "auth", "unknown"):
                text = f"🟢 {PANEL_LABEL} снова доступна"
                await self._emit(PANEL_KEY, "recovery", PANEL_LABEL, text)
            elif new_state == "down":
                await self._emit(
                    PANEL_KEY, "alert", PANEL_LABEL,
                    self._panel_text("down", err, first=False), bump=True,
                )
            elif new_state == "auth" and old != "auth":
                await self._emit(PANEL_KEY, "warn", PANEL_LABEL,
                                 self._panel_text("auth", err, first=False))
            st.state = new_state
            st.detail = err
            st.down_since = _now() if new_state in ("down", "auth") else None
            db.commit()
        finally:
            db.close()

    @staticmethod
    def _panel_text(state: str, err: str, *, first: bool) -> str:
        if state == "down":
            err = (err or "").strip().splitlines()[0][:160] if err else "нет соединения"
            suffix = " (первая проверка после включения мониторинга)" if first else ""
            return f"🔴 {PANEL_LABEL} недоступна{suffix}\n{err}"
        if state == "auth":
            return (f"🟡 {PANEL_LABEL} отвечает, но отклоняет учётные данные.\n"
                    "Проверьте API-токен или логин/пароль панели.")
        return f"🟢 {PANEL_LABEL} снова доступна"

    # ---------------- ноды ----------------

    async def _process_nodes(self, nodes_raw: list[dict]) -> None:
        seen: set[str] = set()
        now = _now()

        for raw in nodes_raw:
            ident, display = _node_identity(raw)
            if not ident:
                continue
            key = node_key(ident)
            seen.add(key)
            new_state = node_state_of(raw)
            await self._node_transition(key, display, new_state, now)

        # исчезнувшие из списка панели
        db = session_factory()
        try:
            prev = db.query(MonitorState).filter(MonitorState.key.like("node:%")).all()
            gone = [
                (s.key, s.display)
                for s in prev
                if s.key not in seen and s.state in ("up", "disabled", "down")
            ]
            for key, display in gone:
                db.delete(db.get(MonitorState, key))
            db.commit()
        finally:
            db.close()
        for key, display in gone:
            await self._emit(
                key, "alert", display or key,
                f"🔴 Нода «{display or key}» исчезла из конфигурации панели",
                bump=True,
            )

    async def _node_transition(
        self, key: str, display: str, new_state: str, now: datetime
    ) -> None:
        db = session_factory()
        try:
            st = db.get(MonitorState, key)
            old = st.state if st else None
            if old is None:
                st = MonitorState(key=key, state=new_state, display=display)
                db.add(st)
                if new_state in ("down", "disabled"):
                    st.last_alert_at = now
                    db.commit()
                    db.close()
                    await self._emit(
                        key, "alert", display,
                        f"🔴 Нода «{display}» недоступна (первая проверка мониторинга)",
                        bump=True,
                    )
                    return
                st.down_since = None
                db.commit()
                return

            if old == new_state:
                st.display = display
                db.commit()
                return

            if new_state == "up":
                text = f"🟢 Нода «{display}» снова в сети"
                level = "recovery"
                bump = False
            elif new_state == "down":
                last_alert = _aware(st.last_alert_at)
                if last_alert and now - last_alert < ALERT_COOLDOWN:
                    st.state = new_state
                    st.display = display
                    db.commit()
                    return
                text = f"🔴 Нода «{display}» недоступна (offline)"
                level = "alert"
                bump = True
            elif new_state == "disabled":
                text = f"⚠️ Нода «{display}» выключена (disabled) в панели"
                level = "warn"
                bump = False
            else:  # down -> disabled и прочие нейтральные
                st.state = new_state
                st.display = display
                if new_state in ("down",):
                    st.down_since = now
                else:
                    st.down_since = None
                db.commit()
                return

            if old == "down" and new_state == "disabled":
                st.state = new_state
                st.display = display
                db.commit()
                return

            st.state = new_state
            st.display = display
            st.down_since = now if new_state in ("down", "auth") else None
            if new_state in ("down",):
                st.last_alert_at = now
            db.commit()
        finally:
            db.close()

        await self._emit(key, level, display, text, bump=bump)

    # ---------------- события и доставка ----------------

    async def _emit(
        self,
        key: str,
        level: str,
        display: str,
        text: str,
        *,
        bump: bool = False,
    ) -> None:
        sent_ok, recipients = await self._broadcast(text)
        db = session_factory()
        try:
            db.add(MonitorEvent(
                key=key, level=level, text=text, sent_ok=sent_ok, recipients=recipients,
            ))
            if bump:
                st = db.get(MonitorState, key)
                if st is not None:
                    st.last_alert_at = _now()
            db.commit()
        finally:
            db.close()
        if level in ("alert", "recovery", "warn"):
            record_bot(
                huid="system",
                username="monitor",
                command=f"monitor:{level}",
                argument=key,
                status="ok" if sent_ok else "error",
                detail=text[:300] + ("" if sent_ok else " [не доставлено в eXpress]"),
            )

    async def _broadcast(self, text: str) -> tuple[bool, int]:
        """Доставка в eXpress всем доверенным HUID. (ok, count)."""
        if self.bot is None:
            return False, 0
        self.provider.refresh()
        accounts = list(self.provider.iter_bot_accounts())
        cfg = self._cfg()
        if not accounts or cfg is None or not (cfg.allowed_huids or "").strip():
            return False, 0
        try:
            bot_id = accounts[0].id
        except Exception:  # noqa: BLE001
            return False, 0

        sent = 0
        for h in (cfg.allowed_huids or "").replace("\r", "").splitlines():
            h = h.strip()
            if not h:
                continue
            try:
                huuid = uuid_mod.UUID(h)
            except ValueError:
                logger.warning("monitor: в whitelist некорректный HUID: %r", h)
                continue
            try:
                chat_id = self._chat_cache.get(h)
                if chat_id is None:
                    info = await self.bot.ensure_personal_chat(
                        bot_id=bot_id, user_huid=huuid
                    )
                    chat_id = str(info.chat_id)
                    self._chat_cache[h] = chat_id
                await self.bot.send_message(
                    bot_id=bot_id,
                    chat_id=uuid_mod.UUID(chat_id),
                    body=text,
                    recipients=[huuid],
                )
                sent += 1
            except Exception:  # noqa: BLE001
                logger.exception("monitor: не удалось отправить алерт в eXpress (%s)", h)
        return sent > 0, sent

    def _trim_events(self) -> None:
        db = session_factory()
        try:
            total = db.query(MonitorEvent).count()
            if total > MAX_EVENTS:
                extra = total - MAX_EVENTS
                db.query(MonitorEvent).order_by(MonitorEvent.id.desc()).offset(
                    MAX_EVENTS
                ).limit(extra).delete(synchronize_session=False)
                db.commit()
        finally:
            db.close()
