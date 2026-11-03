"""Модели БД (SQLite): пользователи админки, сессии, аудит, конфиг bота, события bота."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

from .config import get_settings


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class AccessUser(Base):
    """Локальный пользователь админки (доступ к ней)."""

    __tablename__ = "access_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="viewer")  # viewer|operator|bot_admin|admin
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AccessSession(Base):
    """Серверная сессия (хеш tokena в куке)."""

    __tablename__ = "access_sessions"

    token_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("access_users.id"), index=True)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    """Журнал всех действий (web, bот, обращение к Remnawave, авторизация)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)  # username | bot:<huid> | system
    role: Mapped[str] = mapped_column(String(32), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    category: Mapped[str] = mapped_column(String(32), index=True)  # auth|web|action|bot|remna
    method: Mapped[str] = mapped_column(String(16), default="")
    path: Mapped[str] = mapped_column(String(255), default="")
    target: Mapped[str] = mapped_column(String(255), default="")  # uuid/имя цели
    status: Mapped[str] = mapped_column(String(32), default="ok")  # ok|denied|error|not_configured
    detail: Mapped[str] = mapped_column(Text, default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)


class BotConfig(Base):
    """Одиночный конфиг eXpress (BotX) bота."""

    __tablename__ = "bot_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)  # всегда 1
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    cts_url: Mapped[str] = mapped_column(String(255), default="")
    bot_id: Mapped[str] = mapped_column(String(64), default="")
    secret_enc: Mapped[str] = mapped_column(Text, default="")
    allowed_huids: Mapped[str] = mapped_column(Text, default="")  # по одному HUId в строке
    revision: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class BotEvent(Base):
    """События bота (команды eXpress)."""

    __tablename__ = "bot_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    huid: Mapped[str] = mapped_column(String(64), default="", index=True)
    username: Mapped[str] = mapped_column(String(128), default="")
    command: Mapped[str] = mapped_column(String(64), default="")
    argument: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(32), default="ok")  # ok|denied|error
    detail: Mapped[str] = mapped_column(Text, default="")


_engine = None
_SessionLocal = None


def init_db() -> None:
    global _engine, _SessionLocal
    settings = get_settings()
    import os

    os.makedirs(settings.data_dir, exist_ok=True)
    _engine = create_engine(
        f"sqlite:///{settings.db_path}",
        connect_args={"check_same_thread": False},
        future=True,
    )

    @event.listens_for(_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _record):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)


def get_engine():
    if _engine is None:
        init_db()
    return _engine


class SessionLocal:
    """Обёртка: при первом обращении инициализирует BД."""

    @staticmethod
    def session() -> Session:
        if _SessionLocal is None:
            init_db()
        assert _SessionLocal is not None
        return _SessionLocal()


def session_factory() -> Session:
    if _SessionLocal is None:
        init_db()
    assert _SessionLocal is not None
    return _SessionLocal()
