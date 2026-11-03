"""Настройки приложения из environment (+ .env файла рядом)."""
from __future__ import annotations

import logging
import os
import secrets as _secrets
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("rwadmin.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- приложение ---
    app_name: str = "Remnawave Admin"
    secret_key: str = ""
    data_dir: str = "/data"
    admin_username: str = "admin"
    admin_password: str | None = None
    session_hours: int = 12
    timezone: str = "Europe/Moscow"
    log_level: str = "INFO"

    # --- подключение к панели Remnawave ---
    remnawave_base_url: str | None = None
    remnawave_api_token: str | None = None
    remnawave_username: str | None = None
    remnawave_password: str | None = None
    remnawave_timeout: float = 20.0

    @property
    def remna_configured(self) -> bool:
        return bool(self.remnawave_base_url)

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "app.db")


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if not s.secret_key:
        s.secret_key = _secrets.token_hex(32)
        logger.warning(
            "SECRET_KEY не задан — сгенерирован временный ключ. "
            "Сессии и шифр секретов bота не переживут перезапуск. "
            "Задайте SECRET_KEY в .env."
        )
    os.makedirs(s.data_dir, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, s.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return s
