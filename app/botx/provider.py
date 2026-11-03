"""Динамический BotAccountProvider для pybotx: креды бота читаются из нашей БД.

Реализует протокол pybotx.bot.bot_account_provider.BotAccountProvider.
Provider отдаёт локальный снапшот (без сетевых вызовов) и обновляется
методом refresh() после сохранения настроек в UI. Смена ревизии принуждает
pybotx перечитать JWT-токен бота.
"""
from __future__ import annotations

import logging
from uuid import UUID

from pybotx.bot.exceptions import UnknownBotAccountError
from pybotx.models.bot_account import BotAccountKey, BotAccountWithSecret

from ..db import BotConfig, session_factory
from .crypto import decrypt_secret

logger = logging.getLogger("rwadmin.botx")


class DbBotAccountProvider:
    def __init__(self):
        self._accounts: list[BotAccountWithSecret] = []
        self.refresh()

    # --- обновить снапшот из БД ---
    def refresh(self) -> list[BotAccountWithSecret]:
        db = session_factory()
        try:
            cfg = db.get(BotConfig, 1)
        finally:
            db.close()
        accounts: list[BotAccountWithSecret] = []
        if cfg and cfg.enabled and cfg.cts_url and cfg.bot_id and cfg.secret_enc:
            secret = decrypt_secret(cfg.secret_enc)
            try:
                bot_id = UUID(cfg.bot_id)
            except ValueError:
                logger.warning("BotX bot_id не является корректным UUID: %r", cfg.bot_id)
            else:
                if secret:
                    accounts = [
                        BotAccountWithSecret(
                            id=bot_id,
                            cts_url=cfg.cts_url,
                            secret_key=secret,
                            revision=cfg.revision,
                        )
                    ]
                else:
                    logger.warning(
                        "Секрет bота зашифрован ключом, который больше не читается "
                        "(сменили SECRET_KEY?) — введите секрет заново в разделе «Бот»."
                    )
        self._accounts = accounts
        return accounts

    # --- протокол BotAccountProvider ---
    def get_account(self, key: BotAccountKey) -> BotAccountWithSecret:
        for acc in self._accounts:
            if acc.id == key.bot_id and (
                key.server_id in ("", acc.host) or key.server_id == acc.host
            ):
                return acc
        for acc in self._accounts:
            if acc.id == key.bot_id:
                return acc
        raise UnknownBotAccountError(key.bot_id)

    def get_account_by_bot_id(self, bot_id: UUID) -> BotAccountWithSecret:
        for acc in self._accounts:
            if acc.id == bot_id:
                return acc
        raise UnknownBotAccountError(bot_id)

    def resolve_incoming_account_key(
        self, *, bot_id: UUID, host: str | None
    ) -> BotAccountKey:
        server_id = host or ""
        if not server_id:
            try:
                server_id = self.get_account_by_bot_id(bot_id).host
            except UnknownBotAccountError:
                server_id = ""
        return BotAccountKey(server_id=server_id, bot_id=bot_id)

    def iter_bot_accounts(self):
        yield from self._accounts

    # --- помощь для UI ---
    @property
    def configured(self) -> bool:
        return bool(self._accounts)
