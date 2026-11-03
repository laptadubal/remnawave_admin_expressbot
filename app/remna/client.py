"""Клиент API панели Remnawave (v2, NestJS).

Базовые маршруты проверялись на живой панели (все отвечают 401 без токена):
GET  /api/auth/status, GET /api/nodes, GET /api/users, GET /api/hosts,
GET  /api/subscriptions, GET /api/bandwidth-stats/nodes, GET /api/keygen.

Ответы версии 2 обёрнуты в {"response": ...} — клиент снимает обёртку.
Ошибки панели приходят как {"message": ..., "errorCode": ...}.
"""
from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import quote

import httpx

from ..config import Settings, get_settings

logger = logging.getLogger("rwadmin.remna")


class RemnaError(Exception):
    def __init__(self, message: str, status_code: int | None = None, path: str = ""):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.path = path


class RemnaNotConfigured(RemnaError):
    def __init__(self):
        super().__init__("Панель Remnawave не настроена (REMNAWAVE_BASE_URL пустой)")


class RemnaAuthError(RemnaError):
    pass


def _extract_token(data: Any) -> str | None:
    """Найти accessToken в ответе логина (обёртки/варианты имён)."""
    if isinstance(data, dict):
        for key in ("accessToken", "access_token"):
            if isinstance(data.get(key), str):
                return data[key]
        inner = data.get("response")
        if inner is not None:
            found = _extract_token(inner)
            if found:
                return found
    return None


class RemnawaveClient:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()
        self._http: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._token_exp: float = 0.0
        self._retried = False

    # ---------- инфраструктура ----------
    @property
    def configured(self) -> bool:
        return bool(self.s.remnawave_base_url)

    @property
    def base_url(self) -> str:
        return (self.s.remnawave_base_url or "").rstrip("/")

    def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.s.remnawave_timeout),
                follow_redirects=False,
                headers={"User-Agent": "remnawave-admin/1.0"},
            )
        return self._http

    async def _ensure_token(self) -> str:
        static = self.s.remnawave_api_token
        if static:
            return static
        if self._token and time.time() < self._token_exp:
            return self._token
        if not (self.s.remnawave_username and self.s.remnawave_password):
            raise RemnaAuthError(
                "Не заданы ни API-токен (REMNAWAVE_API_TOKEN), "
                "ни логин/пароль панели (REMNAWAVE_USERNAME/PASSWORD)"
            )
        client = self._client()
        resp = await client.post(
            "/api/auth/login",
            json={
                "username": self.s.remnawave_username,
                "password": self.s.remnawave_password,
            },
        )
        if resp.status_code >= 400:
            raise RemnaAuthError(
                f"Логин в панель Remnawave не удался (HTTP {resp.status_code}): "
                f"{resp.text[:200]}"
            )
        token = _extract_token(resp.json() if resp.content else None)
        if not token:
            raise RemnaAuthError(
                "Панель не вернула accessToken при логине: "
                f"{resp.text[:200]}"
            )
        self._token = token
        # держим токен 50 минут (у панели он живёт дольше; перелогин дешёвый)
        self._token_exp = time.time() + 50 * 60
        logger.info("Remnawave login ok (username=%s)", self.s.remnawave_username)
        return self._token

    def _invalidate_token(self) -> None:
        self._token = None
        self._token_exp = 0.0

    @staticmethod
    def _unwrap(data: Any) -> Any:
        if isinstance(data, dict) and "response" in data and len(data) <= 3:
            return data["response"]
        return data

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> Any:
        if not self.configured:
            raise RemnaNotConfigured()
        started = time.perf_counter()
        client = self._client()
        token = await self._ensure_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.request(method, path, params=params, json=json_body, headers=headers)
        dur_ms = int((time.perf_counter() - started) * 1000)
        logger.debug(
            "remna %s %s -> %s (%d ms)", method, path, resp.status_code, dur_ms
        )

        if resp.status_code == 401 and not self._retried and self._token:
            # сессионный токен истёк — перелогин и один повтор
            self._retried = True
            self._invalidate_token()
            try:
                token = await self._ensure_token()
                headers = {"Authorization": f"Bearer {token}"}
                resp = await client.request(method, path, params=params, json=json_body, headers=headers)
            finally:
                self._retried = False

        if resp.status_code >= 400:
            try:
                body = resp.json()
                msg = body.get("message") or body.get("detail") or resp.text[:200]
            except Exception:  # noqa: BLE001
                msg = resp.text[:200]
            if resp.status_code == 401:
                raise RemnaAuthError(f"Панель отклонила токен (401): {msg}")
            raise RemnaError(f"HTTP {resp.status_code}: {msg}", resp.status_code, path)

        if not resp.content:
            return None
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            return resp.text
        return self._unwrap(data)

    # ---------- авторизация / система ----------
    async def auth_status(self) -> Any:
        return await self._request("GET", "/api/auth/status")

    async def system_info(self) -> Any:
        return await self._request("GET", "/api/system")

    # ---------- ноды ----------
    async def nodes(self) -> Any:
        return await self._request("GET", "/api/nodes")

    async def node(self, node_uuid: str) -> Any:
        return await self._request("GET", f"/api/nodes/{quote(node_uuid)}")

    async def node_action(self, node_uuid: str, action: str, body: dict | None = None) -> Any:
        if action not in ("enable", "disable", "restart", "reset-traffic"):
            raise ValueError(f"Неизвестное действие ноды: {action}")
        return await self._request(
            "POST", f"/api/nodes/{quote(node_uuid)}/actions/{action}", json_body=body or {}
        )

    async def update_node(self, node_uuid: str, body: dict) -> Any:
        return await self._request("PUT", f"/api/nodes/{quote(node_uuid)}", json_body=body)

    # ---------- пользователи ----------
    async def users(self, start: int = 0, size: int = 50) -> Any:
        return await self._request(
            "GET", "/api/users", params={"start": start, "size": size}
        )

    async def user(self, user_uuid: str) -> Any:
        return await self._request("GET", f"/api/users/{quote(user_uuid)}")

    async def user_by_username(self, username: str) -> Any:
        return await self._request("GET", f"/api/users/by-username/{quote(username)}")

    async def create_user(self, body: dict) -> Any:
        return await self._request("POST", "/api/users", json_body=body)

    async def update_user(self, user_uuid: str, body: dict) -> Any:
        merged = dict(body)
        merged.setdefault("uuid", user_uuid)
        return await self._request("PUT", f"/api/users/{quote(user_uuid)}", json_body=merged)

    async def delete_user(self, user_uuid: str) -> Any:
        return await self._request("DELETE", f"/api/users/{quote(user_uuid)}")

    async def user_action(
        self, user_uuid: str, action: str, body: dict | None = None
    ) -> Any:
        allowed = ("enable", "disable", "reset-traffic", "revoke", "extend")
        if action not in allowed:
            raise ValueError(f"Неизвестное действие пользователя: {action}")
        return await self._request(
            "POST",
            f"/api/users/{quote(user_uuid)}/actions/{action}",
            json_body=body or {},
        )

    async def users_bulk(self, action: str, body: dict) -> Any:
        allowed = (
            "delete",
            "update",
            "reset-traffic",
            "revoke-subscription",
            "extend-expiration-date",
        )
        if action not in allowed:
            raise ValueError(f"Неизвестное batch-действие: {action}")
        return await self._request("POST", f"/api/users/bulk/{action}", json_body=body)

    # ---------- подписки ----------
    async def subscription(self, user_uuid: str) -> Any:
        try:
            return await self._request("GET", f"/api/subscriptions/by-uuid/{quote(user_uuid)}")
        except RemnaError as e:
            if e.status_code in (404, 405):
                return await self._request("GET", f"/api/subscriptions/{quote(user_uuid)}")
            raise

    # ---------- хосты ----------
    async def hosts(self) -> Any:
        return await self._request("GET", "/api/hosts")

    async def host(self, host_uuid: str) -> Any:
        return await self._request("GET", f"/api/hosts/{quote(host_uuid)}")

    async def create_host(self, body: dict) -> Any:
        return await self._request("POST", "/api/hosts", json_body=body)

    async def update_host(self, host_uuid: str, body: dict) -> Any:
        merged = dict(body)
        merged.setdefault("uuid", host_uuid)
        return await self._request("PUT", f"/api/hosts/{quote(host_uuid)}", json_body=merged)

    async def delete_host(self, host_uuid: str) -> Any:
        return await self._request("DELETE", f"/api/hosts/{quote(host_uuid)}")

    # ---------- профили конфигов ----------
    async def profiles(self) -> Any:
        return await self._request("GET", "/api/config-profiles")

    async def profile(self, profile_uuid: str) -> Any:
        return await self._request("GET", f"/api/config-profiles/{quote(profile_uuid)}")

    async def create_profile(self, body: dict) -> Any:
        return await self._request("POST", "/api/config-profiles", json_body=body)

    async def update_profile(self, profile_uuid: str, body: dict) -> Any:
        merged = dict(body)
        merged.setdefault("uuid", profile_uuid)
        return await self._request(
            "PUT", f"/api/config-profiles/{quote(profile_uuid)}", json_body=merged
        )

    # ---------- генерация ключей ----------
    async def keygen(self, key_type: str = "x25519") -> Any:
        try:
            return await self._request("GET", "/api/keygen", params={"type": key_type})
        except RemnaError as e:
            if e.status_code in (404, 405):
                return await self._request("POST", "/api/keygen", json_body={"type": key_type})
            raise

    # ---------- статистика ----------
    async def bandwidth_nodes(self) -> Any:
        return await self._request("GET", "/api/bandwidth-stats/nodes")

    async def bandwidth_users(self) -> Any:
        return await self._request("GET", "/api/bandwidth-stats/users")

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()
