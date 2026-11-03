"""Flash-сообщения через httpOnly-куку (один показ, затем удаление).

Значение percent-encode'ится: Starlette кодирует куки в latin-1, а тексты
сообщений — на русском.
"""
from __future__ import annotations

import json
from urllib.parse import quote, unquote

from fastapi import Request
from fastapi.responses import RedirectResponse

FLASH_COOKIE = "rw_flash"


def flash_redirect(redirect_to: str, kind: str, text: str) -> RedirectResponse:
    payload = quote(json.dumps({"k": kind, "t": text}, ensure_ascii=False), safe="")
    r = RedirectResponse(redirect_to, status_code=302)
    r.set_cookie(
        FLASH_COOKIE,
        payload,
        max_age=60,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return r


def pop_flash(request: Request) -> dict | None:
    raw = request.cookies.get(FLASH_COOKIE)
    if not raw:
        return None
    try:
        data = json.loads(unquote(raw))
        if isinstance(data, dict) and "k" in data and "t" in data:
            return data
    except Exception:  # noqa: BLE001
        pass
    return None


def delete_flash_cookie(response) -> None:
    response.delete_cookie(FLASH_COOKIE, path="/")
