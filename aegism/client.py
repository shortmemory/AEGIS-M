from __future__ import annotations

import ipaddress
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class RelayError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def chat_endpoint(base_url: str) -> str:
    value = base_url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url 必须是完整的 http(s) URL")
    if value.endswith("/chat/completions"):
        return value
    if value.endswith("/v1"):
        return value + "/chat/completions"
    return value + "/v1/chat/completions"


def models_endpoint(base_url: str) -> str:
    chat = chat_endpoint(base_url)
    return chat[: -len("chat/completions")] + "models"


@dataclass
class RelayResponse:
    body: dict[str, Any]
    latency_ms: int
    duplicate_json_keys: list[str] | None = None


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward an Authorization header to another origin or to plaintext."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (old.scheme.lower(), old.hostname, old.port) != (new.scheme.lower(), new.hostname, new.port):
            raise RelayError(f"拒绝携带凭据跨源重定向: {old.scheme}://{old.netloc} -> {new.scheme}://{new.netloc}")
        if old.scheme.lower() == "https" and new.scheme.lower() != "https":
            raise RelayError("拒绝将 HTTPS 请求降级重定向到明文 HTTP")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _load_json_with_duplicate_check(raw: bytes) -> tuple[Any, list[str]]:
    duplicates: list[str] = []

    def build_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=build_object), duplicates


class RelayClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 45.0,
        *,
        allow_insecure_http: bool = False,
        max_response_bytes: int = 2 * 1024 * 1024,
    ):
        if not api_key:
            raise ValueError("api_key 不能为空")
        chat_endpoint(base_url)  # Validate scheme and host before any credential is used.
        if max_response_bytes < 1024:
            raise ValueError("max_response_bytes 不能小于 1024")
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme == "http" and not allow_insecure_http and not _is_loopback(parsed.hostname):
            raise ValueError(
                "拒绝通过明文 HTTP 发送 API Key；请改用 HTTPS。仅在授权测试中可显式使用 --allow-insecure-http"
            )
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout
        self.allow_insecure_http = allow_insecure_http
        self.max_response_bytes = max_response_bytes
        self._ssl_context = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            _SafeRedirectHandler(),
            urllib.request.HTTPSHandler(context=self._ssl_context),
        )

    def _request(
        self,
        url: str,
        *,
        payload: dict[str, Any] | None = None,
        api_key: str | None = None,
    ) -> RelayResponse:
        data = None
        method = "GET"
        auth_key = self.api_key if api_key is None else api_key
        headers = {
            "Authorization": f"Bearer {auth_key}",
            "Accept": "application/json",
            "User-Agent": "AEGIS-M/0.1",
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
            method = "POST"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        started = time.perf_counter()
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            raw = exc.read(4096).decode("utf-8", "replace")
            safe_raw = raw.replace(self.api_key, "[REDACTED]").replace(auth_key, "[REDACTED]")
            raise RelayError(f"HTTP {exc.code}: {safe_raw}", status_code=exc.code) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RelayError(f"连接失败: {exc}") from exc
        latency_ms = round((time.perf_counter() - started) * 1000)
        if len(raw) > self.max_response_bytes:
            raise RelayError(f"响应超过安全上限 {self.max_response_bytes} 字节，已中止读取")
        try:
            body, duplicate_keys = _load_json_with_duplicate_check(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RelayError(f"中转站返回了非 JSON 数据: {raw[:300]!r}") from exc
        if not isinstance(body, dict):
            raise RelayError("中转站返回的 JSON 顶层不是对象")
        return RelayResponse(body=body, latency_ms=latency_ms, duplicate_json_keys=duplicate_keys)

    def list_models(self) -> list[str]:
        response = self._request(models_endpoint(self.base_url)).body
        data = response.get("data")
        if not isinstance(data, list):
            raise RelayError("模型列表响应缺少 data 数组")
        return [item["id"] for item in data if isinstance(item, dict) and isinstance(item.get("id"), str)]

    def complete(self, payload: dict[str, Any]) -> RelayResponse:
        return self._request(chat_endpoint(self.base_url), payload=payload)

    def complete_with_api_key(self, payload: dict[str, Any], api_key: str) -> RelayResponse:
        """Send one probe with a deliberately invalid key; neither key is persisted."""
        return self._request(chat_endpoint(self.base_url), payload=payload, api_key=api_key)


def _is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
