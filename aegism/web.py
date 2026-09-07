from __future__ import annotations

import argparse
import json
import mimetypes
import secrets
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any
from urllib.parse import urlsplit

from .client import RelayClient, RelayError
from .scanner import run_scan


MAX_REQUEST_BYTES = 32 * 1024
MAX_JOBS = 20


@dataclass
class ScanJob:
    job_id: str
    state: str = "queued"
    progress: int = 0
    total: int = 9
    current: str = "等待开始"
    created_at: float = field(default_factory=time.time)
    report: dict[str, Any] | None = None
    error: str | None = None

    def public(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "job_id": self.job_id,
            "state": self.state,
            "progress": self.progress,
            "total": self.total,
            "current": self.current,
            "error": self.error,
        }
        if self.report is not None:
            result["report"] = self.report
        return result


class WebApplication:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.token = secrets.token_urlsafe(32)
        self.jobs: dict[str, ScanJob] = {}
        self.lock = threading.Lock()
        self.active = threading.BoundedSemaphore(3)

    def handler(self) -> type[BaseHTTPRequestHandler]:
        application = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "AEGIS-M-Web/0.1"

            def log_message(self, format: str, *args: Any) -> None:
                print(f"[{self.log_date_time_string()}] {format % args}")

            def do_GET(self) -> None:
                path = urlsplit(self.path).path
                if path == "/":
                    raw = application.asset("index.html").decode("utf-8")
                    raw = raw.replace("__AEGIS_SESSION_TOKEN__", application.token)
                    self._send_bytes(raw.encode("utf-8"), "text/html; charset=utf-8")
                    return
                if path in {"/app.js", "/styles.css"}:
                    self._send_bytes(application.asset(path[1:]), mimetypes.guess_type(path)[0] or "application/octet-stream")
                    return
                if path == "/api/health":
                    self._send_json({"status": "ok", "service": "AEGIS-M"})
                    return
                if path.startswith("/api/scans/"):
                    parts = path.strip("/").split("/")
                    if len(parts) not in {3, 4}:
                        self._send_error_json(HTTPStatus.NOT_FOUND, "资源不存在")
                        return
                    if not self._authorized():
                        return
                    job = application.get_job(parts[2])
                    if job is None:
                        self._send_error_json(HTTPStatus.NOT_FOUND, "扫描任务不存在或已过期")
                        return
                    if len(parts) == 4 and parts[3] == "report.json":
                        if job.report is None:
                            self._send_error_json(HTTPStatus.CONFLICT, "报告尚未生成")
                            return
                        body = json.dumps(job.report, ensure_ascii=False, indent=2).encode("utf-8")
                        self._send_bytes(
                            body,
                            "application/json; charset=utf-8",
                            {"Content-Disposition": f'attachment; filename="aegis-report-{job.job_id}.json"'},
                        )
                        return
                    self._send_json(job.public())
                    return
                self._send_error_json(HTTPStatus.NOT_FOUND, "资源不存在")

            def do_POST(self) -> None:
                path = urlsplit(self.path).path
                if not self._authorized():
                    return
                try:
                    payload = self._read_json()
                except ValueError as exc:
                    self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                    return
                if path == "/api/models":
                    try:
                        client = application.client_from(payload)
                        models = client.list_models()
                    except (ValueError, RelayError) as exc:
                        self._send_error_json(HTTPStatus.BAD_GATEWAY, str(exc))
                        return
                    self._send_json({"models": models})
                    return
                if path == "/api/scans":
                    try:
                        client = application.client_from(payload)
                    except ValueError as exc:
                        self._send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                        return
                    if not application.active.acquire(blocking=False):
                        self._send_error_json(HTTPStatus.TOO_MANY_REQUESTS, "已有 3 个扫描正在运行，请稍后再试")
                        return
                    job = application.create_job()
                    model = str(payload.get("model", "")).strip()
                    thread = threading.Thread(
                        target=application.run_job,
                        args=(job.job_id, client, model),
                        name=f"aegis-scan-{job.job_id}",
                        daemon=True,
                    )
                    thread.start()
                    self._send_json(job.public(), status=HTTPStatus.ACCEPTED)
                    return
                self._send_error_json(HTTPStatus.NOT_FOUND, "资源不存在")

            def _authorized(self) -> bool:
                supplied = self.headers.get("X-Aegis-Token", "")
                origin = self.headers.get("Origin")
                allowed_origins = {
                    f"http://127.0.0.1:{application.port}",
                    f"http://localhost:{application.port}",
                }
                if origin and origin not in allowed_origins:
                    self._send_error_json(HTTPStatus.FORBIDDEN, "拒绝跨源请求")
                    return False
                if not secrets.compare_digest(supplied, application.token):
                    self._send_error_json(HTTPStatus.FORBIDDEN, "会话令牌无效")
                    return False
                return True

            def _read_json(self) -> dict[str, Any]:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError as exc:
                    raise ValueError("Content-Length 无效") from exc
                if length <= 0 or length > MAX_REQUEST_BYTES:
                    raise ValueError(f"请求体必须在 1 到 {MAX_REQUEST_BYTES} 字节之间")
                try:
                    value = json.loads(self.rfile.read(length))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise ValueError("请求体不是合法 JSON") from exc
                if not isinstance(value, dict):
                    raise ValueError("JSON 顶层必须是对象")
                return value

            def _send_json(self, value: Any, status: int = HTTPStatus.OK) -> None:
                self._send_bytes(
                    json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                    "application/json; charset=utf-8",
                    status=status,
                )

            def _send_error_json(self, status: int, message: str) -> None:
                self._send_json({"error": message}, status=status)

            def _send_bytes(
                self,
                body: bytes,
                content_type: str,
                extra_headers: dict[str, str] | None = None,
                *,
                status: int = HTTPStatus.OK,
            ) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                )
                for key, value in (extra_headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

        return Handler

    @staticmethod
    def asset(name: str) -> bytes:
        return files("aegism.webui").joinpath(name).read_bytes()

    @staticmethod
    def client_from(payload: dict[str, Any]) -> RelayClient:
        base_url = str(payload.get("base_url", "")).strip()
        api_key = str(payload.get("api_key", "")).strip()
        timeout = payload.get("timeout", 45)
        if not base_url or not api_key:
            raise ValueError("中转站地址和 API Key 都不能为空")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 3 <= timeout <= 180:
            raise ValueError("超时时间必须在 3 到 180 秒之间")
        return RelayClient(
            base_url,
            api_key,
            timeout=float(timeout),
            allow_insecure_http=payload.get("allow_insecure_http") is True,
        )

    def create_job(self) -> ScanJob:
        with self.lock:
            completed = sorted(
                (job for job in self.jobs.values() if job.state in {"complete", "failed"}),
                key=lambda job: job.created_at,
            )
            while len(self.jobs) >= MAX_JOBS and completed:
                old = completed.pop(0)
                self.jobs.pop(old.job_id, None)
            job = ScanJob(job_id=secrets.token_urlsafe(12))
            self.jobs[job.job_id] = job
            return job

    def get_job(self, job_id: str) -> ScanJob | None:
        with self.lock:
            return self.jobs.get(job_id)

    def run_job(self, job_id: str, client: RelayClient, model: str) -> None:
        try:
            with self.lock:
                job = self.jobs[job_id]
                job.state = "running"
                job.current = "准备扫描"
            if not model:
                self.update_job(job_id, 0, 9, "正在获取模型列表")
                models = client.list_models()
                model = self.pick_model(models)

            def progress(index: int, total: int, probe: Any) -> None:
                self.update_job(job_id, index - 1, total, probe.title)

            report = run_scan(client, model, on_progress=progress)
            with self.lock:
                job = self.jobs[job_id]
                job.report = report
                job.progress = job.total
                job.current = "扫描完成"
                job.state = "complete"
        except Exception as exc:
            message = str(exc).replace(client.api_key, "[REDACTED]")
            with self.lock:
                job = self.jobs[job_id]
                job.error = message
                job.current = "扫描失败"
                job.state = "failed"
        finally:
            self.active.release()

    def update_job(self, job_id: str, progress: int, total: int, current: str) -> None:
        with self.lock:
            job = self.jobs[job_id]
            job.progress = progress
            job.total = total
            job.current = current

    @staticmethod
    def pick_model(models: list[str]) -> str:
        unsuitable = ("embed", "tts", "whisper", "audio", "image", "dall-e", "rerank")
        candidates = [model for model in models if not any(word in model.lower() for word in unsuitable)]
        if not candidates:
            raise RelayError("没有发现可用于 Chat Completions 的模型，请手动填写模型 ID")
        return candidates[0]


def serve(host: str = "127.0.0.1", port: int = 8765) -> int:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Web 控制台仅允许监听回环地址")
    if not 1 <= port <= 65535:
        raise ValueError("端口必须在 1 到 65535 之间")
    application = WebApplication(host, port)
    server = ThreadingHTTPServer((host, port), application.handler())
    print(f"AEGIS-M Web 控制台已启动：http://{host}:{port}")
    print("仅监听本机。按 Ctrl+C 停止。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止 Web 控制台…")
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动 AEGIS-M 本机网页控制台")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    return serve(port=args.port)


if __name__ == "__main__":
    raise SystemExit(main())

