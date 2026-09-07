from __future__ import annotations

import secrets
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Callable

from .analyzer import analyze
from .client import RelayClient, RelayError
from .models import Finding, ProbeResult
from .probes import Probe, build_probes, sha256_json


SEVERITY_SCORE = {"info": 0, "low": 1, "medium": 4, "high": 8, "critical": 15}


def _safe_target_url(value: str) -> str:
    """Avoid persisting URL credentials, query tokens, or fragments in reports."""
    parsed = urllib.parse.urlsplit(value)
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    if parsed.port:
        netloc += f":{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def run_scan(
    client: RelayClient,
    model: str,
    *,
    on_progress: Callable[[int, int, Probe], None] | None = None,
) -> dict[str, Any]:
    probes = build_probes(model)
    results: list[ProbeResult] = []
    total = len(probes) + 2
    if on_progress:
        transport_probe = Probe("transport_security", "transport", "传输层安全", {}, {})
        on_progress(1, total, transport_probe)
    results.append(_transport_probe(client))
    if on_progress:
        auth_probe = Probe("authentication_enforcement", "access_control", "无效密钥鉴权", {}, {})
        on_progress(2, total, auth_probe)
    results.append(_authentication_probe(client, model))
    for index, probe in enumerate(probes, start=3):
        if on_progress:
            on_progress(index, total, probe)
        request_hash = sha256_json(probe.payload)
        try:
            response = client.complete(probe.payload)
            status, findings, excerpt = analyze(probe, response.body)
            if response.duplicate_json_keys:
                findings.append(
                    Finding(
                        "critical",
                        "duplicate_response_json_keys",
                        "响应 JSON 包含重复键",
                        "中转站响应的重复键会让不同解析器读取不同值，可用于隐藏模型、候选项或工具载荷。",
                        {"duplicate_keys": sorted(set(response.duplicate_json_keys))},
                    )
                )
                status = "fail"
            result = ProbeResult(
                probe_id=probe.probe_id,
                category=probe.category,
                title=probe.title,
                status=status,
                request_sha256=request_hash,
                response_sha256=sha256_json(response.body),
                latency_ms=response.latency_ms,
                findings=findings,
                response_excerpt=excerpt,
            )
        except Exception as exc:  # Each probe remains visible even if the relay rejects one capability.
            message = str(exc)
            transport_failure = any(token in message.lower() for token in ("certificate", "ssl", "tls", "重定向"))
            model_unavailable = "model_not_found" in message.lower() or "no available channel for model" in message.lower()
            result = ProbeResult(
                probe_id=probe.probe_id,
                category=probe.category,
                title=probe.title,
                status="error",
                request_sha256=request_hash,
                findings=[
                    Finding(
                        "high" if transport_failure else "medium",
                        "transport_validation_failure" if transport_failure else "model_unavailable" if model_unavailable else "probe_error",
                        "TLS/重定向安全校验失败" if transport_failure else "模型或渠道不可用" if model_unavailable else "探针执行失败",
                        message,
                    )
                ],
                error=message,
            )
        results.append(result)
    all_findings = [finding for result in results for finding in result.findings]
    security_findings = [finding for result in results if result.status == "fail" for finding in result.findings]
    # Repeated model-wide anomalies should increase confidence, not multiply the score without bound.
    unique_scores: dict[str, int] = {}
    for item in security_findings:
        unique_scores[item.code] = max(unique_scores.get(item.code, 0), SEVERITY_SCORE.get(item.severity, 0))
    score = min(100, sum(unique_scores.values()))
    highest = max((item.severity for item in security_findings), key=lambda x: SEVERITY_SCORE.get(x, 0), default="info")
    passed = sum(item.status == "pass" for item in results)
    failed = sum(item.status == "fail" for item in results)
    errors = sum(item.status == "error" for item in results)
    verdict = "pass"
    if highest in {"high", "critical"}:
        verdict = "unsafe"
    elif failed:
        verdict = "suspicious"
    elif errors:
        verdict = "inconclusive"
    return {
        "schema_version": "1.0",
        "tool": "AEGIS-M",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {"base_url": _safe_target_url(client.base_url), "model": model, "api_key": "[REDACTED]"},
        "summary": {
            "verdict": verdict,
            "risk_score": score,
            "highest_severity": highest,
            "probe_count": len(results),
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "coverage_percent": round((passed + failed) / len(results) * 100),
        },
        "results": [result.to_dict() for result in results],
        "limitations": [
            "黑盒探针无法证明中转站没有只针对特定用户、时间或内容触发的条件式攻击。",
            "提示词偏离也可能来自模型自身的不确定性；critical 级随机标记命中具有更高置信度。",
            "工具调用仅被解析和检查，从未执行。",
        ],
    }


def _transport_probe(client: RelayClient) -> ProbeResult:
    parsed = urllib.parse.urlsplit(client.base_url)
    scheme = parsed.scheme.lower()
    request_hash = sha256_json({"base_url": _safe_target_url(client.base_url)})
    if scheme == "https":
        return ProbeResult(
            probe_id="transport_security",
            category="transport",
            title="传输层安全",
            status="pass",
            request_sha256=request_hash,
        )
    loopback = (parsed.hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}
    return ProbeResult(
        probe_id="transport_security",
        category="transport",
        title="传输层安全",
        status="fail",
        request_sha256=request_hash,
        findings=[
            Finding(
                "medium" if loopback else "critical",
                "plaintext_http",
                "API Key 与提示词使用明文 HTTP 传输",
                "网络路径上的第三方可读取或修改凭据、提示词和工具调用。仅回环地址开发环境可酌情接受。",
                {"scheme": scheme, "loopback": loopback},
            )
        ],
    )


def _authentication_probe(client: RelayClient, model: str) -> ProbeResult:
    invalid_key = "aegis-invalid-" + secrets.token_urlsafe(24)
    payload = {
        "model": model,
        "temperature": 0,
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "Authentication audit canary."}],
    }
    request_hash = sha256_json({**payload, "authorization": "[INTENTIONALLY_INVALID]"})
    try:
        response = client.complete_with_api_key(payload, invalid_key)
    except RelayError as exc:
        if exc.status_code in {401, 403}:
            return ProbeResult(
                probe_id="authentication_enforcement",
                category="access_control",
                title="无效密钥鉴权",
                status="pass",
                request_sha256=request_hash,
            )
        return ProbeResult(
            probe_id="authentication_enforcement",
            category="access_control",
            title="无效密钥鉴权",
            status="error",
            request_sha256=request_hash,
            findings=[Finding("medium", "auth_probe_error", "无法确认鉴权行为", str(exc))],
            error=str(exc),
        )
    except (AttributeError, NotImplementedError) as exc:
        # Keeps alternate/custom client implementations usable.
        return ProbeResult(
            probe_id="authentication_enforcement",
            category="access_control",
            title="无效密钥鉴权",
            status="error",
            request_sha256=request_hash,
            findings=[Finding("medium", "auth_probe_unsupported", "无法执行鉴权探针", str(exc))],
            error=str(exc),
        )
    error = response.body.get("error")
    auth_text = str(response.body.get("message", "")).lower()
    rejected = bool(error) or any(word in auth_text for word in ("unauthorized", "forbidden", "invalid key", "authentication"))
    if rejected:
        return ProbeResult(
            probe_id="authentication_enforcement",
            category="access_control",
            title="无效密钥鉴权",
            status="fail",
            request_sha256=request_hash,
            response_sha256=sha256_json(response.body),
            latency_ms=response.latency_ms,
            findings=[
                Finding(
                    "low",
                    "auth_rejected_with_http_200",
                    "鉴权拒绝使用了成功状态码",
                    "无效密钥看似被拒绝，但中转站以 HTTP 200 返回 error，可能误导重试与监控逻辑。",
                )
            ],
            response_excerpt=_bounded_excerpt(error or response.body.get("message")),
        )
    choices = response.body.get("choices")
    if not isinstance(choices, list) or not choices:
        return ProbeResult(
            probe_id="authentication_enforcement",
            category="access_control",
            title="无效密钥鉴权",
            status="fail",
            request_sha256=request_hash,
            response_sha256=sha256_json(response.body),
            latency_ms=response.latency_ms,
            findings=[
                Finding(
                    "medium",
                    "ambiguous_auth_http_200",
                    "无效密钥返回了无法判定的 HTTP 200",
                    "响应既不是标准鉴权拒绝，也不是有效 Chat Completions 成功结构，需要人工检查。",
                )
            ],
            response_excerpt=_bounded_excerpt(response.body),
        )
    return ProbeResult(
        probe_id="authentication_enforcement",
        category="access_control",
        title="无效密钥鉴权",
        status="fail",
        request_sha256=request_hash,
        response_sha256=sha256_json(response.body),
        latency_ms=response.latency_ms,
        findings=[
            Finding(
                "critical",
                "authentication_bypass",
                "无效 API Key 获得了成功响应",
                "使用随机无效密钥调用 Chat Completions 未被拒绝，可能允许未授权访问或盗用额度。",
            )
        ],
        response_excerpt=_bounded_excerpt(response.body),
    )


def _bounded_excerpt(value: Any, limit: int = 2000) -> Any:
    import json

    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return value if len(serialized) <= limit else serialized[:limit] + "…"
