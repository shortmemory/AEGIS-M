from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import datetime
from pathlib import Path

from .client import RelayClient, RelayError
from .report import write_html, write_json
from .scanner import run_scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-m",
        description="检测 OpenAI 兼容中转站的工具 JSON 注入与提示词篡改风险。",
    )
    parser.add_argument("--base-url", default=os.getenv("AEGIS_BASE_URL"), help="中转站地址，或设置 AEGIS_BASE_URL")
    parser.add_argument("--api-key", default=os.getenv("AEGIS_API_KEY"), help="API Key，或设置 AEGIS_API_KEY")
    parser.add_argument("--api-key-stdin", action="store_true", help="从隐藏输入读取 API Key，避免出现在命令历史中")
    parser.add_argument("--model", default=os.getenv("AEGIS_MODEL"), help="模型 ID；省略时读取 /v1/models 自动选择")
    parser.add_argument("--timeout", type=float, default=45.0, help="单次请求超时秒数（默认 45）")
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="允许向非本机 HTTP 地址发送密钥（危险，仅限已授权测试）",
    )
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=2 * 1024 * 1024,
        help="单个响应最大字节数（默认 2097152）",
    )
    parser.add_argument("--output-dir", default="reports", help="报告输出目录（默认 reports）")
    parser.add_argument("--list-models", action="store_true", help="只列出中转站模型，不执行探针")
    parser.add_argument("--web", action="store_true", help="启动仅监听本机的网页控制台")
    parser.add_argument("--web-port", type=int, default=8765, help="网页控制台端口（默认 8765）")
    return parser


def _pick_model(models: list[str]) -> str:
    unsuitable = ("embed", "tts", "whisper", "audio", "image", "dall-e", "rerank")
    candidates = [model for model in models if not any(word in model.lower() for word in unsuitable)]
    if not candidates:
        raise RelayError("未发现可用于 chat completions 的模型，请显式传入 --model")
    return candidates[0]


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.web:
        from .web import serve

        return serve(port=args.web_port)
    if args.api_key_stdin:
        args.api_key = getpass.getpass("API Key: ")
    if not args.base_url or not args.api_key:
        print("错误：需要 --base-url 与 --api-key（也可使用 AEGIS_BASE_URL / AEGIS_API_KEY）。", file=sys.stderr)
        return 2
    try:
        client = RelayClient(
            args.base_url,
            args.api_key,
            timeout=args.timeout,
            allow_insecure_http=args.allow_insecure_http,
            max_response_bytes=args.max_response_bytes,
        )
        if args.list_models:
            for model in client.list_models():
                print(model)
            return 0
        model = args.model or _pick_model(client.list_models())
        print(f"目标: {args.base_url}  模型: {model}")
        report = run_scan(
            client,
            model,
            on_progress=lambda i, total, probe: print(f"[{i}/{total}] {probe.title}...", flush=True),
        )
    except (ValueError, RelayError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(args.output_dir).resolve()
    json_path = output_dir / f"aegis-report-{stamp}.json"
    html_path = output_dir / f"aegis-report-{stamp}.html"
    write_json(report, json_path)
    write_html(report, html_path)
    summary = report["summary"]
    print(f"\n结论: {summary['verdict'].upper()}  风险分: {summary['risk_score']}/100")
    print(f"通过 {summary['passed']} / 失败 {summary['failed']} / 错误 {summary['errors']}")
    print(f"JSON: {json_path}\nHTML: {html_path}")
    return 1 if summary["verdict"] != "pass" else 0


if __name__ == "__main__":
    raise SystemExit(main())
