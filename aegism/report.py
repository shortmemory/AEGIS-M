from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def write_json(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def write_html(report: dict[str, Any], path: Path) -> None:
    summary = report["summary"]
    cards: list[str] = []
    for result in report["results"]:
        finding_html = "".join(
            f'<li class="sev-{html.escape(f["severity"])}"><b>{html.escape(f["severity"].upper())}</b> '
            f'{html.escape(f["title"])} — {html.escape(f["detail"])}</li>'
            for f in result["findings"]
        ) or "<li>未发现偏差</li>"
        cards.append(
            f'<section><h2>{html.escape(result["title"])}</h2>'
            f'<p><span class="badge {html.escape(result["status"])}">{html.escape(result["status"])}</span> '
            f'延迟 {html.escape(str(result.get("latency_ms") or "-"))} ms</p><ul>{finding_html}</ul>'
            f'<details><summary>受限响应证据</summary><pre>{html.escape(json.dumps(result.get("response_excerpt"), ensure_ascii=False, indent=2))}</pre></details></section>'
        )
    document = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS-M 安全审计报告</title><style>
body{{font:15px/1.6 system-ui,sans-serif;max-width:980px;margin:40px auto;padding:0 20px;background:#f6f7fb;color:#18202a}}
header,section{{background:white;border:1px solid #dde2ea;border-radius:12px;padding:20px;margin:16px 0;box-shadow:0 2px 8px #0000000a}}
h1,h2{{margin-top:0}} .badge{{padding:3px 9px;border-radius:999px;background:#e8edf4}} .pass{{background:#d8f5e5}} .fail{{background:#ffe1df}} .error{{background:#fff0c7}}
.sev-critical,.sev-high{{color:#a31515}} .sev-medium{{color:#8a5b00}} pre{{white-space:pre-wrap;word-break:break-word;background:#111827;color:#e5e7eb;padding:12px;border-radius:8px;max-height:360px;overflow:auto}}
</style></head><body><header><h1>AEGIS-M 中转站安全审计</h1>
<p>结论：<b>{html.escape(summary["verdict"].upper())}</b>　风险分：{summary["risk_score"]}/100　模型：{html.escape(report["target"]["model"])}</p>
<p>目标：{html.escape(report["target"]["base_url"])}　生成时间：{html.escape(report["generated_at"])}</p></header>
{''.join(cards)}
<section><h2>解释边界</h2><ul>{''.join(f'<li>{html.escape(x)}</li>' for x in report['limitations'])}</ul></section>
</body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")

