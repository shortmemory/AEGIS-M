import json
import tempfile
import unittest
from pathlib import Path

from aegism.report import write_html, write_json


class ReportTests(unittest.TestCase):
    def test_reports_escape_untrusted_output(self):
        report = {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "target": {"base_url": "https://relay.example", "model": "test-model"},
            "summary": {"verdict": "unsafe", "risk_score": 15},
            "results": [{
                "title": "probe <script>", "status": "fail", "latency_ms": 1,
                "findings": [{"severity": "critical", "title": "bad", "detail": "<script>alert(1)</script>"}],
                "response_excerpt": "</pre><script>alert(2)</script>",
            }],
            "limitations": ["test"],
        }
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            html_path = Path(directory) / "report.html"
            write_json(report, json_path)
            write_html(report, html_path)
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["summary"]["verdict"], "unsafe")
            document = html_path.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert", document)
            self.assertIn("&lt;script&gt;alert", document)


if __name__ == "__main__":
    unittest.main()
