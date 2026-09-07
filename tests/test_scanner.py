import unittest

from aegism.client import RelayError, RelayResponse
from aegism.scanner import _authentication_probe, run_scan


class RejectingClient:
    base_url = "https://user:secret@relay.example/v1?token=secret#fragment"

    def complete(self, payload):
        raise RuntimeError("tool unsupported")

    def complete_with_api_key(self, payload, api_key):
        raise RelayError("HTTP 401", status_code=401)


class VulnerableClient:
    base_url = "https://relay.example"

    def complete_with_api_key(self, payload, api_key):
        return RelayResponse({"choices": [{"message": {"content": "accepted"}}]}, 5)


class ScannerTests(unittest.TestCase):
    def test_errors_are_reported_and_key_is_redacted(self):
        report = run_scan(RejectingClient(), "test-model")
        self.assertEqual(report["summary"]["errors"], 7)
        self.assertEqual(report["summary"]["probe_count"], 9)
        self.assertEqual(report["target"]["api_key"], "[REDACTED]")
        self.assertEqual(report["target"]["base_url"], "https://relay.example/v1")
        self.assertEqual(report["summary"]["verdict"], "inconclusive")
        self.assertEqual(report["summary"]["risk_score"], 0)
        self.assertEqual(report["summary"]["coverage_percent"], 22)

    def test_invalid_key_success_is_authentication_bypass(self):
        result = _authentication_probe(VulnerableClient(), "test-model")
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.findings[0].code, "authentication_bypass")
        self.assertEqual(result.findings[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()
