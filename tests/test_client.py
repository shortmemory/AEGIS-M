import unittest

from aegism.client import RelayClient, _load_json_with_duplicate_check, chat_endpoint, models_endpoint


class EndpointTests(unittest.TestCase):
    def test_plain_base(self):
        self.assertEqual(chat_endpoint("https://relay.example"), "https://relay.example/v1/chat/completions")

    def test_v1_base(self):
        self.assertEqual(chat_endpoint("https://relay.example/v1/"), "https://relay.example/v1/chat/completions")

    def test_full_endpoint(self):
        url = "https://relay.example/custom/v1/chat/completions"
        self.assertEqual(chat_endpoint(url), url)
        self.assertEqual(models_endpoint(url), "https://relay.example/custom/v1/models")

    def test_rejects_non_http_url(self):
        with self.assertRaises(ValueError):
            chat_endpoint("relay.example")

    def test_rejects_remote_plaintext_http_by_default(self):
        with self.assertRaises(ValueError):
            RelayClient("http://relay.example", "secret")

    def test_allows_loopback_http(self):
        client = RelayClient("http://127.0.0.1:8000", "secret")
        self.assertEqual(client.base_url, "http://127.0.0.1:8000")

    def test_explicitly_allows_remote_http_for_audit(self):
        client = RelayClient("http://relay.example", "secret", allow_insecure_http=True)
        self.assertTrue(client.allow_insecure_http)

    def test_duplicate_response_keys_are_preserved_as_finding_metadata(self):
        body, duplicates = _load_json_with_duplicate_check(b'{"model":"a","model":"b","choices":[]}')
        self.assertEqual(body["model"], "b")
        self.assertEqual(duplicates, ["model"])


if __name__ == "__main__":
    unittest.main()
