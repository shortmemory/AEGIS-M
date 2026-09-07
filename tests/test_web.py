import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from aegism.web import WebApplication


class WebApplicationTests(unittest.TestCase):
    def test_assets_are_packaged(self):
        html = WebApplication.asset("index.html").decode("utf-8")
        self.assertIn("AEGIS-M", html)
        self.assertIn("__AEGIS_SESSION_TOKEN__", html)

    def test_client_config_rejects_missing_secret(self):
        with self.assertRaises(ValueError):
            WebApplication.client_from({"base_url": "https://relay.example"})

    def test_local_server_requires_session_token_for_api(self):
        app = WebApplication("127.0.0.1", 0)
        server = ThreadingHTTPServer(("127.0.0.1", 0), app.handler())
        app.port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{app.port}"
        try:
            with urllib.request.urlopen(base + "/", timeout=2) as response:
                page = response.read().decode("utf-8")
            self.assertIn(app.token, page)

            request = urllib.request.Request(
                base + "/api/models",
                data=json.dumps({"base_url": "https://relay.example", "api_key": "test"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=2)
            self.assertEqual(caught.exception.code, 403)
            caught.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
