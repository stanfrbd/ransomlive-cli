import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from ransomlive.api import APIError, get_json, make_client


@pytest.mark.skipif(
    shutil.which("openssl") is None, reason="OpenSSL is required for local TLS test"
)
def test_insecure_allows_only_explicitly_requested_untrusted_tls(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://127.0.0.1:{server.server_port}/"
    try:
        with make_client("test-key") as client:
            with pytest.raises(APIError, match="TLS certificate verification failed"):
                get_json(client, url, {})
        with make_client("test-key", verify=False) as client:
            assert get_json(client, url, {}) == {}
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
