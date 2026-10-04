"""Local demo UI (standard library only, bound to 127.0.0.1).

    python -m safety_gate.ui      # then open http://127.0.0.1:8765
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .gate import redact
from .pipeline import run_scenario
from .scenarios import LAYERS, SCENARIOS

HOST, PORT = "127.0.0.1", 8765
PAGE = Path(__file__).with_name("ui.html")


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path == "/":
            return self._send(200, "text/html; charset=utf-8", PAGE.read_bytes())
        if url.path == "/api/run":
            query = parse_qs(url.query)
            name = query.get("scenario", ["A"])[0]
            if name not in SCENARIOS:
                return self._send(400, "application/json", b'{"error": "unknown scenario"}')
            approve = query.get("approve", ["0"])[0] == "1"
            result = redact(run_scenario(name, approver=lambda action: approve))
            result["all_layers"] = LAYERS
            return self._send(200, "application/json", json.dumps(result, default=str).encode())
        self._send(404, "text/plain", b"not found")

    def log_message(self, *args) -> None:  # keep the console quiet
        pass


def main() -> None:
    print(f"Agent Safety Gate demo UI (MOCK mode): http://{HOST}:{PORT}  -  Ctrl+C to stop")
    try:
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
