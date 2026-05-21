#!/usr/bin/env python3
"""
Small local API target for audit/run_all.sh.

This is not the production API. It exists so the load-test harness itself
executes in offline CI and local audit runs instead of being skipped when a
staging API URL is absent. Production load testing still points
`audit/load_tests/api_load.py` at HELIXOR_API_URL for the full 1-hour run.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib handler API
        if self.path == "/health":
            self._json({"ok": True})
            return
        if self.path.startswith("/score/") or (
            self.path.startswith("/agents/") and self.path.endswith("/health")
        ):
            agent = self.path.strip("/").split("/")[1]
            self._json({
                "agent_wallet": agent,
                "score": 900,
                "alert_tier": "green",
                "flags": 0,
                "immediate_red": False,
            })
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, _fmt, *_args):
        return

    def _json(self, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 18081), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
