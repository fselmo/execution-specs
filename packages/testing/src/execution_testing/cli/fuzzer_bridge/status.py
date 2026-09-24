"""
A read-only status page over a running campaign's state files.

The page is meant to be read on a phone over a private network, so it is
built to be harmless if something on that network is hostile, or if the
text it shows is: findings carry client error strings from processes fed
generated input.

- It binds loopback only, with no way to bind anything else; reaching it
  from elsewhere is the network's job (a proxy), not this server's.
- It answers GET for exactly two paths, the page and its JSON, and 405
  for every other method. It serves no files: a bundle's path is shown
  as text.
- The JSON is a projection of the state and manifest the campaign writes,
  with environment values redacted outside `run_manifest.ENV_ALLOWLIST`
  (again: the manifest is already redacted on disk), and `<`
  escaped so no string in it can form a tag.
- The page loads nothing external. Its one inline script and style run
  under a per-response nonce the Content-Security-Policy names, and it
  writes campaign text with `textContent` only.
"""

import html
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional
from urllib.parse import urlsplit

from .run_manifest import redacted_env

HOST = "127.0.0.1"
"""Loopback only; deliberately not configurable."""


COUNTS_SHOWN = (
    "agreed",
    "divergence",
    "all-fail",
    "all-rejected",
    "fill_error",
    "fill_timeout",
    "invariant_violation",
    "contrast-mismatch",
    "producer-disagreement",
    "escalated",
    "BAL-RETRY",
    "BAL-FALLBACK",
)


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def status_view(output: Path) -> Dict[str, Any]:
    """
    Everything the page shows, projected from the campaign's own files.

    Nothing here is derived that the campaign could have written; a field
    the page needs and the state lacks belongs in the campaign.
    """
    state = _read_json(output / "state.json")
    if state is None:
        return {
            "campaign": output.name,
            "status": "absent",
            "status_reason": f"no campaign state in {output}",
            "served_at": time.time(),
        }
    segment = state.get("segment", "")
    manifest = (
        _read_json(output / "segments" / f"{segment}.json")
        or _read_json(output / "manifest.json")
        or {}
    )
    return {
        "campaign": output.name,
        "served_at": time.time(),
        "status": state.get("status", "running"),
        "status_reason": state.get("status_reason", ""),
        "status_at": state.get("status_at", 0.0),
        "started": state.get("started"),
        "next_seed": state.get("next_seed"),
        "summary": state.get("summary", {}),
        "health": state.get("health", {}),
        "segment": {
            "id": segment,
            "fork": manifest.get("fork"),
            "generator_version": manifest.get("generator_version"),
            "eels_commit": manifest.get("eels_commit"),
            "fixture_format": manifest.get("fixture_format"),
            "clients": manifest.get("clients", {}),
            "sources": manifest.get("sources", {}),
            "binaries": manifest.get("binaries", {}),
            "client_env": redacted_env(manifest.get("client_env", {})),
        },
        "segments": [
            {k: s.get(k) for k in ("id", "first_seed", "last_seed")}
            for s in state.get("segments", [])
        ],
        "counts": {k: state.get("counts", {}).get(k, 0) for k in COUNTS_SHOWN},
        "clients": {
            name: {
                "failures": state.get("client_failures", {}).get(name, 0),
                "refused": state.get("rejections", {}).get(name, 0),
                "runner_errors": state.get("runner_errors", {}).get(name, 0),
            }
            for name in sorted(
                set(state.get("client_failures", {}))
                | set(state.get("rejections", {}))
                | set(state.get("runner_errors", {}))
                | set(manifest.get("clients", {}))
            )
        },
        "contrast": state.get("contrast", {}),
        "findings": [
            {
                "digest": digest,
                "client": entry.get("client"),
                "reason": entry.get("reason"),
                "count": entry.get("count", 0),
                "rate": entry.get("rate"),
                "first_seen": entry.get("first_seen"),
                "first_seed": entry.get("first_seed"),
                "first_segment": entry.get("first_segment"),
                "minimized": entry.get("minimized", False),
                "known": entry.get("known", False),
                "bundle": entry.get("bundle"),
            }
            for digest, entry in sorted(
                state.get("signatures", {}).items(),
                key=lambda item: -item[1].get("count", 0),
            )
        ],
    }


def encode_view(view: Mapping[str, Any]) -> bytes:
    """JSON with `<`, `>` and `&` escaped, so no string can form a tag."""
    text = json.dumps(view)
    for char, escape in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026")):
        text = text.replace(char, escape)
    return text.encode()


def _page(nonce: str) -> bytes:
    template = (
        resources.files(__package__)
        .joinpath("status_page.html")
        .read_text(encoding="utf-8")
    )
    return template.replace("{{NONCE}}", html.escape(nonce)).encode()


_COMMON_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
)


def handler_for(output: Path) -> Callable[..., BaseHTTPRequestHandler]:
    """A request handler serving ``output``'s page and nothing else."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "fuzz-status"
        sys_version = ""

        def _send(
            self, status: int, content_type: str, body: bytes, csp: str
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", csp)
            for name, value in _COMMON_HEADERS:
                self.send_header(name, value)
            if status == 405:
                self.send_header("Allow", "GET")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - the stdlib's name
            path = urlsplit(self.path).path
            locked = "default-src 'none'; frame-ancestors 'none'"
            if path in ("/", "/index.html"):
                nonce = secrets.token_urlsafe(16)
                csp = (
                    f"default-src 'none'; script-src 'nonce-{nonce}'; "
                    f"style-src 'nonce-{nonce}'; connect-src 'self'; "
                    "img-src 'self'; base-uri 'none'; form-action 'none'; "
                    "frame-ancestors 'none'"
                )
                self._send(200, "text/html; charset=utf-8", _page(nonce), csp)
            elif path == "/status.json":
                self._send(
                    200,
                    "application/json",
                    encode_view(status_view(output)),
                    locked,
                )
            else:
                self._send(404, "text/plain", b"not found\n", locked)

        def _refuse(self) -> None:
            self._send(
                405,
                "text/plain",
                b"read-only\n",
                "default-src 'none'; frame-ancestors 'none'",
            )

        def __getattr__(self, name: str) -> Any:
            # Every method but GET, including ones the stdlib does not
            # know, is refused rather than answered with a 501.
            if name.startswith("do_"):
                return self._refuse
            raise AttributeError(name)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            del format, args

    return Handler


def serve(output: Path, port: int) -> ThreadingHTTPServer:
    """A loopback-only server for ``output``; the caller runs it."""
    return ThreadingHTTPServer((HOST, port), handler_for(output))
