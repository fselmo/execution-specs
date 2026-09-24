"""The status page: read-only, loopback only, and inert to hostile text."""

import http.client
import json
import re
import threading
from pathlib import Path
from typing import Any, Iterator, Tuple

import pytest

from ..fuzzer_bridge.status import serve

HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>"


@pytest.fixture
def served(tmp_path: Path) -> Iterator[Tuple[str, int]]:
    """A campaign directory with a hostile finding, served on loopback."""
    output = tmp_path / "campaign"
    (output / "segments").mkdir(parents=True)
    (output / "state.json").write_text(
        json.dumps(
            {
                "next_seed": 400,
                "started": 1.0,
                "status": "paused",
                "status_reason": "control besu-gate at 0.00%",
                "segment": "abcd1234",
                "summary": {"cases": 400, "cases_per_second": 2.0},
                "counts": {"agreed": 399, "divergence": 1},
                "signatures": {
                    "deadbeef": {
                        "client": "geth",
                        "reason": HOSTILE,
                        "count": 1,
                        "first_seed": 7,
                        "bundle": str(output / "corpus" / "deadbeef"),
                    }
                },
            }
        )
    )
    (output / "segments" / "abcd1234.json").write_text(
        json.dumps(
            {
                "fork": "Amsterdam",
                "generator_version": 20,
                "eels_commit": "0123abcd",
                "clients": {"besu": "besu 1"},
                "client_env": {
                    "besu": {"JAVA_HOME": "/opt/jdk", "API_TOKEN": "hunter2"}
                },
            }
        )
    )
    server = serve(output, 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        host, port = server.server_address[:2]
        yield str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()


def _request(
    address: Tuple[str, int], method: str, path: str
) -> Tuple[int, Any, bytes]:
    connection = http.client.HTTPConnection(*address, timeout=5)
    connection.request(method, path)
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response.status, response.headers, body


def test_it_binds_loopback_only(served: Tuple[str, int]) -> None:
    """No flag chooses the address: it is always 127.0.0.1."""
    assert served[0] == "127.0.0.1"


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "HEAD", "FOO"])
def test_every_method_but_get_is_refused(
    served: Tuple[str, int], method: str
) -> None:
    """Read-only: any other method, known to the stdlib or not, is 405."""
    status, headers, _ = _request(served, method, "/status.json")
    assert status == 405 and headers["Allow"] == "GET"


@pytest.mark.parametrize(
    "path",
    [
        "/state.json",
        "/segments/abcd1234.json",
        "/../state.json",
        "/corpus/deadbeef/case.json",
        "/status.json/",
    ],
)
def test_nothing_outside_the_allowlist_is_served(
    served: Tuple[str, int], path: str
) -> None:
    """The page and its JSON are served; no file ever is."""
    status, _, _ = _request(served, "GET", path)
    assert status == 404


def test_the_page_runs_only_its_own_script(served: Tuple[str, int]) -> None:
    """
    The Content-Security-Policy allows scripts and styles by a nonce the
    page carries, loads nothing external, and the page's script has no
    sink that would parse text as HTML.
    """
    status, headers, body = _request(served, "GET", "/")
    assert status == 200
    csp = headers["Content-Security-Policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp)
    assert nonce is not None and "default-src 'none'" in csp
    page = body.decode()
    assert page.count(f'nonce="{nonce.group(1)}"') == 2
    assert not re.search(r"(src|href)\s*=\s*[\"']?https?:", page)
    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
    ):
        assert sink not in page
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_a_hostile_finding_arrives_as_text(served: Tuple[str, int]) -> None:
    """
    Client error text is untrusted. In the JSON it cannot form a tag even
    if something sniffed it as HTML, and it parses back to the literal
    string the page then writes with textContent.
    """
    status, headers, body = _request(served, "GET", "/status.json")
    assert status == 200 and headers["Content-Type"] == "application/json"
    assert b"<" not in body and b">" not in body
    view = json.loads(body)
    (finding,) = view["findings"]
    assert finding["reason"] == HOSTILE


def test_no_environment_value_outside_the_allowlist(
    served: Tuple[str, int],
) -> None:
    """A toolchain path is shown; anything else in a client's env is not."""
    _, _, body = _request(served, "GET", "/status.json")
    assert b"hunter2" not in body
    env = json.loads(body)["segment"]["client_env"]["besu"]
    assert env == {"API_TOKEN": "[redacted]", "JAVA_HOME": "/opt/jdk"}


_DOM_HARNESS = """
const sinks = [];
function node(tag) {
  const n = { tag, children: [], className: "", _text: "" };
  return new Proxy(n, {
    set(target, key, value) {
      if (["innerHTML", "outerHTML"].includes(key)) sinks.push(key);
      if (key === "textContent") { target._text = value; return true; }
      target[key] = value;
      return true;
    },
    get(target, key) {
      if (key === "append" || key === "replaceChildren") {
        return (...kids) => {
          if (key === "replaceChildren") target.children = [];
          target.children.push(...kids);
        };
      }
      if (key === "insertAdjacentHTML") { sinks.push(key); return () => {}; }
      if (key === "textContent") return target._text;
      return target[key];
    },
  });
}
const ids = {};
globalThis.document = {
  createElement: (tag) => node(tag),
  getElementById: (id) => (ids[id] = ids[id] || node("div")),
  write: () => sinks.push("document.write"),
};
globalThis.setInterval = () => 0;
const view = JSON.parse(process.argv[2]);
globalThis.fetch = async () => ({ json: async () => view });
function texts(n, out) {
  out.push(n.textContent);
  for (const c of n.children) texts(c, out);
  return out;
}
PAGE_SCRIPT
setTimeout(() => {
  const all = Object.values(ids).flatMap((n) => texts(n, []));
  console.log(JSON.stringify({ sinks, texts: all }));
}, 50);
"""


def test_a_hostile_finding_renders_as_literal_text(
    served: Tuple[str, int], tmp_path: Path
) -> None:
    """
    The page's own script, run against the served JSON on a stand-in DOM,
    puts the hostile reason into a text node verbatim and never touches
    an HTML-parsing sink.
    """
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    _, _, page = _request(served, "GET", "/")
    script = re.search(rb"<script[^>]*>(.*)</script>", page, re.S)
    assert script is not None
    _, _, body = _request(served, "GET", "/status.json")
    harness = tmp_path / "harness.js"
    harness.write_text(
        _DOM_HARNESS.replace("PAGE_SCRIPT", script.group(1).decode())
    )
    run = subprocess.run(
        [node, str(harness), body.decode()],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    assert result["sinks"] == []
    assert HOSTILE in result["texts"]
