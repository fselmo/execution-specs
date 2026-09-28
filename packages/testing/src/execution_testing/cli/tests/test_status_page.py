"""The status page: read-only, loopback only, and inert to hostile text."""

import http.client
import json
import re
import threading
from pathlib import Path
from typing import Any, Iterator, List, Tuple

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
    yield from _serving([output])


def _serving(outputs: List[Path]) -> Iterator[Tuple[str, int]]:
    server = serve(outputs, 0)
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


def _render(served: Tuple[str, int], tmp_path: Path) -> Any:
    """Run the page's own script against the served JSON on a stand-in DOM."""
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
    return json.loads(run.stdout)


def test_a_hostile_finding_renders_as_literal_text(
    served: Tuple[str, int], tmp_path: Path
) -> None:
    """
    The hostile reason lands in a text node verbatim, and the page never
    touches an HTML-parsing sink.
    """
    result = _render(served, tmp_path)
    assert result["sinks"] == []
    assert HOSTILE in result["texts"]


def _shard(
    root: Path, name: str, status: str, cases: int, rate: float, hits: int
) -> Path:
    output = root / name
    output.mkdir()
    (output / "state.json").write_text(
        json.dumps(
            {
                "next_seed": cases,
                "started": 1.0,
                "status": status,
                "summary": {"cases": cases, "cases_per_second": rate},
                "counts": {"agreed": cases - hits, "divergence": hits},
                "client_failures": {"geth": hits},
                "health": {"window": 2000, "window_cases": 2000},
                "signatures": {
                    "deadbeef": {
                        "client": "geth",
                        "reason": "gas mismatch",
                        "count": hits,
                        "first_seed": cases - 1,
                        "first_seen": float(cases),
                    }
                },
            }
        )
    )
    return output


@pytest.fixture
def two_shards(tmp_path: Path) -> Iterator[Tuple[str, int]]:
    """Two shards of one run, one of them paused, served together."""
    yield from _serving(
        [
            _shard(tmp_path, "main", "running", 3000, 5.0, 3),
            _shard(tmp_path, "main-b", "paused", 1000, 4.0, 1),
        ]
    )


def test_shards_are_shown_together_with_their_totals(
    two_shards: Tuple[str, int],
) -> None:
    """
    Cases, rates and counts add across shards and a finding seen on both
    is one finding; health stays per shard, and the view takes the status
    most in need of attention, naming the shard it came from.
    """
    _, _, body = _request(two_shards, "GET", "/status.json")
    view = json.loads(body)
    assert [s["campaign"] for s in view["shards"]] == ["main", "main-b"]
    assert view["status"] == "paused"
    assert view["status_reason"] == "main-b paused"
    assert view["summary"] == {"cases": 4000, "cases_per_second": 9.0}
    assert view["counts"]["divergence"] == 4
    assert view["clients"]["geth"]["failures"] == 4
    (finding,) = view["findings"]
    assert finding["count"] == 4 and finding["rate"] == 0.001
    assert finding["shards"] == ["main", "main-b"]
    assert finding["first_seed"] == 999
    assert view["health"] == {}


def test_the_page_has_a_row_per_shard(
    two_shards: Tuple[str, int], tmp_path: Path
) -> None:
    """Each shard gets its own row and its own health lines."""
    texts = _render(two_shards, tmp_path)["texts"]
    assert "main-b" in texts and "main" in texts
    assert "main-b window" in texts and "main window" in texts
