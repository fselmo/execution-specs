"""The bands a running campaign is held to, and the alert it sends."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Tuple

from ..fuzzer_bridge.health import (
    ALERT_URL_ENV,
    HealthPolicy,
    evaluate,
    send_alert,
    trim,
)


def _sample(cases: int, **kw: Any) -> Dict[str, Any]:
    sample: Dict[str, Any] = {
        "cases": cases,
        "control": 0,
        "runner_errors": 0,
        "producer_disagreements": 0,
        "contrast_compared": {},
    }
    sample.update(kw)
    return sample


CONTROLLED = HealthPolicy(
    window=100, control_client="besu-gate", control_band=(0.03, 0.08)
)


def test_nothing_is_checked_until_the_window_is_full() -> None:
    """A first batch cannot pause a run on noise."""
    rates, problems = evaluate([_sample(50)], CONTROLLED, [], runners=2)
    assert rates["checking"] is False and problems == []


def test_a_control_outside_its_band_pauses_either_way() -> None:
    """Gone quiet and firing too often are both out of band."""
    quiet = evaluate([_sample(100, control=1)], CONTROLLED, [], runners=2)
    loud = evaluate([_sample(100, control=20)], CONTROLLED, [], runners=2)
    inside = evaluate([_sample(100, control=5)], CONTROLLED, [], runners=2)
    assert "control besu-gate at 1.00%" in quiet[1][0]
    assert "control besu-gate at 20.00%" in loud[1][0]
    assert inside[1] == [] and inside[0]["control_rate"] == 0.05


def test_runner_errors_producer_drift_and_silent_lanes_pause() -> None:
    """Each of the other three checks names what it found."""
    policy = HealthPolicy(window=100)
    window = [
        _sample(
            100,
            runner_errors=5,
            producer_disagreements=3,
            contrast_compared={"geth:contrast": 40},
        )
    ]
    _, problems = evaluate(
        window, policy, ["geth:contrast", "erigon:contrast"], runners=2
    )
    assert any("runner errors at 2.50%" in p for p in problems)
    assert any("producer disagrees" in p for p in problems)
    assert any("erigon:contrast compared nothing" in p for p in problems)
    assert not any("geth:contrast" in p for p in problems)


def test_the_window_keeps_the_newest_batches_that_fill_it() -> None:
    """Old batches fall out once the newer ones hold the window."""
    window = [_sample(60, control=9), _sample(60), _sample(60)]
    assert trim(window, 100) == window[1:]


def _receiver() -> Tuple[ThreadingHTTPServer, List[Tuple[str, bytes]]]:
    received: List[Tuple[str, bytes]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - the stdlib's name
            length = int(self.headers["Content-Length"])
            received.append(
                (self.headers["Content-Type"], self.rfile.read(length))
            )
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, received


def test_an_alert_is_posted_as_text_and_a_failure_is_returned(
    monkeypatch: Any,
) -> None:
    """
    Plain receivers such as ntfy take the message as the body; an
    unreachable webhook comes back as a reason, never an exception.
    """
    server, received = _receiver()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/topic"
        monkeypatch.setenv(ALERT_URL_ENV, url)
        assert send_alert("campaign paused") is None
    finally:
        server.shutdown()
    assert received == [("text/plain", b"campaign paused")]
    monkeypatch.setenv(ALERT_URL_ENV, "http://127.0.0.1:9/secret-token")
    failure = send_alert("x")
    assert failure is not None and "secret-token" not in failure
    monkeypatch.delenv(ALERT_URL_ENV)
    assert send_alert("x") is None


def test_a_slack_webhook_gets_json(monkeypatch: Any) -> None:
    """Slack's incoming webhooks take a JSON body with a text field."""
    import urllib.request
    from unittest import mock

    seen: List[Any] = []

    class _Response:
        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *_: Any) -> None:
            return None

    def fake_urlopen(request: Any, timeout: float) -> Any:
        del timeout
        seen.append(request)
        return _Response()

    monkeypatch.setenv(ALERT_URL_ENV, "https://hooks.slack.com/services/x")
    with mock.patch.object(urllib.request, "urlopen", fake_urlopen):
        assert send_alert("hi") is None
    (request,) = seen
    assert json.loads(request.data) == {"text": "hi"}
