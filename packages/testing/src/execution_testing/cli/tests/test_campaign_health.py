"""The bands a running campaign is held to, and the alert it sends."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

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


BASELINE = {"control_baseline": [100, 2000]}
"""A segment whose control fired on 5.00% of its calibration cases."""


def test_a_control_is_held_to_its_segment_baseline() -> None:
    """
    The control's rate moves with the generator, so a drop is judged
    against the segment's own baseline, by the binomial test over a window
    of 2,500 sampled cases: 2.8% against a 5% baseline pauses, 4.7% is
    noise, and a window not yet full waits. Too loud still pauses on the
    band's upper edge.
    """
    fell = evaluate([_sample(2500, control=70)], CONTROLLED, [], 2, BASELINE)
    noise = evaluate([_sample(2500, control=118)], CONTROLLED, [], 2, BASELINE)
    short = evaluate([_sample(2000, control=40)], CONTROLLED, [], 2, BASELINE)
    loud = evaluate([_sample(2500, control=400)], CONTROLLED, [], 2, BASELINE)
    assert "control rate fell" in fell[1][0]
    assert noise[1] == [] and noise[0]["control_baseline"] == 0.05
    assert short[1] == []
    assert "drop test waits for 2500" in short[0]["control_note"]
    assert "above" in loud[1][0]


def test_a_control_cannot_pause_on_a_drop_while_it_calibrates() -> None:
    """Before the segment's baseline is set, only the upper edge holds."""
    rates, problems = evaluate(
        [_sample(2000, control=0)],
        CONTROLLED,
        [],
        2,
        {"control_calibration": {"hits": 0, "cases": 800}},
    )
    assert problems == [] and "calibrating (800/2000" in rates["control_note"]


def test_a_control_that_stops_or_never_fired_pauses() -> None:
    """
    Zero hits where the baseline predicts several is a control that
    stopped, and a baseline of zero hits is no control at all.
    """
    _, stopped = evaluate([_sample(2000)], CONTROLLED, [], 2, BASELINE)
    _, never = evaluate(
        [_sample(2000)], CONTROLLED, [], 2, {"control_baseline": [0, 2000]}
    )
    assert "stopped firing" in stopped[0]
    assert "never fired" in never[0]


def test_control_runner_errors_pause_without_waiting_for_the_window() -> None:
    """
    A control that returns no verdict is not judging: on v28 it returned
    none on every case and only the gate noticed. One is enough, before
    the window fills.
    """
    _, problems = evaluate(
        [_sample(10, control_runner_errors=3)], CONTROLLED, [], 2
    )
    assert problems == ["control besu-gate returned no verdict on 3 case(s)"]


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


def test_the_control_band_widens_for_a_sampled_control() -> None:
    """
    At `control_every` 5 the control judges 400 of a 2,000-case window,
    and its rate over those carries the extra noise of p(1 - p)(1/400 -
    1/2000): the upper edge moves out by that much at `control_alpha`.
    Judging every case, it is exactly the configured edge.
    """
    import math
    from statistics import NormalDist

    policy = HealthPolicy(
        window=2000, control_client="besu-gate", control_band=(0.0, 0.08)
    )

    def window(hits: int, every: int) -> List[Dict[str, Any]]:
        return [
            _sample(200, control=hits if i % every == 0 else 0)
            | {"control_sampled": i % every == 0}
            for i in range(10)
        ]

    z = NormalDist().inv_cdf(0.99)
    extra = 1 / 400 - 1 / 2000
    sampled, _ = evaluate(window(18, 5), policy, [], 2, BASELINE)
    assert sampled["control_cases"] == 400
    (_, high) = sampled["control_band"]
    assert math.isclose(high, 0.08 + z * math.sqrt(0.08 * 0.92 * extra))
    every, _ = evaluate(window(18, 1), policy, [], 2, BASELINE)
    assert every["control_band"] == [0.0, 0.08]


ENGINE = HealthPolicy(window=100, negative_control=True)


def test_negatives_cannot_pause_while_they_calibrate() -> None:
    """Before the segment's baseline is set, no share of negatives pauses."""
    rates, problems = evaluate(
        [_sample(100, negatives={"geth": [0, 10]})],
        ENGINE,
        [],
        2,
        {"negative_calibration": {"cases": 50, "clients": {}}},
    )
    assert problems == []
    assert rates["negatives"]["geth"]["note"] == (
        "calibrating (50/200 negative cases): cannot pause yet"
    )


def test_a_baseline_already_accepting_negatives_is_flagged() -> None:
    """
    Every negative should come back INVALID, so a baseline under the floor
    was set by a client already accepting some, which a drop from that
    baseline cannot catch.
    """
    rates, problems = evaluate(
        [_sample(100, negatives={"besu": [9, 10]})],
        ENGINE,
        [],
        2,
        {"negative_baseline": {"besu": [180, 200]}},
    )
    assert problems == []
    assert "below 99%" in rates["negatives"]["besu"]["note"]


def test_negative_control_needs_the_engine_format() -> None:
    """Only an engine fill draws negatives, so another format is refused."""
    import pytest
    from pydantic import ValidationError

    from ..fuzzer_bridge.config import CampaignConfig

    with pytest.raises(ValidationError, match="blockchain_test_engine"):
        CampaignConfig(
            fork="Amsterdam",
            clients=["geth"],
            health={"negative_control": True},
        )
    CampaignConfig(
        fork="Amsterdam",
        clients=["geth"],
        fixture_format="blockchain_test_engine",
        health={"negative_control": True},
    )


def _simulate_control(
    seed: int, before: float, after: float, batches: int
) -> Optional[int]:
    """
    A campaign's control, batch by batch: 200-case batches, the control
    judging one in five, the baseline calibrated on the first 2,000
    sampled cases at ``before``, and ``after`` from then on. Return the
    sampled cases judged after calibration when the control check first
    pauses, None if it never does.
    """
    import random

    rng = random.Random(seed)
    policy = HealthPolicy(
        window=2000, control_client="besu-gate", control_band=(0.0, 0.08)
    )
    health: List[Dict[str, Any]] = []
    control: List[Dict[str, Any]] = []
    calibration = [0, 0]
    segment: Dict[str, Any] = {}
    judged = 0
    for i in range(batches):
        sampled = i % 5 == 0
        rate = after if "control_baseline" in segment else before
        hits = sum(rng.random() < rate for _ in range(200)) if sampled else 0
        sample = _sample(200, control=hits) | {"control_sampled": sampled}
        if sampled and "control_baseline" not in segment:
            calibration[0] += hits
            calibration[1] += 200
            if calibration[1] >= policy.control_baseline_cases:
                segment["control_baseline"] = list(calibration)
            continue
        if sampled:
            judged += 200
            control = trim([*control, sample], policy.control_window)
        health = trim([*health, sample], policy.window)
        _, problems = evaluate(
            health, policy, [], 4, segment, control_window=control
        )
        if any(p.startswith("control") for p in problems):
            return judged
    return None


CONTROL_RATE = 0.035
"""The control's rate on the continuous panel at v28 to v30."""

DAY_OF_BATCHES = 3312
"""A day of continuous-one: 27,600 cases an hour in batches of 200."""


def test_a_stationary_control_does_not_pause_in_a_day() -> None:
    """
    At an unchanged rate the drop test, judged after every sampled batch
    of a day, never pauses on the noise.
    """
    assert (
        _simulate_control(0, CONTROL_RATE, CONTROL_RATE, DAY_OF_BATCHES)
        is None
    )


def test_a_halved_control_pauses_within_one_window() -> None:
    """
    Halved right after calibration, the control pauses by the time its
    window first holds 2,500 sampled cases of the new rate.
    """
    paused = _simulate_control(1, CONTROL_RATE, CONTROL_RATE / 2, 400)
    assert paused is not None and paused <= 2600
