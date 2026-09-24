"""
Whether a running campaign is still judging, checked after every batch.

A campaign left running for days can stop measuring without stopping:
a runner that errors on everything, a contrast lane that compares
nothing, a producer that drifts from the spec, a positive control that
goes quiet. Each looks like a clean run in the totals. So every batch
adds a sample to a rolling window, and once the window holds enough
cases each rate is held to its band; one out of band pauses the
campaign with the reason written to its state. A run that stops judging
must stop, not keep counting.
"""

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple


@dataclass(frozen=True)
class HealthPolicy:
    """The bands a campaign is held to; see `CampaignConfig.health`."""

    window: int = 2000
    """Cases the rates are measured over; no check until the window
    holds this many, so a campaign's first batches cannot trip it on
    noise."""
    control_client: Optional[str] = None
    """The positive-control client, whose known bug must keep firing."""
    control_reason: Optional[str] = None
    """Substring of the control's signature reason, as `known:` matches."""
    control_band: Tuple[float, float] = (0.0, 1.0)
    """Share of cases the control must fail within: below it the lane
    has gone quiet, above it something else is failing the control."""
    max_runner_error_rate: float = 0.001
    """Share of verdicts the harness may lose before the run is judging
    too little to trust."""
    max_producer_disagreement_rate: float = 0.01
    """Share of cases the producer may fill differently from the spec."""


def batch_sample(
    before: Mapping[str, Any], after: Mapping[str, Any], cases: int
) -> Dict[str, Any]:
    """One batch's contribution to the window, from two state snapshots."""
    return {
        "cases": cases,
        "control": after["control"] - before["control"],
        "runner_errors": after["runner_errors"] - before["runner_errors"],
        "producer_disagreements": after["producer_disagreements"]
        - before["producer_disagreements"],
        "contrast_compared": {
            lane: count - before["contrast_compared"].get(lane, 0)
            for lane, count in after["contrast_compared"].items()
        },
    }


def snapshot(state: Any, policy: HealthPolicy) -> Dict[str, Any]:
    """The counters a sample is the difference of."""
    control = 0
    if policy.control_client is not None:
        control = sum(
            entry["count"]
            for entry in state.signatures.values()
            if entry["client"] == policy.control_client
            and (policy.control_reason or "") in entry["reason"]
        )
    return {
        "control": control,
        "runner_errors": sum(state.runner_errors.values()),
        "producer_disagreements": state.counts.get("producer-disagreement", 0),
        "contrast_compared": {
            lane: tally.get("compared", 0)
            for lane, tally in state.contrast.items()
        },
    }


def trim(window: List[Dict[str, Any]], size: int) -> List[Dict[str, Any]]:
    """The newest samples that together hold at least ``size`` cases."""
    kept: List[Dict[str, Any]] = []
    cases = 0
    for sample in reversed(window):
        kept.append(sample)
        cases += sample["cases"]
        if cases >= size:
            break
    return list(reversed(kept))


def evaluate(
    window: List[Dict[str, Any]],
    policy: HealthPolicy,
    lanes: List[str],
    runners: int,
) -> Tuple[Dict[str, Any], List[str]]:
    """
    The window's rates and every band they fall outside.

    ``lanes`` are the contrast lanes the campaign runs, each of which
    must compare at least one case in the window; ``runners`` is how many
    verdicts each case gets, the runner-error rate's denominator.
    """
    cases = sum(sample["cases"] for sample in window)
    rates: Dict[str, Any] = {
        "window_cases": cases,
        "window": policy.window,
        "control_client": policy.control_client,
        "control_band": list(policy.control_band),
        "max_runner_error_rate": policy.max_runner_error_rate,
        "max_producer_disagreement_rate": (
            policy.max_producer_disagreement_rate
        ),
    }
    if cases < policy.window:
        rates["checking"] = False
        return rates, []
    rates["checking"] = True
    problems = []
    if policy.control_client is not None:
        rate = sum(s["control"] for s in window) / cases
        rates["control_rate"] = rate
        low, high = policy.control_band
        if not low <= rate <= high:
            problems.append(
                f"control {policy.control_client} at {rate:.2%}, outside "
                f"{low:.2%}-{high:.2%}"
            )
    errors = sum(s["runner_errors"] for s in window)
    rate = errors / (cases * max(runners, 1))
    rates["runner_error_rate"] = rate
    if rate > policy.max_runner_error_rate:
        problems.append(
            f"runner errors at {rate:.2%} of verdicts, above "
            f"{policy.max_runner_error_rate:.2%}"
        )
    disagreements = sum(s["producer_disagreements"] for s in window)
    rate = disagreements / cases
    rates["producer_disagreement_rate"] = rate
    if rate > policy.max_producer_disagreement_rate:
        problems.append(
            f"producer disagrees with the spec on {rate:.2%} of cases, "
            f"above {policy.max_producer_disagreement_rate:.2%}"
        )
    compared = {
        lane: sum(s["contrast_compared"].get(lane, 0) for s in window)
        for lane in lanes
    }
    rates["contrast_compared"] = compared
    silent = sorted(lane for lane, count in compared.items() if count == 0)
    if silent:
        problems.append(
            f"contrast lane(s) {', '.join(silent)} compared nothing in "
            f"the last {cases} cases"
        )
    return rates, problems


ALERT_URL_ENV = "FUZZ_ALERT_URL"
"""Environment variable holding the alert webhook. Read at send time and
never written to state, config, report or log: a webhook URL is a
credential."""


def send_alert(message: str) -> Optional[str]:
    """
    Post ``message`` to the webhook in `ALERT_URL_ENV`; return why it
    failed, or None.

    Outbound only. A Slack incoming webhook takes JSON with a `text`
    field; anything else (ntfy, a plain receiver) takes the message as the
    body. A failure is reported by kind and status only, since exception
    text can carry the URL. An alert that cannot be sent never stops the
    campaign: the reason is in its state either way.
    """
    url = os.environ.get(ALERT_URL_ENV)
    if not url:
        return None
    if "hooks.slack.com" in url:
        body = json.dumps({"text": message}).encode()
        headers = {"Content-Type": "application/json"}
    else:
        body = message.encode()
        headers = {"Content-Type": "text/plain"}
    request = urllib.request.Request(
        url, data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10):
            return None
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        return type(exc).__name__
