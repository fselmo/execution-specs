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
    parallel_lanes: Tuple[str, ...] = ()
    """Lanes whose client runs the parallel path as its primary: each
    one's decided fraction is held to its segment's baseline."""
    parallel_drop_tolerance: float = 0.0
    """Proportional drop the decided fraction may take before the binomial
    test is even asked; 0 leaves the test alone to decide."""
    parallel_baseline_blocks: int = 2000
    """BAL-carrying blocks the segment's opening batches must hold before a
    lane's baseline is set; until then the lane is calibrating."""
    parallel_proof_floor: float = 0.9
    """The pre-run proof runs every BAL-carrying block in parallel. A
    baseline below this share was likely set by an already-degraded
    binary, which the drop test can then never catch, so it is flagged."""


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
        "parallel": {
            lane: [
                counts[0] - before["parallel"].get(lane, [0, 0])[0],
                counts[1] - before["parallel"].get(lane, [0, 0])[1],
            ]
            for lane, counts in after["parallel"].items()
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
        "parallel": {
            lane: [tally.get("parallel", 0), tally.get("bal_blocks", 0)]
            for lane, tally in state.parallel.items()
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
    segment: Optional[Mapping[str, Any]] = None,
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
    rates["parallel"], dropped = _parallel_checks(
        window, policy, segment or {}
    )
    problems += dropped
    return rates, problems


def _parallel_checks(
    window: List[Dict[str, Any]],
    policy: HealthPolicy,
    segment: Mapping[str, Any],
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Each parallel-primary lane's decided fraction against its baseline.

    The same binomial test the version-bump guard uses: a drop pauses only
    when it is further than sampling explains. While the segment is still
    calibrating, or for a lane that printed nothing while it did, there is
    no baseline and the lane cannot pause.
    """
    from .density import significant_drops

    rates: Dict[str, Any] = {}
    problems = []
    for lane in policy.parallel_lanes:
        parallel = sum(
            s.get("parallel", {}).get(lane, [0, 0])[0] for s in window
        )
        blocks = sum(
            s.get("parallel", {}).get(lane, [0, 0])[1] for s in window
        )
        entry: Dict[str, Any] = {
            "parallel": parallel,
            "bal_blocks": blocks,
            "fraction": parallel / blocks if blocks else None,
        }
        baseline = segment.get("parallel_baseline")
        base = (baseline or {}).get(lane)
        if baseline is None:
            calibrated = segment.get("parallel_calibration", {}).get(
                "bal_blocks", 0
            )
            entry["baseline"] = None
            entry["note"] = (
                f"calibrating ({calibrated}/{policy.parallel_baseline_blocks}"
                " BAL blocks): cannot pause yet"
            )
        elif not base or not base[1]:
            entry["baseline"] = None
            entry["note"] = "no baseline for this segment: cannot pause"
        else:
            entry["baseline"] = base[0] / base[1]
            if entry["baseline"] < policy.parallel_proof_floor:
                entry["note"] = (
                    f"baseline {entry['baseline']:.2%} is below the pre-run "
                    f"proof's all-parallel (floor "
                    f"{policy.parallel_proof_floor:.0%}): a binary degraded "
                    "before the segment opened set it, and a drop from it "
                    "cannot catch that"
                )
            if blocks:
                drops = significant_drops(
                    {lane: base[0]},
                    {lane: parallel},
                    base[1],
                    blocks,
                    tolerance=policy.parallel_drop_tolerance,
                )
                if drops:
                    problems.append(
                        f"parallel decisions on {lane} fell: {drops[0]}"
                    )
        rates[lane] = entry
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
