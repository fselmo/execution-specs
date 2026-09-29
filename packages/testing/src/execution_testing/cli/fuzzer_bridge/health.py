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
import math
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from statistics import NormalDist
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
    """Only the upper edge is held: above it something else is failing
    the control (widened for a sampled control, see `control_band_for`).
    The lower edge is not a fixed floor any more: the control's rate moves
    with the generator (4.56% at v26, about 3.5% at v28 and v30), so a
    drop is judged against the segment's own calibrated baseline."""
    control_baseline_cases: int = 2000
    """Sampled cases the control judges at a segment's opening before its
    baseline rate is set; until then the relative check cannot pause."""
    control_drop_tolerance: float = 0.0
    """Proportional drop the control's rate may take before the binomial
    test is asked; 0 leaves the test alone to decide."""
    control_dead_expected: float = 5.0
    """Hits the baseline must predict in the window for zero hits to read
    as a control that stopped firing, whatever the drop test says."""
    control_alpha: float = 0.01
    """One-sided chance of pausing on sampling noise alone that the band
    is widened to, when the control judges a sample of the window."""
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
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    cases: int,
    *,
    contrast_sampled: bool = True,
    control_sampled: bool = True,
    verdicts: Optional[int] = None,
) -> Dict[str, Any]:
    """
    One batch's contribution to the window, from two state snapshots.

    ``contrast_sampled`` and ``control_sampled`` say whether the contrast
    lanes and the control judged this batch; ``verdicts`` is how many
    verdicts the primaries gave, the runner-error rate's denominator.
    """
    return {
        "cases": cases,
        "contrast_sampled": contrast_sampled,
        "control_sampled": control_sampled,
        "verdicts": verdicts,
        "control_runner_errors": after.get("control_runner_errors", 0)
        - before.get("control_runner_errors", 0),
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
        "control_runner_errors": (
            state.runner_errors.get(policy.control_client, 0)
            if policy.control_client is not None
            else 0
        ),
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


def control_band_for(
    policy: HealthPolicy, sampled_cases: int, window_cases: int
) -> Tuple[float, float]:
    """
    The control's band when it judged ``sampled_cases`` of the window.

    The configured band holds for a rate measured over the whole window.
    A rate over a sample of it carries more sampling noise, by
    p(1 - p)(1/sampled - 1/window) in variance at a true rate p, so each
    edge moves out by that much noise at `control_alpha`. Judging every
    case, the band is exactly the configured one.
    """
    low, high = policy.control_band
    if sampled_cases >= window_cases or sampled_cases == 0:
        return low, high
    z = NormalDist().inv_cdf(1 - policy.control_alpha)
    extra = 1 / sampled_cases - 1 / window_cases

    def noise(p: float) -> float:
        return z * math.sqrt(p * (1 - p) * extra)

    return max(0.0, low - noise(low)), min(1.0, high + noise(high))


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
    problems = []
    # A control that returns no verdict is not judging at all, and no
    # window of noise explains it: this check does not wait for the window.
    control_errors = sum(s.get("control_runner_errors", 0) for s in window)
    if policy.control_client is not None and control_errors:
        problems.append(
            f"control {policy.control_client} returned no verdict on "
            f"{control_errors} case(s)"
        )
    if cases < policy.window:
        rates["checking"] = False
        return rates, problems
    rates["checking"] = True
    if policy.control_client is not None:
        problems += _control_checks(
            window, policy, cases, rates, segment or {}
        )
    errors = sum(s["runner_errors"] for s in window)
    verdicts = sum(
        s["cases"] * max(runners, 1)
        if s.get("verdicts") is None
        else s["verdicts"]
        for s in window
    )
    rate = errors / max(verdicts, 1)
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
    # A contrast lane can only be silent in a batch it judged.
    contrasted = [s for s in window if s.get("contrast_sampled", True)]
    compared = {
        lane: sum(s["contrast_compared"].get(lane, 0) for s in contrasted)
        for lane in lanes
    }
    rates["contrast_compared"] = compared
    silent = sorted(lane for lane, count in compared.items() if count == 0)
    if silent and contrasted:
        problems.append(
            f"contrast lane(s) {', '.join(silent)} compared nothing in "
            f"the {sum(s['cases'] for s in contrasted)} sampled cases of "
            f"the last {cases}"
        )
    rates["parallel"], dropped = _parallel_checks(
        window, policy, segment or {}
    )
    problems += dropped
    return rates, problems


def _control_checks(
    window: List[Dict[str, Any]],
    policy: HealthPolicy,
    cases: int,
    rates: Dict[str, Any],
    segment: Mapping[str, Any],
) -> List[str]:
    """
    The control's rate over the batches it judged, against the segment's
    baseline and the band's upper edge.
    """
    from .density import significant_drops

    problems: List[str] = []
    judged = [s for s in window if s.get("control_sampled", True)]
    sampled = sum(s["cases"] for s in judged)
    hits = sum(s["control"] for s in judged)
    rates["control_cases"] = sampled
    if not sampled:
        return problems
    rate = hits / sampled
    rates["control_rate"] = rate
    _, high = control_band_for(policy, sampled, cases)
    rates["control_band"] = [0.0, high]
    name = policy.control_client or "control"
    if rate > high:
        problems.append(
            f"control {name} at {rate:.2%} over {sampled} sampled cases, "
            f"above {high:.2%}: something else is failing it"
        )
    baseline = segment.get("control_baseline")
    if baseline is None:
        calibrated = segment.get("control_calibration", {}).get("cases", 0)
        rates["control_baseline"] = None
        rates["control_note"] = (
            f"calibrating ({calibrated}/{policy.control_baseline_cases} "
            "sampled cases): cannot pause on a drop yet"
        )
        return problems
    base_hits, base_cases = baseline
    rates["control_baseline"] = base_hits / base_cases if base_cases else 0
    if not base_hits:
        problems.append(
            f"control {name} never fired in the segment's {base_cases} "
            "calibration cases: it is no control"
        )
        return problems
    expected = base_hits / base_cases * sampled
    if not hits and expected >= policy.control_dead_expected:
        problems.append(
            f"control {name} stopped firing: 0 in {sampled} sampled cases, "
            f"where its baseline predicts {expected:.1f}"
        )
        return problems
    drops = significant_drops(
        {name: base_hits},
        {name: hits},
        base_cases,
        sampled,
        tolerance=policy.control_drop_tolerance,
    )
    if drops:
        problems.append(f"control rate fell: {drops[0]}")
    return problems


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
