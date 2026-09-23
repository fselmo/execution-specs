"""
Long-running differential campaign: generate, fill, run every client's
standalone runner over whole fixture files, and keep only what is new.

A campaign is meant to be left running in a terminal for hours. Its state
(next seed, counters, the signatures seen so far) is rewritten after every
batch, so an interrupted run resumes where it stopped and always leaves a
valid report behind. A bug that fires thousands of times is one signature
with a count, not thousands of files.
"""

import contextlib
import hashlib
import io
import json
import re
import resource
import shutil
import signal
import sys
import tempfile
import time
import warnings
from collections import deque
from concurrent.futures import (
    Future,
    ProcessPoolExecutor,
    ThreadPoolExecutor,
)
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from execution_testing.client_clis import TransitionTool
from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.evm_tools.t8n.evm_trace.bal_witness import (
    bracket_width,
)
from execution_testing.fixtures import BlockchainFixture
from execution_testing.forks import Fork
from execution_testing.specs.invariants import (
    InvariantViolationWarning,
    enable_invariant_checks,
    invariant_checks_enabled,
)

from .baseline import StaleClientError
from .converter import blockchain_test_from_fuzzer
from .corpus import minimize, save_case
from .differential import _fork_by_name, is_tool_rejection
from .generator import GENERATOR_VERSION, generate_fuzzer_output
from .models import FuzzerOutput
from .reproducer import client_judge, write_reproducer
from .run_manifest import RunManifest, _eels_commit
from .runners import FixtureRunner, Verdict, is_runner_error

Signature = Tuple[str, str]
"""One client and the normalized reason it rejected a block."""

KnownSignature = Tuple[Optional[str], str]
"""A client (or any) and a reason substring to suppress from findings."""


_HEX = re.compile(r"0x[0-9a-fA-F]+")
_NUMBER = re.compile(r"\b\d+\b")
_SPACES = re.compile(r"\s+")


def normalize_error(error: str) -> str:
    """
    Reduce a client's error text to the shape of the failure.

    Hashes and numbers vary per case; the words around them do not, so
    stripping them lets one bug collapse to one signature.
    """
    first = next(
        (line for line in error.splitlines() if line.strip()), error
    ).strip()
    first = _HEX.sub("<hex>", first)
    first = _NUMBER.sub("<n>", first)
    return _SPACES.sub(" ", first)[:200]


def per_client_signatures(
    verdicts: Mapping[str, Verdict],
) -> List[Signature]:
    """
    One signature per failing client, each with *its own* reason.

    Keying on the whole failing set would fragment: two independent bugs
    that happen to fire on the same case (common when both touch the block
    access list) would land under one ``besu+erigon`` row wearing one
    client's error text. Per-client keying keeps each bug to its own row.
    """
    return [
        (name, normalize_error(v.error))
        for name, v in sorted(verdicts.items())
        if not v.passed
    ]


def is_known(signature: Signature, known: Sequence[KnownSignature]) -> bool:
    """Whether ``signature`` matches a configured known (suppressed) entry."""
    client, reason = signature
    low = reason.lower()
    for known_client, known_reason in known:
        if known_client is not None and known_client != client:
            continue
        if known_reason.lower() in low:
            return True
    return False


SEED_SAMPLE_CAP = 500
"""Seeds retained per signature. A signature that fires rarely is the one
worth bucketing by mechanism later, and it is kept whole; a signature
firing tens of thousands of times is sampled. Recording only `first_seed`
made the 46 erigon hits of the first blind campaign unrecoverable."""


def partition_rejections(
    verdicts: Mapping[str, Verdict],
) -> "Tuple[Dict[str, Verdict], Dict[str, Verdict]]":
    """
    Split verdicts into tools that ran and tools that refused the input.

    A refusal is not a consensus disagreement, so it is excluded from
    both sides of the comparison exactly as the t8n lane excludes it: it
    neither counts as a client failure nor lets the remaining clients
    read as a divergence against it.
    """
    ran, rejected = {}, {}
    for name, verdict in verdicts.items():
        if not verdict.passed and is_tool_rejection(verdict.error):
            rejected[name] = verdict
        else:
            ran[name] = verdict
    return ran, rejected


def partition_runner_errors(
    verdicts: Mapping[str, Verdict],
) -> "Tuple[Dict[str, Verdict], Dict[str, Verdict]]":
    """
    Split verdicts into clients that answered and clients the harness
    never got an answer from.

    A timeout, a non-zero exit with no parseable report, or a fixture the
    runner never mentioned means the client did not judge the case. Left
    in, it counts as that client failing while the others pass -- a
    divergence, a signature, and a bundle, all manufactured by our own
    harness. Excluded here for the same reason a refused input is, and
    counted per client so a runner that is simply broken still shows.

    Applied before :func:`partition_rejections`: a batch-level failure
    carries the runner's whole stderr, which may quote a refusal phrase
    for one case while saying nothing about the other few hundred in the
    file. That is a harness outcome for all of them, not a refusal of
    each.
    """
    ran, errored = {}, {}
    for name, verdict in verdicts.items():
        if not verdict.passed and is_runner_error(verdict.error):
            errored[name] = verdict
        else:
            ran[name] = verdict
    return ran, errored


def classify(verdicts: Mapping[str, Verdict]) -> str:
    """
    ``agreed`` when every client accepts, ``all-fail`` when none does (a
    suspect block or a spec-side change, never a client finding), else
    ``divergence``.
    """
    if not verdicts:
        return "all-rejected"
    failed = sum(1 for v in verdicts.values() if not v.passed)
    if failed == 0:
        return "agreed"
    if failed == len(verdicts):
        return "all-fail"
    return "divergence"


def contrast_excluded(primary: Verdict, contrast: Verdict) -> bool:
    """
    Whether a client's two runs cannot be compared to each other.

    Either run refusing the input or never reporting leaves nothing to
    compare; the pair is dropped from the contrast tally as well as from
    the finding, so the mismatch rate stays a rate over real comparisons.
    """
    return any(
        is_tool_rejection(verdict.error) or is_runner_error(verdict.error)
        for verdict in (primary, contrast)
    )


def contrast_mismatch(primary: Verdict, contrast: Verdict) -> Optional[str]:
    """
    Why one run of a client failed where its other run passed.

    The primary run (the client's `runner_flags`) is the client's vote in
    the panel; the contrast run is the same binary under
    `contrast_flags`. When they disagree the client has diverged from
    itself, and no spec or other client is needed to call it a finding.
    None when they agree, when either refused the input, or when either
    run never reported -- a client cannot be said to disagree with itself
    on a case one of its runs never judged.
    """
    if contrast_excluded(primary, contrast):
        return None
    if primary.passed == contrast.passed:
        return None
    if primary.passed:
        return f"contrast run failed: {normalize_error(contrast.error)}"
    return f"primary run failed: {normalize_error(primary.error)}"


def signature_id(signature: Signature) -> str:
    """
    A short, stable directory name for a signature.

    Client errors often share a long generic prefix, so the readable slug
    is suffixed with a digest of the whole reason to keep ids distinct.
    """
    client, reason = signature
    slug = re.sub(r"[^a-z0-9]+", "-", reason.lower()).strip("-")[:40]
    digest = hashlib.sha256(reason.encode()).hexdigest()[:8]
    return f"{client}--{slug or 'error'}-{digest}"


SIG_VERSION = 2
"""Bumped when the signature scheme changes; a stale state recounts."""


@dataclass
class CampaignState:
    """Everything a campaign needs to resume."""

    path: Path
    next_seed: int
    started: float = field(default_factory=time.time)
    counts: Dict[str, int] = field(
        default_factory=lambda: {
            "agreed": 0,
            "divergence": 0,
            "all-fail": 0,
            "all-rejected": 0,
            "fill_error": 0,
            "fill_timeout": 0,
            "invariant_violation": 0,
            "contrast-mismatch": 0,
            "escalated": 0,
            "producer-disagreement": 0,
            "escalation-error": 0,
        }
    )
    client_failures: Dict[str, int] = field(default_factory=dict)
    rejections: Dict[str, int] = field(default_factory=dict)
    runner_errors: Dict[str, int] = field(default_factory=dict)
    """Per client: cases its runner never returned a verdict on. Kept
    apart from `rejections` because this one accuses the harness, and a
    number climbing here means a campaign judged fewer cases than it
    counted."""
    by_tx_type: Dict[str, Dict[str, int]] = field(default_factory=dict)
    """Per transaction type: cases seen, and per-client failures and
    refusals. A client rejecting a typed transaction the spec accepts is
    where typed-transaction bugs have historically surfaced, and it is
    invisible in a total that mixes the types together."""
    by_event: Dict[str, Dict[str, int]] = field(default_factory=dict)
    """Per execution event (the signature's L1 layer): cases carrying it,
    and per-client failures and refusals. A signature keys on the
    client's error text, and one error text can carry two mechanisms;
    the event whose presence moves a client's failure rate is what
    tells them apart."""
    contrast: Dict[str, Dict[str, int]] = field(default_factory=dict)
    """Per client run under a second flag set: fixtures both runs judged,
    and how many they judged differently."""
    signatures: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    signatures_reset: bool = field(default=False, compare=False)

    @classmethod
    def load(cls, path: Path, *, seed_start: int) -> "CampaignState":
        """Resume from ``path`` if it exists, else start at ``seed_start``."""
        if path.is_file():
            data = json.loads(path.read_text())
            signatures = data.get("signatures", {})
            reset = data.get("sig_version") != SIG_VERSION
            if reset:
                signatures = {}
            state = cls(
                path=path,
                next_seed=data["next_seed"],
                started=data.get("started", time.time()),
                counts=data.get("counts", {}),
                client_failures=data.get("client_failures", {}),
                rejections=data.get("rejections", {}),
                runner_errors=data.get("runner_errors", {}),
                by_tx_type=data.get("by_tx_type", {}),
                by_event=data.get("by_event", {}),
                contrast=data.get("contrast", {}),
                signatures=signatures,
            )
            state.signatures_reset = reset and bool(data.get("signatures"))
            return state
        return cls(path=path, next_seed=seed_start)

    def save(self) -> None:
        """Persist atomically enough for a Ctrl-C: write, then rename."""
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "sig_version": SIG_VERSION,
                    "next_seed": self.next_seed,
                    "started": self.started,
                    "counts": self.counts,
                    "client_failures": self.client_failures,
                    "rejections": self.rejections,
                    "runner_errors": self.runner_errors,
                    "by_tx_type": self.by_tx_type,
                    "by_event": self.by_event,
                    "contrast": self.contrast,
                    "signatures": self.signatures,
                },
                indent=1,
            )
        )
        tmp.replace(self.path)

    def record_signature(
        self,
        client: str,
        reason: str,
        *,
        seed: int,
        bundle: Optional[str],
        known: bool = False,
        events: Sequence[str] = (),
    ) -> bool:
        """
        Count a per-client signature; return True when it is new.

        ``events`` are the hit's execution events. The entry keeps their
        intersection over every hit: an event in every hit is necessary
        to the mechanism, and a signature whose intersection holds none
        of the rarer events is suspected of folding two mechanisms.
        """
        key = signature_id((client, reason))
        entry = self.signatures.get(key)
        if entry is None:
            self.signatures[key] = {
                "client": client,
                "reason": reason,
                "count": 1,
                "first_seed": seed,
                "seeds": [seed],
                "bundle": bundle,
                "known": known,
                "events_necessary": sorted(events),
            }
            return True
        entry["count"] += 1
        seeds = entry.setdefault("seeds", [entry["first_seed"]])
        if len(seeds) < SEED_SAMPLE_CAP:
            seeds.append(seed)
        if "events_necessary" in entry:
            entry["events_necessary"] = sorted(
                set(entry["events_necessary"]) & set(events)
            )
        return False

    def unique_findings(self) -> int:
        """Distinct signatures that are not configured as known."""
        return sum(1 for e in self.signatures.values() if not e.get("known"))


TX_TYPE_LABELS: Dict[int, str] = {
    0: "legacy",
    1: "access-list",
    2: "fee-market",
    3: "blob",
    4: "set-code",
}


def _per_client(tally: Dict[str, int]) -> str:
    """Render a per-client count, or a dash when there is nothing."""
    return ", ".join(f"{n}={c}" for n, c in sorted(tally.items()) if c) or "-"


def _event_contrast(
    tally: Mapping[str, int],
    total_cases: int,
    client_failures: Mapping[str, int],
) -> str:
    """
    Per client, the failure rate with the event against the rate without.

    ``besu=312/320 (97.5% -> 0.4%)`` reads: of the 320 cases carrying the
    event besu failed 312, and it failed 0.4% of the cases without it.
    """
    with_cases = tally.get("cases", 0)
    without_cases = total_cases - with_cases
    parts = []
    for key, failed_with in sorted(tally.items()):
        if not key.startswith("failed:") or not failed_with:
            continue
        client = key.split(":", 1)[1]
        failed_without = client_failures.get(client, 0) - failed_with
        rate_with = failed_with / with_cases if with_cases else 0.0
        rate_without = (
            failed_without / without_cases if without_cases > 0 else 0.0
        )
        parts.append(
            f"{client}={failed_with}/{with_cases} "
            f"({rate_with:.1%} -> {rate_without:.1%})"
        )
    return ", ".join(parts) or "-"


def render_report(
    state: CampaignState,
    *,
    fork: str,
    versions: Mapping[str, str],
    elapsed_seconds: float,
) -> str:
    """Render the campaign report; valid at any point of the run."""
    cases = sum(
        state.counts.get(k, 0) for k in ("agreed", "divergence", "all-fail")
    )
    rate = cases / elapsed_seconds if elapsed_seconds > 0 else 0.0
    fill_errors = state.counts.get("fill_error", 0)
    generated = cases + fill_errors
    fill_error_rate = fill_errors / generated if generated else 0.0
    lines = [
        f"# Fuzz campaign: {fork}",
        "",
        "| | |",
        "| --- | --- |",
        f"| cases | {cases} (next seed {state.next_seed}) |",
        f"| elapsed | {elapsed_seconds / 3600:.2f} h ({rate:.1f} cases/s) |",
        f"| agreed | {state.counts.get('agreed', 0)} |",
        f"| divergences | {state.counts.get('divergence', 0)} "
        f"({state.unique_findings()} unique) |",
        f"| all-fail (suspect) | {state.counts.get('all-fail', 0)} |",
        f"| all-rejected (no tool ran) | "
        f"{state.counts.get('all-rejected', 0)} |",
        f"| fill timeouts | {state.counts.get('fill_timeout', 0)} |",
        f"| invariant violations | "
        f"{state.counts.get('invariant_violation', 0)} |",
        f"| contrast mismatches (client vs itself) | "
        f"{state.counts.get('contrast-mismatch', 0)} |",
        f"| fill errors | {fill_errors} "
        f"({fill_error_rate:.1%} of {generated} candidates) |",
    ]
    if state.counts.get("escalated"):
        lines += [
            f"| escalated to EELS | {state.counts['escalated']} "
            f"(producer disagreed on "
            f"{state.counts.get('producer-disagreement', 0)}, "
            f"EELS could not fill "
            f"{state.counts.get('escalation-error', 0)}) |",
        ]
    fill_ms = state.counts.get("fill_ms", 0)
    fill_filled = state.counts.get("fill_filled", 0)
    if fill_filled:
        lines += [
            f"| fill worker-side | {fill_ms / fill_filled:.1f} ms/case, "
            f"peak worker rss {state.counts.get('rss_mb_peak', 0)} MB |",
        ]
    lines += [
        "",
        "## Versions",
        "",
        "| tool | version |",
        "| --- | --- |",
    ]
    lines += [f"| {name} | {version} |" for name, version in versions.items()]
    lines += [
        "",
        "## Failures per client",
        "",
        "| client | fixtures failed | inputs refused | no verdict |",
        "| --- | --- | --- | --- |",
    ]
    lines += [
        f"| {name} | {state.client_failures.get(name, 0)} "
        f"| {state.rejections.get(name, 0)} "
        f"| {state.runner_errors.get(name, 0)} |"
        for name in sorted(
            set(state.client_failures)
            | set(state.rejections)
            | set(state.runner_errors)
        )
    ]
    if state.contrast:
        lines += [
            "",
            "## Same client, two flag sets",
            "",
            "The primary run is the client's vote above; the contrast run "
            "is the same binary under `contrast_flags`. A fixture the two "
            "judge differently is the client disagreeing with itself, a "
            "finding that needs no other witness. Compared counts only "
            "fixtures neither run refused.",
            "",
            "| client | compared | primary failed | contrast failed | "
            "mismatches |",
            "| --- | --- | --- | --- | --- |",
        ]
        lines += [
            f"| {name} | {tally.get('compared', 0)} | "
            f"{tally.get('primary_failed', 0)} | "
            f"{tally.get('contrast_failed', 0)} | "
            f"{tally.get('mismatches', 0)} |"
            for name, tally in sorted(state.contrast.items())
        ]
    if state.by_tx_type:
        lines += [
            "",
            "## Per transaction type",
            "",
            "A case carrying several types counts under each. A client "
            "refusing a type the spec accepts is a finding, not noise.",
            "",
            "| type | cases | failures | refusals |",
            "| --- | --- | --- | --- |",
        ]
        for key in sorted(state.by_tx_type, key=int):
            tally = state.by_tx_type[key]
            failed = {
                k.split(":", 1)[1]: v
                for k, v in tally.items()
                if k.startswith("failed:")
            }
            refused = {
                k.split(":", 1)[1]: v
                for k, v in tally.items()
                if k.startswith("refused:")
            }
            name = TX_TYPE_LABELS.get(int(key), key)
            lines.append(
                f"| {key} ({name}) | {tally.get('cases', 0)} | "
                f"{_per_client(failed)} | {_per_client(refused)} |"
            )

    if state.by_event:
        lines += [
            "",
            "## Per execution event",
            "",
            "Failure rate among cases carrying the event, against the rate "
            "among cases without it. A client whose rate moves with an "
            "event fails through that event; two events that move it "
            "independently are two mechanisms, whatever the error text "
            "says.",
            "",
            "| event | cases | failed: with -> without |",
            "| --- | --- | --- |",
        ]
        for event, tally in sorted(state.by_event.items()):
            lines.append(
                f"| {event} | {tally.get('cases', 0)} | "
                f"{_event_contrast(tally, cases, state.client_failures)} |"
            )

    findings = sorted(
        (e for e in state.signatures.values() if not e.get("known")),
        key=lambda e: -e["count"],
    )
    lines += [
        "",
        "## Unique signatures",
        "",
        "The necessary events are those present in every hit; a row "
        "whose necessary events are only the ones nearly every case "
        "carries is suspected of folding more than one mechanism.",
        "",
        "| client | count | first seed | reason | necessary events | bundle |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for entry in findings:
        necessary = entry.get("events_necessary")
        lines.append(
            f"| {entry['client']} | {entry['count']} | "
            f"{entry['first_seed']} | {entry['reason']} | "
            f"{' '.join(necessary) if necessary else '-'} | "
            f"{entry.get('bundle') or '-'} |"
        )
    known = sorted(
        (e for e in state.signatures.values() if e.get("known")),
        key=lambda e: -e["count"],
    )
    if known:
        lines += [
            "",
            "## Known (suppressed)",
            "",
            "| client | count | reason |",
            "| --- | --- | --- |",
        ]
        for entry in known:
            lines.append(
                f"| {entry['client']} | {entry['count']} | {entry['reason']} |"
            )
    return "\n".join(lines) + "\n"


_FILL: Dict[str, Any] = {}


def _init_fill_worker(
    fork_name: str, invariants: bool = False, producer: Optional[str] = None
) -> None:
    """Build the per-process fill tool once."""
    _FILL["fork"] = _fork_by_name(fork_name)
    _FILL["invariants"] = invariants
    _FILL["producer"] = producer
    if invariants:
        # Checks are a process-global switch, so a worker opts in once
        # rather than per case.
        enable_invariant_checks()
    _FILL["eels"] = _reference_tool()
    _FILL["capabilities"] = _capabilities(_FILL["eels"])


def _capabilities(eels: Any) -> Dict[str, Any]:
    """What a worker's reference tool is configured to observe."""
    return {
        "tool": type(eels).__name__,
        "compute_signature": bool(getattr(eels, "compute_signature", False)),
        "compute_bal_witness": bool(
            getattr(eels, "compute_bal_witness", False)
        ),
        "invariants": invariant_checks_enabled(),
    }


class RecoveryMismatchError(RuntimeError):
    """
    A tool rebuilt on a recovery path lacks a capability the original had.

    Recovery is rarely taken, so a degraded rebuild goes unnoticed: the
    tool a worker took after its first fill timeout came back without the
    signature tracer or the access witness, and every later case in that
    worker was filled blind. The rebuilt tool has to prove it observes
    exactly what the original did.
    """


def _recover_tool() -> Any:
    """Rebuild the reference tool after a timeout, proving it lost nothing."""
    tool = _reference_tool()
    expected, actual = _FILL["capabilities"], _capabilities(tool)
    if actual != expected:
        raise RecoveryMismatchError(
            f"rebuilt reference tool observes {actual}, "
            f"the original observed {expected}"
        )
    return tool


def _reference_tool() -> Any:
    """
    The tool this worker fills through: the producer if configured, else
    EELS traced for its execution signature.

    The events are what lets one error text be read as two mechanisms,
    and they cost about a quarter of an EELS fill (70 -> 86 ms/case on
    600 seeds). A producer has no tracer; its cases carry no events, and
    EELS traces the ones escalated to it. The access witness is asked
    for only under invariant checks.
    """
    producer = _FILL.get("producer")
    if producer is not None:
        return TransitionTool.from_binary_path(binary_path=Path(producer))
    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    if _FILL.get("invariants"):
        eels.compute_bal_witness = True
    return eels


def fill_case(
    case: FuzzerOutput,
    fork: Fork,
    eels: ExecutionSpecsTransitionTool,
    violations: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """
    Fill one case into a blockchain fixture's JSON, with its `_info`.

    A block that fails to build makes the spec dump traces and allocs to
    stdout before raising; unfillable candidates are routine here, so that
    output is discarded and the exception is the whole story.
    """
    test = blockchain_test_from_fuzzer(case, fork)
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            # A violation is a counted finding here, not a warning printed
            # into a log nobody keeps -- the failure mode that lost the
            # per-case timings twice.
            warnings.simplefilter("ignore", InvariantViolationWarning)
            result = test.generate(t8n=eels, fixture_format=BlockchainFixture)
    if violations is not None:
        violations.extend(test.invariant_violations)
    return result.fixture.json_dict_with_info()


def _fill_seed(
    seed: int,
) -> Tuple[int, Optional[Dict[str, Any]], Optional[str]]:
    fork = _FILL["fork"]
    try:
        return (
            seed,
            fill_case(generate_fuzzer_output(fork, seed), fork, _FILL["eels"]),
            None,
        )
    except Exception as exc:  # noqa: BLE001 - a fill failure is data, not a crash
        return seed, None, f"{type(exc).__name__}: {exc}"[:200]


def _fill_pool(
    workers: int,
    fork: Fork,
    invariants: bool = False,
    producer: Optional[Path] = None,
) -> ProcessPoolExecutor:
    return ProcessPoolExecutor(
        max_workers=workers,
        initializer=_init_fill_worker,
        initargs=(
            fork.name(),
            invariants,
            str(producer) if producer is not None else None,
        ),
    )


def fill_batch(
    seeds: range, pool: Any
) -> Tuple[Dict[str, Dict[str, Any]], Dict[int, str]]:
    """
    Fill ``seeds`` one task per seed (kept for the scaling probes).

    The campaign itself fills through ``_fill_slice`` shards: per-seed
    dispatch measurably leaves pool workers idle at higher worker counts.
    """
    fixtures: Dict[str, Dict[str, Any]] = {}
    errors: Dict[int, str] = {}
    for seed, fixture, error in pool.map(_fill_seed, seeds):
        if fixture is not None:
            fixtures[f"seed_{seed}"] = fixture
        else:
            errors[seed] = error or "unknown"
    return fixtures, errors


def shard_path(fixtures_dir: Path, seeds: Sequence[int]) -> Path:
    """Name a shard by its seed range, so provenance is derivable."""
    return fixtures_dir / f"batch_{seeds[0]}_{seeds[-1]}.json"


def _worker_rss_mb() -> int:
    """Return the process's peak RSS in MB (bytes on macOS, KB elsewhere)."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    return int(peak / divisor)


FILL_TIMEOUT_SECONDS = 30.0
"""Per-case fill budget. One pathological case can hold a whole slice:
seed 800030 of the v12 smoke ran 112 s on the server against a 62 ms
median -- 80% of that shard's fill time in one case, which moved the
shard's mean ms/case by more than 2x with nothing else changing.

The timeout protects throughput; it is not the fix. Cost is linear in
opcodes executed (that case ran 297,066 against a neighbour's 346, at a
*lower* cost per opcode), so the fix is the per-shape depth budget that
bounds the recursive fan-out generating them.
"""


class FillTimeoutError(Exception):
    """One case exceeded the per-case fill budget."""


@contextlib.contextmanager
def _case_deadline(seconds: float) -> Iterator[None]:
    """
    Raise `FillTimeoutError` in this worker if a case outruns its budget.

    SIGALRM only fires on a process's main thread, which is what a pool
    worker is. Where it is unavailable the budget is simply not enforced.
    """
    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _fire(signum: int, frame: object) -> None:
        del signum, frame  # the handler needs neither
        raise FillTimeoutError(f"fill exceeded {seconds:g}s")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _case_tx_types(case: Any) -> Set[int]:
    """
    The EIP-2718 types a case's transactions carry.

    Read off the input rather than the trace, the same analytic witness
    the signature uses. A case carrying several types is attributed to
    each: the question a per-type readout answers is "does any client
    mishandle this type", and a case containing one is evidence about
    it whatever else it contains.
    """
    types = set()
    for tx in case.transactions:
        if tx.authorization_list:
            types.add(4)
        elif tx.max_fee_per_blob_gas is not None:
            types.add(3)
        elif tx.max_fee_per_gas is not None:
            types.add(2)
        elif tx.access_list:
            types.add(1)
        else:
            types.add(0)
    return types


def _case_events(eels: Any) -> List[str]:
    """Execution events of the case just filled, empty when untraced."""
    signature = getattr(eels, "last_signature", None)
    return sorted(signature.events) if signature is not None else []


def _case_opcodes(eels: Any) -> int:
    """Opcodes executed by the case just filled, 0 when uncounted."""
    total = 0
    for block in eels.opcode_count_per_block or []:
        root = block.root if hasattr(block, "root") else block
        total += sum(dict(root).values())
    return total


class MixedGeneratorError(RuntimeError):
    """
    A shard was filled by a different generator than the run started with.

    Editing the working tree during a long campaign is enough to cause it:
    the parent holds the version it imported at start, while a pool worker
    respawned after a fill timeout imports whatever is on disk then. The
    result is a run whose cases come from two generators with no record of
    which is which, which is not a result that can be quoted.
    """


def _fill_slice(args: Tuple[List[int], str]) -> Dict[str, Any]:
    """
    Fill a slice of seeds, write its shard and metadata, return a summary.

    The worker writes the fixture file itself and hands back only names,
    errors, and telemetry: per-case dispatch through the pool leaves
    workers idle, and the fixtures never need to transit the parent.
    """
    seeds, fixtures_dir = args
    fork = _FILL["fork"]
    started = time.perf_counter()
    fixtures: Dict[str, Dict[str, Any]] = {}
    errors: Dict[int, str] = {}
    timeouts: Dict[int, float] = {}
    violating: Dict[int, List[str]] = {}
    case_types: Dict[str, List[int]] = {}
    case_events: Dict[str, List[str]] = {}
    widest = 0
    case_ms: List[Tuple[int, float]] = []
    opcodes: Dict[int, int] = {}
    for seed in seeds:
        case_started = time.perf_counter()
        _FILL["eels"].reset_opcode_count()
        if hasattr(_FILL["eels"], "last_signature"):
            _FILL["eels"].last_signature = None
        seen: List[Any] = []
        case = generate_fuzzer_output(fork, seed)
        try:
            with _case_deadline(FILL_TIMEOUT_SECONDS):
                fixtures[f"seed_{seed}"] = fill_case(
                    case, fork, _FILL["eels"], violations=seen
                )
        except FillTimeoutError:
            timeouts[seed] = FILL_TIMEOUT_SECONDS
            # The interrupted fill may have left the tool mid-transition,
            # so the worker takes a fresh one rather than carrying that
            # into the next case.
            _FILL["eels"] = _recover_tool()
        except Exception as exc:  # noqa: BLE001 - a fill failure is data
            errors[seed] = f"{type(exc).__name__}: {exc}"[:200]
        else:
            opcodes[seed] = _case_opcodes(_FILL["eels"])
            case_types[f"seed_{seed}"] = sorted(_case_tx_types(case))
            case_events[f"seed_{seed}"] = _case_events(_FILL["eels"])
            if seen:
                violating[seed] = [v.invariant for v in seen]
            witness = getattr(_FILL["eels"], "last_bal_witness", None)
            if witness is not None:
                widest = max(widest, bracket_width(witness))
        case_ms.append((seed, (time.perf_counter() - case_started) * 1000))
    seconds = time.perf_counter() - started
    path = shard_path(Path(fixtures_dir), seeds)
    if fixtures:
        path.write_text(json.dumps(fixtures))
    rss_mb = _worker_rss_mb()
    path.with_suffix(".meta.json").write_text(
        json.dumps(
            {
                "seeds": [seeds[0], seeds[-1]],
                "generator_version": GENERATOR_VERSION,
                "filled": len(fixtures),
                "fill_errors": {str(k): v for k, v in errors.items()},
                "worker_seconds": round(seconds, 3),
                "ms_per_case": round(seconds / len(fixtures) * 1000, 2)
                if fixtures
                else None,
                # A mean over this distribution hides the tail that
                # dominates it; the quantiles are what make a slow shard
                # readable without a rerun.
                **_timing_summary(case_ms),
                "opcodes_per_case_median": _median(
                    [float(v) for v in opcodes.values()]
                ),
                "opcodes_max": max(opcodes.values(), default=0),
                "fill_timeouts": {str(k): v for k, v in timeouts.items()},
                # Named for the parent's `*_max` merge rule, which folds it
                # with no rule of its own.
                "bracket_width_max": widest,
                "invariant_violations": {
                    str(k): v for k, v in violating.items()
                },
                "rss_mb": rss_mb,
            },
            indent=1,
        )
    )
    return {
        "path": str(path) if fixtures else None,
        "names": list(fixtures),
        "case_types": case_types,
        "case_events": case_events,
        "errors": errors,
        "timeouts": timeouts,
        "violations": violating,
        # The worker's own value, not the parent's: a pool worker
        # respawned mid-run imports whatever is on disk at that moment.
        "generator_version": GENERATOR_VERSION,
        "seconds": seconds,
        "rss_mb": rss_mb,
    }


def _median(values: List[float]) -> Optional[float]:
    """Median of `values`, None when empty."""
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return round(ordered[middle], 2)
    return round((ordered[middle - 1] + ordered[middle]) / 2, 2)


def _timing_summary(case_ms: List[Tuple[int, float]]) -> Dict[str, Any]:
    """Per-case fill quantiles and the slowest seed in the shard."""
    if not case_ms:
        return {}
    times = [ms for _, ms in case_ms]
    ordered = sorted(times)
    slowest_seed, slowest_ms = max(case_ms, key=lambda pair: pair[1])
    return {
        "ms_per_case_median": _median(times),
        "ms_per_case_p90": round(
            ordered[min(len(ordered) - 1, int(len(ordered) * 0.9))], 2
        ),
        "ms_per_case_max": round(slowest_ms, 2),
        "slowest_seed": slowest_seed,
    }


@dataclass
class CampaignOptions:
    """Everything a campaign run is parameterized by."""

    fork: Fork
    clients: Dict[str, Path]
    output: Path
    seed_start: int = 0
    hours: Optional[float] = None
    count: Optional[int] = None
    batch: int = 200
    fill_workers: int = 4
    minimize: bool = False
    fresh: bool = False
    baseline: bool = True
    keep_fixtures: bool = False
    invariant_checks: bool = False
    known: Tuple[KnownSignature, ...] = ()
    runner_flags: Mapping[str, Sequence[str]] = field(default_factory=dict)
    contrast_flags: Mapping[str, Sequence[str]] = field(default_factory=dict)
    """Per client, a second flag set the same binary is also run with;
    see `contrast_mismatch`."""
    contrast_env: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    """Per client, environment overrides for that second run. A client
    may appear here, in `contrast_flags`, or in both."""
    producer: Optional[Path] = None
    """A transition tool that fills instead of EELS; see `escalate`."""
    producer_name: str = "producer"
    sources: Mapping[str, str] = field(default_factory=dict)
    """Per client, where its binary came from, for the manifest."""


def _seed_of(fixture_name: str) -> int:
    return int(fixture_name.rsplit("_", 1)[1])


def _header(fixture: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(fixture["blocks"][0]["blockHeader"])


def header_differences(
    produced: Mapping[str, Any], spec: Mapping[str, Any]
) -> List[str]:
    """The block-header fields on which two fixtures of one case differ."""
    a, b = _header(produced), _header(spec)
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


@dataclass
class Escalation:
    """What escalating a batch's non-agreed cases to EELS found."""

    escalated: List[str] = field(default_factory=list)
    disagreements: Dict[str, List[str]] = field(default_factory=dict)
    """Cases whose producer fixture differs from EELS's, by header field."""
    spec_fixtures: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    events: Dict[str, List[str]] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)


def escalate(
    names: Sequence[str],
    results: Dict[str, Dict[str, Verdict]],
    fixtures: Mapping[str, Dict[str, Any]],
    *,
    fill_spec: Callable[[str], Tuple[Dict[str, Any], List[str]]],
    runners: Mapping[str, FixtureRunner],
    spec_file: Path,
) -> Escalation:
    """
    Run EELS on the cases the panel did not agree on, and re-judge the
    clients wherever the producer was the one that disagreed.

    The producer's fixture is the panel's oracle until someone dissents;
    then EELS fills the same case. A producer that matches EELS leaves
    the verdicts standing (the dissent is a client's). A producer that
    differs is recorded as a `producer-disagreement`, and the clients are
    judged again on the spec's fixture -- all such cases of the batch in
    one file, one runner invocation each -- so a producer bug never
    reads as a client bug. ``results`` is corrected in place.
    """
    found = Escalation()
    for name in names:
        answered, _ = partition_runner_errors(
            {c: results[c][name] for c in results}
        )
        ran, _ = partition_rejections(answered)
        if classify(ran) == "agreed":
            continue
        found.escalated.append(name)
        try:
            spec_fixture, events = fill_spec(name)
        except Exception as exc:  # noqa: BLE001 - recorded, verdicts stand
            found.errors[name] = f"{type(exc).__name__}: {exc}"[:200]
            continue
        found.events[name] = events
        differing = header_differences(fixtures[name], spec_fixture)
        if differing:
            found.disagreements[name] = differing
            found.spec_fixtures[name] = spec_fixture
    if found.spec_fixtures:
        spec_file.write_text(json.dumps(found.spec_fixtures))
        rejudged = list(found.spec_fixtures)
        with ThreadPoolExecutor(max_workers=max(1, len(runners))) as tp:
            futures = {
                client: tp.submit(runner.run_file, spec_file, rejudged)
                for client, runner in runners.items()
            }
            for client, future in futures.items():
                results[client].update(future.result())
    return found


def run_campaign(
    options: CampaignOptions, *, echo: Callable[[str], None] = print
) -> CampaignState:
    """
    Run batches until the time or count budget is spent.

    Batches are filled as pipelined slices: several batch-sized fill tasks
    stay in flight, each worker writes its own seed-range-named shard (plus
    metadata), and the parent receives names and telemetry only -- per-case
    pool dispatch measurably left workers idle. Batches are processed in
    submission order, so state and resume semantics stay contiguous. Per
    processed batch: run each client's runner over the shard concurrently,
    classify each fixture, bundle new signatures, persist state, rewrite
    the report. The first batch of a fresh campaign doubles as the
    baseline: a client failing more than half of it is stale.
    """
    output = options.output
    if options.fresh and output.exists():
        shutil.rmtree(output)
    fixtures_dir = output / "fixtures"
    corpus_dir = output / "corpus"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    state = CampaignState.load(
        output / "state.json", seed_start=options.seed_start
    )
    fresh_start = sum(state.counts.values()) == 0

    runners = {
        name: FixtureRunner.detect(
            name, path, options.runner_flags.get(name, ())
        )
        for name, path in options.clients.items()
    }
    contrast_runners = {}
    for name in set(options.contrast_flags) | set(options.contrast_env):
        if name not in runners:
            continue
        variant = runners[name]
        if name in options.contrast_flags:
            variant = variant.with_flags(options.contrast_flags[name])
        if name in options.contrast_env:
            variant = variant.with_env(options.contrast_env[name])
        contrast_runners[name] = variant
    versions = {"eels": _eels_commit()}
    versions.update(
        {name: runner.version() for name, runner in runners.items()}
    )
    producer_version = ""
    spec_tool: Optional[ExecutionSpecsTransitionTool] = None
    if options.producer is not None:
        producer_tool = TransitionTool.from_binary_path(
            binary_path=options.producer
        )
        producer_version = producer_tool.version()
        versions[f"producer ({options.producer_name})"] = producer_version
        spec_tool = ExecutionSpecsTransitionTool()
        spec_tool.compute_signature = True
    RunManifest(
        fork=options.fork.name(),
        generator_version=GENERATOR_VERSION,
        eels_commit=versions["eels"],
        clients={
            n: v
            for n, v in versions.items()
            if n != "eels" and not n.startswith("producer")
        },
        seed_start=options.seed_start,
        count=options.count or 0,
        created=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        producer=producer_version
        and f"{options.producer_name}: {producer_version}",
        sources=dict(options.sources),
    ).write(output / "manifest.json")

    def fill_spec(fixture_name: str) -> Tuple[Dict[str, Any], List[str]]:
        assert spec_tool is not None
        spec_tool.last_signature = None
        case = generate_fuzzer_output(options.fork, _seed_of(fixture_name))
        fixture = fill_case(case, options.fork, spec_tool)
        return fixture, _case_events(spec_tool)

    if state.signatures_reset:
        echo(
            "signature scheme changed since this state was written; "
            "recounting signatures from scratch (counts and seeds kept)"
        )
    run_started = time.time()
    deadline = run_started + options.hours * 3600 if options.hours else None
    end_seed = (
        options.seed_start + options.count
        if options.count is not None
        else None
    )
    fill_batches = 0

    def write_report() -> None:
        elapsed = time.time() - state.started
        (output / "report.md").write_text(
            render_report(
                state,
                fork=options.fork.name(),
                versions=versions,
                elapsed_seconds=elapsed,
            )
        )

    if end_seed is not None and state.next_seed >= end_seed:
        echo(
            f"seeds {options.seed_start}..{end_seed - 1} are already "
            f"covered (next seed {state.next_seed}); raise --count, use "
            "--hours, or pass --fresh to start over"
        )
        write_report()
        return state

    with _fill_pool(
        options.fill_workers,
        options.fork,
        options.invariant_checks,
        options.producer,
    ) as pool:
        in_flight = max(2 * options.fill_workers, 2)
        pending: Deque[Tuple[range, "Future[Dict[str, Any]]"]] = deque()
        submit_cursor = state.next_seed

        def submit_one() -> bool:
            nonlocal submit_cursor
            if end_seed is not None and submit_cursor >= end_seed:
                return False
            if deadline is not None and time.time() >= deadline:
                return False
            stop = submit_cursor + options.batch
            if end_seed is not None:
                stop = min(stop, end_seed)
            seeds = range(submit_cursor, stop)
            future = pool.submit(_fill_slice, (list(seeds), str(fixtures_dir)))
            pending.append((seeds, future))
            submit_cursor = stop
            return True

        while True:
            while len(pending) < in_flight and submit_one():
                pass
            if not pending:
                break
            if deadline is not None and time.time() >= deadline:
                while len(pending) > 1 and pending[-1][1].cancel():
                    pending.pop()
            seeds, future = pending.popleft()
            slice_result = future.result()
            names: List[str] = slice_result["names"]
            fill_errors = slice_result["errors"]
            state.counts["fill_error"] = state.counts.get(
                "fill_error", 0
            ) + len(fill_errors)
            shard_version = slice_result.get("generator_version")
            if shard_version != GENERATOR_VERSION:
                raise MixedGeneratorError(
                    f"shard filled by generator v{shard_version} while this "
                    f"run is v{GENERATOR_VERSION}: a worker respawned onto a "
                    "different checkout, so the batch is a mix of two "
                    "generators. Stop, do not quote the run."
                )
            state.counts["fill_timeout"] = state.counts.get(
                "fill_timeout", 0
            ) + len(slice_result.get("timeouts", {}))
            state.counts["invariant_violation"] = state.counts.get(
                "invariant_violation", 0
            ) + len(slice_result.get("violations", {}))
            case_types: Dict[str, List[int]] = slice_result.get(
                "case_types", {}
            )
            case_events: Dict[str, List[str]] = slice_result.get(
                "case_events", {}
            )
            state.counts["fill_ms"] = state.counts.get("fill_ms", 0) + int(
                slice_result["seconds"] * 1000
            )
            state.counts["fill_filled"] = state.counts.get(
                "fill_filled", 0
            ) + len(names)
            state.counts["rss_mb_peak"] = max(
                state.counts.get("rss_mb_peak", 0),
                int(slice_result["rss_mb"]),
            )

            keep_file = False
            runner_seconds: Dict[str, float] = {}
            if names:
                batch_file = Path(slice_result["path"])
                with ThreadPoolExecutor(
                    max_workers=max(1, len(runners) + len(contrast_runners))
                ) as tp:
                    futures = {
                        name: tp.submit(_timed_run, runner, batch_file, names)
                        for name, runner in runners.items()
                    }
                    contrast_futures = {
                        name: tp.submit(_timed_run, runner, batch_file, names)
                        for name, runner in contrast_runners.items()
                    }
                    timed = {name: f.result() for name, f in futures.items()}
                    contrast_results = {
                        name: f.result()[0]
                        for name, f in contrast_futures.items()
                    }
                results = {
                    name: verdicts for name, (verdicts, _) in timed.items()
                }
                runner_seconds = {
                    name: seconds for name, (_, seconds) in timed.items()
                }

                shard_fixtures: Optional[Dict[str, Any]] = None
                if spec_tool is not None:
                    shard_fixtures = json.loads(batch_file.read_text())
                    found = escalate(
                        names,
                        results,
                        shard_fixtures,
                        fill_spec=fill_spec,
                        runners=runners,
                        spec_file=batch_file.with_name(
                            batch_file.stem + "_eels.json"
                        ),
                    )
                    state.counts["escalated"] = state.counts.get(
                        "escalated", 0
                    ) + len(found.escalated)
                    state.counts["escalation-error"] = state.counts.get(
                        "escalation-error", 0
                    ) + len(found.errors)
                    state.counts["producer-disagreement"] = state.counts.get(
                        "producer-disagreement", 0
                    ) + len(found.disagreements)
                    case_events.update(found.events)
                    for fixture_name, differing in found.disagreements.items():
                        keep_file = True
                        signature = (
                            f"producer:{options.producer_name}",
                            "header: " + ", ".join(differing),
                        )
                        bundle = corpus_dir / signature_id(signature)
                        new = state.record_signature(
                            signature[0],
                            signature[1],
                            seed=_seed_of(fixture_name),
                            bundle=str(bundle),
                            events=found.events.get(fixture_name, []),
                        )
                        if new:
                            bundle.mkdir(parents=True, exist_ok=True)
                            (bundle / "producer_fixture.json").write_text(
                                json.dumps(
                                    {
                                        fixture_name: shard_fixtures[
                                            fixture_name
                                        ]
                                    },
                                    indent=1,
                                )
                            )
                            _write_bundle(
                                bundle,
                                options,
                                fixture_name,
                                found.spec_fixtures[fixture_name],
                                {c: results[c][fixture_name] for c in runners},
                                runners,
                                focus_client=None,
                                events=found.events.get(fixture_name, []),
                            )
                        # From here on the spec's fixture is the case's.
                        shard_fixtures[fixture_name] = found.spec_fixtures[
                            fixture_name
                        ]
                batch_failures = dict.fromkeys(runners, 0)
                for fixture_name in names:
                    verdicts = {
                        name: results[name][fixture_name] for name in runners
                    }
                    verdicts, errored = partition_runner_errors(verdicts)
                    for name in errored:
                        state.runner_errors[name] = (
                            state.runner_errors.get(name, 0) + 1
                        )
                    verdicts, rejected = partition_rejections(verdicts)
                    for name in rejected:
                        state.rejections[name] = (
                            state.rejections.get(name, 0) + 1
                        )
                    tallies = [
                        state.by_tx_type.setdefault(str(t), {"cases": 0})
                        for t in case_types.get(fixture_name, [])
                    ]
                    if spec_tool is None:
                        # Under a producer only escalated cases carry
                        # events, and a rate over those alone would lie.
                        tallies += [
                            state.by_event.setdefault(e, {"cases": 0})
                            for e in case_events.get(fixture_name, [])
                        ]
                    for tally in tallies:
                        tally["cases"] += 1
                        for name in rejected:
                            key = f"refused:{name}"
                            tally[key] = tally.get(key, 0) + 1
                        for name, verdict in verdicts.items():
                            if not verdict.passed:
                                key = f"failed:{name}"
                                tally[key] = tally.get(key, 0) + 1
                    seed = _seed_of(fixture_name)
                    events = case_events.get(fixture_name, [])
                    for name, other in contrast_results.items():
                        primary = results[name][fixture_name]
                        if contrast_excluded(primary, other[fixture_name]):
                            continue
                        tally = state.contrast.setdefault(
                            name, {"compared": 0, "mismatches": 0}
                        )
                        tally["compared"] += 1
                        # Per-mode counts: a divergence in one mode and a
                        # divergence in both look the same in a digest
                        # table unless each mode's failures are kept.
                        if not primary.passed:
                            tally["primary_failed"] = (
                                tally.get("primary_failed", 0) + 1
                            )
                        if not other[fixture_name].passed:
                            tally["contrast_failed"] = (
                                tally.get("contrast_failed", 0) + 1
                            )
                        reason = contrast_mismatch(
                            primary, other[fixture_name]
                        )
                        if reason is None:
                            continue
                        tally["mismatches"] += 1
                        state.counts["contrast-mismatch"] = (
                            state.counts.get("contrast-mismatch", 0) + 1
                        )
                        signature = (f"{name}:contrast", reason)
                        known = is_known(signature, options.known)
                        bundle = corpus_dir / signature_id(signature)
                        new = state.record_signature(
                            signature[0],
                            reason,
                            seed=seed,
                            bundle=None if known else str(bundle),
                            known=known,
                            events=events,
                        )
                        if new and not known:
                            keep_file = True
                            if shard_fixtures is None:
                                shard_fixtures = json.loads(
                                    batch_file.read_text()
                                )
                            _write_bundle(
                                bundle,
                                options,
                                fixture_name,
                                shard_fixtures[fixture_name],
                                {
                                    name: primary,
                                    f"{name} (contrast)": other[fixture_name],
                                },
                                runners,
                                focus_client=None,
                                events=events,
                            )
                    kind = classify(verdicts)
                    state.counts[kind] = state.counts.get(kind, 0) + 1
                    for name, verdict in verdicts.items():
                        if not verdict.passed:
                            state.client_failures[name] = (
                                state.client_failures.get(name, 0) + 1
                            )
                            batch_failures[name] += 1
                    if kind != "divergence":
                        continue
                    for signature in per_client_signatures(verdicts):
                        known = is_known(signature, options.known)
                        bundle = corpus_dir / signature_id(signature)
                        client, reason = signature
                        new = state.record_signature(
                            client,
                            reason,
                            seed=seed,
                            bundle=None if known else str(bundle),
                            known=known,
                            events=events,
                        )
                        if new and not known:
                            keep_file = True
                            if shard_fixtures is None:
                                shard_fixtures = json.loads(
                                    batch_file.read_text()
                                )
                            _write_bundle(
                                bundle,
                                options,
                                fixture_name,
                                shard_fixtures[fixture_name],
                                verdicts,
                                runners,
                                focus_client=client,
                                events=events,
                            )

                if fresh_start and fill_batches == 0 and options.baseline:
                    stale = {
                        name: count
                        for name, count in batch_failures.items()
                        if count > len(names) / 2
                    }
                    if stale:
                        state.save()
                        write_report()
                        raise StaleClientError(stale, len(names))

                if not keep_file and not options.keep_fixtures:
                    batch_file.unlink(missing_ok=True)
                    batch_file.with_suffix(".meta.json").unlink(
                        missing_ok=True
                    )

            state.next_seed = seeds.stop
            state.save()
            write_report()
            fill_batches += 1
            elapsed = time.time() - run_started
            counts = state.counts
            fill_ms_case = (
                slice_result["seconds"] / len(names) * 1000 if names else 0.0
            )
            echo(
                f"seeds {seeds.start}..{seeds.stop - 1}: "
                f"agreed {counts.get('agreed', 0)} "
                f"divergent {counts.get('divergence', 0)} "
                f"({state.unique_findings()} unique) "
                f"all-fail {counts.get('all-fail', 0)} "
                f"fill-errors {counts.get('fill_error', 0)} "
                f"| fill {fill_ms_case:.0f}ms/case "
                f"rss {slice_result['rss_mb']}MB "
                f"| {elapsed / 60:.1f} min | runners "
                + " ".join(f"{n} {s:.1f}s" for n, s in runner_seconds.items())
            )
    write_report()
    return state


def _timed_run(
    runner: FixtureRunner, batch_file: Path, names: List[str]
) -> Tuple[Dict[str, Verdict], float]:
    started = time.time()
    return runner.run_file(batch_file, names), time.time() - started


def _write_bundle(
    bundle: Path,
    options: CampaignOptions,
    fixture_name: str,
    fixture: Dict[str, Any],
    verdicts: Mapping[str, Verdict],
    runners: Mapping[str, FixtureRunner],
    *,
    focus_client: Optional[str],
    events: Sequence[str] = (),
) -> None:
    """
    Save what a reviewer needs to reproduce a new signature.

    ``events.json`` holds the case's execution events and, after
    minimization, the minimized case's: the events that survive
    minimization are the mechanism, with the incidental ones gone.
    Minimization needs a ``focus_client`` whose failure is the predicate;
    a contrast mismatch has none (its predicate is two runs disagreeing,
    which the corpus predicate does not express yet) and is saved as is.
    """
    bundle.mkdir(parents=True, exist_ok=True)
    seed = _seed_of(fixture_name)
    case = generate_fuzzer_output(options.fork, seed)
    save_case(case, bundle / "case.json")
    mechanism: Dict[str, Any] = {"case": list(events), "minimized": None}
    (bundle / "events.json").write_text(json.dumps(mechanism, indent=1))
    (bundle / "fixture.json").write_text(
        json.dumps({fixture_name: fixture}, indent=1)
    )
    (bundle / "verdicts.json").write_text(
        json.dumps(
            {
                name: {"pass": v.passed, "error": v.error}
                for name, v in verdicts.items()
            },
            indent=1,
        )
    )
    if focus_client is None:
        return
    eels = ExecutionSpecsTransitionTool()
    if not options.minimize:
        _reproducer(bundle, case, options, eels, runners[focus_client])
        return

    def still_fails(candidate: FuzzerOutput) -> bool:
        try:
            filled = fill_case(candidate, options.fork, eels)
        except Exception:  # noqa: BLE001 - an unfillable candidate is not a reduction
            return False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "candidate.json"
            path.write_text(json.dumps({"candidate": filled}))
            return (
                not runners[focus_client]
                .run_file(path, ["candidate"])["candidate"]
                .passed
            )

    minimized = minimize(case, still_fails)
    save_case(minimized, bundle / "minimized.json")
    eels.compute_signature = True
    eels.last_signature = None
    fill_case(minimized, options.fork, eels)
    mechanism["minimized"] = _case_events(eels)
    (bundle / "events.json").write_text(json.dumps(mechanism, indent=1))
    _reproducer(bundle, minimized, options, eels, runners[focus_client])


def _reproducer(
    bundle: Path,
    case: FuzzerOutput,
    options: CampaignOptions,
    eels: Any,
    runner: FixtureRunner,
) -> None:
    """
    The state-test reproducer for a one-transaction case, if it survives.

    Whatever goes wrong here is recorded in the bundle rather than
    raised: the bundle already holds the blockchain fixture, and a
    campaign must not stop because a reproducer could not be written.
    """
    try:
        write_reproducer(
            bundle,
            case,
            options.fork,
            eels,
            client_judge(runner, "reproducer"),
        )
    except Exception as exc:  # noqa: BLE001 - recorded in the bundle
        (bundle / "reproducer.md").write_text(
            f"Writing the reproducer failed: {type(exc).__name__}: {exc}\n"
        )
