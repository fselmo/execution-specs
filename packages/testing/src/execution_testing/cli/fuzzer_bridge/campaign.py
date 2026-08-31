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
    Tuple,
)

from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.fixtures import BlockchainFixture
from execution_testing.forks import Fork

from .baseline import StaleClientError
from .converter import blockchain_test_from_fuzzer
from .corpus import minimize, save_case
from .differential import _fork_by_name, is_tool_rejection
from .generator import GENERATOR_VERSION, generate_fuzzer_output
from .models import FuzzerOutput
from .run_manifest import RunManifest, _eels_commit
from .runners import FixtureRunner, Verdict

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
        }
    )
    client_failures: Dict[str, int] = field(default_factory=dict)
    rejections: Dict[str, int] = field(default_factory=dict)
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
    ) -> bool:
        """Count a per-client signature; return True when it is new."""
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
            }
            return True
        entry["count"] += 1
        seeds = entry.setdefault("seeds", [entry["first_seed"]])
        if len(seeds) < SEED_SAMPLE_CAP:
            seeds.append(seed)
        return False

    def unique_findings(self) -> int:
        """Distinct signatures that are not configured as known."""
        return sum(1 for e in self.signatures.values() if not e.get("known"))


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
        f"| fill errors | {fill_errors} "
        f"({fill_error_rate:.1%} of {generated} candidates) |",
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
        "| client | fixtures failed | inputs refused |",
        "| --- | --- | --- |",
    ]
    lines += [
        f"| {name} | {state.client_failures.get(name, 0)} "
        f"| {state.rejections.get(name, 0)} |"
        for name in sorted(set(state.client_failures) | set(state.rejections))
    ]
    findings = sorted(
        (e for e in state.signatures.values() if not e.get("known")),
        key=lambda e: -e["count"],
    )
    lines += [
        "",
        "## Unique signatures",
        "",
        "| client | count | first seed | reason | bundle |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in findings:
        lines.append(
            f"| {entry['client']} | {entry['count']} | "
            f"{entry['first_seed']} | {entry['reason']} | "
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


def _init_fill_worker(fork_name: str) -> None:
    """Build the per-process reference tool once."""
    _FILL["fork"] = _fork_by_name(fork_name)
    _FILL["eels"] = ExecutionSpecsTransitionTool()


def fill_case(
    case: FuzzerOutput, fork: Fork, eels: ExecutionSpecsTransitionTool
) -> Dict[str, Any]:
    """
    Fill one case into a blockchain fixture's JSON, with its `_info`.

    A block that fails to build makes the spec dump traces and allocs to
    stdout before raising; unfillable candidates are routine here, so that
    output is discarded and the exception is the whole story.
    """
    test = blockchain_test_from_fuzzer(case, fork)
    with contextlib.redirect_stdout(io.StringIO()):
        result = test.generate(t8n=eels, fixture_format=BlockchainFixture)
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


def _fill_pool(workers: int, fork: Fork) -> ProcessPoolExecutor:
    return ProcessPoolExecutor(
        max_workers=workers,
        initializer=_init_fill_worker,
        initargs=(fork.name(),),
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
    case_ms: List[Tuple[int, float]] = []
    opcodes: Dict[int, int] = {}
    for seed in seeds:
        case_started = time.perf_counter()
        _FILL["eels"].reset_opcode_count()
        try:
            with _case_deadline(FILL_TIMEOUT_SECONDS):
                fixtures[f"seed_{seed}"] = fill_case(
                    generate_fuzzer_output(fork, seed), fork, _FILL["eels"]
                )
        except FillTimeoutError:
            timeouts[seed] = FILL_TIMEOUT_SECONDS
            # The interrupted fill may have left the tool mid-transition,
            # so the worker takes a fresh one rather than carrying that
            # into the next case.
            _FILL["eels"] = ExecutionSpecsTransitionTool()
        except Exception as exc:  # noqa: BLE001 - a fill failure is data
            errors[seed] = f"{type(exc).__name__}: {exc}"[:200]
        else:
            opcodes[seed] = _case_opcodes(_FILL["eels"])
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
                "rss_mb": rss_mb,
            },
            indent=1,
        )
    )
    return {
        "path": str(path) if fixtures else None,
        "names": list(fixtures),
        "errors": errors,
        "timeouts": timeouts,
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
    known: Tuple[KnownSignature, ...] = ()


def _seed_of(fixture_name: str) -> int:
    return int(fixture_name.rsplit("_", 1)[1])


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
        name: FixtureRunner.detect(name, path)
        for name, path in options.clients.items()
    }
    versions = {"eels": _eels_commit()}
    versions.update(
        {name: runner.version() for name, runner in runners.items()}
    )
    RunManifest(
        fork=options.fork.name(),
        generator_version=GENERATOR_VERSION,
        eels_commit=versions["eels"],
        clients={n: v for n, v in versions.items() if n != "eels"},
        seed_start=options.seed_start,
        count=options.count or 0,
        created=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    ).write(output / "manifest.json")

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

    with _fill_pool(options.fill_workers, options.fork) as pool:
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
                    max_workers=max(1, len(runners))
                ) as tp:
                    futures = {
                        name: tp.submit(_timed_run, runner, batch_file, names)
                        for name, runner in runners.items()
                    }
                    timed = {name: f.result() for name, f in futures.items()}
                results = {
                    name: verdicts for name, (verdicts, _) in timed.items()
                }
                runner_seconds = {
                    name: seconds for name, (_, seconds) in timed.items()
                }

                shard_fixtures: Optional[Dict[str, Any]] = None
                batch_failures = dict.fromkeys(runners, 0)
                for fixture_name in names:
                    verdicts = {
                        name: results[name][fixture_name] for name in runners
                    }
                    verdicts, rejected = partition_rejections(verdicts)
                    for name in rejected:
                        state.rejections[name] = (
                            state.rejections.get(name, 0) + 1
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
                    seed = _seed_of(fixture_name)
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
    focus_client: str,
) -> None:
    """Save what a reviewer needs to reproduce a new signature."""
    bundle.mkdir(parents=True, exist_ok=True)
    seed = _seed_of(fixture_name)
    case = generate_fuzzer_output(options.fork, seed)
    save_case(case, bundle / "case.json")
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
    if not options.minimize:
        return
    eels = ExecutionSpecsTransitionTool()

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
