"""Tests for the campaign loop's client-independent core."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from execution_testing.forks import Osaka

from ..fuzzer_bridge.campaign import (
    CampaignState,
    Verdict,
    classify,
    normalize_error,
    per_client_signatures,
    render_report,
    shard_path,
)
from ..fuzzer_bridge.generator import GENERATOR_VERSION
from ..fuzzer_bridge.runners import RUNNER_ERROR_PREFIX


def test_normalize_error_strips_hashes_and_numbers() -> None:
    """Two instances of one bug produce one signature."""
    a = "block access list mismatch: got 0x3cdf1e41 header 0xfb5f at block 7"
    b = "block access list mismatch: got 0xaaaabbbb header 0xcccc at block 12"
    assert normalize_error(a) == normalize_error(b)
    assert "mismatch" in normalize_error(a)


def test_per_client_signatures_one_row_per_failing_client() -> None:
    """Two clients failing one case give two signatures, each its text."""
    verdicts = {
        "geth": Verdict(passed=True, error=""),
        "erigon": Verdict(passed=False, error="state root mismatch: 0x1"),
        "besu": Verdict(passed=False, error="block access list mismatch 0x2"),
    }
    signatures = per_client_signatures(verdicts)
    assert signatures == [
        ("besu", normalize_error("block access list mismatch 0x2")),
        ("erigon", normalize_error("state root mismatch: 0x1")),
    ]


def test_classify_agreed_divergence_and_all_fail() -> None:
    """All-pass is agreement, all-fail is suspect, otherwise a divergence."""
    ok = Verdict(passed=True, error="")
    bad = Verdict(passed=False, error="boom 1")
    assert classify({"a": ok, "b": ok}) == "agreed"
    assert classify({"a": bad, "b": bad}) == "all-fail"
    assert classify({"a": ok, "b": bad}) == "divergence"


def test_state_round_trips_and_resumes(tmp_path: Path) -> None:
    """State survives a restart: seeds continue, signatures stay deduped."""
    state = CampaignState.load(tmp_path / "state.json", seed_start=100)
    assert state.next_seed == 100
    state.next_seed = 300
    state.record_signature("erigon", "x mismatch", seed=5, bundle="corpus/s1")
    state.record_signature("erigon", "x mismatch", seed=9, bundle="corpus/s1")
    state.counts["agreed"] += 199
    state.save()
    again = CampaignState.load(tmp_path / "state.json", seed_start=100)
    assert again.next_seed == 300
    assert again.counts["agreed"] == 199
    assert len(again.signatures) == 1
    entry = next(iter(again.signatures.values()))
    assert entry["count"] == 2 and entry["first_seed"] == 5


def test_report_lists_signatures_and_versions(tmp_path: Path) -> None:
    """The report is self-contained: versions, throughput, signatures."""
    state = CampaignState.load(tmp_path / "state.json", seed_start=0)
    state.next_seed = 400
    state.counts.update({"agreed": 398, "divergence": 2})
    state.record_signature(
        "erigon", "bal mismatch", seed=17, bundle="corpus/a"
    )
    text = render_report(
        state,
        fork="Amsterdam",
        versions={"eels": "abc123", "erigon": "evm version 3.7"},
        elapsed_seconds=120.0,
    )
    assert (
        "Amsterdam" in text and "abc123" in text and "evm version 3.7" in text
    )
    assert "erigon" in text and "bal mismatch" in text and "corpus/a" in text
    assert "cases/s" in text
    json.dumps(state.signatures)  # JSON-serializable


def test_report_shows_fill_error_rate(tmp_path: Path) -> None:
    """The report shows unfillable candidates as a rate, not just a count."""
    state = CampaignState.load(tmp_path / "state.json", seed_start=0)
    state.counts.update({"agreed": 90, "fill_error": 10})
    text = render_report(
        state,
        fork="Amsterdam",
        versions={"eels": "abc"},
        elapsed_seconds=10.0,
    )
    assert "10.0% of 100 candidates" in text


class _FakePool:
    """Synchronous stand-in pool: fills a slice of trivial fixtures."""

    def __enter__(self) -> "_FakePool":
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def submit(self, _fn: Any, args: Any) -> Any:
        from concurrent.futures import Future

        seeds, fixtures_dir = args
        fixtures = {f"seed_{s}": {"blocks": [], "seed": s} for s in seeds}
        path = shard_path(Path(fixtures_dir), seeds)
        path.write_text(json.dumps(fixtures))
        future: Any = Future()
        future.set_result(
            {
                "path": str(path),
                "names": list(fixtures),
                "case_types": {
                    f"seed_{s}": [0, 4] if s % 2 else [0] for s in seeds
                },
                "case_events": {
                    f"seed_{s}": ["precompile", "state-gas"]
                    if s % 3 == 1
                    else ["state-gas"]
                    for s in seeds
                },
                "errors": {},
                "seconds": 0.01,
                "rss_mb": 1,
                "generator_version": GENERATOR_VERSION,
            }
        )
        return future


class _FakeRunner:
    """
    Scripted runner: `failing` decides which seeds this client rejects;
    `contrast` does the same for the run under `contrast_flags`.
    """

    def __init__(
        self,
        name: str,
        failing: Any,
        contrast: Any = None,
        flags: Any = (),
        env: Any = None,
    ) -> None:
        self.name = name
        self.failing = failing
        self.contrast = contrast
        self.flags = tuple(flags)
        self.env = dict(env or {})
        self.last_stderr = ""

    def with_flags(self, flags: Any) -> "_FakeRunner":
        return _FakeRunner(self.name, self.contrast, None, flags, self.env)

    def with_env(self, env: Any) -> "_FakeRunner":
        # Swap to the contrast script only if `with_flags` has not
        # already done it: a client may contrast on env alone, and a
        # double swap would hand the contrast run the primary verdicts.
        if self.contrast is not None:
            failing = self.contrast
        else:
            failing = self.failing
        return _FakeRunner(
            self.name, failing, None, self.flags, {**self.env, **env}
        )

    def version(self) -> str:
        return f"{self.name} version 1"

    def run_file(self, _path: Path, fixture_names: Any) -> Dict[str, Verdict]:
        out = {}
        for fixture_name in fixture_names:
            seed = int(fixture_name.split("_")[1])
            if self.failing(seed):
                out[fixture_name] = Verdict(
                    False, f"{self.name} mismatch at {seed}"
                )
            else:
                out[fixture_name] = Verdict(True)
        return out


def _campaign(
    tmp_path: Path,
    monkeypatch: Any,
    failing: Dict[str, Any],
    echo: Any = None,
    contrast: Optional[Dict[str, Any]] = None,
    contrast_via_env: bool = False,
    runner: Any = None,
    **kw: Any,
) -> Any:
    from ..fuzzer_bridge import campaign as campaign_module
    from ..fuzzer_bridge.campaign import CampaignOptions, run_campaign

    contrast = contrast or {}
    make = runner or (
        lambda name, flags: _FakeRunner(
            name, failing[name], contrast.get(name), flags
        )
    )

    def detect(
        _cls: Any, name: str, _binary: Any, flags: Any = (), env: Any = None
    ) -> Any:
        made = make(name, flags)
        if env:
            made.env = dict(env)
        return made

    monkeypatch.setattr(
        campaign_module.FixtureRunner,
        "detect",
        classmethod(detect),
    )
    if contrast and contrast_via_env:
        kw["contrast_env"] = {n: {"EXEC3_WORKERS": "1"} for n in contrast}
    elif contrast:
        kw["contrast_flags"] = {n: ["--contrast"] for n in contrast}
    monkeypatch.setattr(campaign_module, "_eels_commit", lambda: "abc123")
    monkeypatch.setattr(
        campaign_module,
        "_fill_pool",
        lambda *_args, **_kwargs: _FakePool(),
    )
    options = CampaignOptions(
        fork=Osaka,
        clients={name: tmp_path / name for name in failing},
        output=tmp_path / "out",
        seed_start=0,
        **kw,
    )
    return run_campaign(options, echo=echo or (lambda _msg: None))


def test_campaign_records_divergences_and_resumes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Failures on one client become one deduped signature with a bundle."""
    failing = {"geth": lambda _s: False, "erigon": lambda s: s % 3 == 1}
    state = _campaign(tmp_path, monkeypatch, failing, count=6, batch=3)
    assert state.next_seed == 6
    assert state.counts["divergence"] == 2 and state.counts["agreed"] == 4
    assert len(state.signatures) == 1
    entry = next(iter(state.signatures.values()))
    assert entry["client"] == "erigon" and entry["count"] == 2
    bundle = Path(entry["bundle"])
    assert (bundle / "verdicts.json").is_file()
    assert (tmp_path / "out" / "report.md").is_file()
    again = _campaign(tmp_path, monkeypatch, failing, count=9, batch=3)
    assert again.next_seed == 9 and again.counts["divergence"] == 3


def test_per_type_and_per_event_tallies_reach_the_report(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    The worker's per-case attributions must cross into the parent: the
    first per-type readout shipped with the worker collecting the types
    and never returning them, so every type showed zero cases.
    """
    failing = {"geth": lambda _s: False, "erigon": lambda s: s % 3 == 1}
    state = _campaign(tmp_path, monkeypatch, failing, count=6, batch=3)
    assert state.by_tx_type["0"]["cases"] == 6
    assert state.by_tx_type["4"] == {"cases": 3, "failed:erigon": 1}
    assert state.by_event["precompile"] == {"cases": 2, "failed:erigon": 2}
    report = (tmp_path / "out" / "report.md").read_text()
    assert "| 0 (legacy) | 6 | erigon=2 | - |" in report
    assert "| precompile | 2 | erigon=2/2 (100.0% -> 0.0%) |" in report
    assert "| state-gas | 6 | erigon=2/6 (33.3% -> 0.0%) |" in report
    entry = next(iter(state.signatures.values()))
    assert entry["events_necessary"] == ["precompile", "state-gas"]
    assert "| precompile state-gas |" in report
    mechanism = json.loads((Path(entry["bundle"]) / "events.json").read_text())
    assert mechanism == {
        "case": ["precompile", "state-gas"],
        "minimized": None,
    }


def test_necessary_events_are_the_intersection_of_the_hits() -> None:
    """
    An event in every hit is necessary to the mechanism. A signature
    whose hits share nothing but the events every case carries is the
    two-mechanisms-in-one-error-text fold the readout has to expose.
    """
    state = CampaignState(path=Path("/tmp/x.json"), next_seed=0)
    state.record_signature(
        "besu",
        "header mismatch",
        seed=1,
        bundle="b",
        events=["call-entry-oog", "precompile", "state-gas"],
    )
    state.record_signature(
        "besu",
        "header mismatch",
        seed=2,
        bundle="b",
        events=["child-revert", "precompile", "state-gas"],
    )
    entry = next(iter(state.signatures.values()))
    assert entry["events_necessary"] == ["precompile", "state-gas"]
    # An entry written before events were recorded is left as it was.
    state.signatures[next(iter(state.signatures))].pop("events_necessary")
    state.record_signature(
        "besu", "header mismatch", seed=3, bundle="b", events=["precompile"]
    )
    assert "events_necessary" not in entry


def test_event_contrast_reads_the_rate_without_from_the_totals() -> None:
    """The rate without the event is the remainder, not a second tally."""
    from ..fuzzer_bridge.campaign import _event_contrast

    text = _event_contrast(
        {"cases": 320, "failed:besu": 312, "refused:geth": 4},
        total_cases=1000,
        client_failures={"besu": 315},
    )
    assert text == "besu=312/320 (97.5% -> 0.4%)"
    assert _event_contrast({"cases": 5}, 10, {}) == "-"


def test_a_contrast_declared_only_by_environment_still_runs(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    Erigon's path contrast is `EXEC3_WORKERS`, not argv. A
    client declaring `contrast_env` and no `contrast_flags` must still
    get a contrast run, or its half of the panel has no self-witness.
    """
    failing = {"geth": lambda _s: False, "erigon": lambda s: s % 3 == 1}
    contrast = {"erigon": lambda s: s % 2 == 0}
    state = _campaign(
        tmp_path,
        monkeypatch,
        failing,
        contrast=contrast,
        contrast_via_env=True,
        count=6,
        batch=3,
    )
    assert state.counts["contrast-mismatch"] == 3
    assert state.contrast["erigon:contrast"]["compared"] == 6


class _KnobRunner(_FakeRunner):
    """Scripted by environment: which seeds fail under each knob setting."""

    def __init__(self, name: str, scripts: Dict[str, Any], env: Any = None):
        self.scripts = scripts
        knob = ",".join(f"{k}={v}" for k, v in sorted((env or {}).items()))
        super().__init__(name, scripts[knob], None, (), env)

    def with_flags(self, _flags: Any) -> "_FakeRunner":
        return self

    def with_env(self, env: Any) -> "_FakeRunner":
        return _KnobRunner(self.name, self.scripts, {**self.env, **env})


def test_each_named_contrast_is_its_own_witness(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    Erigon's hints-off and serial runs are different questions: a client
    that only differs serial has no hint-consumption bug, so each run
    keeps its own tally and its own signature name.
    """
    from ..fuzzer_bridge.config import ContrastRun

    scripts = {
        "": lambda s: s % 3 == 1,
        "IGNORE_BAL=true": lambda s: s % 3 == 1,
        "EXEC3_WORKERS=1": lambda _s: False,
    }
    failing = {"geth": lambda _s: False, "erigon": scripts[""]}
    state = _campaign(
        tmp_path,
        monkeypatch,
        failing,
        runner=lambda name, _flags: (
            _KnobRunner(name, scripts)
            if name == "erigon"
            else _FakeRunner(name, failing[name])
        ),
        contrasts={
            "erigon": {
                "hints-off": ContrastRun(env={"IGNORE_BAL": "true"}),
                "serial": ContrastRun(env={"EXEC3_WORKERS": "1"}),
            }
        },
        count=6,
        batch=3,
    )
    assert state.contrast["erigon:hints-off"]["compared"] == 6
    assert state.contrast["erigon:hints-off"]["mismatches"] == 0
    assert state.contrast["erigon:serial"]["mismatches"] == 2
    contrast_clients = {
        e["client"] for e in state.signatures.values() if ":" in e["client"]
    }
    assert contrast_clients == {"erigon:serial"}
    report = (tmp_path / "out" / "report.md").read_text()
    assert "| erigon:hints-off | 6 | 0 |" in report
    assert "| erigon:serial | 6 | 0 |" in report


class _SilentRunner(_FakeRunner):
    """A contrast run that never reports: every verdict a runner error."""

    def run_file(self, _path: Path, fixture_names: Any) -> Dict[str, Verdict]:
        return {
            name: Verdict(False, f"{RUNNER_ERROR_PREFIX}no result")
            for name in fixture_names
        }


class _GoesSilentRunner(_FakeRunner):
    """A primary run whose environment contrast never reports."""

    def with_env(self, env: Any) -> "_FakeRunner":
        return _SilentRunner(
            self.name, self.failing, None, self.flags, {**self.env, **env}
        )


class _RetryingRunner(_FakeRunner):
    """Passes everything, and prints a sequential retry on seed 4."""

    def run_file(self, path: Path, fixture_names: Any) -> Dict[str, Verdict]:
        names = list(fixture_names)
        self.last_stderr = (
            "BAL-RETRY block=1 "
            "exception=InvalidBlockLevelAccessListException\n"
            if "seed_4" in names
            else "unrelated noise\n"
        )
        return super().run_file(path, names)


def test_a_tagged_stderr_line_is_logged_counted_and_keeps_its_batch(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    Nethermind's retry is invisible in its verdict, so the line it prints
    is the only record: counted, logged with its lane and batch, and the
    batch kept so the line can be traced to its fixture.
    """
    failing = {"geth": lambda _s: False, "nethermind": lambda _s: False}
    state = _campaign(
        tmp_path,
        monkeypatch,
        failing,
        runner=lambda name, flags: (
            _RetryingRunner(name, failing[name], None, flags)
            if name == "nethermind"
            else _FakeRunner(name, failing[name], None, flags)
        ),
        count=6,
        batch=3,
    )
    assert state.counts["BAL-RETRY"] == 1
    log = (tmp_path / "out" / "stderr_tags.log").read_text().splitlines()
    assert len(log) == 1
    batch, lane, line = log[0].split("\t")
    assert lane == "nethermind" and line.startswith("BAL-RETRY block=1")
    assert (tmp_path / "out" / "fixtures" / batch).is_file()
    report = (tmp_path / "out" / "report.md").read_text()
    row = "| parallel retries/fallbacks (BAL-RETRY, BAL-FALLBACK) | 1, 0 |"
    assert row in report


def test_a_contrast_run_that_never_reports_fails_the_campaign(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    A lane that compares nothing reads like a lane that found nothing, so
    it stops the campaign by name after its first batch rather than
    becoming a count: erigon's contrast once lost every verdict to its
    parser and nothing made anyone look. The report is still written, so
    the stopped run leaves its row behind.
    """
    from ..fuzzer_bridge.campaign import SilentContrastError
    from ..fuzzer_bridge.config import ContrastRun

    failing = {"geth": lambda _s: False, "erigon": lambda _s: False}

    with pytest.raises(SilentContrastError, match="erigon:serial") as caught:
        _campaign(
            tmp_path,
            monkeypatch,
            failing,
            runner=lambda name, flags: (
                _GoesSilentRunner(name, failing[name], None, flags)
                if name == "erigon"
                else _FakeRunner(name, failing[name], None, flags)
            ),
            contrasts={"erigon": {"serial": ContrastRun(env={"X": "1"})}},
            count=6,
            batch=3,
        )
    assert caught.value.silent == {"erigon:serial": 3}
    report = (tmp_path / "out" / "report.md").read_text()
    assert "| erigon:serial | 0 | 3 |" in report


def test_a_client_disagreeing_with_itself_is_a_contrast_mismatch(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    The contrast run is the same client under other flags. Where the two
    runs judge a fixture differently the client has diverged from itself,
    counted and bundled without touching the panel's own classification.
    """
    failing = {"geth": lambda _s: False, "nethermind": lambda s: s % 3 == 1}
    contrast = {"nethermind": lambda s: s % 2 == 0}
    state = _campaign(
        tmp_path, monkeypatch, failing, contrast=contrast, count=6, batch=3
    )
    # Primary fails {1, 4}, contrast fails {0, 2, 4}: they differ on 0, 1, 2.
    assert state.counts["contrast-mismatch"] == 3
    assert state.contrast == {
        "nethermind:contrast": {
            "compared": 6,
            "mismatches": 3,
            "primary_failed": 2,
            "contrast_failed": 3,
        }
    }
    # The panel still sees only the primary run's two failures.
    assert state.counts["divergence"] == 2 and state.counts["agreed"] == 4
    reasons = sorted(
        e["reason"]
        for e in state.signatures.values()
        if e["client"] == "nethermind:contrast"
    )
    assert reasons == [
        "contrast run failed: nethermind mismatch at <n>",
        "primary run failed: nethermind mismatch at <n>",
    ]
    bundle = next(
        Path(e["bundle"])
        for e in state.signatures.values()
        if e["client"] == "nethermind:contrast"
    )
    verdicts = json.loads((bundle / "verdicts.json").read_text())
    assert set(verdicts) == {"nethermind", "nethermind (contrast)"}
    report = (tmp_path / "out" / "report.md").read_text()
    assert "| nethermind:contrast | 6 | 0 | 2 | 3 | 3 |" in report
    assert "| contrast mismatches (client vs itself) | 3 |" in report


def test_contrast_mismatch_ignores_refusals_and_agreement() -> None:
    """Only a pass on one side and a real failure on the other counts."""
    from ..fuzzer_bridge.campaign import contrast_mismatch

    ok, bad = Verdict(True), Verdict(False, "state root mismatch 0xab")
    refused = Verdict(False, "unable to validate fork Amsterdam")
    assert contrast_mismatch(ok, ok) is None
    assert contrast_mismatch(bad, bad) is None
    assert contrast_mismatch(ok, refused) is None
    assert contrast_mismatch(refused, ok) is None
    assert (
        contrast_mismatch(ok, bad)
        == "contrast run failed: state root mismatch <hex>"
    )
    assert (
        contrast_mismatch(bad, ok)
        == "primary run failed: state root mismatch <hex>"
    )


def test_campaign_stops_on_a_stale_client(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A client failing most of the first batch is reported as stale."""
    from ..fuzzer_bridge.baseline import StaleClientError

    failing = {"geth": lambda _s: False, "erigon": lambda _s: True}
    with pytest.raises(StaleClientError, match="erigon"):
        _campaign(tmp_path, monkeypatch, failing, count=4, batch=4)


def test_all_fail_is_not_a_client_finding(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A block every client rejects is counted, never a client signature."""
    failing = {"geth": lambda s: s == 2, "erigon": lambda s: s == 2}
    state = _campaign(
        tmp_path, monkeypatch, failing, count=4, batch=4, baseline=False
    )
    assert state.counts["all-fail"] == 1 and not state.signatures


def test_campaign_says_when_the_count_is_already_covered(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Rerunning with a count the state already passed does no work."""
    failing = {"geth": lambda _s: False}
    _campaign(tmp_path, monkeypatch, failing, count=4, batch=2)
    messages: list = []
    state = _campaign(
        tmp_path, monkeypatch, failing, echo=messages.append, count=2, batch=2
    )
    assert state.next_seed == 4
    assert any("already covered" in m for m in messages)


def test_fill_case_swallows_the_spec_debug_dump(
    monkeypatch: Any, capsys: Any
) -> None:
    """A block that fails to build raises without printing allocs."""
    from ..fuzzer_bridge import campaign as campaign_module

    class _Loud:
        def generate(self, **_: Any) -> Any:
            print("Alloc(root={...})")
            raise RuntimeError("invalid block")

    monkeypatch.setattr(
        campaign_module, "blockchain_test_from_fuzzer", lambda _c, _f: _Loud()
    )
    monkeypatch.setattr(
        campaign_module, "resolve_measured_gas", lambda case, _f, _fill: case
    )
    with pytest.raises(RuntimeError, match="invalid block"):
        campaign_module.fill_case(None, Osaka, None)  # type: ignore[arg-type]
    assert capsys.readouterr().out == ""


def test_co_failure_yields_one_signature_per_client(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A case both clients reject records two signatures, not a joint one."""
    failing = {
        "geth": lambda _s: False,
        "besu": lambda _s: True,
        "erigon": lambda s: s == 0,
    }
    state = _campaign(
        tmp_path, monkeypatch, failing, count=2, batch=2, baseline=False
    )
    clients = {e["client"] for e in state.signatures.values()}
    assert clients == {"besu", "erigon"}
    erigon = next(
        e for e in state.signatures.values() if e["client"] == "erigon"
    )
    assert erigon["count"] == 1
    for entry in state.signatures.values():
        assert "besu" not in entry["reason"] or entry["client"] == "besu"


def test_known_signature_is_counted_but_not_bundled(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A known reason suppresses bundling and findings, keeping the count."""
    failing = {"geth": lambda _s: False, "besu": lambda _s: True}
    state = _campaign(
        tmp_path,
        monkeypatch,
        failing,
        count=3,
        batch=3,
        baseline=False,
        known=(("besu", "mismatch"),),
    )
    assert state.unique_findings() == 0
    entry = next(iter(state.signatures.values()))
    assert entry["known"] and entry["count"] == 3 and entry["bundle"] is None
    assert not any((tmp_path / "out" / "corpus").iterdir())
    report = (tmp_path / "out" / "report.md").read_text()
    assert "Known (suppressed)" in report


def test_state_reset_when_signature_scheme_changes(tmp_path: Path) -> None:
    """An older-scheme state keeps its counts but recounts signatures."""
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "next_seed": 500,
                "counts": {"divergence": 9},
                "client_failures": {"besu": 9},
                "signatures": {"besu+erigon--x": {"minority": ["besu"]}},
            }
        )
    )
    state = CampaignState.load(path, seed_start=0)
    assert state.next_seed == 500 and state.counts["divergence"] == 9
    assert state.signatures == {} and state.signatures_reset


def test_a_refused_input_is_not_a_client_failure() -> None:
    """
    A tool that refuses the input never ran, so it is excluded from both
    sides: it is not a failure, and the clients that did run are judged
    only against each other.
    """
    from ..fuzzer_bridge.campaign import classify, partition_rejections
    from ..fuzzer_bridge.runners import Verdict

    verdicts = {
        "geth": Verdict(False, "Unable to validate CALLF"),
        "besu": Verdict(True),
        "erigon": Verdict(True),
    }
    ran, rejected = partition_rejections(verdicts)
    assert set(rejected) == {"geth"}
    assert set(ran) == {"besu", "erigon"}
    # Without the partition this reads as a geth divergence.
    assert classify(ran) == "agreed"


def test_every_tool_refusing_is_its_own_bucket() -> None:
    """No tool ran, so the case is neither agreement nor divergence."""
    from ..fuzzer_bridge.campaign import classify, partition_rejections
    from ..fuzzer_bridge.runners import Verdict

    ran, rejected = partition_rejections(
        {"geth": Verdict(False, "Unable to validate CALLF")}
    )
    assert not ran and set(rejected) == {"geth"}
    assert classify(ran) == "all-rejected"


def test_a_real_failure_is_never_read_as_a_refusal() -> None:
    """The near-miss: a genuine divergence must survive the partition."""
    from ..fuzzer_bridge.campaign import classify, partition_rejections
    from ..fuzzer_bridge.runners import Verdict

    ran, rejected = partition_rejections(
        {
            "erigon": Verdict(False, "block access list mismatch"),
            "geth": Verdict(True),
        }
    )
    assert not rejected
    assert classify(ran) == "divergence"


def test_a_runner_that_never_answered_is_not_a_client_failure() -> None:
    """
    A timed-out runner produced no judgement, so the clients that did
    answer are judged only against each other. Left in, the harness
    manufactures a divergence and a signature out of its own timeout.
    """
    from ..fuzzer_bridge.campaign import classify, partition_runner_errors
    from ..fuzzer_bridge.runners import Verdict

    verdicts = {
        "nethermind": Verdict(False, "runner-error: timed out after 30s"),
        "geth": Verdict(True),
        "besu": Verdict(True),
    }
    ran, errored = partition_runner_errors(verdicts)
    assert set(errored) == {"nethermind"}
    assert set(ran) == {"geth", "besu"}
    assert classify(ran) == "agreed"


def test_a_fixture_the_runner_skipped_is_not_a_client_failure() -> None:
    """
    The other half of a harness outcome: the runner ran but never
    mentioned this fixture, so it holds no verdict on it.
    """
    from ..fuzzer_bridge.campaign import classify, partition_runner_errors
    from ..fuzzer_bridge.runners import Verdict

    ran, errored = partition_runner_errors(
        {
            "besu": Verdict(False, "runner-error: no result from besu"),
            "geth": Verdict(True),
        }
    )
    assert set(errored) == {"besu"}
    assert classify(ran) == "agreed"


def test_a_real_failure_is_never_read_as_a_runner_error() -> None:
    """
    The near-miss: a client that answered and rejected the block is a
    finding, however much its text reads like plumbing.
    """
    from ..fuzzer_bridge.campaign import classify, partition_runner_errors
    from ..fuzzer_bridge.runners import Verdict

    ran, errored = partition_runner_errors(
        {
            "erigon": Verdict(False, "error: no result for block <hex>"),
            "geth": Verdict(True),
        }
    )
    assert not errored
    assert classify(ran) == "divergence"


def test_a_batch_level_failure_is_a_harness_outcome_not_a_refusal() -> None:
    """
    The confusable case, and why the runner-error partition runs first.

    A runner exiting non-zero reports one stderr for the whole file, so a
    refusal phrase in it describes at most one of the few hundred cases
    the message is attached to. Counting all of them as inputs geth
    refused would overstate refusals by the batch size and hide the fact
    that geth judged nothing.
    """
    from ..fuzzer_bridge.campaign import (
        partition_rejections,
        partition_runner_errors,
    )
    from ..fuzzer_bridge.runners import Verdict

    verdicts = {
        "geth": Verdict(False, "runner-error: Unable to validate CALLF"),
        "besu": Verdict(True),
    }
    ran, errored = partition_runner_errors(verdicts)
    assert set(errored) == {"geth"}
    # Without the ordering this lands in rejections and reads as a
    # per-case refusal of every fixture in the file.
    assert not partition_rejections(ran)[1]


def test_a_contrast_pair_missing_a_verdict_is_not_a_mismatch() -> None:
    """
    A client cannot disagree with itself on a case one of its two runs
    never judged; the pair leaves no finding and no comparison.
    """
    from ..fuzzer_bridge.campaign import (
        contrast_excluded,
        contrast_mismatch,
    )
    from ..fuzzer_bridge.runners import Verdict

    timed_out = Verdict(False, "runner-error: timed out after 30s")
    assert contrast_excluded(timed_out, Verdict(True))
    assert contrast_mismatch(timed_out, Verdict(True)) is None
    # The kill check: a genuine self-disagreement still reports.
    real = Verdict(False, "block access list mismatch")
    assert not contrast_excluded(real, Verdict(True))
    assert contrast_mismatch(real, Verdict(True)) is not None


def test_every_hit_seed_is_recorded_up_to_the_cap(tmp_path: Path) -> None:
    """
    Signature dedup must not lose the seeds. The first blind campaign
    kept only `first_seed`, which made its 46 erigon hits unrecoverable.
    """
    from ..fuzzer_bridge.campaign import SEED_SAMPLE_CAP, CampaignState

    state = CampaignState(path=tmp_path / "state.json", next_seed=0)
    for seed in range(SEED_SAMPLE_CAP + 10):
        state.record_signature(
            "erigon", "block access list mismatch", seed=seed, bundle="b"
        )
    entry = next(iter(state.signatures.values()))
    assert entry["count"] == SEED_SAMPLE_CAP + 10
    assert entry["seeds"] == list(range(SEED_SAMPLE_CAP))
    assert entry["first_seed"] == 0


def test_seeds_and_rejections_survive_a_resume(tmp_path: Path) -> None:
    """A Ctrl-C mid-campaign must not drop either record."""
    from ..fuzzer_bridge.campaign import CampaignState

    path = tmp_path / "state.json"
    state = CampaignState(path=path, next_seed=0)
    state.rejections["geth"] = 7
    state.record_signature("erigon", "boom", seed=42, bundle="b")
    state.record_signature("erigon", "boom", seed=99, bundle="b")
    state.save()

    resumed = CampaignState.load(path, seed_start=0)
    assert resumed.rejections == {"geth": 7}
    assert next(iter(resumed.signatures.values()))["seeds"] == [42, 99]


def test_the_case_deadline_interrupts_a_runaway_fill() -> None:
    """The budget fires, and only inside the block it guards."""
    import time as _time

    from ..fuzzer_bridge.campaign import FillTimeoutError, _case_deadline

    with pytest.raises(FillTimeoutError):
        with _case_deadline(0.2):
            _time.sleep(5)
    # The timer is cleared on the way out, so later work is not hit.
    with _case_deadline(5):
        _time.sleep(0.05)


def test_timing_summary_reports_the_tail_and_names_the_seed() -> None:
    """
    A mean hides the case that dominates a shard; the quantiles and the
    slowest seed are what make it readable without a rerun.
    """
    from ..fuzzer_bridge.campaign import _timing_summary

    summary = _timing_summary([(1, 10.0), (2, 50.0), (3, 9000.0), (4, 20.0)])
    assert summary["ms_per_case_median"] == 35.0
    assert summary["ms_per_case_max"] == 9000.0
    assert summary["slowest_seed"] == 3


def test_a_timed_out_case_is_recorded_and_the_slice_continues(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """One pathological case must not cost the rest of its shard."""
    import time as _time

    from ..fuzzer_bridge import campaign as mod

    class _Eels:
        opcode_count_per_block: list = []
        compute_signature = False
        last_signature = None

        def reset_opcode_count(self) -> None:
            pass

    monkeypatch.setattr(mod, "FILL_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(mod, "ExecutionSpecsTransitionTool", _Eels)
    monkeypatch.setattr(
        mod, "_FILL", {"fork": Osaka, "format": mod.BlockchainFixture}
    )
    mod._FILL["eels"] = mod._reference_tool()
    mod._FILL["capabilities"] = mod._capabilities(mod._FILL["eels"])

    def fake_generate(fork: Any, seed: int) -> Any:
        del fork
        return SimpleNamespace(transactions=[], _seed=seed)

    monkeypatch.setattr(mod, "generate_fuzzer_output", fake_generate)

    def fake_fill(
        case: Any,
        fork: Any,
        eels: Any,
        violations: Any = None,
        fixture_format: Any = None,
    ) -> Dict[str, Any]:
        del fork, eels, violations, fixture_format
        if case._seed == 2:
            _time.sleep(5)
        return {"ok": case._seed}

    monkeypatch.setattr(mod, "fill_case", fake_fill)
    result = mod._fill_slice(([1, 2, 3], str(tmp_path)))

    assert result["timeouts"] == {2: 0.2}
    assert result["names"] == ["seed_1", "seed_3"]
    assert result["case_types"] == {"seed_1": [], "seed_3": []}
    assert result["case_events"] == {"seed_1": [], "seed_3": []}
    # The replacement tool is configured like the first, not bare.
    assert mod._FILL["eels"].compute_signature is True
    meta = json.loads(next(tmp_path.glob("*.meta.json")).read_text())
    assert meta["fill_timeouts"] == {"2": 0.2}
    assert meta["slowest_seed"] == 2


def test_a_degraded_rebuild_after_a_timeout_stops_the_worker(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    Recovery is rarely taken, so a rebuilt tool that silently lost the
    tracer or the witness fills every later case blind. The rebuild must
    observe exactly what the original did, or the worker stops.
    """
    import time as _time

    from ..fuzzer_bridge import campaign as mod

    class _Eels:
        opcode_count_per_block: list = []
        compute_signature = False
        compute_bal_witness = False
        last_signature = None

        def reset_opcode_count(self) -> None:
            pass

    monkeypatch.setattr(mod, "FILL_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(mod, "ExecutionSpecsTransitionTool", _Eels)
    monkeypatch.setattr(
        mod, "_FILL", {"fork": Osaka, "format": mod.BlockchainFixture}
    )
    original = mod._reference_tool()
    original.compute_bal_witness = True
    mod._FILL["eels"] = original
    mod._FILL["capabilities"] = mod._capabilities(original)
    monkeypatch.setattr(
        mod, "generate_fuzzer_output", lambda _f, s: SimpleNamespace(_seed=s)
    )

    def fake_fill(*_: Any, **__: Any) -> Dict[str, Any]:
        _time.sleep(5)
        return {}

    monkeypatch.setattr(mod, "fill_case", fake_fill)
    with pytest.raises(mod.RecoveryMismatchError, match="compute_bal_witness"):
        mod._fill_slice(([1], str(tmp_path)))


def test_a_shard_from_another_generator_stops_the_run() -> None:
    """
    A worker respawned onto a different checkout fills with a different
    generator; the parent must refuse the mix rather than record a run
    whose cases came from two versions with no record of which is which.
    """
    from ..fuzzer_bridge.campaign import MixedGeneratorError
    from ..fuzzer_bridge.generator import GENERATOR_VERSION

    def check(shard_version: int) -> None:
        if shard_version != GENERATOR_VERSION:
            raise MixedGeneratorError("mixed")

    check(GENERATOR_VERSION)
    with pytest.raises(MixedGeneratorError):
        check(GENERATOR_VERSION - 1)


def test_a_fill_slice_reports_its_own_generator_version(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The value must come from the worker, not from the parent."""
    from ..fuzzer_bridge import campaign as mod
    from ..fuzzer_bridge.generator import GENERATOR_VERSION

    class _Eels:
        opcode_count_per_block: list = []

        def reset_opcode_count(self) -> None:
            pass

    monkeypatch.setattr(
        mod,
        "_FILL",
        {"fork": Osaka, "eels": _Eels(), "format": mod.BlockchainFixture},
    )

    def fake_generate(fork: Any, seed: int) -> Any:
        del fork
        return SimpleNamespace(transactions=[], _seed=seed)

    monkeypatch.setattr(mod, "generate_fuzzer_output", fake_generate)

    def fake_fill(
        case: Any,
        fork: Any,
        eels: Any,
        violations: Any = None,
        fixture_format: Any = None,
    ) -> Dict[str, Any]:
        del fork, eels, violations, fixture_format
        return {"ok": case._seed}

    monkeypatch.setattr(mod, "fill_case", fake_fill)
    result = mod._fill_slice(([1, 2], str(tmp_path)))
    assert result["generator_version"] == GENERATOR_VERSION


def test_invariant_violations_are_counted_not_warned(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    A violation has to survive the run as a number with its seed.

    Warned-only diagnostics are the failure that lost the per-case
    timings twice: they land in a log stream nobody retains and the first
    real one is scrolled past in a 600-minute run.
    """
    from ..fuzzer_bridge import campaign as mod

    class _Eels:
        opcode_count_per_block: list = []
        last_bal_witness = None

        def reset_opcode_count(self) -> None:
            pass

    monkeypatch.setattr(
        mod,
        "_FILL",
        {"fork": Osaka, "eels": _Eels(), "format": mod.BlockchainFixture},
    )

    def fake_generate(fork: Any, seed: int) -> Any:
        del fork
        return SimpleNamespace(transactions=[], _seed=seed)

    def fake_fill(
        case: Any,
        fork: Any,
        eels: Any,
        violations: Any = None,
        fixture_format: Any = None,
    ) -> Dict[str, Any]:
        del fork, eels, fixture_format
        if case._seed == 2 and violations is not None:
            violations.append(SimpleNamespace(invariant="bal_access_witness"))
        return {"ok": case._seed}

    monkeypatch.setattr(mod, "generate_fuzzer_output", fake_generate)
    monkeypatch.setattr(mod, "fill_case", fake_fill)
    result = mod._fill_slice(([1, 2, 3], str(tmp_path)))

    assert result["violations"] == {2: ["bal_access_witness"]}
    meta = json.loads(next(tmp_path.glob("*.meta.json")).read_text())
    assert meta["invariant_violations"] == {"2": ["bal_access_witness"]}
    assert "bracket_width_max" in meta


def test_the_campaign_leaves_invariant_checks_off_by_default() -> None:
    """
    Enabling them is a per-run choice, not a default: they are a
    process-global switch and a long lane should not acquire one
    implicitly.
    """
    from ..fuzzer_bridge.campaign import CampaignOptions

    assert CampaignOptions.__dataclass_fields__[
        "invariant_checks"
    ].default is (False)


def test_per_type_tallies_split_failures_and_refusals() -> None:
    """
    A client refusing a type the spec accepts is where typed-transaction
    bugs have surfaced, and a total that mixes the types together cannot
    show it. A case carrying several types counts under each.
    """
    from ..fuzzer_bridge.campaign import CampaignState, render_report

    state = CampaignState(path=Path("/tmp/x.json"), next_seed=0)
    state.by_tx_type = {
        "0": {"cases": 40, "failed:besu": 3},
        "4": {"cases": 12, "refused:geth": 5, "failed:erigon": 1},
    }
    report = render_report(
        state, fork="Amsterdam", versions={"geth": "v1"}, elapsed_seconds=1.0
    )
    assert "| 0 (legacy) | 40 | besu=3 | - |" in report
    assert "| 4 (set-code) | 12 | erigon=1 | geth=5 |" in report


def test_case_tx_types_reads_every_type_present() -> None:
    """Attribution is per type carried, not per transaction."""
    from ..fuzzer_bridge.campaign import _case_tx_types

    case = SimpleNamespace(
        transactions=[
            SimpleNamespace(
                authorization_list=None,
                max_fee_per_blob_gas=None,
                max_fee_per_gas=None,
                access_list=None,
            ),
            SimpleNamespace(
                authorization_list=[object()],
                max_fee_per_blob_gas=None,
                max_fee_per_gas=1,
                access_list=None,
            ),
            SimpleNamespace(
                authorization_list=None,
                max_fee_per_blob_gas=None,
                max_fee_per_gas=1,
                access_list=None,
            ),
        ]
    )
    assert _case_tx_types(case) == {0, 2, 4}


class _SpecAwareRunner:
    """Passes a fixture iff its header says it came from the spec."""

    def __init__(self, name: str, fail_producer_seeds: Any) -> None:
        self.name = name
        self.fail_producer_seeds = fail_producer_seeds

    def run_file(self, path: Path, names: Any) -> Dict[str, Verdict]:
        fixtures = json.loads(Path(path).read_text())
        out = {}
        for n in names:
            root = fixtures[n]["blocks"][0]["blockHeader"]["stateRoot"]
            seed = int(n.split("_")[1])
            failing = root == "producer" and seed in self.fail_producer_seeds
            out[n] = Verdict(
                not failing, f"{self.name} root mismatch" if failing else ""
            )
        return out


def test_escalation_rejudges_clients_only_where_the_producer_was_wrong(
    tmp_path: Path,
) -> None:
    """
    Seed 2: the client dissents and EELS agrees with the producer -- a
    client finding, verdicts stand. Seed 3: the client dissents and EELS
    disagrees with the producer -- the producer was wrong; the client is
    judged again on the spec's fixture and passes. Seed 1 agreed and is
    never escalated.
    """
    from ..fuzzer_bridge.campaign import escalate

    names = ["seed_1", "seed_2", "seed_3"]
    produced = {
        n: {
            "blocks": [
                {"blockHeader": {"stateRoot": "producer", "gasUsed": 1}}
            ]
        }
        for n in names
    }
    batch = tmp_path / "batch_1_3.json"
    batch.write_text(json.dumps(produced))
    erigon = _SpecAwareRunner("erigon", {2, 3})
    geth = _SpecAwareRunner("geth", set())
    runners: Any = {"geth": geth, "erigon": erigon}
    results = {c: r.run_file(batch, names) for c, r in runners.items()}
    assert not results["erigon"]["seed_2"].passed
    assert not results["erigon"]["seed_3"].passed

    def fill_spec(name: str) -> Any:
        root = "producer" if name == "seed_2" else "spec"
        return (
            {"blocks": [{"blockHeader": {"stateRoot": root, "gasUsed": 1}}]},
            ["state-gas"],
        )

    found = escalate(
        names,
        results,
        produced,
        fill_spec=fill_spec,
        runners=runners,
        spec_file=tmp_path / "batch_1_3_eels.json",
    )
    assert found.escalated == ["seed_2", "seed_3"]
    assert found.disagreements == {"seed_3": ["stateRoot"]}
    assert found.events == {"seed_2": ["state-gas"], "seed_3": ["state-gas"]}
    # Seed 2 stands as a client finding; seed 3 was the producer.
    assert not results["erigon"]["seed_2"].passed
    assert (
        results["erigon"]["seed_3"].passed and results["geth"]["seed_3"].passed
    )
    assert set(json.loads((tmp_path / "batch_1_3_eels.json").read_text())) == {
        "seed_3"
    }


def test_a_producer_fill_carries_no_events(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The producer has no tracer; its shards say so instead of guessing."""
    from ..fuzzer_bridge import campaign as mod

    class _Producer:
        opcode_count_per_block: list = []

        def reset_opcode_count(self) -> None:
            pass

    monkeypatch.setattr(
        mod.TransitionTool,
        "from_binary_path",
        classmethod(lambda _cls, **_: _Producer()),
    )
    monkeypatch.setattr(mod, "_FILL", {})
    monkeypatch.setattr(mod, "_fork_by_name", lambda _n: Osaka)
    mod._init_fill_worker("Osaka", False, "/opt/evmone/evmone")
    assert mod._FILL["capabilities"]["tool"] == "_Producer"
    assert mod._FILL["capabilities"]["compute_signature"] is False
    monkeypatch.setattr(
        mod,
        "generate_fuzzer_output",
        lambda _f, s: SimpleNamespace(transactions=[], _seed=s),
    )
    monkeypatch.setattr(
        mod, "fill_case", lambda case, *_, **__: {"ok": case._seed}
    )
    result = mod._fill_slice(([7], str(tmp_path)))
    assert result["names"] == ["seed_7"]
    assert result["case_events"] == {"seed_7": []}


def test_a_campaign_writes_only_formats_its_runners_can_read() -> None:
    """
    The import lane and the newPayload lane each read one format. Engine X
    is refused until a campaign can give each case its own pre-allocation
    group; asking for it has to fail before a campaign starts, not after
    it has filled a night of cases no runner will read.
    """
    from ..fuzzer_bridge.campaign import CampaignOptions, campaign_format

    assert campaign_format("blockchain_test").format_name == "blockchain_test"
    assert (
        campaign_format("blockchain_test_engine").format_name
        == "blockchain_test_engine"
    )
    for refused in ("blockchain_test_engine_x", "state_test", "bogus"):
        with pytest.raises(ValueError, match="not one a campaign writes"):
            campaign_format(refused)
    with pytest.raises(ValueError, match="not one a campaign writes"):
        CampaignOptions(
            fork=Osaka,
            clients={},
            output=Path("unused"),
            fixture_format="blockchain_test_engine_x",
        )


def test_an_engine_fixture_carries_the_access_list_where_loaders_read_it() -> (
    None
):
    """
    The premise the newPayload lane rests on, witnessed on a real fill:
    nethermind's blocktest loader drops the list, its engine loader reads
    it from `params[0].blockAccessList`. If the engine format stopped
    putting it there, the lane would reach the parallel processor on
    nothing -- so this fills a real case rather than trusting the model.
    The near-miss is the import format, which has no payload to carry it.
    """
    from ..fuzzer_bridge import campaign as mod
    from ..fuzzer_bridge.generator import generate_fuzzer_output

    mod._init_fill_worker("Amsterdam", fixture_format="blockchain_test_engine")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    case = generate_fuzzer_output(fork, 700001)

    engine = mod.fill_case(
        case, fork, eels, fixture_format=mod._FILL["format"]
    )
    assert engine["_info"]["fixture-format"] == "blockchain_test_engine"
    payload = engine["engineNewPayloads"][0]
    assert int(payload["newPayloadVersion"]) >= 5
    assert payload["params"][0]["blockAccessList"]

    imported = mod.fill_case(case, fork, eels)
    assert "engineNewPayloads" not in imported
    assert imported["_info"]["fixture-format"] == "blockchain_test"


def test_the_manifest_records_each_client_s_environment(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    A verdict is reproducible only if the toolchain it ran under is
    written down with it.
    """
    failing = {"besu": lambda _s: False}
    _campaign(
        tmp_path,
        monkeypatch,
        failing,
        count=3,
        batch=3,
        client_env={"besu": {"JAVA_HOME": "/opt/jdk-25"}},
    )
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["client_env"] == {"besu": {"JAVA_HOME": "/opt/jdk-25"}}


def test_the_manifest_names_the_format_the_run_wrote(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    A verdict is about a client's import path or its newPayload path,
    which are different code; a manifest silent on which would leave every
    verdict in the run ambiguous about what it exercised.
    """
    failing = {"geth": lambda _s: False}
    _campaign(
        tmp_path,
        monkeypatch,
        failing,
        count=3,
        batch=3,
        fixture_format="blockchain_test_engine",
    )
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["fixture_format"] == "blockchain_test_engine"


def _splitting_runner(fails: Any) -> Any:
    """A runner whose file runs error on every fixture when `fails` says."""
    from ..fuzzer_bridge.runners import (
        RUNNER_ERROR_PREFIX,
        FixtureRunner,
        Verdict,
    )

    runner = FixtureRunner("besu", Path("/bin/x"), "BesuFixtureConsumer")
    runner.runs = []  # type: ignore[attr-defined]

    def run_file(_path: Path, names: Any) -> Any:
        names = list(names)
        runner.runs.append(names)  # type: ignore[attr-defined]
        runner.last_stderr = f"BAL-RETRY {len(names)}\n"
        if fails(names):
            return {
                n: Verdict(False, f"{RUNNER_ERROR_PREFIX}parse failed")
                for n in names
            }
        return {n: Verdict(True) for n in names}

    runner.run_file = run_file  # type: ignore[assignment]
    return runner


def test_a_runner_error_is_split_down_to_the_fixture_that_caused_it(
    tmp_path: Path,
) -> None:
    """
    One fixture the runner cannot load errors its whole streamed batch.
    Halves holding the error are judged again until only that fixture
    carries it; every other verdict comes back, the split files are
    removed, and stderr from every run is kept.
    """
    from ..fuzzer_bridge.campaign import judge_splitting

    names = [f"seed_{i}" for i in range(8)]
    batch = tmp_path / "batch.json"
    batch.write_text(json.dumps({n: {} for n in names}))
    runner = _splitting_runner(lambda part: "seed_5" in part)
    verdicts = judge_splitting(runner, batch, names)
    assert [n for n, v in verdicts.items() if not v.passed] == ["seed_5"]
    # A streamed batch errors on every fixture, so both halves run at
    # each level: 1 + 2 + 2 + 2, not one run per fixture.
    assert len(runner.runs) == 7
    assert sorted(p.name for p in tmp_path.iterdir()) == ["batch.json"]
    assert runner.last_stderr.count("BAL-RETRY") == 7


def test_a_runner_that_fails_everything_is_not_split_to_the_bottom(
    tmp_path: Path,
) -> None:
    """
    When both halves error on every fixture the runner is failing, not a
    fixture: splitting stops after one level instead of running every
    fixture alone, and every verdict stays a runner error.
    """
    from ..fuzzer_bridge.campaign import judge_splitting

    names = [f"seed_{i}" for i in range(8)]
    batch = tmp_path / "batch.json"
    batch.write_text(json.dumps({n: {} for n in names}))
    runner = _splitting_runner(lambda _part: True)
    verdicts = judge_splitting(runner, batch, names)
    assert not any(v.passed for v in verdicts.values())
    assert len(runner.runs) == 3


def test_a_clean_batch_is_judged_once(tmp_path: Path) -> None:
    """No runner error, no split."""
    from ..fuzzer_bridge.campaign import judge_splitting

    names = ["seed_0", "seed_1"]
    batch = tmp_path / "batch.json"
    batch.write_text(json.dumps({n: {} for n in names}))
    runner = _splitting_runner(lambda _part: False)
    assert all(
        v.passed for v in judge_splitting(runner, batch, names).values()
    )
    assert len(runner.runs) == 1


def test_a_stop_signal_finishes_the_batch_saves_state_and_resumes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    With no budget a campaign runs until stopped. SIGTERM mid-batch lets
    that batch finish and be counted, saves state as stopped, and drops
    the batches still filling; a resumed run starts at the next seed.
    """
    import os
    import signal

    sent: List[int] = []

    def geth(seed: int) -> bool:
        if not sent:
            sent.append(seed)
            os.kill(os.getpid(), signal.SIGTERM)
        return False

    quiet = {"geth": geth, "erigon": lambda _s: False}
    state = _campaign(tmp_path, monkeypatch, quiet, batch=3, baseline=False)
    assert state.next_seed == 3
    assert state.counts["agreed"] == 3
    assert (state.status, state.status_reason) == (
        "stopped",
        "SIGTERM after seed 2",
    )
    saved = json.loads((tmp_path / "out" / "state.json").read_text())
    assert saved["status"] == "stopped" and saved["next_seed"] == 3
    assert list((tmp_path / "out" / "fixtures").iterdir()) == []
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL

    resumed = _campaign(
        tmp_path,
        monkeypatch,
        {"geth": lambda _s: False, "erigon": lambda _s: False},
        batch=3,
        count=6,
        baseline=False,
    )
    assert resumed.next_seed == 6 and resumed.counts["agreed"] == 6
    assert resumed.status == "done"


def test_a_control_gone_quiet_pauses_the_campaign(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    The positive control never fires, so once the window is full the
    control rate is below its band: the campaign pauses after that batch
    with the reason in its state, instead of counting on. A resumed run
    starts a fresh window.
    """
    from ..fuzzer_bridge.health import HealthPolicy

    policy = HealthPolicy(
        window=3, control_client="geth", control_band=(0.5, 1.0)
    )
    quiet = {"geth": lambda _s: False, "erigon": lambda _s: False}
    state = _campaign(
        tmp_path, monkeypatch, quiet, batch=3, baseline=False, health=policy
    )
    assert state.next_seed == 3
    assert state.status == "paused"
    assert "control geth at 0.00%" in state.status_reason
    saved = json.loads((tmp_path / "out" / "state.json").read_text())
    assert saved["status"] == "paused" and saved["health"]["checking"]

    firing = {"geth": lambda _s: True, "erigon": lambda _s: False}
    resumed = _campaign(
        tmp_path,
        monkeypatch,
        firing,
        batch=3,
        count=9,
        baseline=False,
        health=policy,
    )
    assert resumed.next_seed == 9 and resumed.status == "done"
    assert resumed.health["control_rate"] == 1.0


def test_a_rebuilt_binary_opens_a_new_segment(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    Segments hold the binaries fixed. A client rebuilt between runs
    closes the first segment at the last seed it judged and opens a new
    one; a finding counts its hits per segment and its bundle names the
    segment, whose manifest names the binaries.
    """
    (tmp_path / "geth").write_text("build one")
    (tmp_path / "erigon").write_text("erigon")
    failing = {"geth": lambda _s: False, "erigon": lambda _s: True}
    first = _campaign(
        tmp_path, monkeypatch, failing, batch=3, count=3, baseline=False
    )
    (only,) = first.segments
    assert (only["id"], only["first_seed"]) == (first.segment, 0)

    (tmp_path / "geth").write_text("build two")
    second = _campaign(
        tmp_path, monkeypatch, failing, batch=3, count=6, baseline=False
    )
    old, new = second.segments
    assert old["id"] == first.segment and old["last_seed"] == 2
    assert new["id"] == second.segment != first.segment
    assert new["first_seed"] == 3 and new["last_seed"] is None
    (finding,) = second.signatures.values()
    assert finding["first_segment"] == first.segment
    assert finding["segments"] == {first.segment: 3, second.segment: 3}
    manifests = tmp_path / "out" / "segments"
    assert {p.stem for p in manifests.iterdir()} == {old["id"], new["id"]}
    bundle = Path(finding["bundle"])
    assert json.loads((bundle / "segment.json").read_text())["segment"] == (
        first.segment
    )


def test_a_new_segment_runs_the_baseline_gate_again(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    The gate that refuses a stale client runs on a campaign's first
    batch; a new segment is a new comparison, so it runs again there,
    while a plain resume within the same segment does not.
    """
    from ..fuzzer_bridge.baseline import StaleClientError

    (tmp_path / "geth").write_text("build one")
    (tmp_path / "erigon").write_text("erigon")
    clean = {"geth": lambda _s: False, "erigon": lambda _s: False}
    _campaign(tmp_path, monkeypatch, clean, batch=3, count=3)
    broken = {"geth": lambda _s: True, "erigon": lambda _s: False}
    resumed = _campaign(tmp_path, monkeypatch, broken, batch=3, count=6)
    assert resumed.next_seed == 6

    (tmp_path / "geth").write_text("build two")
    with pytest.raises(StaleClientError):
        _campaign(tmp_path, monkeypatch, broken, batch=3, count=9)


def test_a_new_finding_alerts_once_and_a_known_one_never(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    A digest the campaign has not seen, and that `known:` does not list,
    raises one alert in the batch it first appears; its later hits and
    every known digest only count.
    """
    from ..fuzzer_bridge import campaign as campaign_module

    sent: List[str] = []
    monkeypatch.setattr(campaign_module, "send_alert", sent.append)
    failing = {
        "geth": lambda s: s in (0, 3),
        "erigon": lambda s: s in (1, 4),
    }
    state = _campaign(
        tmp_path,
        monkeypatch,
        failing,
        batch=3,
        count=6,
        baseline=False,
        known=(("geth", "geth mismatch"),),
    )
    assert len(state.signatures) == 2
    (alert,) = sent
    assert "seeds 0..2" in alert and "1 new finding(s)" in alert
    assert "erigon" in alert and "geth" not in alert


def test_a_token_in_a_client_env_never_reaches_disk(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    Manifests keep a toolchain path and only the names of other
    variables: a token put in a client's `env:` by mistake is in neither
    the run's manifest nor its segment's.
    """
    failing = {"besu": lambda _s: False}
    state = _campaign(
        tmp_path,
        monkeypatch,
        failing,
        count=3,
        batch=3,
        client_env={
            "besu": {"JAVA_HOME": "/opt/jdk-25", "API_TOKEN": "hunter2"}
        },
    )
    out = tmp_path / "out"
    for path in (
        out / "manifest.json",
        out / "segments" / f"{state.segment}.json",
    ):
        text = path.read_text()
        assert "hunter2" not in text
        assert json.loads(text)["client_env"] == {
            "besu": {"API_TOKEN": "[redacted]", "JAVA_HOME": "/opt/jdk-25"}
        }
