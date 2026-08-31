"""Tests for the campaign loop's client-independent core."""

import json
from pathlib import Path
from typing import Any, Dict

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
                "errors": {},
                "seconds": 0.01,
                "rss_mb": 1,
            }
        )
        return future


class _FakeRunner:
    """Scripted runner: `failing` decides which seeds this client rejects."""

    def __init__(self, name: str, failing: Any) -> None:
        self.name = name
        self.failing = failing

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
    **kw: Any,
) -> Any:
    from ..fuzzer_bridge import campaign as campaign_module
    from ..fuzzer_bridge.campaign import CampaignOptions, run_campaign

    monkeypatch.setattr(
        campaign_module.FixtureRunner,
        "detect",
        classmethod(
            lambda _cls, name, _binary: _FakeRunner(name, failing[name])
        ),
    )
    monkeypatch.setattr(campaign_module, "_eels_commit", lambda: "abc123")
    monkeypatch.setattr(
        campaign_module, "_fill_pool", lambda _workers, _fork: _FakePool()
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

        def reset_opcode_count(self) -> None:
            pass

    monkeypatch.setattr(mod, "FILL_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(mod, "_FILL", {"fork": Osaka, "eels": _Eels()})
    monkeypatch.setattr(mod, "ExecutionSpecsTransitionTool", _Eels)

    def fake_generate(fork: Any, seed: int) -> int:
        del fork
        return seed

    monkeypatch.setattr(mod, "generate_fuzzer_output", fake_generate)

    def fake_fill(case: Any, fork: Any, eels: Any) -> Dict[str, Any]:
        del fork, eels
        if case == 2:
            _time.sleep(5)
        return {"ok": case}

    monkeypatch.setattr(mod, "fill_case", fake_fill)
    result = mod._fill_slice(([1, 2, 3], str(tmp_path)))

    assert result["timeouts"] == {2: 0.2}
    assert result["names"] == ["seed_1", "seed_3"]
    meta = json.loads(next(tmp_path.glob("*.meta.json")).read_text())
    assert meta["fill_timeouts"] == {"2": 0.2}
    assert meta["slowest_seed"] == 2
