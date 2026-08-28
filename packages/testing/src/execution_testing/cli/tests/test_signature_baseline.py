"""Tests for signature novelty tracking and the generator baseline."""

from typing import Iterable, Tuple

from execution_testing.cli.fuzzer_bridge.signature_baseline import (
    NoveltyTracker,
    fork_reach_space,
    novelty_curve,
    render_curve,
    render_unreached,
    signature_baseline,
    unreachable_on_fork,
)
from execution_testing.evm_tools.t8n.evm_trace.signature import (
    EMPTY_SIGNATURE,
    Signature,
)
from execution_testing.forks import Amsterdam


def _sig(
    frames: Iterable[Tuple[int, str, str]] = (),
    events: Iterable[str] = (),
    bigrams: Iterable[Tuple[str, str]] = (),
    max_depth: int = 0,
) -> Signature:
    return Signature(
        frozenset(frames), frozenset(events), frozenset(bigrams), max_depth
    )


def test_novelty_first_is_novel_duplicate_is_not() -> None:
    """The first signature grows the union; an identical one does not."""
    tracker = NoveltyTracker()
    signature = _sig(frames={(0, "call", "CALL")})
    assert tracker.observe(signature) is True
    assert tracker.observe(signature) is False


def test_bigram_only_growth_is_not_novel() -> None:
    """L2 is a tie-breaker: bigram growth alone never promotes."""
    tracker = NoveltyTracker()
    tracker.observe(_sig(bigrams={("ADD", "MUL")}))
    grown = _sig(bigrams={("ADD", "MUL"), ("PUSH1", "POP")})
    assert tracker.observe(grown) is False
    assert tracker.counts()[2] == 2  # still tracked for ranking


def test_a_new_event_is_novel() -> None:
    """L1 growth promotes even when frames and bigrams are unchanged."""
    tracker = NoveltyTracker()
    tracker.observe(_sig(events={"create"}))
    assert tracker.observe(_sig(events={"create", "revert"})) is True


def test_empty_signature_is_not_novel() -> None:
    """An empty signature never grows the union."""
    assert NoveltyTracker().observe(EMPTY_SIGNATURE) is False


def test_fill_signature_is_deterministic() -> None:
    """A real fill produces a non-empty, reproducible signature."""
    from execution_testing.cli.fuzzer_bridge.campaign import fill_case
    from execution_testing.cli.fuzzer_bridge.generator import (
        generate_fuzzer_output,
    )
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )

    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    eels.last_signature = None
    fill_case(generate_fuzzer_output(Amsterdam, 1), Amsterdam, eels)
    first = eels.last_signature
    assert first is not None and not first.is_empty()
    eels.last_signature = None
    fill_case(generate_fuzzer_output(Amsterdam, 1), Amsterdam, eels)
    assert eels.last_signature == first


def test_unreached_maps_shrink_as_signatures_arrive() -> None:
    """Observed events and frame cells leave the unreached complement."""
    tracker = NoveltyTracker()
    assert "create" in tracker.unreached_events()
    cells_before = len(tracker.unreached_frames())
    tracker.observe(_sig(frames={(0, "call", "CALL")}, events={"create"}))
    assert "create" not in tracker.unreached_events()
    assert (0, "call", "CALL") not in tracker.unreached_frames()
    assert len(tracker.unreached_frames()) == cells_before - 1
    assert "unreached events" in render_unreached(tracker)


def test_fork_reach_space_derives_from_the_fork() -> None:
    """Halt kinds come from the fork's own exception classes."""
    call_ops, halt_kinds = fork_reach_space(Amsterdam)
    assert "CREATE2" in call_ops and "CALL" in call_ops
    assert {"STOP", "Revert", "OutOfGasError"} <= halt_kinds
    assert "KZGProofError" in halt_kinds  # beyond any static list


def test_capped_fork_marks_depth_limit_unreachable() -> None:
    """A 7825 tx-gas cap makes the 1024 depth limit unreachable."""
    events, cells = unreachable_on_fork(Amsterdam)
    assert "call-depth-limit" in events
    assert (0, "halt", "StackDepthLimitError") in cells
    assert (0, "halt", "WriteInStaticContext") in cells


def test_render_unreached_separates_fork_unreachable() -> None:
    """Fork-impossible cells render apart from the target list."""
    text = render_unreached(NoveltyTracker(), fork=Amsterdam)
    assert "unreachable on this fork" in text
    assert "KZGProofError" in text  # derived cell shows as unreached
    assert "call-depth-limit" not in text.splitlines()[0]


def test_novelty_curve_checkpoints_are_cumulative() -> None:
    """The curve rows grow monotonically and end at the full seed count."""
    rows = novelty_curve(Amsterdam, range(3), checkpoint=1)
    assert [r.seeds for r in rows] == [1, 2, 3]
    for earlier, later in zip(rows, rows[1:], strict=False):
        assert later.frames >= earlier.frames
        assert later.events >= earlier.events
        assert later.bigrams >= earlier.bigrams
        assert later.novel >= earlier.novel
    assert "seeds" in render_curve(rows)


def test_baseline_over_real_seeds_reports_novelty() -> None:
    """The baseline fills real seeds and reports growing novelty."""
    report = signature_baseline(Amsterdam, range(3))
    assert report.seeds == 3
    assert 1 <= report.novel <= 3
    assert report.frames > 0 and report.bigrams > 0
    assert report.max_depth >= 1  # real fills reach a child frame
    assert "novel" in report.summary() and "max depth" in report.summary()
