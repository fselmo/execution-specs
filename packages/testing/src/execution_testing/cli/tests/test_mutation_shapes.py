"""Tests for named shape mutants and the differential kill oracle."""

import json
import subprocess
from pathlib import Path
from typing import Any, List

import pytest

from ..mutation import runner as runner_mod
from ..mutation.runner import (
    DifferentialOptions,
    Oracle,
    Verdict,
    _classify,
    _run_differential,
)
from ..mutation.shapes import (
    SHAPES,
    Edit,
    Shape,
    ShapeMismatchError,
    applied,
    repo_root,
)


def _shape(tmp_path: Path) -> Shape:
    (tmp_path / "a.py").write_text("x = 1\ny = 2\n")
    (tmp_path / "b.py").write_text("z = 3\n")
    return Shape(
        name="demo",
        description="two-file edit",
        edits=(
            Edit(module="a.py", find="x = 1\n", replace="x = 10\n"),
            Edit(module="a.py", find="y = 2\n", replace="y = 20\n"),
            Edit(module="b.py", find="z = 3\n", replace="z = 30\n"),
        ),
    )


def test_applied_edits_then_restores(tmp_path: Path) -> None:
    """Every edit lands while applied; every file is restored after."""
    shape = _shape(tmp_path)
    with applied(shape, root=tmp_path):
        assert (tmp_path / "a.py").read_text() == "x = 10\ny = 20\n"
        assert (tmp_path / "b.py").read_text() == "z = 30\n"
    assert (tmp_path / "a.py").read_text() == "x = 1\ny = 2\n"
    assert (tmp_path / "b.py").read_text() == "z = 3\n"


def test_applied_restores_on_error(tmp_path: Path) -> None:
    """An exception inside the block still restores the sources."""
    shape = _shape(tmp_path)
    with pytest.raises(RuntimeError):
        with applied(shape, root=tmp_path):
            raise RuntimeError("boom")
    assert (tmp_path / "a.py").read_text() == "x = 1\ny = 2\n"


def test_stale_anchor_is_an_error_and_restores(tmp_path: Path) -> None:
    """A stale anchor fails loudly and leaves no edit behind."""
    (tmp_path / "a.py").write_text("x = 1\n")
    shape = Shape(
        name="stale",
        description="",
        edits=(
            Edit(module="a.py", find="x = 1\n", replace="x = 2\n"),
            Edit(module="a.py", find="nope\n", replace="never\n"),
        ),
    )
    with pytest.raises(ShapeMismatchError, match="a.py"):
        with applied(shape, root=tmp_path):
            pass
    assert (tmp_path / "a.py").read_text() == "x = 1\n"


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_shipped_shape_anchors_match_the_spec(name: str) -> None:
    """Each shipped shape's anchors occur exactly once in the live source."""
    root = repo_root()
    for edit in SHAPES[name].edits:
        text = (root / edit.module).read_text()
        assert text.count(edit.find) == 1, f"{name}: {edit.module}"


def test_run_differential_builds_the_fuzz_diff_command(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The oracle shells out to `fuzz diff` with the campaign options."""
    seen: List[List[str]] = []

    def fake_run(
        cmd: List[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess:
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(runner_mod.subprocess, "run", fake_run)
    options = DifferentialOptions(
        fork="Amsterdam",
        count=50,
        clients=(tmp_path / "evm",),
        workers=4,
    )
    _run_differential(options, tmp_path / "summary.json", timeout=10)
    cmd = seen[0]
    assert cmd[:4] == ["uv", "run", "fuzz", "diff"]
    assert "--fork" in cmd and cmd[cmd.index("--fork") + 1] == "Amsterdam"
    assert cmd[cmd.index("--count") + 1] == "50"
    assert "--no-minimize" in cmd and "--no-baseline" in cmd
    assert cmd[cmd.index("--client") + 1] == str(tmp_path / "evm")
    assert cmd[cmd.index("-j") + 1] == "4"
    assert cmd[cmd.index("--summary-json") + 1] == str(
        tmp_path / "summary.json"
    )


def test_classify_differential_divergence_is_a_kill() -> None:
    """A nonzero `fuzz diff` exit (divergence) kills under the oracle."""
    process = subprocess.CompletedProcess([], 1, "", "")
    assert (
        _classify(process, 0, oracle=Oracle.DIFFERENTIAL)
        is Verdict.KILLED_DIFFERENTIAL
    )
    clean = subprocess.CompletedProcess([], 0, "", "")
    assert _classify(clean, 0, oracle=Oracle.DIFFERENTIAL) is Verdict.SURVIVED


def test_summary_detail_reads_first_divergent_seed(tmp_path: Path) -> None:
    """The reach detail names how many seeds diverged and the first one."""
    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps({"seeds": 300, "diverged": 34, "first_divergent_seed": 2})
    )
    assert runner_mod.summary_detail(summary) == (
        "34/300 diverged, first at seed 2"
    )
    summary.write_text(
        json.dumps({"seeds": 300, "diverged": 0, "first_divergent_seed": None})
    )
    assert runner_mod.summary_detail(summary) == "0/300 diverged"


def test_a_reach_probe_says_so_in_structured_form() -> None:
    """
    A shape that over-approximates its named bug must be marked, so the
    calibration column can refuse to quote its kill rate.

    Both state-gas shapes are probes and both were measured that way:
    `child-spill-credit` kills 35% in-spec against 0 divergences in 2,000
    cases on a binary verified pre-fix (>=233x), and
    `halt-spill-to-reservoir` kills 83%. Neither is coverage of
    nethermind#12965; the reproducer test is.
    """
    assert SHAPES["child-spill-credit"].models_client_bug is False
    assert SHAPES["halt-spill-to-reservoir"].models_client_bug is False
    # The two that have never failed calibration stay models.
    assert SHAPES["child-read-rollback"].models_client_bug is True
    assert SHAPES["precompile-value-callcode-refund"].models_client_bug


def test_every_probe_explains_itself() -> None:
    """A probe's description must say it is not coverage, in the open."""
    for shape in SHAPES.values():
        if shape.models_client_bug:
            continue
        lowered = shape.description.lower()
        assert "not a" in lowered or "not coverage" in lowered, shape.name
