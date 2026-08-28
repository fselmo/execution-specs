"""Tests for the drift-resilient held-out mutant set."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from execution_testing.cli.mutation import cli as mutation_cli
from execution_testing.cli.mutation import held_out as ho
from execution_testing.cli.mutation.held_out import (
    HeldOutDriftError,
    Stratum,
    check_held_out,
    freeze_held_out,
    held_out_report,
    load_held_out,
    resolve,
    run_held_out,
    stratified_mutants,
)
from execution_testing.cli.mutation.runner import DifferentialOptions

SRC = "def f(a, b):\n    return a + b\n"


def test_stratified_mutants_confined_to_operators() -> None:
    """Selection respects the stratum's operator subset."""
    picked = stratified_mutants(
        {Stratum("s", "m.py", ("binop",)): SRC}, per_stratum=10, seed=0
    )
    assert picked
    for held in picked:
        assert held.stratum == "s" and held.operator == "binop"


def test_resolve_survives_a_rename_and_line_shift() -> None:
    """A mutant still resolves after its function is renamed and moved."""
    held = stratified_mutants(
        {Stratum("s", "m.py", ("binop",)): SRC}, per_stratum=10, seed=0
    )[0]
    renamed = "# padding\n# lines\n" + SRC.replace("def f", "def renamed")
    assert resolve(held, renamed) is not None


def test_resolve_is_none_when_construct_changes() -> None:
    """A changed construct no longer resolves (drift)."""
    held = stratified_mutants(
        {Stratum("s", "m.py", ("binop",)): SRC}, per_stratum=10, seed=0
    )[0]
    assert resolve(held, SRC.replace("a + b", "a * b")) is None


def test_freeze_load_and_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A frozen set round-trips and reports drift when the construct moves."""
    module = tmp_path / "m.py"
    module.write_text(SRC)
    monkeypatch.setattr(ho, "repo_root", lambda: tmp_path)
    manifest = tmp_path / "held_out.json"
    freeze_held_out(
        [Stratum("s", "m.py", ("binop",))],
        manifest,
        per_stratum=10,
        seed=0,
    )
    assert load_held_out(manifest)
    assert not check_held_out(manifest).drifted
    module.write_text(SRC.replace("a + b", "a * b"))
    report = check_held_out(manifest)
    assert report.drifted and not report.valid


def test_check_reports_missing_module_as_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A moved/removed module is reported as drift, never a crash."""
    module = tmp_path / "m.py"
    module.write_text(SRC)
    monkeypatch.setattr(ho, "repo_root", lambda: tmp_path)
    manifest = tmp_path / "held_out.json"
    freeze_held_out(
        [Stratum("s", "m.py", ("binop",))],
        manifest,
        per_stratum=10,
        seed=0,
    )
    module.unlink()
    assert check_held_out(manifest).drifted


def test_run_held_out_scores_each_mutant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each frozen mutant is applied and scored by the differential oracle."""
    module = tmp_path / "m.py"
    module.write_text(SRC)
    monkeypatch.setattr(ho, "repo_root", lambda: tmp_path)
    manifest = tmp_path / "held_out.json"
    freeze_held_out(
        [Stratum("s", "m.py", ("binop",))],
        manifest,
        per_stratum=2,
        seed=0,
    )

    def fake_diff(
        _options: object, summary_path: Path, _timeout: int
    ) -> object:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(
            '{"diverged": 5, "seeds": 300, "first_divergent_seed": 9}'
        )
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(ho, "_run_differential", fake_diff)
    results = run_held_out(
        manifest, DifferentialOptions(fork="Amsterdam"), timeout=5
    )
    assert results and all(r.killed for r in results)
    assert results[0].first_kill_seed == 9
    report = held_out_report(results)
    assert "kill-rate" in report and "overall" in report


def test_run_held_out_raises_on_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A drifted set refuses to run rather than under-reporting reach."""
    module = tmp_path / "m.py"
    module.write_text(SRC)
    monkeypatch.setattr(ho, "repo_root", lambda: tmp_path)
    manifest = tmp_path / "held_out.json"
    freeze_held_out(
        [Stratum("s", "m.py", ("binop",))],
        manifest,
        per_stratum=2,
        seed=0,
    )
    module.write_text(SRC.replace("a + b", "a * b"))
    with pytest.raises(HeldOutDriftError):
        run_held_out(
            manifest, DifferentialOptions(fork="Amsterdam"), timeout=5
        )


def test_mutate_freeze_and_check_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CLI freezes a set and reports it clean via --held-out-check."""
    module = tmp_path / "m.py"
    module.write_text(SRC)
    monkeypatch.setattr(ho, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(
        mutation_cli,
        "DEFAULT_STRATA",
        (Stratum("s", "m.py", ("binop",)),),
    )
    manifest = tmp_path / "held_out.json"
    runner = CliRunner()
    frozen = runner.invoke(
        mutation_cli.mutate,
        ["--freeze-held-out", str(manifest), "--held-out-per-stratum", "5"],
    )
    assert frozen.exit_code == 0, frozen.output
    assert manifest.exists()
    checked = runner.invoke(
        mutation_cli.mutate, ["--held-out-check", str(manifest)]
    )
    assert checked.exit_code == 0, checked.output
    assert "valid" in checked.output
