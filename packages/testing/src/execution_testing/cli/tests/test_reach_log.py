"""Tests for reach-log persistence and trending."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from execution_testing.cli.mutation import cli as mutation_cli
from execution_testing.cli.mutation.reach_log import (
    append_reach_log,
    reach_record,
    reach_trend,
    summary_data,
)
from execution_testing.cli.mutation.runner import ShapeResult, Verdict
from execution_testing.cli.mutation.shapes import SHAPES


def test_summary_data_parses_a_diff_summary(tmp_path: Path) -> None:
    """A written `fuzz diff` summary parses back into a dict."""
    path = tmp_path / "summary.json"
    path.write_text(
        json.dumps(
            {
                "fork": "Amsterdam",
                "generator_version": 5,
                "clients": ["geth"],
                "eels_commit": "abc123",
                "seed_start": 0,
                "seeds": 300,
                "agreed": 266,
                "diverged": 34,
                "eels_runs": 300,
                "first_divergent_seed": 7,
                "fields": {"block_access_list_hash": 34},
            }
        )
    )
    data = summary_data(path)
    assert data is not None
    assert data["diverged"] == 34 and data["first_divergent_seed"] == 7


def test_summary_data_missing_file_is_none(tmp_path: Path) -> None:
    """A missing summary file yields None, never raises."""
    assert summary_data(tmp_path / "nope.json") is None


def test_reach_record_flattens_a_shape_result() -> None:
    """A shape result flattens to a trendable record."""
    result = ShapeResult(
        SHAPES["child-read-rollback"],
        Verdict.KILLED_DIFFERENTIAL,
        "34/300 diverged, first at seed 7",
        {
            "diverged": 34,
            "seeds": 300,
            "first_divergent_seed": 7,
            "generator_version": 5,
        },
    )
    record = reach_record(
        result,
        fork="Amsterdam",
        eels_commit="abc123",
        timestamp="2026-08-28T00:00:00Z",
    )
    assert record["shape"] == "child-read-rollback"
    assert record["killed"] is True
    assert record["diverged"] == 34 and record["seeds"] == 300
    assert record["first_kill_seed"] == 7


def test_append_reach_log_is_jsonl(tmp_path: Path) -> None:
    """Records append as one JSON object per line."""
    path = tmp_path / "reach.jsonl"
    append_reach_log([{"a": 1}], path)
    append_reach_log([{"a": 2}], path)
    lines = path.read_text().splitlines()
    assert [json.loads(x)["a"] for x in lines] == [1, 2]


def test_reach_trend_groups_by_shape(tmp_path: Path) -> None:
    """The trend reader groups diverged/seeds per shape, oldest first."""
    path = tmp_path / "reach.jsonl"
    for diverged in (30, 34):
        append_reach_log(
            [
                {
                    "shape": "child-read-rollback",
                    "seeds": 300,
                    "diverged": diverged,
                    "first_kill_seed": 7,
                    "eels_commit": "abc",
                }
            ],
            path,
        )
    text = reach_trend(path)
    assert "child-read-rollback" in text
    assert "30/300" in text and "34/300" in text


def test_mutate_writes_reach_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`mutate --reach-log` persists a record per shape result."""
    canned = [
        ShapeResult(
            SHAPES["child-read-rollback"],
            Verdict.KILLED_DIFFERENTIAL,
            "d",
            {
                "seeds": 300,
                "diverged": 34,
                "first_divergent_seed": 7,
                "generator_version": 5,
            },
        )
    ]
    monkeypatch.setattr(mutation_cli, "run_shapes", lambda *_a, **_k: canned)
    monkeypatch.setattr(mutation_cli, "eels_commit", lambda: "abc")
    client = tmp_path / "evm"
    client.touch()
    log = tmp_path / "reach.jsonl"
    result = CliRunner().invoke(
        mutation_cli.mutate,
        [
            "--shape",
            "child-read-rollback",
            "--oracle",
            "differential",
            "--fork",
            "Amsterdam",
            "--client",
            str(client),
            "--reach-log",
            str(log),
        ],
    )
    assert result.exit_code == 0, result.output
    assert log.exists() and "child-read-rollback" in log.read_text()
