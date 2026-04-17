"""Unit tests for the rss_profile plugin's RssTracker."""

from __future__ import annotations

import json
from pathlib import Path

from execution_testing.cli.pytest_commands.plugins.filler.rss_profile import (
    RssTracker,
    merge_partial_rss_files,
)


def test_tracker_peak_is_max_over_test_window() -> None:
    """RSS tracker records the max RSS observed while a test was active."""
    tracker = RssTracker(root_pid=0)
    tracker._samples.extend(
        [
            (1.0, 100),
            (2.0, 200),
            (3.0, 500),
            (4.0, 150),
            (5.0, 50),
        ]
    )
    tracker._test_start_time["test_a"] = 1.5
    tracker._test_end_time["test_a"] = 3.5
    tracker._test_start_time["test_b"] = 3.5
    tracker._test_end_time["test_b"] = 5.5

    peaks = tracker.peak_rss_per_test()
    assert peaks == {"test_a": 500, "test_b": 150}


def test_tracker_peak_ignores_samples_outside_window() -> None:
    """Samples before the start or after the end of a test don't count."""
    tracker = RssTracker(root_pid=0)
    tracker._samples.extend(
        [
            (0.0, 999),
            (1.0, 100),
            (2.0, 200),
            (10.0, 999),
        ]
    )
    tracker._test_start_time["t"] = 0.5
    tracker._test_end_time["t"] = 5.0
    peaks = tracker.peak_rss_per_test()
    assert peaks == {"t": 200}


def test_tracker_peak_handles_missing_end_time() -> None:
    """If a test never recorded an end, fall back to the latest sample."""
    tracker = RssTracker(root_pid=0)
    tracker._samples.extend([(1.0, 100), (2.0, 200)])
    tracker._test_start_time["t"] = 0.5
    peaks = tracker.peak_rss_per_test()
    assert peaks == {"t": 200}


def test_merge_partial_rss_files_combines_maps(tmp_path: Path) -> None:
    """Merge walks worker partials and produces a single per_test_rss.json."""
    meta = tmp_path / ".meta"
    meta.mkdir()
    (meta / "per_test_rss.partial.gw0.json").write_text(
        json.dumps({"a": 100, "b": 200})
    )
    (meta / "per_test_rss.partial.gw1.json").write_text(
        json.dumps({"c": 300, "b": 150})
    )

    merge_partial_rss_files(tmp_path)

    merged = json.loads((meta / "per_test_rss.json").read_text())
    assert merged == {"a": 100, "b": 200, "c": 300}


def test_merge_partial_rss_files_ignores_missing_meta(tmp_path: Path) -> None:
    """No .meta dir → no-op, no exception."""
    merge_partial_rss_files(tmp_path)
    assert not (tmp_path / ".meta" / "per_test_rss.json").exists()
