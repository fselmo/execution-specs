"""Unit tests for the heavy_state classifier plugin."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

import pytest

from execution_testing.cli.pytest_commands.plugins.filler.heavy_state import (
    DEFAULT_HEAVY_THRESHOLD_BYTES,
    classify_items,
)


def _classify(
    items: List["FakeItem"],
    **kwargs: Any,
) -> None:
    """Invoke the classifier with FakeItems cast to pytest.Item."""
    classify_items(cast(List[pytest.Item], items), **kwargs)


class FakeMarker:
    """Stand-in for `pytest.Mark` used by synthetic items under test."""

    def __init__(self, name: str) -> None:
        self.name = name


class FakeItem:
    """Minimal `pytest.Item` double that tracks marker additions."""

    def __init__(
        self, nodeid: str, markers: Optional[List[str]] = None
    ) -> None:
        self.nodeid = nodeid
        self._markers: List[str] = list(markers or [])
        self.added: List[str] = []

    def iter_markers(self, name: str) -> List[FakeMarker]:
        """Yield fake markers whose name matches."""
        return [FakeMarker(m) for m in self._markers if m == name]

    def get_closest_marker(self, name: str) -> Optional[FakeMarker]:
        """Return a fake marker with the given name if present."""
        for m in self._markers:
            if m == name:
                return FakeMarker(m)
        return None

    def add_marker(self, marker: Any) -> None:
        """Record a marker addition for later assertion."""
        if isinstance(marker, str):
            name = marker
        else:
            name = getattr(marker, "name", str(marker))
        self._markers.append(name)
        self.added.append(name)


def _items(*specs: Any) -> List[FakeItem]:
    """Build FakeItems from (nodeid[, markers]) tuples."""
    out: List[FakeItem] = []
    for spec in specs:
        if isinstance(spec, str):
            out.append(FakeItem(spec))
        else:
            nodeid, markers = spec
            out.append(FakeItem(nodeid, markers))
    return out


def _write_cache(path: Path, mapping: Dict[str, int]) -> None:
    path.write_text(json.dumps(mapping))


def test_classifier_noop_without_cache_path() -> None:
    """No cache path configured → no markers added (bootstrap mode)."""
    items = _items("tests/a.py::test_x", "tests/b.py::test_y")
    _classify(items, cache_path=None)
    for item in items:
        assert item.added == []


def test_classifier_noop_when_cache_file_missing(tmp_path: Path) -> None:
    """Cache path given but file absent → no modifications."""
    items = _items("tests/a.py::test_x")
    _classify(items, cache_path=tmp_path / "missing.json")
    assert items[0].added == []


def test_classifier_adds_marker_to_cached_heavy(tmp_path: Path) -> None:
    """Tests whose cached RSS ≥ threshold get the heavy_state marker."""
    cache = tmp_path / "rss.json"
    _write_cache(
        cache,
        {
            "tests/a.py::test_x": DEFAULT_HEAVY_THRESHOLD_BYTES + 1,
            "tests/b.py::test_y": DEFAULT_HEAVY_THRESHOLD_BYTES - 1,
        },
    )
    items = _items("tests/a.py::test_x", "tests/b.py::test_y")
    _classify(items, cache_path=cache)
    assert items[0].added == ["heavy_state"]
    assert items[1].added == []


def test_classifier_adds_marker_to_unknown_test(tmp_path: Path) -> None:
    """Tests absent from cache default to heavy (fail-safe)."""
    cache = tmp_path / "rss.json"
    _write_cache(cache, {"tests/known.py::test_light": 1_000_000})
    items = _items("tests/new.py::test_unknown")
    _classify(items, cache_path=cache)
    assert items[0].added == ["heavy_state"]


def test_classifier_skips_already_marked(tmp_path: Path) -> None:
    """Items already carrying heavy_state are left untouched."""
    cache = tmp_path / "rss.json"
    _write_cache(
        cache, {"tests/a.py::test_x": DEFAULT_HEAVY_THRESHOLD_BYTES + 1}
    )
    items = _items(("tests/a.py::test_x", ["heavy_state"]))
    _classify(items, cache_path=cache)
    assert items[0].added == []


def test_classifier_respects_custom_threshold(tmp_path: Path) -> None:
    """Override threshold controls what counts as heavy."""
    cache = tmp_path / "rss.json"
    _write_cache(
        cache,
        {
            "tests/a.py::test_x": 2_000_000_000,
            "tests/b.py::test_y": 500_000_000,
        },
    )
    items = _items("tests/a.py::test_x", "tests/b.py::test_y")
    _classify(items, cache_path=cache, threshold_bytes=1_000_000_000)
    assert items[0].added == ["heavy_state"]
    assert items[1].added == []


def test_classifier_tolerates_malformed_cache(tmp_path: Path) -> None:
    """Corrupt cache file → treat as bootstrap (no additions, no raise)."""
    cache = tmp_path / "rss.json"
    cache.write_text("{not valid json")
    items = _items("tests/a.py::test_x")
    _classify(items, cache_path=cache)
    assert items[0].added == []


def test_classifier_is_idempotent(tmp_path: Path) -> None:
    """Re-running the classifier doesn't double-mark the same item."""
    cache = tmp_path / "rss.json"
    _write_cache(cache, {"tests/other.py::test_known": 0})
    items = _items("tests/new.py::test_unknown")
    _classify(items, cache_path=cache)
    _classify(items, cache_path=cache)
    assert items[0].added == ["heavy_state"]


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear classifier env vars so tests start from a known state."""
    monkeypatch.delenv("PER_TEST_RSS_CACHE", raising=False)
    monkeypatch.delenv("HEAVY_STATE_THRESHOLD_BYTES", raising=False)
