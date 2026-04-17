"""
Pytest plugin that auto-classifies tests as memory-heavy based on recorded
per-test peak RSS, injecting the `heavy_state` marker so the CI matrix can
route tests to dedicated low-parallelism runners.

Operates in two modes:

1. Bootstrap (no cache): do nothing — routing falls back to tests that already
   carry `@pytest.mark.heavy_state`.
2. Cache present: read `per_test_rss.json`; for every collected item, attach
   the `heavy_state` marker when cached RSS ≥ threshold OR when the item is
   absent from the cache (fail-safe: unknown tests are heavy).

The cache path is configured via `PER_TEST_RSS_CACHE`; the threshold via
`HEAVY_STATE_THRESHOLD_BYTES` (default 4 GiB).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, Iterable, Optional

import pytest

logger = logging.getLogger("fill.heavy_state")

DEFAULT_HEAVY_THRESHOLD_BYTES = 4 * 1024 * 1024 * 1024
CACHE_ENV_VAR = "PER_TEST_RSS_CACHE"
THRESHOLD_ENV_VAR = "HEAVY_STATE_THRESHOLD_BYTES"


def _load_cache(cache_path: Optional[Path]) -> Optional[Dict[str, int]]:
    if cache_path is None or not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text())
    except (OSError, json.JSONDecodeError):
        logger.warning(
            "Failed to read RSS cache at %s; bootstrap mode", cache_path
        )
        return None
    return {str(k): int(v) for k, v in data.items()}


def classify_items(
    items: Iterable[pytest.Item],
    cache_path: Optional[Path],
    threshold_bytes: int = DEFAULT_HEAVY_THRESHOLD_BYTES,
) -> None:
    """
    Add `heavy_state` markers to items in `items` whose cached RSS meets the
    threshold or which are missing from the cache.

    A `None` cache (or missing file) leaves items untouched — bootstrap mode.
    """
    cache = _load_cache(cache_path)
    if cache is None:
        return
    for item in items:
        if item.get_closest_marker("heavy_state") is not None:
            continue
        rss = cache.get(item.nodeid)
        if rss is None or rss >= threshold_bytes:
            item.add_marker(pytest.mark.heavy_state)


def _resolve_cache_path() -> Optional[Path]:
    raw = os.environ.get(CACHE_ENV_VAR)
    if not raw:
        return None
    return Path(raw)


def _resolve_threshold() -> int:
    raw = os.environ.get(THRESHOLD_ENV_VAR)
    if not raw:
        return DEFAULT_HEAVY_THRESHOLD_BYTES
    try:
        return int(raw)
    except ValueError:
        logger.warning(
            "Ignoring non-integer %s=%r; using default %d",
            THRESHOLD_ENV_VAR,
            raw,
            DEFAULT_HEAVY_THRESHOLD_BYTES,
        )
        return DEFAULT_HEAVY_THRESHOLD_BYTES


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Inject heavy_state markers before pytest's `-m` filter runs."""
    del config
    classify_items(
        items,
        cache_path=_resolve_cache_path(),
        threshold_bytes=_resolve_threshold(),
    )
