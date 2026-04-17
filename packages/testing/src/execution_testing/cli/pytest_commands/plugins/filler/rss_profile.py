"""
Pytest plugin that records per-test peak RSS across the whole process tree
(Python + any `evm` / t8n subprocesses a test spawns) and persists the result
for downstream classification by the `heavy_state` plugin.

Each xdist worker writes `<output>/.meta/per_test_rss.partial.{worker_id}.json`
during `pytest_sessionfinish`; the master merges those into
`<output>/.meta/per_test_rss.json`.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Tuple

import psutil
import pytest

logger = logging.getLogger("fill.rss_profile")

SAMPLE_INTERVAL_S = 0.5
RSS_PARTIAL_PREFIX = "per_test_rss.partial."
RSS_FINAL_FILENAME = "per_test_rss.json"


class RssTracker:
    """Background process-tree RSS sampler with per-test peak computation."""

    def __init__(self, root_pid: int) -> None:
        self.root_pid = root_pid
        self._running = False
        self._thread: threading.Thread | None = None
        self._samples: List[Tuple[float, int]] = []
        self._test_start_time: Dict[str, float] = {}
        self._test_end_time: Dict[str, float] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        """Begin sampling in a daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop sampling and join the thread."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def _sample_loop(self) -> None:
        while self._running:
            self._sample()
            time.sleep(SAMPLE_INTERVAL_S)
        self._sample()

    def _sample(self) -> None:
        try:
            root = psutil.Process(self.root_pid)
        except psutil.NoSuchProcess:
            return
        procs = [root] + list(root.children(recursive=True))
        total_rss = 0
        for p in procs:
            try:
                total_rss += p.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        ts = time.time()
        with self._lock:
            self._samples.append((ts, total_rss))

    def record_test_start(self, nodeid: str) -> None:
        """Mark the moment a test's execution window opens."""
        with self._lock:
            self._test_start_time[nodeid] = time.time()

    def record_test_end(self, nodeid: str) -> None:
        """Mark the moment a test's execution window closes."""
        with self._lock:
            self._test_end_time[nodeid] = time.time()

    def peak_rss_per_test(self) -> Dict[str, int]:
        """Return `{nodeid: peak_rss_bytes}` across each test's window."""
        with self._lock:
            samples = list(self._samples)
            starts = dict(self._test_start_time)
            ends = dict(self._test_end_time)
        latest_sample_ts = samples[-1][0] if samples else 0.0
        result: Dict[str, int] = {}
        for nodeid, t_start in starts.items():
            t_end = ends.get(nodeid, latest_sample_ts)
            peak = 0
            for ts, rss in samples:
                if t_start <= ts <= t_end and rss > peak:
                    peak = rss
            result[nodeid] = peak
        return result


def _worker_id(config: pytest.Config) -> str:
    """Return the xdist worker id (e.g. 'gw3'), or 'master' outside xdist."""
    workerinput = getattr(config, "workerinput", None)
    if workerinput is None:
        return "master"
    return str(workerinput.get("workerid", "worker"))


def _meta_dir(config: pytest.Config) -> Path | None:
    fixture_output = getattr(config, "fixture_output", None)
    if fixture_output is None:
        return None
    if getattr(fixture_output, "is_stdout", False):
        return None
    directory = getattr(fixture_output, "directory", None)
    if directory is None:
        return None
    meta = Path(directory) / ".meta"
    meta.mkdir(parents=True, exist_ok=True)
    return meta


def merge_partial_rss_files(output_dir: Path) -> None:
    """
    Merge `<output>/.meta/per_test_rss.partial.*.json` → `per_test_rss.json`.

    When two partials cover the same nodeid, keep the larger value — the
    conservative budget for a future run.
    """
    meta = Path(output_dir) / ".meta"
    if not meta.exists():
        return
    partials = sorted(meta.glob(f"{RSS_PARTIAL_PREFIX}*.json"))
    if not partials:
        return
    merged: Dict[str, int] = {}
    for partial in partials:
        try:
            data = json.loads(partial.read_text())
        except (OSError, json.JSONDecodeError):
            logger.warning("Failed to read %s; skipping", partial)
            continue
        for nodeid, rss in data.items():
            existing = merged.get(nodeid, 0)
            if int(rss) > existing:
                merged[nodeid] = int(rss)
    (meta / RSS_FINAL_FILENAME).write_text(
        json.dumps(merged, indent=2, sort_keys=True)
    )


_TRACKER_KEY = pytest.StashKey[RssTracker]()


def pytest_sessionstart(session: pytest.Session) -> None:
    """Start the background sampler for this pytest invocation."""
    tracker = RssTracker(root_pid=os.getpid())
    tracker.start()
    session.config.stash[_TRACKER_KEY] = tracker


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    """Record the start of a test's RSS-observation window."""
    tracker = item.config.stash.get(_TRACKER_KEY, None)
    if tracker is not None:
        tracker.record_test_start(item.nodeid)


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item: pytest.Item) -> None:
    """Record the end of a test's RSS-observation window."""
    tracker = item.config.stash.get(_TRACKER_KEY, None)
    if tracker is not None:
        tracker.record_test_end(item.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Stop the sampler and emit a worker-scoped partial RSS file."""
    del exitstatus
    tracker = session.config.stash.get(_TRACKER_KEY, None)
    if tracker is None:
        return
    tracker.stop()
    peaks = tracker.peak_rss_per_test()
    if not peaks:
        return
    meta = _meta_dir(session.config)
    if meta is None:
        return
    partial = meta / f"{RSS_PARTIAL_PREFIX}{_worker_id(session.config)}.json"
    partial.write_text(json.dumps(peaks, indent=2, sort_keys=True))
    logger.debug(
        "Wrote %d per-test peak RSS values to %s", len(peaks), partial
    )
