"""
Whole-file execution of a fixture file through a client's standalone
test runner, returning one verdict per fixture.

The runner binaries are the ones EEST's fixture consumers already wrap
(`evm blocktest`, `evmone-blockchaintest`, `evmtool block-test`, `nethtest`);
this module runs them over an entire file in one process, which is what
makes a campaign cheap, and parses whatever each emits. Where a runner
reports only a summary, failing fixtures are re-run by name so the failure
can be attributed.
"""

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Sequence

from execution_testing.client_clis import FixtureConsumerTool


@dataclass(frozen=True)
class Verdict:
    """One client's judgement of one fixture."""

    passed: bool
    error: str = ""


_NETHERMIND_SUFFIX = re.compile(r"_d\d+g\d+v\d+_$")


def parse_json_array(stdout: str) -> Dict[str, Verdict]:
    """Verdicts from a `[{"name", "pass", "error"}, ...]` list in stdout."""
    start = stdout.find("[")
    if start < 0:
        return {}
    try:
        results = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return {}
    verdicts: Dict[str, Verdict] = {}
    for entry in results:
        if isinstance(entry, dict) and "name" in entry:
            verdicts[str(entry["name"])] = Verdict(
                passed=bool(entry.get("pass")),
                error=str(entry.get("error") or ""),
            )
    return verdicts


_BESU_RUNNING = re.compile(r"^Running (\S+)$", re.MULTILINE)
_BESU_FAILED = re.compile(r"^  - (\S+): (.*)$", re.MULTILINE)


def parse_besu_summary(stdout: str) -> Dict[str, Verdict]:
    """
    Verdicts from `evmtool block-test` output.

    Every `Running <name>` passed unless the closing summary lists it under
    `Failed tests:` with a reason.
    """
    failed = dict(_BESU_FAILED.findall(stdout.partition("Failed tests:")[2]))
    return {
        name: Verdict(name not in failed, failed.get(name, ""))
        for name in _BESU_RUNNING.findall(stdout)
    }


_MISMATCH_FIELD = re.compile(r"^\s*([a-z][a-z ]*[a-z]):\s*$", re.MULTILINE)


def summarize_gtest_failure(text: str) -> str:
    """
    Lead with the mismatched fields (`state root`, `gas used`, ...).

    Evmone's failure text starts with a source location, which would make
    every failure one signature; the field names are what differed.
    """
    fields = list(dict.fromkeys(_MISMATCH_FIELD.findall(text)))
    if not fields:
        return text
    return f"mismatch: {', '.join(fields)}\n{text}"


def parse_gtest_report(report: Dict[str, Any]) -> Dict[str, Verdict]:
    """Verdicts from a gtest JSON report (evmone)."""
    verdicts: Dict[str, Verdict] = {}
    for suite in report.get("testsuites", []):
        for test in suite.get("testsuite", []):
            failures = test.get("failures", [])
            text = ", ".join(str(f.get("failure", "")) for f in failures)
            verdicts[str(test["name"])] = Verdict(
                passed=not failures, error=summarize_gtest_failure(text)
            )
    return verdicts


def strip_nethermind_suffix(name: str) -> str:
    """Drop the `_d0g0v0_` decoration nethtest appends to test names."""
    return _NETHERMIND_SUFFIX.sub("", name)


@dataclass
class FixtureRunner:
    """One client's standalone runner, keyed by EEST's consumer class."""

    name: str
    binary: Path
    kind: str
    timeout: float = 1800.0
    _last_error: str = ""

    @classmethod
    def detect(cls, name: str, binary: Path) -> "FixtureRunner":
        """Identify the runner behind ``binary`` via EEST detection."""
        consumer = FixtureConsumerTool.from_binary_path(binary_path=binary)
        return cls(name=name, binary=binary, kind=type(consumer).__name__)

    def version(self) -> str:
        """The runner's `--version` line."""
        proc = subprocess.run(
            [str(self.binary), "--version"], capture_output=True, text=True
        )
        return (proc.stdout or proc.stderr).strip().splitlines()[0]

    def _run(self, args: Sequence[str]) -> subprocess.CompletedProcess:
        command = [str(self.binary), *args]
        try:
            return subprocess.run(
                command, capture_output=True, text=True, timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(
                command, -1, "", f"timed out after {self.timeout:.0f}s"
            )

    def run_file(
        self, path: Path, fixture_names: Iterable[str]
    ) -> Dict[str, Verdict]:
        """
        Judge every fixture in ``path``.

        Fixtures the runner did not report on come back as failures with a
        `runner-error` prefix, so a broken runner is visible rather than
        silently counted as agreement.
        """
        names = list(fixture_names)
        self._last_error = ""
        if self.kind in ("GethFixtureConsumer", "ErigonFixtureConsumer"):
            verdicts = self._run_json_array(path)
        elif self.kind == "EvmOneBlockchainFixtureConsumer":
            verdicts = self._run_gtest(path)
        elif self.kind == "BesuFixtureConsumer":
            verdicts = self._run_besu(path)
        elif self.kind == "NethtestFixtureConsumer":
            verdicts = self._run_nethermind(path)
        else:
            raise ValueError(f"{self.name}: unsupported runner {self.kind}")
        missing = [n for n in names if n not in verdicts]
        for name in missing:
            verdicts[name] = Verdict(
                False, f"runner-error: no result from {self.name}"
            )
        return verdicts

    def _run_json_array(self, path: Path) -> Dict[str, Verdict]:
        args = ["blocktest"]
        if self.kind == "ErigonFixtureConsumer":
            args.append("--jsonout")
        proc = self._run([*args, str(path)])
        verdicts = parse_json_array(proc.stdout)
        if not verdicts and proc.returncode != 0:
            return self._all_failed(
                f"runner-error: {proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _run_gtest(self, path: Path) -> Dict[str, Verdict]:
        with tempfile.NamedTemporaryFile(suffix=".json") as report:
            proc = self._run([f"--gtest_output=json:{report.name}", str(path)])
            try:
                data = json.loads(Path(report.name).read_text() or "{}")
            except json.JSONDecodeError:
                data = {}
        verdicts = parse_gtest_report(data)
        if not verdicts and proc.returncode not in (0, 1):
            return self._all_failed(
                f"runner-error: {proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _run_besu(self, path: Path) -> Dict[str, Verdict]:
        proc = self._run(["block-test", str(path)])
        verdicts = parse_besu_summary(proc.stdout)
        if not verdicts and proc.returncode != 0:
            return self._all_failed(
                f"runner-error: {proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _run_nethermind(self, path: Path) -> Dict[str, Verdict]:
        proc = self._run(["--blockTest", "--input", str(path)])
        parsed = parse_json_array(proc.stdout)
        verdicts = {strip_nethermind_suffix(n): v for n, v in parsed.items()}
        if not verdicts and proc.returncode != 0:
            return self._all_failed(
                f"runner-error: {proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _all_failed(self, error: str) -> Dict[str, Verdict]:
        self._last_error = error
        return {}
