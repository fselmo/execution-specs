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
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from execution_testing.client_clis import FixtureConsumerTool
from execution_testing.client_clis.clis.besu import BesuExceptionMapper
from execution_testing.client_clis.clis.erigon import ErigonExceptionMapper
from execution_testing.client_clis.clis.ethrex import EthrexExceptionMapper
from execution_testing.client_clis.clis.evmone import EvmoneExceptionMapper
from execution_testing.client_clis.clis.geth import GethExceptionMapper
from execution_testing.client_clis.clis.nethermind import (
    NethermindExceptionMapper,
)
from execution_testing.client_clis.clis.reth import RethExceptionMapper
from execution_testing.exceptions import ExceptionMapper

from .clients import client_environment, native_version


@dataclass(frozen=True)
class Verdict:
    """One client's judgement of one fixture."""

    passed: bool
    error: str = ""
    rejections: Tuple[Tuple[int, str], ...] = ()
    """The client's own error for each block or payload it rejected, by
    its index in the fixture, as a runner on the shared interface reports
    them (`docs/fuzzing/runner-interface.md` §5)."""
    unmapped: str = ""
    """A rejection error the client's mapper names no exception for: the
    client rejected as expected, but why cannot be read. A gap in EEST's
    mapper, so the verdict stays a pass and the campaign lists it apart."""


RUNNER_ERROR_PREFIX = "runner-error: "
"""Marks a verdict the harness produced, not the client: a timed-out
runner, a non-zero exit with no parseable report, or a fixture the runner
never mentioned.

The client never judged the case, so this is the same class as a tool
refusing the input -- never a failure, never a divergence, never a
signature. It keeps its own prefix rather than borrowing the refusal
patterns because the two say different things: a refusal is a property of
the case, a runner error is a property of our harness, and a broken
runner has to stay visible instead of reading as a stream of refusals."""


def is_runner_error(message: str) -> bool:
    """Whether a verdict's error came from the harness, not the client."""
    return message.startswith(RUNNER_ERROR_PREFIX)


_NETHERMIND_SUFFIX = re.compile(r"_d\d+g\d+v\d+_$")


def parse_json_array(stdout: str) -> Dict[str, Verdict]:
    """
    Verdicts from a `[{"name", "pass", "error", "rejections"}, ...]` list
    in stdout.

    The list is the first line-initial `[` that decodes: erigon prints
    `[WARN] ... use ERIGON_ prefix` lines ahead of it whenever an
    environment knob such as `IGNORE_BAL` is set, and taking the first `[`
    lost every verdict of its contrast run.
    """
    decoder = json.JSONDecoder()
    results: Any = None
    for match in re.finditer(r"^\[", stdout, re.MULTILINE):
        try:
            results, _ = decoder.raw_decode(stdout, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(results, list):
            break
        results = None
    if results is None:
        return {}
    verdicts: Dict[str, Verdict] = {}
    for entry in results:
        if isinstance(entry, dict) and "name" in entry:
            verdicts[str(entry["name"])] = Verdict(
                passed=bool(entry.get("pass")),
                error=str(entry.get("error") or ""),
                rejections=tuple(
                    (int(r["index"]), str(r.get("error") or ""))
                    for r in entry.get("rejections") or []
                ),
            )
    return verdicts


def expected_rejection(fixture: Mapping[str, Any]) -> Optional[str]:
    """
    The rejection ``fixture`` expects, as it names it, or None when it
    expects every block valid: a blockchain test's `expectException`, an
    engine test's `validationError`.
    """
    found = _expected_rejection_at(fixture)
    return None if found is None else found[1]


def _expected_rejection_at(
    fixture: Mapping[str, Any],
) -> Optional[Tuple[int, str]]:
    """The first block expected rejected: its index and exception."""
    for index, block in enumerate(fixture.get("blocks", [])):
        if block.get("expectException"):
            return index, str(block["expectException"])
    for index, payload in enumerate(fixture.get("engineNewPayloads", [])):
        if payload.get("validationError"):
            return index, str(payload["validationError"])
    return None


EXCEPTION_MAPPERS: Dict[str, type[ExceptionMapper]] = {
    "GethFixtureConsumer": GethExceptionMapper,
    "ErigonFixtureConsumer": ErigonExceptionMapper,
    "BesuFixtureConsumer": BesuExceptionMapper,
    "NethtestFixtureConsumer": NethermindExceptionMapper,
    "EthrexFixtureConsumer": EthrexExceptionMapper,
    "RethFixtureConsumer": RethExceptionMapper,
    "EvmOneBlockchainFixtureConsumer": EvmoneExceptionMapper,
}
"""Each runner's mapping from its client's errors to exception names: the
one `consume` uses for that client."""

WRONG_REASON = "rejected for the wrong reason: "


def check_rejection_reasons(
    kind: str,
    verdicts: Dict[str, Verdict],
    fixtures: Mapping[str, Any],
) -> None:
    """
    Fail each fixture its runner rejected as expected, but for another
    reason than the one the fixture names.

    A runner on the shared interface reports the client's own error for
    each rejected block without checking it, so its verdict passes on any
    rejection; the error at the block the fixture expects rejected is
    mapped here through the client's mapper instead. A runner from before
    the interface may carry that error in `error`. A pass with neither is
    left alone: that runner checked the reason itself. An error mapping to
    no exception is a gap in the mapper, not a finding: the pass stands,
    carrying the error in `unmapped`.
    """
    mapper = EXCEPTION_MAPPERS[kind]()
    for name, verdict in verdicts.items():
        found = _expected_rejection_at(fixtures.get(name) or {})
        if not verdict.passed or found is None:
            continue
        index, expected = found
        error = dict(verdict.rejections).get(index, verdict.error)
        if not error:
            continue
        mapped = mapper.message_to_exception(error)
        if not isinstance(mapped, list):
            verdicts[name] = replace(verdict, unmapped=error)
            continue
        names = [str(exception) for exception in mapped]
        if set(names).isdisjoint(expected.split("|")):
            verdicts[name] = Verdict(
                False, f"{WRONG_REASON}{'|'.join(names)}\n{error}"
            )


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


def parse_besu_ndjson(stdout: str) -> Dict[str, Verdict]:
    """Verdicts from `evmtool state-test`: one JSON object per line."""
    verdicts: Dict[str, Verdict] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = entry.get("name", entry.get("test"))
        if name is not None:
            verdicts[str(name)] = Verdict(
                passed=bool(entry.get("pass")),
                error=str(entry.get("error") or ""),
            )
    return verdicts


class StateTestsUnsupportedError(Exception):
    """The runner behind this binary judges blockchain fixtures only."""


def strip_nethermind_suffix(name: str) -> str:
    """Drop the `_d0g0v0_` decoration nethtest appends to test names."""
    return _NETHERMIND_SUFFIX.sub("", name)


ENGINE_RUNNERS = (
    "NethtestFixtureConsumer",
    "GethFixtureConsumer",
    "BesuFixtureConsumer",
    "EthrexFixtureConsumer",
    "ErigonFixtureConsumer",
    "RethFixtureConsumer",
)
"""Runners with an Engine API path wired: `nethtest --engineTest`, geth's
and erigon's `evm enginetest`, besu's `evmtool engine-test --json-array`,
ethrex's `ethrex-enginetest` and reth's `ef-test-runner enginetest`. Each
prints the same `name`, `pass`, `error` list its block runner does."""


class EngineRunnerUnsupportedError(ValueError):
    """An engine-format campaign named a client with no engine runner."""


def _native_kind(
    name: str, binary: Path, env: Mapping[str, str], engine: bool
) -> Optional[str]:
    """
    The kind of a runner EEST cannot detect, from its `--version` line.

    None for every other binary, which EEST's detection then identifies. A
    binary built for the other fixture format is refused here, since it
    would judge every case as unreadable.
    """
    line = native_version(binary, env)
    if line is None:
        return None
    if line.startswith("ef-test-runner"):
        return "RethFixtureConsumer"
    if line.startswith("ethrex-enginetest") != engine:
        wanted = "ethrex-enginetest" if engine else "ethrex-blocktest"
        raise ValueError(
            f"{name}: {line.split()[0]} judges the other fixture format; "
            f"this campaign needs {wanted}"
        )
    return "EthrexFixtureConsumer"


@dataclass
class FixtureRunner:
    """One client's standalone runner, keyed by EEST's consumer class."""

    name: str
    binary: Path
    kind: str
    flags: Tuple[str, ...] = ()
    env: Dict[str, str] = field(default_factory=dict)
    """Environment overrides layered on the parent environment. Some
    clients take their knobs this way rather than on argv -- erigon's
    `EXEC3_WORKERS` and `IGNORE_BAL` -- so a contrast run that only varies
    argv cannot reach them."""
    timeout: float = 1800.0
    engine: bool = False
    """Judge through the client's Engine API path (`blockchain_test_engine`
    fixtures) instead of its block import; see `ENGINE_RUNNERS`."""
    _last_error: str = ""
    last_stderr: str = ""
    """Standard error of the latest run: where a client prints what its
    verdict cannot carry, such as nethermind's sequential retry."""

    @classmethod
    def detect(
        cls,
        name: str,
        binary: Path,
        flags: Sequence[str] = (),
        env: Optional[Mapping[str, str]] = None,
        engine: bool = False,
    ) -> "FixtureRunner":
        """
        Identify the runner behind ``binary`` via EEST detection.

        Detection runs the binary, so it runs under the client's own
        environment; the runner then carries that environment into every
        run, and a contrast layers its overrides on top.
        """
        kind = _native_kind(name, binary, env or {}, engine)
        if kind is None:
            with client_environment(env or {}):
                consumer = FixtureConsumerTool.from_binary_path(
                    binary_path=binary
                )
            kind = type(consumer).__name__
        if engine and kind not in ENGINE_RUNNERS:
            raise EngineRunnerUnsupportedError(
                f"{name}: {kind} has no engine runner wired; an engine-format "
                f"campaign can judge only with {', '.join(ENGINE_RUNNERS)}"
            )
        return cls(
            name=name,
            binary=binary,
            kind=kind,
            flags=tuple(flags),
            env=dict(env or {}),
            engine=engine,
        )

    def with_flags(self, flags: Sequence[str]) -> "FixtureRunner":
        """The same binary driven with a different flag set."""
        return replace(
            self, flags=tuple(flags), _last_error="", last_stderr=""
        )

    def with_env(self, env: Mapping[str, str]) -> "FixtureRunner":
        """The same binary driven with extra environment overrides."""
        return replace(
            self,
            env={**self.env, **dict(env)},
            _last_error="",
            last_stderr="",
        )

    def _environ(self) -> Dict[str, str]:
        """The parent environment with this runner's overrides on top."""
        return {**os.environ, **self.env}

    def version(self) -> str:
        """The runner's `--version` line."""
        proc = subprocess.run(
            [str(self.binary), "--version"],
            capture_output=True,
            text=True,
            env=self._environ(),
        )
        return (proc.stdout or proc.stderr).strip().splitlines()[0]

    def _run(self, args: Sequence[str]) -> subprocess.CompletedProcess:
        command = [str(self.binary), *args]
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=self._environ(),
            )
        except subprocess.TimeoutExpired:
            proc = subprocess.CompletedProcess(
                command, -1, "", f"timed out after {self.timeout:.0f}s"
            )
        self.last_stderr = proc.stderr or ""
        return proc

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
        elif self.kind == "EthrexFixtureConsumer":
            verdicts = self._run_ethrex(path)
        elif self.kind == "RethFixtureConsumer":
            verdicts = self._run_reth(path)
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
                False, f"{RUNNER_ERROR_PREFIX}no result from {self.name}"
            )
        # Read the fixtures only when some pass carries an error to check.
        if any(
            v.passed and (v.error or v.rejections) for v in verdicts.values()
        ):
            check_rejection_reasons(
                self.kind, verdicts, json.loads(path.read_text())
            )
        return verdicts

    def run_state_file(
        self, path: Path, fixture_names: Iterable[str]
    ) -> Dict[str, Verdict]:
        """
        Judge every state test in ``path``, as `run_file` does for blocks.

        evmone splits the two formats across binaries, so the campaign's
        `evmone-blockchaintest` cannot judge a state test and says so.
        """
        names = list(fixture_names)
        self._last_error = ""
        if self.kind in ("GethFixtureConsumer", "ErigonFixtureConsumer"):
            args = ["statetest"]
            if self.kind == "ErigonFixtureConsumer":
                args.append("--jsonout")
            proc = self._run([*args, *self.flags, str(path)])
            verdicts = parse_json_array(proc.stdout)
        elif self.kind == "BesuFixtureConsumer":
            proc = self._run(["state-test", *self.flags, str(path)])
            verdicts = parse_besu_ndjson(proc.stdout)
        elif self.kind == "NethtestFixtureConsumer":
            # nethtest traces failing state tests to stdout by default,
            # which would bury the result list; the trace is not wanted.
            proc = self._run(
                [
                    "--stateTest",
                    "--neverTrace",
                    *self.flags,
                    "--input",
                    str(path),
                ]
            )
            verdicts = {
                strip_nethermind_suffix(n): v
                for n, v in parse_json_array(proc.stdout).items()
            }
        else:
            raise StateTestsUnsupportedError(
                f"{self.name}: {self.kind} judges blockchain fixtures only"
            )
        if not verdicts and proc.returncode != 0:
            verdicts = self._all_failed(
                f"{RUNNER_ERROR_PREFIX}{proc.stderr.strip()[:200]}"
            )
        for name in names:
            verdicts.setdefault(
                name,
                Verdict(
                    False,
                    f"{RUNNER_ERROR_PREFIX}no result from {self.name}",
                ),
            )
        return verdicts

    def _run_json_array(self, path: Path) -> Dict[str, Verdict]:
        # geth's `blocktest` reports `stateRoot` before #34650 and
        # `lastBlockHash` with an always-present `error` after it; only
        # `name`, `pass` and `error` are read, so both parse.
        args = ["enginetest" if self.engine else "blocktest"]
        if self.kind == "ErigonFixtureConsumer":
            args.append("--jsonout")
        proc = self._run([*args, *self.flags, str(path)])
        verdicts = parse_json_array(proc.stdout)
        if not verdicts and proc.returncode != 0:
            return self._all_failed(
                f"{RUNNER_ERROR_PREFIX}{proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _run_reth(self, path: Path) -> Dict[str, Verdict]:
        command = "enginetest" if self.engine else "blocktest"
        proc = self._run([command, "--json-array", *self.flags, str(path)])
        verdicts = parse_json_array(proc.stdout)
        if not verdicts and proc.returncode != 0:
            return self._all_failed(
                f"{RUNNER_ERROR_PREFIX}{proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _run_ethrex(self, path: Path) -> Dict[str, Verdict]:
        # One binary per format, so no subcommand: the flags and the file.
        proc = self._run([*self.flags, "--json", "--path", str(path)])
        verdicts = parse_json_array(proc.stdout)
        if not verdicts and proc.returncode != 0:
            return self._all_failed(
                f"{RUNNER_ERROR_PREFIX}{proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _run_gtest(self, path: Path) -> Dict[str, Verdict]:
        with tempfile.NamedTemporaryFile(suffix=".json") as report:
            proc = self._run(
                [f"--gtest_output=json:{report.name}", *self.flags, str(path)]
            )
            try:
                data = json.loads(Path(report.name).read_text() or "{}")
            except json.JSONDecodeError:
                data = {}
        verdicts = parse_gtest_report(data)
        if not verdicts and proc.returncode not in (0, 1):
            return self._all_failed(
                f"{RUNNER_ERROR_PREFIX}{proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _run_besu(self, path: Path) -> Dict[str, Verdict]:
        if self.engine:
            proc = self._run(
                ["engine-test", "--json-array", *self.flags, str(path)]
            )
            verdicts = parse_json_array(proc.stdout)
        else:
            proc = self._run(["block-test", *self.flags, str(path)])
            verdicts = parse_besu_summary(proc.stdout)
        if not verdicts and proc.returncode != 0:
            return self._all_failed(
                f"{RUNNER_ERROR_PREFIX}{proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _run_nethermind(self, path: Path) -> Dict[str, Verdict]:
        mode = "--engineTest" if self.engine else "--blockTest"
        proc = self._run([mode, *self.flags, "--input", str(path)])
        parsed = parse_json_array(proc.stdout)
        verdicts = {strip_nethermind_suffix(n): v for n, v in parsed.items()}
        if not verdicts and proc.returncode != 0:
            return self._all_failed(
                f"{RUNNER_ERROR_PREFIX}{proc.stderr.strip()[:200]}"
            )
        return verdicts

    def _all_failed(self, error: str) -> Dict[str, Verdict]:
        self._last_error = error
        return {}
