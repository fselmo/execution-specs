"""
Run mutants against an oracle, in parallel, without touching the checkout.

Each worker owns a copy of `src/` that it imports through `PYTHONPATH`, so
the checkout's own `src/` is never edited. Before any mutant runs, each
area's oracle must pass on the unmutated spec, under coverage: a mutant
on a line the oracle never executes is reported as not reached without
being run, a mutant is killed only when tests ran and failed, and it
survives when the oracle passes.
"""

import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from queue import Queue
from typing import Dict, List, Optional, Sequence, Set, Tuple

from execution_testing.forks import Fork, get_forks

from ethereum_spec_tools.utils import resolve_fork

from .areas import AREAS, Area
from .operators import (
    Mutant,
    apply,
    construct,
    function_mutants,
    function_source,
    gas_constants,
    previous_fork_mutants,
    same_function,
)

ORACLES = ("properties", "fixtures")

CRASHES = ("TypeError", "NameError", "AttributeError", "UnboundLocalError")
"""Errors that mean a mutant broke the code's shape, not its result: the
first test to run it fails whatever it asserts, so the kill shows that the
line is reached and nothing about what is checked."""

_RAISED = re.compile(r"^E\s+(?:\w+\.)*(\w+(?:Error|Exception))\b", re.M)


def fork_by_name(name: str) -> Fork:
    """The framework fork named ``name``."""
    for fork in get_forks():
        if fork.name().lower() == name.lower():
            return fork
    raise ValueError(f"no framework fork named {name}")


def package_of(fork: Fork) -> str:
    """The short name of ``fork``'s spec package."""
    return resolve_fork(fork.transition_tool_name()).short_name


def packages_before(fork: Fork) -> List[str]:
    """The spec packages of the forks before ``fork``, newest first."""
    target = package_of(fork)
    out: List[str] = []
    for other in get_forks():
        if other == fork:
            break
        try:
            package = package_of(other)
        except Exception:  # noqa: BLE001 - a fork without its own package
            continue
        if package != target and package not in out:
            out.append(package)
    return out[::-1]


def resolve(package: str, relative: str) -> str:
    """An area's file path, relative to the repository root."""
    if relative.startswith("@"):
        return f"src/{relative[1:]}"
    return f"src/ethereum/forks/{package}/{relative}"


@dataclass(frozen=True)
class Planned:
    """A mutant with the area it belongs to."""

    area: str
    mutant: Mutant


def plan(root: Path, fork: Fork, areas: Sequence[str]) -> List[Planned]:
    """Every mutant of ``areas`` at ``fork``, in a stable order."""
    package = package_of(fork)
    before = packages_before(fork)
    gas_path = root / resolve(package, "vm/gas.py")
    gas = gas_constants(gas_path.read_text()) if gas_path.exists() else {}
    out: List[Planned] = []
    for name in areas:
        area = AREAS[name]
        for relative, patterns in area.functions:
            path = resolve(package, relative)
            source = (root / path).read_text()
            missing = [
                pattern
                for pattern in patterns
                if not pattern.endswith("*")
                and function_source(source, pattern) is None
            ]
            if missing:
                raise ValueError(f"{name}: {path} has no {missing}")
            mutants = function_mutants(path, source, patterns, gas)
            if before and not relative.startswith("@"):
                previous = root / resolve(before[0], relative)
                if previous.exists():
                    mutants += previous_fork_mutants(
                        path, source, previous.read_text(), patterns
                    )
            out += [Planned(name, mutant) for mutant in mutants]
    return out


def sample(planned: List[Planned], per_area: int, seed: int) -> List[Planned]:
    """
    At most ``per_area`` mutants of each area. Each area's draw depends only
    on ``seed`` and the area, so a sample stays the same whatever other
    areas a run includes.
    """
    if per_area <= 0:
        return planned
    out: List[Planned] = []
    for area in dict.fromkeys(p.area for p in planned):
        mine = [p for p in planned if p.area == area]
        random.Random(f"{seed}:{area}").shuffle(mine)
        out += sorted(mine[:per_area], key=planned.index)
    return out


def carried_forks(
    root: Path, fork: Fork, path: str, function: str
) -> List[str]:
    """
    The other spec packages whose copy of ``function`` is the same code as
    ``fork``'s, so a result for this fork holds for them unchanged.
    """
    package = package_of(fork)
    prefix = f"src/ethereum/forks/{package}/"
    if not path.startswith(prefix):
        return []
    relative = path[len(prefix) :]
    here = function_source((root / path).read_text(), function)
    out = []
    for other in sorted((root / "src/ethereum/forks").iterdir()):
        candidate = other / relative
        if other.name == package or not candidate.exists():
            continue
        if same_function(
            here, function_source(candidate.read_text(), function)
        ):
            out.append(other.name)
    return out


def spec_state(root: Path) -> str:
    """The commit and uncommitted changes of the checkout, as one hash."""
    parts = [
        subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        for arguments in (["rev-parse", "HEAD"], ["diff", "HEAD"])
    ]
    return hashlib.sha256("".join(parts).encode()).hexdigest()


def fill_fixtures(root: Path, out: Path, fork: Fork, area: Area) -> Path:
    """
    Fill ``area``'s EEST tests from the unmutated spec, unless the fixtures
    there were filled from this same checkout state.
    """
    target = out / "fixtures" / fork.name()
    marker = target / ".filled"
    wanted = "\n".join((*area.fixtures, spec_state(root)))
    if marker.exists() and marker.read_text() == wanted:
        return target / "blockchain_tests"
    command = [
        "uv",
        "run",
        "fill",
        *area.fixtures,
        "--fork",
        fork.name(),
        "--output",
        str(target),
        "--clean",
        "-q",
        "-n",
        "4",
    ]
    subprocess.run(command, cwd=root, check=True, stdout=subprocess.DEVNULL)
    marker.write_text(wanted)
    return target / "blockchain_tests"


def oracle_commands(
    root: Path,
    out: Path,
    fork: Fork,
    area_name: str,
    oracle: str,
) -> List[List[str]]:
    """
    The pytest arguments of each run that must pass for a mutant to
    survive.
    """
    area = AREAS[area_name]
    base = ["-x", "-q", "-p", "no:cacheprovider"]
    if oracle == "properties":
        if not area.properties:
            raise ValueError(f"{area_name} has no property tests")
        selector = ["-k", fork.name()] if area.forked else []
        return [
            [*base, f"tests_property/{module}.py", *selector]
            for module in area.properties
        ]
    if not area.fixtures:
        raise ValueError(f"{area_name} has no fixtures")
    fixtures = fill_fixtures(root, out / area_name, fork, area)
    return [[*base, "-p", "tests.json_loader.conftest", str(fixtures)]]


def _environment(copy: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(copy / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


@dataclass(frozen=True)
class Baseline:
    """What an area's oracle does on the unmutated spec."""

    seconds: float
    """How long the oracle took."""
    lines: Dict[str, Set[int]]
    """The lines it executed, by file relative to the repository root."""

    def reaches(self, mutant: Mutant) -> bool:
        """Whether the oracle executes any line ``mutant`` edits."""
        executed = self.lines.get(mutant.path, set())
        return any(
            line in executed
            for line in range(mutant.lineno, mutant.end_lineno + 1)
        )


def baseline(
    root: Path, copy: Path, area: str, commands: List[List[str]], out: Path
) -> Baseline:
    """
    Run ``area``'s oracle on the unmutated spec, under coverage. It must
    pass: an oracle that fails, or selects no test, would report every
    mutant killed.
    """
    # A development dependency, needed only when mutants are run.
    from coverage import CoverageData

    data = out / f"coverage-{area}"
    data.unlink(missing_ok=True)
    env = _environment(copy)
    env.setdefault("COVERAGE_CORE", "sysmon")
    started = time.monotonic()
    for command in commands:
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--append",
                f"--data-file={data}",
                f"--include={copy}/src/ethereum/*",
                "-m",
                "pytest",
                *command,
            ],
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if process.returncode != 0:
            raise RuntimeError(
                f"{area}: the oracle does not pass on the unmutated spec "
                f"(pytest {' '.join(command)} exited "
                f"{process.returncode}):\n{process.stdout[-600:]}"
            )
    seconds = time.monotonic() - started
    measured = CoverageData(str(data))
    measured.read()
    lines = {
        str(Path(name).relative_to(copy)): set(measured.lines(name) or ())
        for name in measured.measured_files()
    }
    return Baseline(seconds, lines)


def run_one(
    root: Path,
    copy: Path,
    planned: Planned,
    commands: List[List[str]],
    timeout: float,
) -> Dict[str, object]:
    """Apply one mutant to ``copy``, run the oracle, and undo it."""
    mutant = planned.mutant
    target = copy / mutant.path
    original = (root / mutant.path).read_text()
    target.write_text(apply(original, mutant))
    verdict, by, started = "survived", "", time.monotonic()
    try:
        for command in commands:
            process = subprocess.Popen(
                [sys.executable, "-m", "pytest", *command],
                cwd=root,
                env=_environment(copy),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            try:
                output, _ = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                verdict, by = "timed-out", " ".join(command[-2:])
                break
            # pytest exits 1 when tests ran and some failed. Anything else
            # non-zero (a usage error, no test selected) says nothing about
            # the mutant.
            if process.returncode == 1:
                failed = [
                    line
                    for line in output.splitlines()
                    if line.startswith(("FAILED", "ERROR"))
                ]
                raised = _RAISED.search(output)
                crashed = raised is not None and raised.group(1) in CRASHES
                verdict = "crashed" if crashed else "killed"
                by = (failed[0] if failed else output[-300:])[:300]
                break
            if process.returncode != 0:
                verdict = "error"
                by = f"pytest exited {process.returncode}: {output[-300:]}"
                break
    finally:
        target.write_text(original)
    return _row(planned, verdict, by, time.monotonic() - started)


def _row(
    planned: Planned, verdict: str, by: str, seconds: float
) -> Dict[str, object]:
    return {
        "area": planned.area,
        **asdict(planned.mutant),
        "id": planned.mutant.ident,
        "verdict": verdict,
        "by": by,
        "seconds": round(seconds, 1),
    }


def run(
    root: Path,
    out: Path,
    fork: Fork,
    chosen: List[Planned],
    oracle: str,
    workers: int,
    timeout: int,
) -> Path:
    """
    Run ``chosen`` against ``oracle``; return the results file. A
    ``timeout`` of zero allows each mutant ten times its area's baseline.
    """
    out.mkdir(parents=True, exist_ok=True)
    results = out / f"results-{oracle}.jsonl"
    state = spec_state(root)
    stamp = out / f"results-{oracle}.state"
    if results.exists() and (not stamp.exists() or stamp.read_text() != state):
        # Verdicts for another state of the spec or its tests say nothing
        # about this one.
        results.rename(results.with_suffix(f".{int(time.time())}.jsonl"))
    stamp.write_text(state)
    done = set()
    if results.exists():
        done = {
            json.loads(line)["id"] for line in results.read_text().splitlines()
        }
    todo = [p for p in chosen if p.mutant.ident not in done]
    print(f"{len(todo)} mutants to run, {len(done)} already done")
    if not todo:
        return results
    # Fresh copies every run: one left mutated by a killed run, or made
    # from an older checkout, would corrupt every verdict after it.
    shutil.rmtree(out / "workers", ignore_errors=True)
    slots: "Queue[int]" = Queue()
    for i in range(workers):
        shutil.copytree(
            root / "src",
            out / "workers" / str(i) / "src",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        slots.put(i)
    commands: Dict[str, List[List[str]]] = {}
    baselines: Dict[str, Baseline] = {}
    for area in dict.fromkeys(p.area for p in todo):
        commands[area] = oracle_commands(root, out, fork, area, oracle)
        baselines[area] = baseline(
            root, out / "workers" / "0", area, commands[area], out
        )
        print(f"{area}: baseline passes in {baselines[area].seconds:.0f} s")

    def task(planned: Planned) -> Dict[str, object]:
        if not baselines[planned.area].reaches(planned.mutant):
            return _row(planned, "not-reached", "", 0.0)
        i = slots.get()
        try:
            return run_one(
                root,
                out / "workers" / str(i),
                planned,
                commands[planned.area],
                timeout or 10 * baselines[planned.area].seconds + 30,
            )
        finally:
            slots.put(i)

    with ThreadPoolExecutor(workers) as pool, results.open("a") as log:
        futures = [pool.submit(task, p) for p in todo]
        for n, future in enumerate(as_completed(futures), 1):
            result = future.result()
            log.write(json.dumps(result) + "\n")
            log.flush()
            print(
                f"[{n}/{len(todo)}] {result['verdict']:<12} "
                f"{result['area']} {result['path']}:{result['lineno']} "
                f"{result['operator']}",
                flush=True,
            )
    return results


def _construct(row: Dict[str, object]) -> str:
    return construct(
        str(row["function"]), str(row["original"]), str(row["mutated"])
    )


def summarize(
    root: Path, fork: Fork, results: Path, ids: Optional[Sequence[str]]
) -> str:
    """
    A table per area, then every mutant the tests ran over without
    noticing, then the ones they never ran.
    """
    rows = [json.loads(line) for line in results.read_text().splitlines()]
    if ids is not None:
        wanted = set(ids)
        rows = [row for row in rows if row["id"] in wanted]
    lines = [
        "| area | mutants | killed | crashed | timed out | survived | "
        "known equivalent | not reached |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    listed: Dict[str, List[Tuple[str, Dict[str, object]]]] = {
        "survived": [],
        "not-reached": [],
        "error": [],
    }
    for area in dict.fromkeys(row["area"] for row in rows):
        mine = [row for row in rows if row["area"] == area]
        notes = AREAS[area].notes
        count = {
            verdict: sum(row["verdict"] == verdict for row in mine)
            for verdict in (
                "killed",
                "crashed",
                "timed-out",
                "survived",
                "not-reached",
            )
        }
        equivalent = sum(
            row["verdict"] == "survived" and _construct(row) in notes
            for row in mine
        )
        lines.append(
            f"| {area} | {len(mine)} | {count['killed']} | "
            f"{count['crashed']} | {count['timed-out']} | "
            f"{count['survived'] - equivalent} | {equivalent} | "
            f"{count['not-reached']} |"
        )
        for row in mine:
            if row["verdict"] in listed and _construct(row) not in notes:
                listed[str(row["verdict"])].append((area, row))
    for verdict, title in (
        ("survived", "Ran and went unnoticed"),
        ("not-reached", "Never ran"),
        ("error", "Could not be judged"),
    ):
        if not listed[verdict]:
            continue
        lines += ["", f"{title}:", ""]
        for area, row in listed[verdict]:
            carried = carried_forks(
                root, fork, str(row["path"]), str(row["function"])
            )
            also = f" (same code in {', '.join(carried)})" if carried else ""
            lines.append(
                f"- `{row['id']}` {area} `{row['path']}:{row['lineno']}` "
                f"`{row['function']}` {row['operator']}: "
                f"`{' '.join(str(row['original']).split())[:80]}` -> "
                f"`{' '.join(str(row['mutated']).split())[:80]}`{also}"
            )
    return "\n".join(lines)
