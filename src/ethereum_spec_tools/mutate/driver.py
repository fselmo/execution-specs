"""
Run mutants against an oracle, in parallel, without touching the checkout.

Each worker owns a copy of `src/` that it imports through `PYTHONPATH`, so
the checkout's own `src/` is never edited and an interrupted run leaves
nothing behind. A mutant is killed when its oracle fails or times out,
and survives when the oracle passes.
"""

import json
import os
import random
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from queue import Queue
from typing import Dict, List, Optional, Sequence, Tuple

from execution_testing.forks import Fork, get_forks

from ethereum_spec_tools.utils import resolve_fork

from .areas import AREAS, Area
from .operators import (
    Mutant,
    construct,
    function_mutants,
    function_source,
    gas_constants,
    previous_fork_mutants,
    same_function,
)

ORACLES = ("properties", "fixtures")


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


def fill_fixtures(root: Path, out: Path, fork: Fork, area: Area) -> Path:
    """Fill ``area``'s EEST tests once, from the unmutated spec."""
    target = out / "fixtures" / fork.name()
    marker = target / ".filled"
    wanted = "\n".join(area.fixtures)
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
    """The commands that must all pass for a mutant to survive."""
    area = AREAS[area_name]
    python = sys.executable
    base = [python, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"]
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


def run_one(
    root: Path,
    copy: Path,
    planned: Planned,
    commands: List[List[str]],
    timeout: int,
    scratch: Path,
) -> Dict[str, object]:
    """Apply one mutant to ``copy``, run the oracle, and undo it."""
    from .operators import apply

    mutant = planned.mutant
    target = copy / mutant.path
    original = target.read_text()
    target.write_text(apply(original, mutant))
    env = dict(os.environ)
    env["PYTHONPATH"] = str(copy / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HYPOTHESIS_STORAGE_DIRECTORY"] = str(scratch)
    verdict, by, started = "survived", "", time.monotonic()
    try:
        for command in commands:
            process = subprocess.Popen(
                command,
                cwd=root,
                env=env,
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
                verdict, by = "killed-timeout", " ".join(command[-2:])
                break
            if process.returncode != 0:
                failed = [
                    line
                    for line in output.splitlines()
                    if line.startswith(("FAILED", "ERROR"))
                ]
                verdict = "killed"
                by = (failed[0] if failed else output[-300:])[:300]
                break
    finally:
        target.write_text(original)
    return {
        "area": planned.area,
        **asdict(mutant),
        "id": mutant.ident,
        "verdict": verdict,
        "by": by,
        "seconds": round(time.monotonic() - started, 1),
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
    """Run ``chosen`` against ``oracle``; return the results file."""
    out.mkdir(parents=True, exist_ok=True)
    results = out / f"results-{oracle}.jsonl"
    done = set()
    if results.exists():
        done = {
            json.loads(line)["id"] for line in results.read_text().splitlines()
        }
    todo = [p for p in chosen if p.mutant.ident not in done]
    commands = {
        area: oracle_commands(root, out, fork, area, oracle)
        for area in dict.fromkeys(p.area for p in todo)
    }
    print(f"{len(todo)} mutants to run, {len(done)} already done")
    slots: "Queue[int]" = Queue()
    for i in range(workers):
        copy = out / "workers" / str(i)
        if not copy.exists():
            shutil.copytree(
                root / "src",
                copy / "src",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        (out / "workers" / f"hypothesis-{i}").mkdir(exist_ok=True)
        slots.put(i)

    def task(planned: Planned) -> Dict[str, object]:
        i = slots.get()
        try:
            return run_one(
                root,
                out / "workers" / str(i),
                planned,
                commands[planned.area],
                timeout,
                out / "workers" / f"hypothesis-{i}",
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
                f"[{n}/{len(todo)}] {result['verdict']:<14} "
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
    """A table per area and operator, then every survivor."""
    rows = [json.loads(line) for line in results.read_text().splitlines()]
    if ids is not None:
        wanted = set(ids)
        rows = [row for row in rows if row["id"] in wanted]
    lines = ["| area | mutants | killed | survived | known equivalent |"]
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    survivors: List[Tuple[str, Dict[str, object]]] = []
    for area in dict.fromkeys(row["area"] for row in rows):
        mine = [row for row in rows if row["area"] == area]
        notes = AREAS[area].notes
        alive = [row for row in mine if row["verdict"] == "survived"]
        equivalent = [row for row in alive if _construct(row) in notes]
        lines.append(
            f"| {area} | {len(mine)} | {len(mine) - len(alive)} | "
            f"{len(alive) - len(equivalent)} | {len(equivalent)} |"
        )
        survivors += [
            (area, row) for row in alive if _construct(row) not in notes
        ]
    lines.append("")
    for area, row in survivors:
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
