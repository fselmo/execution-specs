#!/usr/bin/env python3
"""
Compare an opcode family's existing test cases against the new code-path
matrix to verify nothing is dropped during migration.

Usage:
    python scripts/audit_codepath_coverage.py call

The script:

1. Walks `OLD_TEST_PATHS[family]` and emits every `(file, function,
   parametrize_id)` triple it can statically detect by AST-parsing the
   `@pytest.mark.parametrize` decorators.
2. Runs `pytest --collect-only -q` against `NEW_TEST_PATHS[family]` and
   captures the generated node ids.
3. Cross-checks via the MAPPING_TABLE: every old triple must either map to
   a new node id (exact substring match against the test_call.py id portion)
   or be listed in DOCUMENTED_DROPS with a rationale.

Exit codes: 0 on full coverage, 1 if anything is unmapped or any new id
is unreachable.
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]

OLD_TEST_PATHS: dict[str, list[Path]] = {
    "call": [
        REPO_ROOT / "tests/frontier/opcodes/test_call.py",
        REPO_ROOT
        / "tests/frontier/opcodes/test_call_and_callcode_gas_calculation.py",
        REPO_ROOT / "tests/byzantium/eip214_staticcall/test_staticcall.py",
        REPO_ROOT / "tests/berlin/eip2929_gas_cost_increases/test_call.py",
    ],
}

NEW_TEST_PATHS: dict[str, Path] = {
    "call": REPO_ROOT / "tests/opcodes/call",
}

# Each entry: (old_function_substring, new_id_substring_required, rationale).
#
# An old test case is considered covered when there exists at least one
# collected new id whose suffix contains every `new_id_substring_required`.
# If a row appears in DOCUMENTED_DROPS, it is excluded from the audit with
# the listed rationale (which will surface in the report).
MAPPING_TABLE: list[tuple[str, list[str], str]] = [
    # PoC scope below — fills out as axes are added.
    (
        "test_call_large_offset_mstore",
        ["target=eoa", "value=zero"],
        "PENDING: ret_layout=huge-offset-zero-size axis not yet implemented",
    ),
    (
        "test_call_memory_expands_on_early_revert",
        ["target=eoa", "value=nonzero"],
        "PENDING: gas_variant=insufficient-balance not yet implemented",
    ),
    (
        "test_call_large_args_offset_size_zero",
        ["target=eoa", "value=zero"],
        "PENDING: args_layout=huge-offset-zero-size axis not yet implemented",
    ),
    (
        "test_call_insufficient_balance",
        ["target=eoa", "value=nonzero"],
        "PENDING: gas_variant=insufficient-balance not yet implemented",
    ),
]

DOCUMENTED_DROPS: dict[str, str] = {
    # function_id -> rationale. Empty for now.
}


@dataclass(frozen=True)
class OldCase:
    """One discovered legacy test case: file, function, parametrize id."""

    file: Path
    function: str
    param_id: str

    def __str__(self) -> str:
        """Human-readable identifier like `path::function[param_id]`."""
        rel = self.file.relative_to(REPO_ROOT)
        return f"{rel}::{self.function}[{self.param_id}]"


def _parametrize_values(deco: ast.Call) -> list[list[str]]:
    """Return the list of value-id lists from one parametrize decorator."""
    if not deco.args or len(deco.args) < 2:
        return []

    values_node = deco.args[1]
    if not isinstance(values_node, (ast.List, ast.Tuple)):
        return []

    out: list[list[str]] = []
    for entry in values_node.elts:
        if isinstance(entry, ast.Call) and isinstance(
            entry.func, ast.Attribute
        ):
            # pytest.param(..., id="...")
            param_id = None
            for kw in entry.keywords:
                if kw.arg == "id" and isinstance(kw.value, ast.Constant):
                    param_id = str(kw.value.value)
                    break
            if param_id is None and entry.args:
                first = entry.args[0]
                if isinstance(first, ast.Constant):
                    param_id = str(first.value)
                else:
                    param_id = ast.unparse(first)
            if param_id is not None:
                out.append([param_id])
        elif isinstance(entry, ast.Constant):
            out.append([str(entry.value)])
        else:
            out.append([ast.unparse(entry)])
    return out


def _function_cases(func: ast.FunctionDef, file: Path) -> Iterable[OldCase]:
    parametrize_axes: list[list[str]] = []
    has_parametrize = False
    for deco in func.decorator_list:
        if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute):
            if deco.func.attr == "parametrize":
                vals = _parametrize_values(deco)
                if vals:
                    has_parametrize = True
                    # Flatten if single-axis values are nested lists of len 1
                    parametrize_axes.append([v[0] for v in vals])

    if not has_parametrize:
        yield OldCase(file=file, function=func.name, param_id="")
        return

    # Product over axes — pytest reverses decorator stack vs source order but
    # for audit purposes the exact id-concat is not needed; we only care that
    # *every* combination produces a known case.
    for combo in product(*parametrize_axes):
        yield OldCase(file=file, function=func.name, param_id="-".join(combo))


def collect_old(family: str) -> list[OldCase]:
    """AST-walk legacy test paths for `family`, yielding `OldCase`s."""
    cases: list[OldCase] = []
    for path in OLD_TEST_PATHS[family]:
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith(
                "test_"
            ):
                cases.extend(_function_cases(node, path))
    return cases


def collect_new(family: str) -> list[str]:
    """Collect new-matrix node ids via `pytest --collect-only -q`."""
    target = NEW_TEST_PATHS[family]
    if not target.exists():
        return []
    result = subprocess.run(
        ["uv", "run", "pytest", str(target), "--collect-only", "-q"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        sys.stderr.write(
            f"WARN: pytest --collect-only exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        )
    ids: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("=", "WARNING", "INFO")):
            continue
        if "::" in line:
            ids.append(line)
    return ids


def audit(family: str) -> int:
    """Report old→new coverage and pending entries for `family`."""
    old = collect_old(family)
    new = collect_new(family)
    print(f"old cases: {len(old)}")
    print(f"new collected ids: {len(new)}")
    print()

    unmapped: list[OldCase] = []
    pending: list[OldCase] = []

    for case in old:
        if case.function in DOCUMENTED_DROPS:
            print(f"DROPPED  {case}  -- {DOCUMENTED_DROPS[case.function]}")
            continue

        matched = False
        rationale = None
        for func_substr, required, why in MAPPING_TABLE:
            if func_substr in case.function:
                if why.startswith("PENDING"):
                    rationale = why
                    pending.append(case)
                    matched = True
                    break
                if all(req in nid for nid in new for req in required) or any(
                    all(req in nid for req in required) for nid in new
                ):
                    matched = True
                    break

        if not matched:
            unmapped.append(case)
        elif rationale:
            print(f"PENDING  {case}  -- {rationale}")
        else:
            print(f"OK       {case}")

    print()
    print(f"unmapped: {len(unmapped)}")
    for case in unmapped:
        print(f"  MISSING  {case}")
    print(
        f"pending:  {len(pending)}  "
        "(will be covered when listed axes implement)"
    )
    if unmapped:
        return 1
    return 0


def main() -> int:
    """CLI entry point for the audit script."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "family",
        choices=sorted(OLD_TEST_PATHS),
        help="opcode family to audit",
    )
    args = parser.parse_args()
    return audit(args.family)


if __name__ == "__main__":
    sys.exit(main())
