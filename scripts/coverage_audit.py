#!/usr/bin/env python3
r"""
Coverage audit for the opcode-targeted test layer.

Reads the `.coverage` SQLite file produced by `uv run fill --cov=src/ethereum
--cov-context=test` and reports:

1. Uncovered spec lines per fork (the "where are the gaps" answer).
2. Aggregate coverage percentage per spec file and per fork.
3. (Best effort) per-test contribution — currently limited because pytest-cov
   + `fill` only records ONE context per matrix run. The per-test
   attribution requires further work in the filler/pytest-cov integration;
   tracked as a separate follow-up.

Usage:
    # 1. Generate coverage data
    uv run fill tests/opcodes/call/ --fork=Amsterdam \\
        --output=/tmp/opcodes-fixtures --clean \\
        --cov=src/ethereum --cov-context=test --cov-report=

    # 2. Run this audit
    uv run python scripts/coverage_audit.py --fork=Amsterdam

    # Limit to specific spec subtree:
    uv run python scripts/coverage_audit.py \\
        --fork=Amsterdam --path=vm/instructions

    # Function-level: report coverage only for named functions. Useful
    # while a feature is partially implemented (e.g., CALL implemented,
    # CALLCODE / DELEGATECALL / STATICCALL still NotImplementedError).
    uv run python scripts/coverage_audit.py \\
        --fork=Amsterdam --function=call,generic_call

Exit code is always 0 — this script is informational, not a gate.
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

import coverage

REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class FileCoverage:
    """Aggregate coverage for one spec file."""

    path: Path
    covered: frozenset[int]
    total: int  # executable lines in the file (covered + uncovered)

    @property
    def uncovered(self) -> frozenset[int]:
        """Executable-but-uncovered lines. Filled by `_collect_files`."""
        return frozenset()

    @property
    def pct(self) -> float:
        """Percent of executable lines that are covered."""
        if not self.total:
            return 100.0
        return 100.0 * len(self.covered) / self.total


def _function_line_ranges(
    spec_file: Path, names: set[str]
) -> list[tuple[str, Path, range]]:
    """
    AST-parse `spec_file` and return [(func_name, path, lineno_range), ...]
    for every top-level function whose name is in `names`.

    `range(start, end+1)` covers `def name(...):` through the function's
    last line. Methods on classes and nested functions are NOT returned.
    Async functions ARE included.
    """
    try:
        tree = ast.parse(spec_file.read_text(), filename=str(spec_file))
    except SyntaxError:
        return []
    out: list[tuple[str, Path, range]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in names:
                end = node.end_lineno or node.lineno
                out.append((node.name, spec_file, range(node.lineno, end + 1)))
    return out


def _resolve_fork_root(fork: str) -> Path:
    """Map a fork name to its spec source directory."""
    candidate = REPO_ROOT / "src" / "ethereum" / "forks" / fork.lower()
    if not candidate.is_dir():
        forks_dir = REPO_ROOT / "src/ethereum/forks"
        known = [p.name for p in forks_dir.iterdir() if p.is_dir()]
        raise SystemExit(
            f"fork={fork!r}: no spec directory at {candidate}. "
            f"Known forks: {known}"
        )
    return candidate


def _collect_files(
    cov: coverage.Coverage,
    fork_root: Path,
    path_filter: str | None,
) -> list[tuple[Path, frozenset[int], frozenset[int]]]:
    """
    Return [(file_path, covered_lines, missing_lines), ...] for every
    spec file under `fork_root` that matches `path_filter` (if given).
    """
    data = cov.get_data()
    measured = {Path(f).resolve() for f in data.measured_files()}

    rows: list[tuple[Path, frozenset[int], frozenset[int]]] = []
    for spec_file in fork_root.rglob("*.py"):
        if path_filter and path_filter not in str(
            spec_file.relative_to(fork_root)
        ):
            continue
        if spec_file.resolve() not in measured:
            # The framework didn't import this file in the measured run.
            # Either dead code path or a file that requires a different
            # test selection to reach. Report it as fully uncovered.
            _, executable, _, missing, _ = cov.analysis2(str(spec_file))
            rows.append((spec_file, frozenset(), frozenset(executable)))
            continue
        _, executable, _, missing, _ = cov.analysis2(str(spec_file))
        covered = frozenset(executable) - frozenset(missing)
        rows.append((spec_file, covered, frozenset(missing)))
    return rows


def _contexts_summary(cov: coverage.Coverage) -> tuple[int, list[str]]:
    """Return (count_with_real_context, sample_of_contexts)."""
    data = cov.get_data()
    contexts = sorted(c for c in data.measured_contexts() if c)
    return len(contexts), contexts[:5]


def audit_functions(
    *,
    fork: str,
    path_filter: str | None,
    function_names: set[str],
) -> int:
    """Function-level coverage report. Filters to named top-level defs."""
    coverage_file = REPO_ROOT / ".coverage"
    if not coverage_file.exists():
        print("ERROR: .coverage not found.", file=sys.stderr)
        return 2

    cov = coverage.Coverage(data_file=str(coverage_file))
    cov.load()

    fork_root = _resolve_fork_root(fork)

    print(f"=== Function-level coverage for fork={fork} ===")
    print(f"functions: {sorted(function_names)}")
    if path_filter:
        print(f"path filter: {path_filter}")
    print()

    found_any = False
    header = (
        f"{'pct':>6}  {'cov':>4}/{'tot':>4}  {'missing':>7}  function  (file)"
    )
    print(header)
    print("-" * 78)
    for spec_file in sorted(fork_root.rglob("*.py")):
        if path_filter and path_filter not in str(
            spec_file.relative_to(fork_root)
        ):
            continue
        for name, _, lineno_range in _function_line_ranges(
            spec_file, function_names
        ):
            found_any = True
            _, executable, _, missing, _ = cov.analysis2(str(spec_file))
            exec_in_fn = {ln for ln in executable if ln in lineno_range}
            missing_in_fn = {ln for ln in missing if ln in lineno_range}
            covered_in_fn = exec_in_fn - missing_in_fn
            total = len(exec_in_fn)
            pct = 100.0 * len(covered_in_fn) / total if total else 100.0
            rel = spec_file.relative_to(fork_root)
            print(
                f"{pct:6.1f}  {len(covered_in_fn):4d}/{total:4d}  "
                f"{len(missing_in_fn):7d}  {name}  ({rel})"
            )
            if missing_in_fn:
                sample = sorted(missing_in_fn)[:10]
                suffix = "..." if len(missing_in_fn) > 10 else ""
                print(
                    f"          missing: {sample}{suffix} "
                    f"(in {lineno_range.start}-{lineno_range.stop - 1})"
                )

    if not found_any:
        filter_note = f" (path filter: {path_filter})" if path_filter else ""
        print(
            f"No functions named {sorted(function_names)} found under "
            f"{fork_root}{filter_note}."
        )
    return 0


def audit(*, fork: str, path_filter: str | None) -> int:
    """Aggregate-mode coverage report for `fork` (default mode)."""
    coverage_file = REPO_ROOT / ".coverage"
    if not coverage_file.exists():
        print(
            "ERROR: .coverage not found. Generate it first:\n"
            "  uv run fill tests/opcodes/call/ --fork="
            f"{fork} --cov=src/ethereum --cov-context=test --cov-report=",
            file=sys.stderr,
        )
        return 2

    cov = coverage.Coverage(data_file=str(coverage_file))
    cov.load()

    fork_root = _resolve_fork_root(fork)
    rows = _collect_files(cov, fork_root, path_filter)

    total_covered = sum(len(c) for _, c, _ in rows)
    total_executable = sum(len(c) + len(m) for _, c, m in rows)
    if total_executable:
        overall_pct = 100.0 * total_covered / total_executable
    else:
        overall_pct = 100.0

    print(f"=== Coverage audit for fork={fork} ===")
    if path_filter:
        print(f"path filter: {path_filter}")
    print()
    print(
        f"Overall: {total_covered} / {total_executable} lines covered "
        f"({overall_pct:.1f}%)"
    )
    print()

    n_ctx, ctx_sample = _contexts_summary(cov)
    print(f"Per-test contexts recorded: {n_ctx}")
    for ctx in ctx_sample:
        print(f"  {ctx}")
    if n_ctx <= 1:
        print(
            "  WARNING: pytest-cov + fill integration currently records "
            "only ~1 context per matrix run.\n"
            "  Per-test attribution is unavailable; aggregate coverage is "
            "still trustworthy. See script docstring for follow-up."
        )
    print()

    print("Per-file coverage (sorted by uncovered lines, descending):")
    for spec_file, covered, missing in sorted(
        rows, key=lambda r: len(r[2]), reverse=True
    ):
        rel = spec_file.relative_to(fork_root)
        n_cov = len(covered)
        n_miss = len(missing)
        total = n_cov + n_miss
        pct = 100.0 * n_cov / total if total else 100.0
        marker = " ✓" if n_miss == 0 else ""
        print(
            f"  {pct:6.1f}%  {n_cov:4d}/{total:4d}  "
            f"uncovered={n_miss:4d}  {rel}{marker}"
        )

    print()
    # Top gaps: files with most uncovered lines AND with at least some
    # coverage (i.e., we hit the file but missed branches).
    print("Top gaps (files with >0 covered AND >0 missing):")
    gaps = [(f, c, m) for f, c, m in rows if len(c) > 0 and len(m) > 0]
    gaps.sort(key=lambda r: len(r[2]), reverse=True)
    for spec_file, _covered, missing in gaps[:5]:
        rel = spec_file.relative_to(fork_root)
        sample = sorted(missing)[:10]
        suffix = "..." if len(missing) > 10 else ""
        print(f"  {rel}: {len(missing)} missing lines: {sample}{suffix}")

    return 0


def main() -> int:
    """CLI entry point: dispatch to aggregate or function-level audit."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fork",
        required=True,
        help=(
            "Fork name (e.g., Amsterdam, Prague). "
            "Lowercased to find the spec dir."
        ),
    )
    parser.add_argument(
        "--path",
        dest="path_filter",
        default=None,
        help="Optional substring filter on spec file paths.",
    )
    parser.add_argument(
        "--function",
        dest="function_names",
        default=None,
        help=(
            "Comma-separated list of top-level function names to report. "
            "When set, switches to function-level coverage. Useful while "
            "siblings are still NotImplementedError stubs."
        ),
    )
    args = parser.parse_args()
    if args.function_names:
        names = {
            n.strip() for n in args.function_names.split(",") if n.strip()
        }
        return audit_functions(
            fork=args.fork,
            path_filter=args.path_filter,
            function_names=names,
        )
    return audit(fork=args.fork, path_filter=args.path_filter)


if __name__ == "__main__":
    sys.exit(main())
