"""Command-line interface for spec mutation testing."""

from pathlib import Path
from typing import List

import click

from .runner import Oracle, Verdict, run_mutation_testing


@click.command()
@click.option(
    "--module",
    "module_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Spec source file to mutate (e.g. forks/osaka/vm/gas.py).",
)
@click.option(
    "--test",
    "test_paths",
    required=True,
    multiple=True,
    help="Test path(s) to run as the kill oracle. Repeatable.",
)
@click.option(
    "--oracle",
    type=click.Choice([o.value for o in Oracle]),
    default=Oracle.FILL.value,
    show_default=True,
    help="Kill oracle: 'fill' (conformance suite) or 'properties' "
    "(the tests_property suite).",
)
@click.option(
    "--fork",
    default="",
    help="Fork to fill against (required for the 'fill' oracle).",
)
@click.option(
    "--max-mutants",
    type=int,
    default=None,
    help="Cap the number of mutants (deterministic sample).",
)
@click.option("--seed", type=int, default=0, show_default=True)
@click.option(
    "--timeout",
    type=int,
    default=600,
    show_default=True,
    help="Per-run timeout in seconds; a timeout counts as a kill.",
)
@click.option(
    "--include-constants",
    is_flag=True,
    help="Also mutate integer/boolean constants (numerous, noisier).",
)
def mutate(
    module_path: Path,
    test_paths: tuple[str, ...],
    oracle: str,
    fork: str,
    max_mutants: int,
    seed: int,
    timeout: int,
    include_constants: bool,
) -> None:
    """
    Mutation-test a spec module: measure how many small spec errors the
    test suite catches, and list the survivors as coverage gaps.
    """
    oracle_choice = Oracle(oracle)
    if oracle_choice is Oracle.FILL and not fork:
        raise click.UsageError("--fork is required for the 'fill' oracle")
    paths: List[str] = list(test_paths)
    click.echo(
        f"Mutating {module_path} against {len(paths)} test path(s) "
        f"[{oracle} oracle]..."
    )

    report = run_mutation_testing(
        module_path,
        paths,
        fork,
        oracle=oracle_choice,
        max_mutants=max_mutants,
        seed=seed,
        timeout=timeout,
        include_constants=include_constants,
    )

    click.echo(
        f"\nmutation score: {report.killed}/{report.total} "
        f"({report.score:.0%})"
    )
    for verdict in Verdict:
        count = sum(1 for r in report.results if r.verdict == verdict)
        if count:
            click.echo(f"  {verdict.value}: {count}")

    if report.invariant_only:
        click.echo("\ncaught by invariants but missed by tests:")
        for result in report.invariant_only:
            click.echo(f"  {result.mutant.description}")

    if report.survivors:
        click.echo("\nSURVIVORS (suite coverage gaps):")
        for result in report.survivors:
            click.echo(f"  {result.mutant.description}")
    else:
        click.echo("\nno survivors — suite kills every sampled mutant")


if __name__ == "__main__":
    mutate()
