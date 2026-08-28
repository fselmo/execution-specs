"""Command-line interface for spec mutation testing."""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

import click

from .reach_log import (
    append_reach_log,
    eels_commit,
    reach_record,
    reach_trend,
)
from .runner import (
    DifferentialOptions,
    Oracle,
    Verdict,
    run_mutation_testing,
    run_shapes,
)
from .shapes import SHAPES


@click.command()
@click.option(
    "--module",
    "module_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Spec source file to mutate (e.g. forks/osaka/vm/gas.py).",
)
@click.option(
    "--shape",
    "shape_names",
    multiple=True,
    type=click.Choice(sorted(SHAPES)),
    help="Named bug-class shape to apply instead of operator mutants; "
    "repeatable. `all` is spelled by repeating every name.",
)
@click.option(
    "--test",
    "test_paths",
    multiple=True,
    help="Test path(s) to run as the kill oracle (fill/properties). "
    "Repeatable.",
)
@click.option(
    "--oracle",
    type=click.Choice([o.value for o in Oracle]),
    default=Oracle.FILL.value,
    show_default=True,
    help="Kill oracle: 'fill' (conformance suite), 'properties' (the "
    "tests_property suite) or 'differential' (`fuzz diff` vs clients).",
)
@click.option(
    "--fork",
    default="",
    help="Fork to fill or fuzz against (fill and differential oracles).",
)
@click.option(
    "--campaign",
    default=None,
    help="fuzz.yaml campaign for the differential oracle.",
)
@click.option(
    "--client",
    "clients",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Client t8n binary for the differential oracle; repeatable.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="fuzz.yaml for the differential oracle.",
)
@click.option(
    "--diff-count",
    type=int,
    default=300,
    show_default=True,
    help="Seeds per differential oracle run.",
)
@click.option(
    "-j",
    "--workers",
    type=int,
    default=1,
    show_default=True,
    help="Worker processes for the differential oracle.",
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
@click.option(
    "--reach-log",
    "reach_log_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Append trendable reach records (JSONL) here after a shape run.",
)
@click.option(
    "--reach-trend",
    "reach_trend_path",
    type=click.Path(exists=True, path_type=Path, dir_okay=False),
    default=None,
    help="Print the reach trend from this log and exit.",
)
def mutate(
    module_path: Optional[Path],
    shape_names: Sequence[str],
    test_paths: Sequence[str],
    oracle: str,
    fork: str,
    campaign: Optional[str],
    clients: Sequence[Path],
    config_path: Optional[Path],
    diff_count: int,
    workers: int,
    max_mutants: Optional[int],
    seed: int,
    timeout: int,
    include_constants: bool,
    reach_log_path: Optional[Path],
    reach_trend_path: Optional[Path],
) -> None:
    """
    Mutation-test a spec module: measure how many small spec errors the
    test suite catches, and list the survivors as coverage gaps.

    With `--shape`, apply named bug-class models instead and report
    whether the oracle notices each -- under the differential oracle that
    is the generator's reach for the class.
    """
    if reach_trend_path is not None:
        click.echo(reach_trend(reach_trend_path))
        return
    oracle_choice = Oracle(oracle)
    if (module_path is None) == (not shape_names):
        raise click.UsageError("pass exactly one of --module or --shape")
    if oracle_choice in (Oracle.FILL, Oracle.PROPERTIES) and not test_paths:
        raise click.UsageError(f"--test is required for the {oracle} oracle")
    if oracle_choice in (Oracle.FILL, Oracle.DIFFERENTIAL) and not fork:
        raise click.UsageError(f"--fork is required for the {oracle} oracle")
    differential = None
    if oracle_choice is Oracle.DIFFERENTIAL:
        if campaign is None and not clients:
            raise click.UsageError(
                "the differential oracle needs --campaign or --client"
            )
        differential = DifferentialOptions(
            fork=fork,
            count=diff_count,
            campaign=campaign,
            clients=tuple(clients),
            workers=workers,
            config=config_path,
        )
    paths: List[str] = list(test_paths)

    if shape_names:
        shapes = [SHAPES[name] for name in shape_names]
        click.echo(
            f"Applying {len(shapes)} shape(s) [{oracle} oracle"
            f"{f', {diff_count} seeds' if differential else ''}]..."
        )
        results = run_shapes(
            shapes,
            oracle_choice,
            paths,
            fork,
            differential=differential,
            timeout=timeout,
        )
        for result in results:
            detail = f"  {result.detail}" if result.detail else ""
            click.echo(
                f"  {result.shape.name:<34} {result.verdict.value}{detail}"
            )
        if reach_log_path is not None:
            stamp = datetime.now(timezone.utc).isoformat()
            commit = eels_commit()
            append_reach_log(
                [
                    reach_record(
                        r, fork=fork, eels_commit=commit, timestamp=stamp
                    )
                    for r in results
                ],
                reach_log_path,
            )
            click.echo(f"reach log appended: {reach_log_path}")
        return

    assert module_path is not None
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
        for caught in report.invariant_only:
            click.echo(f"  {caught.mutant.description}")

    if report.survivors:
        click.echo("\nSURVIVORS (suite coverage gaps):")
        for survivor in report.survivors:
            click.echo(f"  {survivor.mutant.description}")
    else:
        click.echo("\nno survivors -- suite kills every sampled mutant")


if __name__ == "__main__":
    mutate()
