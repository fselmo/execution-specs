"""Command-line interface for in-process fuzzing against the reference spec."""

from pathlib import Path
from typing import Optional

import click

from execution_testing.forks import get_forks

from .fuzz import fuzz as run_fuzz
from .generator import GENERATOR_VERSION


def _resolve_fork(name: str) -> object:
    for fork in get_forks():
        if fork.name() == name:
            return fork
    raise click.BadParameter(
        f"unknown fork {name!r}; known forks: "
        + ", ".join(f.name() for f in get_forks())
    )


@click.command()
@click.option(
    "--fork",
    "fork_name",
    required=True,
    help="Fork to fuzz (e.g. Osaka).",
)
@click.option(
    "--seed-start",
    type=int,
    default=0,
    show_default=True,
    help="First seed (inclusive).",
)
@click.option(
    "--count",
    type=int,
    default=100,
    show_default=True,
    help="Number of seeds to fuzz.",
)
@click.option(
    "--corpus",
    "corpus_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory to save interesting (violating/crashing) cases.",
)
@click.option(
    "--no-minimize",
    is_flag=True,
    help="Skip delta-debugging minimization of interesting cases.",
)
def fuzz(
    fork_name: str,
    seed_start: int,
    count: int,
    corpus_dir: Optional[Path],
    no_minimize: bool,
) -> None:
    """
    Generate seeded cases, fill them through the reference spec (EELS), and
    report invariant violations and crashes.

    Every case is reproducible from ``(fork, generator version, seed)``; the
    generator version is printed so a run is exactly replayable.
    """
    fork = _resolve_fork(fork_name)
    seeds = range(seed_start, seed_start + count)

    click.echo(
        f"Fuzzing {fork_name} "
        f"(generator v{GENERATOR_VERSION}), "
        f"seeds {seed_start}..{seed_start + count - 1}"
    )

    report = run_fuzz(
        fork,  # type: ignore[arg-type]
        seeds,
        corpus_dir=corpus_dir,
        minimize_cases=not no_minimize,
    )

    click.echo(
        f"\nfilled {report.filled}/{report.seeds}  "
        f"crashes {report.crashes}  "
        f"invariant-violation cases {report.violation_cases}"
    )
    for outcome in report.outcomes:
        if outcome.error is not None:
            click.echo(f"  seed {outcome.seed}: CRASH {outcome.error}")
        elif outcome.violations:
            for message in outcome.violations:
                click.echo(f"  seed {outcome.seed}: {message}")
    if corpus_dir is not None and (report.crashes or report.violation_cases):
        click.echo(f"\ninteresting cases saved to {corpus_dir}")


if __name__ == "__main__":
    fuzz()
