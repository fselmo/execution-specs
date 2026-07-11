"""Command-line interface for EELS-vs-client differential fuzzing."""

from pathlib import Path
from typing import Optional

import click

from execution_testing.forks import get_forks

from .differential import differential_fuzz
from .generator import GENERATOR_VERSION


def _resolve_fork(name: str) -> object:
    for fork in get_forks():
        if fork.name() == name:
            return fork
    raise click.BadParameter(f"unknown fork {name!r}")


@click.command()
@click.option("--fork", "fork_name", required=True, help="Fork to fuzz.")
@click.option(
    "--evm-bin",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to the client transition tool (geth's evm binary).",
)
@click.option("--seed-start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=100, show_default=True)
@click.option(
    "--corpus",
    "corpus_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory to save divergent cases.",
)
@click.option("--no-minimize", is_flag=True)
@click.option(
    "-j",
    "--workers",
    type=int,
    default=1,
    show_default=True,
    help="Parallel worker processes; large runs benefit from more.",
)
def differential(
    fork_name: str,
    evm_bin: Path,
    seed_start: int,
    count: int,
    corpus_dir: Optional[Path],
    no_minimize: bool,
    workers: int,
) -> None:
    """
    Compare the reference spec (EELS) against a client transition tool on
    generated cases, and report consensus-relevant divergences.
    """
    fork = _resolve_fork(fork_name)
    seeds = range(seed_start, seed_start + count)

    click.echo(
        f"Differential {fork_name} (generator v{GENERATOR_VERSION}) "
        f"EELS vs {evm_bin.name}, seeds {seed_start}..{seed_start + count - 1}"
        f" ({workers} worker{'s' if workers != 1 else ''})"
    )

    report = differential_fuzz(
        fork,  # type: ignore[arg-type]
        seeds,
        client_binary=evm_bin,
        corpus_dir=corpus_dir,
        minimize_cases=not no_minimize,
        workers=workers,
    )

    click.echo(
        f"\nagreed {report.agreed}/{report.seeds}  diverged {report.diverged}"
    )
    for outcome in report.outcomes:
        if outcome.error is not None:
            click.echo(f"  seed {outcome.seed}: {outcome.error}")
        for divergence in outcome.divergences:
            click.echo(
                f"  seed {outcome.seed}: {divergence.field} "
                f"eels={divergence.eels} client={divergence.client}"
            )
    if corpus_dir is not None and report.diverged:
        click.echo(f"\ndivergent cases saved to {corpus_dir}")


if __name__ == "__main__":
    differential()
