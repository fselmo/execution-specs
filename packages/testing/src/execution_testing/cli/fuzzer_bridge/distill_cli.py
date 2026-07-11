"""Command-line interface for distilling a corpus case into a test."""

import json
from pathlib import Path
from typing import Optional

import click

from .distill import distill_source
from .generator import GENERATOR_VERSION
from .models import FuzzerOutput


def _infer_seed(path: Path) -> Optional[int]:
    """Recover the seed from a corpus filename like ``..._seed12.json``."""
    stem = path.stem
    marker = "seed"
    if marker in stem:
        tail = stem.rsplit(marker, 1)[-1]
        if tail.isdigit():
            return int(tail)
    return None


@click.command()
@click.argument(
    "case_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument(
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
)
@click.option(
    "--reason",
    default="fuzzer finding",
    help="Why this case is interesting (goes in the test docstring).",
)
def distill(case_path: Path, output_path: Path, reason: str) -> None:
    """
    Render a corpus case (FuzzerOutput JSON) as a reviewable spec test.

    CASE_PATH is a corpus JSON file produced by `fuzz` or `fuzz-differential`.
    OUTPUT_PATH is the Python test file to write.
    """
    case = FuzzerOutput(**json.loads(case_path.read_text()))
    source = distill_source(
        case,
        fork_name=case.fork.name(),
        reason=reason,
        seed=_infer_seed(case_path),
        generator_version=GENERATOR_VERSION,
    )
    output_path.write_text(source)
    click.echo(f"wrote {output_path}")


if __name__ == "__main__":
    distill()
