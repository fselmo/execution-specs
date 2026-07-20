"""CLI to print a fork's derived change manifest."""

from collections import defaultdict
from typing import Dict, List

import click

from execution_testing.forks import Fork, get_forks

from .manifest import Change, derived_checklist_sections, diff_forks


def _resolve_fork(name: str) -> Fork:
    for fork in get_forks():
        if fork.name() == name:
            return fork
    raise click.BadParameter(f"unknown fork {name!r}")


@click.command()
@click.option("--from", "from_name", required=True, help="Base fork.")
@click.option("--to", "to_name", required=True, help="Target fork.")
def eip_manifest(from_name: str, to_name: str) -> None:
    """
    Derive and print the change manifest between two forks, grouped by EIP.

    The manifest is computed from the forks' own typed surface: scalar
    predicates, GasCosts fields, opcode/system-contract sets, and the
    calculator methods each new EIP mixin overrides.
    """
    fork_a = _resolve_fork(from_name)
    fork_b = _resolve_fork(to_name)
    changes = diff_forks(fork_a, fork_b)

    by_eip: Dict[str, List[Change]] = defaultdict(list)
    for change in changes:
        for eip in change.eips or ["(unattributed)"]:
            by_eip[eip].append(change)

    click.echo(
        f"Change manifest {from_name} -> {to_name}: "
        f"{len(changes)} changes across {len(by_eip)} EIPs\n"
    )
    for eip in sorted(by_eip):
        click.echo(f"{eip}:")
        for change in by_eip[eip]:
            click.echo(f"  {change}")
        click.echo("")

    sections = derived_checklist_sections(changes)
    click.echo("Derived checklist sections required for this fork:")
    for section in sorted(sections):
        click.echo(f"  - {section}")


if __name__ == "__main__":
    eip_manifest()
