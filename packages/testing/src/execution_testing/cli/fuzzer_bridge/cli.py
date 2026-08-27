"""The `fuzz` command group."""

from pathlib import Path
from typing import Optional, Sequence

import click

from .clients import client_status
from .corpus import load_case
from .differential import (
    _COMPARED_FIELDS,
    build_tools,
    compare_results,
    post_state_diff,
    run_tools,
)
from .differential_cli import (
    campaign_or_fail,
    differential,
    load_config_or_fail,
    name_clients,
    resolve_campaign_clients,
)
from .distill_cli import distill
from .fuzz_cli import fuzz as run


@click.group()
def fuzz() -> None:
    """Generate cases, fuzz the spec, and compare clients against it."""


@fuzz.command("clients")
@click.option(
    "--update",
    is_flag=True,
    help="Re-resolve refs and build new commits for source builds.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="fuzz.yaml to read (default: nearest one in parent directories).",
)
def clients(update: bool, config_path: Optional[Path]) -> None:
    """Show each configured client: source, binary, and version."""
    config = load_config_or_fail(config_path)
    if not config.clients:
        click.echo("no clients configured; declare them in fuzz.yaml")
        return
    for client in config.clients:
        click.echo(f"{client.name:<14} {client_status(client, update=update)}")


@fuzz.command("replay")
@click.argument(
    "case_path", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--campaign",
    "campaign_name",
    default=None,
    help="Campaign from fuzz.yaml supplying the clients.",
)
@click.option(
    "--client",
    "client_paths",
    type=click.Path(exists=True, path_type=Path),
    multiple=True,
    help="Client t8n binary; repeat for several clients (auto-detected).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="fuzz.yaml to read (default: nearest one in parent directories).",
)
def replay(
    case_path: Path,
    campaign_name: Optional[str],
    client_paths: Sequence[Path],
    config_path: Optional[Path],
) -> None:
    """
    Re-run one corpus case through EELS and every client, field by field.

    Exits 1 when the tools disagree, so a fixed client can be re-checked
    from a script.
    """
    config = load_config_or_fail(config_path)
    campaign = campaign_or_fail(config, campaign_name)
    clients = (
        resolve_campaign_clients(config, campaign.clients) if campaign else {}
    )
    clients.update(name_clients(client_paths))
    if not clients:
        raise click.UsageError(
            "no clients to compare: pass --client PATH or a --campaign"
        )

    case = load_case(case_path)
    tools = build_tools(clients)
    results, errors, allocs = run_tools(tools, case, case.fork)
    divergence_list = compare_results(results) if results else []
    divergences = {d.field: d for d in divergence_list}

    for field_name in (*_COMPARED_FIELDS, "rejected_transactions"):
        divergence = divergences.get(field_name)
        click.echo(field_name)
        for name in tools:
            if name in errors:
                click.echo(f"  {name:<12} (failed)")
                continue
            result = results[name]
            if field_name == "rejected_transactions":
                value = str(
                    sorted(int(r.index) for r in result.rejected_transactions)
                )
            else:
                value = str(getattr(result, field_name, None))
            mark = (
                "   <- minority"
                if divergence is not None and name in divergence.minority
                else ""
            )
            click.echo(f"  {name:<12} {value}{mark}")
    for name, error in errors.items():
        click.echo(f"{name} failed: {error}")
    for tool, diff in post_state_diff(divergence_list, allocs).items():
        click.echo(f"post-state: {tool} differs from eels on")
        for address, account in diff.items():
            click.echo(f"  {address}: {account}")

    if divergences or (errors and len(errors) < len(tools)):
        raise SystemExit(1)


fuzz.add_command(run, name="run")
fuzz.add_command(differential, name="diff")
fuzz.add_command(distill, name="distill")
