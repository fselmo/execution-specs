"""The `fuzz` command group."""

from pathlib import Path
from typing import Optional, Sequence

import click

from execution_testing.forks import get_forks

from .baseline import StaleClientError
from .campaign import CampaignOptions, run_campaign
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
    "--client",
    "only",
    multiple=True,
    help="Limit to these clients; repeat for several. Required with "
    "--update, which would otherwise re-resolve every branch-ref client.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="fuzz.yaml to read (default: nearest one in parent directories).",
)
def clients(
    update: bool, only: Sequence[str], config_path: Optional[Path]
) -> None:
    """
    Show each configured client: source, binary, and version.

    `--update` re-resolves a client's ref, so on a client pinned to a
    branch it silently replaces the binary with whatever that branch now
    points at. A rediscovery run depends on its clients being *older*
    than the fix they are meant to carry, and a blanket update destroys
    that premise without anyone choosing it -- erigon's block-access-list
    fix reached its devnet branch the day before the campaign that found
    the bug. So an update names its clients.
    """
    config = load_config_or_fail(config_path)
    if not config.clients:
        click.echo("no clients configured; declare them in fuzz.yaml")
        return
    known = {client.name for client in config.clients}
    unknown = sorted(set(only) - known)
    if unknown:
        raise click.BadParameter(
            f"unknown client(s): {', '.join(unknown)}; "
            f"declared: {', '.join(sorted(known))}",
            param_hint="--client",
        )
    if update and not only:
        raise click.UsageError(
            "--update needs --client NAME (repeat for several): updating "
            "every client at once re-resolves branch-pinned clients to "
            "their current heads. Pass --client for each one you mean to "
            "rebuild."
        )
    selected = [c for c in config.clients if not only or c.name in only]
    for client in selected:
        click.echo(f"{client.name:<14} {client_status(client, update=update)}")


@fuzz.command("campaign")
@click.argument("name")
@click.option("--hours", type=float, default=None, help="Time budget.")
@click.option("--count", type=int, default=None, help="Seed budget.")
@click.option("--batch", type=int, default=200, show_default=True)
@click.option(
    "--output",
    type=click.Path(path_type=Path, file_okay=False),
    default=None,
    help="Campaign directory [default: campaigns/NAME].",
)
@click.option(
    "--fill-workers", type=int, default=None, help="EELS fill processes."
)
@click.option(
    "--minimize", is_flag=True, help="Delta-debug each new signature."
)
@click.option("--fresh", is_flag=True, help="Discard prior state and corpus.")
@click.option(
    "--no-baseline", is_flag=True, help="Skip the stale-client check."
)
@click.option(
    "--invariant-checks",
    is_flag=True,
    help="Check spec-side invariants on every fill, counting violations "
    "(costs ~2% of fill; catches errors no client comparison can).",
)
@click.option("--keep-fixtures", is_flag=True, help="Keep every batch file.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="fuzz.yaml to read (default: nearest one in parent directories).",
)
def campaign(
    name: str,
    hours: Optional[float],
    count: Optional[int],
    batch: int,
    output: Optional[Path],
    fill_workers: Optional[int],
    minimize: bool,
    fresh: bool,
    no_baseline: bool,
    invariant_checks: bool,
    keep_fixtures: bool,
    config_path: Optional[Path],
) -> None:
    """
    Run a long-lived differential campaign: fill batches through EELS and
    judge them with every client's standalone runner, keeping only what is
    new. Resumable; leave it in a terminal.
    """
    if hours is None and count is None:
        raise click.UsageError("pass --hours or --count")
    config = load_config_or_fail(config_path)
    campaign_config = campaign_or_fail(config, name)
    assert campaign_config is not None
    clients = resolve_campaign_clients(config, campaign_config.clients)
    fork = next(f for f in get_forks() if f.name() == campaign_config.fork)
    options = CampaignOptions(
        fork=fork,
        clients=clients,
        output=output or Path("campaigns") / name,
        seed_start=campaign_config.seed_start,
        hours=hours,
        count=count,
        batch=batch,
        fill_workers=fill_workers or campaign_config.workers,
        minimize=minimize,
        fresh=fresh,
        baseline=not no_baseline,
        keep_fixtures=keep_fixtures,
        invariant_checks=invariant_checks,
        known=tuple((k.client, k.reason) for k in campaign_config.known),
    )
    click.echo(
        f"campaign {name}: {campaign_config.fork} vs {', '.join(clients)} "
        f"-> {options.output} "
        f"(batch {batch}, {options.fill_workers} fill workers)"
    )
    try:
        state = run_campaign(options, echo=click.echo)
    except StaleClientError as exc:
        raise click.ClickException(
            f"{exc}\nrebuild the stale client(s) (`fuzz clients --update`) "
            "or pass --no-baseline"
        ) from exc
    except KeyboardInterrupt:
        click.echo(
            "\ninterrupted; state saved -- rerun the same command to resume"
        )
        return
    click.echo(
        f"done: {state.unique_findings()} unique signature(s); "
        f"report at {options.output / 'report.md'}"
    )


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
    results, errors, rejections, allocs = run_tools(tools, case, case.fork)
    errors = {**errors, **rejections}
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
