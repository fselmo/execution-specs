"""The `fuzz` command group."""

from pathlib import Path
from typing import Optional, Sequence

import click

from execution_testing.forks import get_forks

from .baseline import StaleClientError
from .campaign import CampaignOptions, contrast_lanes, run_campaign
from .clients import client_status, verify_client
from .corpus import load_case
from .differential import (
    _COMPARED_FIELDS,
    as_chain,
    block_prefix,
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
    resolve_campaign,
)
from .distill_cli import distill
from .fuzz_cli import fuzz as run
from .health import HealthPolicy
from .status import serve as serve_status
from .status import status_view


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
    "--campaign",
    "campaign_name",
    default=None,
    help="Limit to the clients a campaign names, its producer included.",
)
@click.option(
    "--verify",
    is_flag=True,
    help="Exit non-zero unless every selected client resolves to a binary "
    "that answers --version. Never builds.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="fuzz.yaml to read (default: nearest one in parent directories).",
)
def clients(
    update: bool,
    only: Sequence[str],
    campaign_name: Optional[str],
    verify: bool,
    config_path: Optional[Path],
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

    `--verify` turns the same report into a gate: it exits non-zero unless
    every selected client resolves to a binary that answers, which is the
    check to run against `--campaign NAME` before a long run.
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
    campaign = campaign_or_fail(config, campaign_name)
    wanted = set(only)
    if campaign is not None:
        wanted |= set(campaign.clients)
        if campaign.producer:
            wanted.add(campaign.producer)
    selected = [c for c in config.clients if not wanted or c.name in wanted]
    if campaign is not None:
        missing = sorted(wanted - {c.name for c in config.clients})
        if missing:
            raise click.ClickException(
                f"campaign {campaign_name!r} names undeclared client(s): "
                f"{', '.join(missing)}"
            )
    if verify:
        if update:
            raise click.UsageError(
                "--verify reports the pool as it stands and never builds; "
                "run it after --update, not with it."
            )
        unusable = []
        for client in selected:
            ok, detail = verify_client(client)
            click.echo(
                f"{client.name:<14} {'ok  ' if ok else 'FAIL'} {detail}"
            )
            if not ok:
                unusable.append(client.name)
        if unusable:
            raise click.ClickException(
                f"{len(unusable)} of {len(selected)} client(s) cannot run: "
                f"{', '.join(unusable)}"
            )
        click.echo(f"{len(selected)} client(s) verified")
        return
    for client in selected:
        click.echo(f"{client.name:<14} {client_status(client, update=update)}")


@fuzz.command("campaign")
@click.argument("name")
@click.option(
    "--hours",
    type=float,
    default=None,
    help="Time budget. With neither this nor --count the campaign runs "
    "until stopped: SIGTERM or Ctrl-C finishes the current batch, saves "
    "state and exits.",
)
@click.option("--count", type=int, default=None, help="Seed budget.")
@click.option(
    "--continue",
    "resume",
    is_flag=True,
    help="Resume the campaign at its next seed; refuse if it has no state.",
)
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
    "--producer",
    "producer_name",
    default=None,
    help="Declared client whose transition tool fills instead of EELS "
    "(overrides the campaign's `producer`).",
)
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
    resume: bool,
    batch: int,
    output: Optional[Path],
    fill_workers: Optional[int],
    minimize: bool,
    fresh: bool,
    no_baseline: bool,
    invariant_checks: bool,
    keep_fixtures: bool,
    producer_name: Optional[str],
    config_path: Optional[Path],
) -> None:
    """
    Run a long-lived differential campaign: fill batches through EELS and
    judge them with every client's standalone runner, keeping only what is
    new. Resumable; leave it in a terminal.
    """
    if resume and fresh:
        raise click.UsageError("--continue and --fresh contradict each other")
    config = load_config_or_fail(config_path)
    campaign_config = campaign_or_fail(config, name)
    assert campaign_config is not None
    resolved = resolve_campaign(config, campaign_config.clients)
    clients = {n: r.binary for n, r in resolved.items()}
    sources = {n: r.source for n, r in resolved.items()}
    fork = next(f for f in get_forks() if f.name() == campaign_config.fork)
    producer_name = producer_name or campaign_config.producer
    producer = None
    if producer_name:
        producer_client = resolve_campaign(config, [producer_name])[
            producer_name
        ]
        producer = producer_client.binary
        sources[f"producer ({producer_name})"] = producer_client.source
    output = output or Path("campaigns") / name
    health = campaign_config.health
    if resume and not (output / "state.json").is_file():
        raise click.UsageError(
            f"--continue: {output} holds no campaign state to resume"
        )
    options = CampaignOptions(
        fork=fork,
        clients=clients,
        output=output,
        reproduce_runs=campaign_config.reproduce_runs,
        runner_concurrency=campaign_config.runner_concurrency,
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
        runner_flags={
            n: config.client(n).runner_flags for n in campaign_config.clients
        },
        contrast_flags={
            n: flags
            for n in campaign_config.clients
            if (flags := config.client(n).contrast_flags) is not None
        },
        contrast_env={
            n: env
            for n in campaign_config.clients
            if (env := config.client(n).contrast_env) is not None
        },
        client_env={n: dict(r.env) for n, r in resolved.items() if r.env},
        contrasts={
            n: runs
            for n in campaign_config.clients
            if (runs := config.client(n).contrasts)
        },
        producer=producer,
        producer_name=producer_name or "producer",
        fixture_format=campaign_config.fixture_format,
        sources=sources,
        health=HealthPolicy(
            window=health.window,
            control_client=health.control.client if health.control else None,
            control_reason=health.control.reason if health.control else None,
            control_band=health.control_band,
            max_runner_error_rate=health.max_runner_error_rate,
            max_producer_disagreement_rate=(
                health.max_producer_disagreement_rate
            ),
            parallel_lanes=tuple(health.parallel_lanes),
            parallel_drop_tolerance=health.parallel_drop_tolerance,
        ),
    )
    if producer is not None:
        click.echo(
            f"  {producer_name} fills the cases; EELS judges only where "
            "the panel disagrees"
        )
    click.echo(
        f"campaign {name}: {campaign_config.fork} vs {', '.join(clients)} "
        f"-> {options.output} "
        f"(batch {batch}, {options.fill_workers} fill workers, "
        f"{options.fixture_format})"
    )
    for lane, (_, contrast_run) in sorted(contrast_lanes(options).items()):
        knobs = [
            *(
                contrast_run.flags
                if contrast_run.flags is not None
                else ["(primary flags)"]
            ),
            *(f"{k}={v}" for k, v in contrast_run.env.items()),
        ]
        click.echo(
            f"  {lane} runs under {' '.join(knobs) or '(no flags)'}; a "
            "fixture judged differently there is a contrast-mismatch"
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
            "\ninterrupted mid-batch; state holds the last finished batch "
            "-- resume with --continue"
        )
        return
    click.echo(
        f"done: {state.unique_findings()} unique signature(s); "
        f"report at {options.output / 'report.md'}"
    )


@fuzz.command("status")
@click.argument("name")
@click.option(
    "--output",
    type=click.Path(path_type=Path, file_okay=False),
    default=None,
    help="Campaign directory [default: campaigns/NAME].",
)
@click.option(
    "--serve",
    is_flag=True,
    help="Serve a read-only status page on 127.0.0.1 until interrupted.",
)
@click.option("--port", type=int, default=8787, show_default=True)
def status(name: str, output: Optional[Path], serve: bool, port: int) -> None:
    """
    Show a campaign's status: one line, or with --serve a read-only page
    on loopback for a proxy (Tailscale) to expose. It binds 127.0.0.1
    only, answers GET for the page and its JSON, and serves no files.
    """
    output = output or Path("campaigns") / name
    view = status_view(output)
    summary = view.get("summary", {})
    click.echo(
        f"{name}: {view['status']}"
        + (f" ({view['status_reason']})" if view.get("status_reason") else "")
        + f", {summary.get('cases', 0)} cases, "
        f"{len(view.get('findings', []))} finding(s), "
        f"segment {view.get('segment', {}).get('id') or '-'}"
    )
    if not serve:
        return
    server = serve_status(output, port)
    click.echo(f"serving http://127.0.0.1:{server.server_address[1]}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


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
    resolved = resolve_campaign(config, campaign.clients) if campaign else {}
    clients = {name: r.binary for name, r in resolved.items()}
    clients.update(name_clients(client_paths))
    if not clients:
        raise click.UsageError(
            "no clients to compare: pass --client PATH or a --campaign"
        )

    case = load_case(case_path)
    tools = build_tools(
        clients, {n: r.env for n, r in resolved.items() if r.env}
    )
    results, errors, rejections, allocs = run_tools(tools, case, case.fork)
    errors = {**errors, **rejections}
    divergence_list = compare_results(results) if results else []
    divergences = {d.field: d for d in divergence_list}

    chains = {name: as_chain(result) for name, result in results.items()}
    blocks = max((len(chain) for chain in chains.values()), default=0)
    for index in range(blocks):
        for field_name in (*_COMPARED_FIELDS, "rejected_transactions"):
            key = block_prefix(index) + field_name
            divergence = divergences.get(key)
            click.echo(key)
            for name in tools:
                if name in errors or index >= len(chains.get(name, [])):
                    click.echo(f"  {name:<12} (failed)")
                    continue
                result = chains[name][index]
                if field_name == "rejected_transactions":
                    value = str(
                        sorted(
                            int(r.index) for r in result.rejected_transactions
                        )
                    )
                else:
                    value = str(getattr(result, field_name, None))
                if divergence is not None and name in divergence.minority:
                    mark = "   <- minority"
                else:
                    mark = ""
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
