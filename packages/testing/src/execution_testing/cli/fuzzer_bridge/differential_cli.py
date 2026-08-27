"""Command-line interface for EELS-vs-client differential fuzzing."""

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, TypeVar

import click

from execution_testing.forks import get_forks

from .baseline import StaleClientError
from .clients import resolve_client
from .config import CampaignConfig, FuzzConfig, load_fuzz_config
from .differential import differential_fuzz
from .generator import GENERATOR_VERSION

T = TypeVar("T")


def _resolve_fork(name: str) -> object:
    for fork in get_forks():
        if fork.name() == name:
            return fork
    raise click.BadParameter(f"unknown fork {name!r}", param_hint="--fork")


def name_clients(paths: Sequence[Path]) -> Dict[str, Path]:
    """Key clients by binary stem, suffixing duplicates (`evm`, `evm-2`)."""
    names: Dict[str, Path] = {}
    for path in paths:
        name, n = path.stem, 2
        while name in names:
            name, n = f"{path.stem}-{n}", n + 1
        names[name] = path
    return names


def resolve_campaign_clients(
    config: FuzzConfig, names: Sequence[str]
) -> Dict[str, Path]:
    """Map campaign client names to binaries, building sources if needed."""
    clients: Dict[str, Path] = {}
    for name in names:
        try:
            clients[name] = resolve_client(config.client(name)).binary
        except subprocess.CalledProcessError as exc:
            raise click.ClickException(f"building {name}: {exc}") from exc
    return clients


def _pick(flag: Optional[T], campaign_value: Optional[T], default: T) -> T:
    """Flag beats campaign beats default."""
    if flag is not None:
        return flag
    if campaign_value is not None:
        return campaign_value
    return default


def load_config_or_fail(path: Optional[Path]) -> FuzzConfig:
    """Load fuzz.yaml, reporting a broken file as a CLI error."""
    try:
        return load_fuzz_config(path)
    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


def campaign_or_fail(
    config: FuzzConfig, name: Optional[str]
) -> Optional[CampaignConfig]:
    """Look up a campaign by name; an unknown name is a CLI error."""
    if name is None:
        return None
    try:
        return config.campaigns[name]
    except KeyError:
        known = ", ".join(config.campaigns) or "none"
        raise click.BadParameter(
            f"unknown campaign {name!r}; declared: {known}",
            param_hint="--campaign",
        ) from None


@click.command()
@click.option(
    "--campaign",
    "campaign_name",
    default=None,
    help="Campaign from fuzz.yaml supplying fork, clients, and run size.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="fuzz.yaml to read (default: nearest one in parent directories).",
)
@click.option("--fork", "fork_name", default=None, help="Fork to fuzz.")
@click.option(
    "--client",
    "client_paths",
    type=click.Path(exists=True, path_type=Path),
    multiple=True,
    help="Client t8n binary; repeat for several clients (auto-detected).",
)
@click.option(
    "--seed-start", type=int, default=None, help="First seed [default: 0]."
)
@click.option(
    "--count", type=int, default=None, help="Number of seeds [default: 100]."
)
@click.option(
    "--corpus",
    "corpus_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory to save divergent cases.",
)
@click.option("--no-minimize", is_flag=True)
@click.option(
    "--baseline-seeds",
    type=int,
    default=None,
    help="Seeds every client must agree with EELS on first [default: 20].",
)
@click.option(
    "--no-baseline", is_flag=True, help="Skip the stale-client check."
)
@click.option(
    "--no-tiering",
    is_flag=True,
    help="Run EELS on every case instead of only on client disagreement.",
)
@click.option(
    "--summary-json",
    "summary_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Write a machine-readable summary of the run here.",
)
@click.option(
    "-j",
    "--workers",
    type=int,
    default=None,
    help="Parallel worker processes [default: 1].",
)
def differential(
    campaign_name: Optional[str],
    config_path: Optional[Path],
    fork_name: Optional[str],
    client_paths: Sequence[Path],
    seed_start: Optional[int],
    count: Optional[int],
    corpus_dir: Optional[Path],
    no_minimize: bool,
    baseline_seeds: Optional[int],
    no_baseline: bool,
    no_tiering: bool,
    summary_path: Optional[Path],
    workers: Optional[int],
) -> None:
    """
    Compare the reference spec (EELS) against client transition tools on
    generated cases, and report consensus-relevant divergences.

    A campaign supplies the defaults; explicit flags override it. Exits 1
    when any seed diverged, so scripts and the mutation oracle can branch
    on it.
    """
    config = load_config_or_fail(config_path)
    campaign = campaign_or_fail(config, campaign_name)

    fork_name = _pick(fork_name, campaign.fork if campaign else None, "")
    if not fork_name:
        raise click.UsageError("--fork or --campaign is required")
    fork = _resolve_fork(fork_name)

    clients = (
        resolve_campaign_clients(config, campaign.clients) if campaign else {}
    )
    clients.update(name_clients(client_paths))
    if not clients:
        raise click.UsageError(
            "no clients to compare: pass --client PATH or a --campaign"
        )

    seed_start = _pick(
        seed_start, campaign.seed_start if campaign else None, 0
    )
    count = _pick(count, campaign.count if campaign else None, 100)
    workers = _pick(workers, campaign.workers if campaign else None, 1)
    corpus_dir = _pick(corpus_dir, campaign.corpus if campaign else None, None)
    baseline_seeds = _pick(
        baseline_seeds, campaign.baseline_seeds if campaign else None, 20
    )
    if no_baseline:
        baseline_seeds = 0
    seeds = range(seed_start, seed_start + count)

    click.echo(
        f"Differential {fork_name} (generator v{GENERATOR_VERSION}) "
        f"EELS vs {', '.join(clients)}, "
        f"seeds {seed_start}..{seed_start + count - 1}"
        f" ({workers} worker{'s' if workers != 1 else ''})"
    )

    try:
        report = differential_fuzz(
            fork,  # type: ignore[arg-type]
            seeds,
            clients=clients,
            corpus_dir=corpus_dir,
            minimize_cases=not no_minimize,
            workers=workers,
            baseline_seeds=baseline_seeds,
            manifest_path=(
                corpus_dir / "manifest.json" if corpus_dir else None
            ),
            tiered=not no_tiering,
        )
    except StaleClientError as exc:
        raise click.ClickException(
            f"{exc}\nrebuild or repoint the stale client(s) "
            "(`fuzz clients --update`), or pass --no-baseline"
        ) from exc

    manifest = report.manifest
    if manifest is not None:
        versions = ", ".join(
            f"{name} [{version}]" for name, version in manifest.clients.items()
        )
        click.echo(f"eels@{manifest.eels_commit} vs {versions}")
    if baseline_seeds:
        click.echo(f"baseline: all clients agree on {baseline_seeds} seeds")

    click.echo(
        f"\nagreed {report.agreed}/{report.seeds}  diverged {report.diverged}"
        f"  (eels adjudicated {report.eels_runs}/{report.seeds})"
    )
    for outcome in report.outcomes:
        if outcome.asymmetric_failure:
            for tool, error in outcome.errors.items():
                click.echo(f"  seed {outcome.seed}: {tool} failed: {error}")
        for divergence in outcome.divergences:
            values = " ".join(
                f"{tool}={value}" for tool, value in divergence.values.items()
            )
            click.echo(
                f"  seed {outcome.seed}: {divergence.field} {values} "
                f"(minority: {', '.join(divergence.minority)})"
            )
    if corpus_dir is not None and report.diverged:
        click.echo(f"\ndivergent cases saved to {corpus_dir}")
    if summary_path is not None:
        write_summary(report, seeds, summary_path)
    if report.diverged:
        raise SystemExit(1)


def write_summary(report: Any, seeds: range, path: Path) -> Path:
    """Write the run's counts, first divergent seed, and field tally."""
    divergent = [o for o in report.outcomes if o.diverged]
    fields: Dict[str, int] = {}
    for outcome in divergent:
        for divergence in outcome.divergences:
            fields[divergence.field] = fields.get(divergence.field, 0) + 1
    manifest = report.manifest
    data = {
        "fork": report.fork,
        "generator_version": report.generator_version,
        "clients": report.clients,
        "eels_commit": manifest.eels_commit if manifest else None,
        "seed_start": seeds.start,
        "seeds": report.seeds,
        "agreed": report.agreed,
        "diverged": report.diverged,
        "eels_runs": report.eels_runs,
        "first_divergent_seed": min(o.seed for o in divergent)
        if divergent
        else None,
        "fields": fields,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path


if __name__ == "__main__":
    differential()
