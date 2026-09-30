"""
Focused runs over a recorded case: hold most draws, vary a few.

`fuzz case` replays a seed or a recorded tree with chosen labels varied or
set and everything else pinned, and fills each run through EELS. `fuzz
triage` does the same for a campaign finding, one label at a time, and
judges every variant with the panel: the labels whose variation loses
the divergence are the ones the bug needs.
"""

import contextlib
import io
import json
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from execution_testing.forks import Fork

from .draws import DrawError, DrawTree, Plan, focus_plan
from .generator import GENERATOR_VERSION, record_case
from .models import FuzzerOutput


def policy(label: str, plan: Plan) -> str:
    """How ``plan`` treats ``label``: pin, set, vary or redraw."""
    if label in plan.set_labels:
        return "set"
    if label in plan.varied:
        return "vary"
    if plan.resampled(label):
        return "redraw"
    return "pin"


def label_table(tree: DrawTree, plan: Optional[Plan] = None) -> str:
    """The tree as text: each label with its kind, value and policy."""
    plan = plan or Plan(values=tree.values())
    width = max((len(d.label) for d in tree.draws), default=5)
    lines = [f"{'label':<{width}}  {'kind':<10}  {'policy':<6}  value"]
    for d in tree.draws:
        lines.append(
            f"{d.label:<{width}}  {d.kind:<10}  "
            f"{policy(d.label, plan):<6}  {d.value}"
        )
    return "\n".join(lines)


def base_tree(
    fork: Fork, seed: Optional[int], tree_file: Optional[Path]
) -> DrawTree:
    """The recorded tree a focused run starts from."""
    if tree_file is not None:
        tree = DrawTree.from_json(tree_file.read_text())
        if tree.generator_version != GENERATOR_VERSION:
            raise ValueError(
                f"{tree_file} was recorded by generator "
                f"v{tree.generator_version}; this is v{GENERATOR_VERSION}, "
                "so its labels would mean something else"
            )
        if tree.fork != fork.name():
            raise ValueError(f"{tree_file} is for {tree.fork}")
        _, replayed = record_case(
            fork, tree.seed, plan=Plan(values=tree.values())
        )
        return replayed
    if seed is None:
        raise ValueError("a focused run needs a seed or a recorded tree")
    return record_case(fork, seed)[1]


def fill(
    case: FuzzerOutput, fork: Fork, fixture_format: Any = None
) -> Dict[str, Any]:
    """Fill ``case`` through a plain EELS tool into a fixture's JSON."""
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )
    from execution_testing.fixtures import BlockchainFixture

    from .campaign import fill_case

    tool = _TOOLS.setdefault("eels", ExecutionSpecsTransitionTool())
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return fill_case(
                case,
                fork,
                tool,
                fixture_format=fixture_format or BlockchainFixture,
            )


_TOOLS: Dict[str, Any] = {}


@dataclass
class Variant:
    """One focused run: what it drew, and whether it filled."""

    salt: int
    varied: Dict[str, Any]
    """The value each varied or redrawn label took, where it moved."""
    case: Optional[FuzzerOutput] = None
    fixture: Optional[Dict[str, Any]] = None
    error: str = ""
    """Why it could not be generated or filled; empty when it filled."""


@dataclass
class FocusReport:
    """A focused run's plan and each run's outcome."""

    pinned: List[str]
    varied: List[str]
    sets: Dict[str, Any]
    variants: List[Variant] = field(default_factory=list)

    def render(self) -> str:
        """The report as text."""
        lines = [
            f"pinned {len(self.pinned)} labels; varied: "
            f"{', '.join(self.varied) or 'none'}; set: "
            + (", ".join(f"{k}={v!r}" for k, v in self.sets.items()) or "none")
        ]
        for v in self.variants:
            outcome = f"unfillable: {v.error}" if v.error else "filled"
            moved = ", ".join(f"{k}={val!r}" for k, val in v.varied.items())
            lines.append(f"  run {v.salt}: {outcome}; {moved or 'no change'}")
        return "\n".join(lines)


def focus(
    fork: Fork,
    tree: DrawTree,
    *,
    vary: Sequence[str] = (),
    pin: Sequence[str] = (),
    sets: Optional[Mapping[str, Any]] = None,
    runs: int = 1,
    fill_cases: bool = True,
    fixture_format: Any = None,
) -> FocusReport:
    """
    Replay ``tree`` ``runs`` times with ``vary`` resampled and ``sets``
    given, everything else pinned; fill each through EELS when asked.

    A run that cannot be generated or filled is reported with its error,
    never dropped: an unfillable variation says something about the case.
    """
    first = focus_plan(tree, vary=vary, pin=pin, sets=sets, salt=1)
    report = FocusReport(
        pinned=sorted(k for k in first.values if k not in first.set_labels),
        varied=list(vary),
        sets=dict(sets or {}),
    )
    base = tree.values()
    for salt in range(1, runs + 1):
        plan = focus_plan(tree, vary=vary, pin=pin, sets=sets, salt=salt)
        variant = Variant(salt=salt, varied={})
        try:
            case, drawn = record_case(fork, tree.seed, plan=plan)
        except DrawError:
            # A value outside its label's domain is the plan's mistake,
            # not a property of the case.
            raise
        except Exception as exc:  # noqa: BLE001 - a run's failure is data
            variant.error = f"{type(exc).__name__}: {exc}"[:300]
            report.variants.append(variant)
            continue
        variant.case = case
        variant.varied = {
            k: v
            for k, v in drawn.values().items()
            if (plan.resampled(k) or k in plan.set_labels) and base.get(k) != v
        }
        if fill_cases:
            try:
                variant.fixture = fill(case, fork, fixture_format)
            except Exception as exc:  # noqa: BLE001 - unfillable is data
                variant.error = f"{type(exc).__name__}: {exc}"[:300]
        report.variants.append(variant)
    return report


@dataclass
class LabelOutcome:
    """How varying one label moved a finding."""

    label: str
    kind: str
    kept: int = 0
    lost: int = 0
    other: int = 0
    """Runs where the client still failed, with another reason."""
    unfillable: int = 0
    unchanged: int = 0
    """Runs whose draw came out the same case as the finding's."""


def triage_table(outcomes: Sequence[LabelOutcome], runs: int) -> str:
    """The narrowing table: the labels the finding needs first."""
    ordered = sorted(
        outcomes,
        key=lambda o: (-o.lost, -o.other, o.kept, o.label),
    )
    width = max((len(o.label) for o in ordered), default=5)
    lines = [
        f"{'label':<{width}}  {'kind':<10}  kept  lost  other  "
        f"unfillable  same  (of {runs} runs each)"
    ]
    for o in ordered:
        lines.append(
            f"{o.label:<{width}}  {o.kind:<10}  {o.kept:>4}  {o.lost:>4}  "
            f"{o.other:>5}  {o.unfillable:>10}  {o.unchanged:>4}"
        )
    return "\n".join(lines)


Judge = Callable[[Path, List[str]], Dict[str, Dict[str, Any]]]
"""Runs a batch file through the panel: client -> fixture -> verdict."""


def triage(
    fork: Fork,
    seed: int,
    target: str,
    judge: Judge,
    *,
    runs: int = 3,
    labels: Optional[Sequence[str]] = None,
    fixture_format: Any = None,
    workdir: Optional[Path] = None,
) -> List[LabelOutcome]:
    """
    Vary each label of the finding's case on its own, ``runs`` times,
    and count the variants whose panel verdicts keep the ``target``
    signature id, lose it, or fail the same client another way.

    The finding's own case is judged first; a finding that does not
    reproduce on it has nothing to narrow, and raises.
    """
    from .campaign import per_client_signatures, signature_id

    base_case, tree = record_case(fork, seed)
    kinds = tree.kinds()
    chosen = list(labels) if labels is not None else list(kinds)
    target_client = target.split("--", 1)[0]
    fixtures: Dict[str, Dict[str, Any]] = {}
    fixtures["base"] = fill(base_case, fork, fixture_format)
    outcomes: Dict[str, LabelOutcome] = {
        label: LabelOutcome(label, kinds[label]) for label in chosen
    }
    names: Dict[str, str] = {}
    base_json = base_case.model_dump_json()
    for label in chosen:
        for salt in range(1, runs + 1):
            plan = focus_plan(tree, vary=[label], salt=salt)
            try:
                case, _ = record_case(fork, seed, plan=plan)
                if case.model_dump_json() == base_json:
                    outcomes[label].unchanged += 1
                    continue
                name = f"v{len(names)}"
                fixtures[name] = fill(case, fork, fixture_format)
                names[name] = label
            except Exception:  # noqa: BLE001 - counted, not raised
                outcomes[label].unfillable += 1
    with tempfile.TemporaryDirectory(dir=workdir) as tmp:
        path = Path(tmp) / "triage.json"
        path.write_text(json.dumps(fixtures))
        verdicts = judge(path, list(fixtures))

    def signatures(name: str) -> List[str]:
        panel = {c: v[name] for c, v in verdicts.items() if name in v}
        failing = {c: v for c, v in panel.items() if not v.passed}
        return [signature_id(s) for s in per_client_signatures(failing)]

    if target not in signatures("base"):
        raise ValueError(
            f"{target} does not reproduce on seed {seed}'s case: the panel "
            f"gives {signatures('base') or 'no failure'}"
        )
    for name, label in names.items():
        found = signatures(name)
        if target in found:
            outcomes[label].kept += 1
        elif any(s.startswith(target_client + "--") for s in found):
            outcomes[label].other += 1
        else:
            outcomes[label].lost += 1
    return list(outcomes.values())
