"""
`ethereum-spec-mutate`: mutation testing of the spec against its tests.

```console
ethereum-spec-mutate bal --fork Bogota                    # property tests
ethereum-spec-mutate bal --fork Bogota --oracle fixtures  # filled fixtures
ethereum-spec-mutate bal tx-admission --fork Osaka --sample 40
ethereum-spec-mutate --fork Bogota --list
ethereum-spec-mutate bal --fork Bogota --rerun 3f2a9c01b7d4
```
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .areas import AREAS
from .driver import ORACLES, fork_by_name, plan, run, sample, summarize


def main(argv: Optional[List[str]] = None) -> int:
    """Run the mutants of the chosen areas and print what survived."""
    parser = argparse.ArgumentParser(
        prog="ethereum-spec-mutate", description=__doc__.split("\n")[1]
    )
    parser.add_argument("areas", nargs="*", help=", ".join(AREAS))
    parser.add_argument(
        "--fork",
        required=True,
        help="framework fork whose spec package is mutated",
    )
    parser.add_argument("--oracle", choices=ORACLES, default="properties")
    parser.add_argument(
        "--sample",
        type=int,
        default=0,
        help="at most this many mutants per area (0: all)",
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--timeout", type=int, default=300, help="seconds per oracle run"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".just/mutate"),
        help="results, worker copies and filled fixtures",
    )
    parser.add_argument(
        "--rerun", nargs="+", metavar="ID", help="run exactly these mutants"
    )
    parser.add_argument(
        "--list", action="store_true", help="count the mutants and stop"
    )
    args = parser.parse_args(argv)

    root = Path.cwd()
    if not (root / "src/ethereum").is_dir():
        parser.error("run from the repository root")
    unknown = [area for area in args.areas if area not in AREAS]
    if unknown:
        parser.error(f"unknown areas {unknown}; known: {', '.join(AREAS)}")
    fork = fork_by_name(args.fork)
    areas = args.areas or list(AREAS)
    planned = plan(root, fork, areas)
    if args.rerun:
        wanted = set(args.rerun)
        chosen = [p for p in planned if p.mutant.ident in wanted]
        missing = wanted - {p.mutant.ident for p in chosen}
        if missing:
            parser.error(f"no such mutants at {fork.name()}: {missing}")
    else:
        chosen = sample(planned, args.sample, args.seed)
    if args.list:
        for area in areas:
            count = sum(p.area == area for p in chosen)
            print(f"{area}: {count}")
        print(f"total: {len(chosen)} at {fork.name()}")
        return 0

    output = args.output / fork.name()
    results = run(
        root,
        output,
        fork,
        chosen,
        args.oracle,
        args.workers,
        args.timeout,
    )
    ids = [p.mutant.ident for p in chosen]
    print(summarize(root, fork, results, ids))
    return 0


if __name__ == "__main__":
    sys.exit(main())
