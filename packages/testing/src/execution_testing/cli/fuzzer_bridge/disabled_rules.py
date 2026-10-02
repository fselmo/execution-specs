"""
Fill a case with one of EELS's validity rules switched off. Testing only.

A negative that tests "the client rejects for rule R" is filled with R
off: the transaction breaking R executes, so the block's header, state
root and receipts are those of a chain where it did. Only R can then
reject the block. Filled with R on, the transaction is left out of the
execution while the block still carries it, and a client lacking R
executes it and rejects the block anyway, on its state root, for the
wrong reason: the client lagging the rule passes.

Each rule is switched off by patching the fork's own module for the
duration of the fill, and restored after. Nothing here touches
`src/ethereum`; a rule this cannot switch off for a fork raises.

A rule is switched off only where the transaction can then execute as a
client without it would run it. The intrinsic-gas shortfall cannot be:
gas below the intrinsic cost leaves no gas to start from, so that case is
filled with its rule on.
"""

import contextlib
import importlib
from typing import Any, Iterator, List, Sequence, Tuple

DISABLED_RULES: Tuple[str, ...] = (
    "total_cap",
    "floor",
    "block_gas_capacity",
)
"""The rules a fill can switch off:

- `total_cap`: `tx.gas` above `TX_MAX_TOTAL_GAS_LIMIT` (EIP-8037).
- `floor`: the calldata floor, in validation and at settlement alike, as
  for a client without it: neither `tx.gas` below the floor nor a floor
  above `TX_MAX_GAS_LIMIT` is refused, and no floor is charged.
- `block_gas_capacity`: a transaction's gas against what is left of the
  block's execution and state gas (EIP-8037's per-dimension check).
"""


def _patches(fork_short_name: str, rule: str) -> List[Tuple[Any, str, Any]]:
    """(object, attribute, replacement) that switch ``rule`` off."""
    package = f"ethereum.forks.{fork_short_name}"
    if rule == "total_cap":
        gas = importlib.import_module(f"{package}.vm.gas")
        limit = gas.GasCosts.TX_MAX_TOTAL_GAS_LIMIT
        return [
            (gas.GasCosts, "TX_MAX_TOTAL_GAS_LIMIT", type(limit)(2**64 - 1))
        ]
    elif rule == "floor":
        transactions = importlib.import_module(f"{package}.transactions")
        intrinsic = transactions.calculate_intrinsic_cost

        def without_floor(tx: Any, sender: Any) -> Any:
            cost = intrinsic(tx, sender)
            return type(cost)(
                execution=cost.execution,
                calldata_floor=type(cost.calldata_floor)(0),
            )

        return [(transactions, "calculate_intrinsic_cost", without_floor)]
    elif rule == "block_gas_capacity":
        fork = importlib.import_module(f"{package}.fork")

        def no_capacity_check(*_args: Any, **_kwargs: Any) -> None:
            return None

        return [(fork, "check_block_gas_capacity", no_capacity_check)]
    raise ValueError(f"no switch for validity rule {rule!r}")


@contextlib.contextmanager
def rules_disabled(
    fork_short_name: str, rules: Sequence[str]
) -> Iterator[None]:
    """Switch ``rules`` off in the fork's modules while the block runs."""
    saved: List[Tuple[Any, str, Any]] = []
    try:
        for rule in dict.fromkeys(rules):
            for target, name, replacement in _patches(fork_short_name, rule):
                if not hasattr(target, name):
                    raise ValueError(
                        f"{fork_short_name} has no {name} to switch off "
                        f"for {rule!r}"
                    )
                saved.append((target, name, getattr(target, name)))
                setattr(target, name, replacement)
        yield
    finally:
        for target, name, original in reversed(saved):
            setattr(target, name, original)
