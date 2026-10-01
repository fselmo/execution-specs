"""A generated case for tests to build their own cases from."""

import itertools
from functools import lru_cache

from execution_testing.forks import Amsterdam

from ..fuzzer_bridge.generator import generate_fuzzer_output
from ..fuzzer_bridge.models import FuzzerOutput


@lru_cache(maxsize=1)
def template_seed() -> int:
    """
    The first seed whose Amsterdam case has the ordinary shape: no block
    it expects rejected, no negative draw, and the drawn gas limit. A case
    drawn at the access list's size cap or ending in an invalid
    transaction carries a derived limit or a rejection that a case built
    from it would inherit.
    """
    for seed in itertools.count():
        case = generate_fuzzer_output(Amsterdam, seed)
        if (
            case.bal_cap_offset is None
            and case.negative is None
            and not any(tx.error for tx in case.transactions)
        ):
            return seed
    raise AssertionError("unreachable")


def template_case() -> FuzzerOutput:
    """The case of `template_seed`."""
    return generate_fuzzer_output(Amsterdam, template_seed())
