"""
Filled cases imported back through EELS's own block import.

The transition tool that fills a case never imports a block, so the
spec's import checks never run on a generated case. Importing the filled
fixture runs them: a block the fixture expects valid must import, and one
it expects rejected must be refused.
"""

import contextlib
import io
import warnings
from typing import Any, Dict

from execution_testing.forks import Amsterdam

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.eels_import import import_fixture
from ..fuzzer_bridge.generator import generate_fuzzer_output
from ..fuzzer_bridge.models import FuzzerOutput


def _fill(case: FuzzerOutput) -> Dict[str, Any]:
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return mod.fill_case(case, fork, eels)


def test_a_filled_case_imports_cleanly() -> None:
    """Every block EELS filled as valid imports through EELS."""
    for seed in range(3):
        result = import_fixture(
            _fill(generate_fuzzer_output(Amsterdam, seed)), "amsterdam"
        )
        assert result.agreed, result.reason


def test_a_block_drawn_to_be_rejected_is_refused() -> None:
    """
    A block the fixture expects rejected is refused on import, and the
    import agrees with the fixture.
    """
    from .test_reach_thresholds import _near_full

    fixture = _fill(_near_full(1))
    assert "expectException" in fixture["blocks"][-1]
    assert import_fixture(fixture, "amsterdam").agreed


def test_a_valid_block_refused_on_import_is_a_disagreement() -> None:
    """
    The oracle's own teeth: a fixture whose valid block has a corrupted
    receipts root is refused, and the import reports it.
    """
    fixture = _fill(generate_fuzzer_output(Amsterdam, 0))
    import copy

    from ethereum.crypto.hash import keccak256
    from ethereum_rlp import rlp
    from ethereum_spec_tools.loaders.fixture_loader import Load

    broken = copy.deepcopy(fixture)
    load = Load("amsterdam")
    block, _, _ = load.json_to_block(broken["blocks"][0])
    header = load.fork.Header(
        **{
            **{
                f: getattr(block.header, f)
                for f in block.header.__dataclass_fields__
            },
            "receipt_root": keccak256(b"not the receipts"),
        }
    )
    tampered = load.fork.Block(
        **{
            **{f: getattr(block, f) for f in block.__dataclass_fields__},
            "header": header,
        }
    )
    broken["blocks"] = [
        {
            "rlp": "0x" + rlp.encode(tampered).hex(),
            "blockHeader": {
                **broken["blocks"][0]["blockHeader"],
                "hash": "0x" + keccak256(rlp.encode(header)).hex(),
            },
        }
    ]
    result = import_fixture(broken, "amsterdam")
    assert not result.agreed and "expected valid, refused" in result.reason


def test_an_engine_fixture_imports_cleanly() -> None:
    """Every payload EELS filled as valid imports through EELS."""
    from execution_testing.fixtures import BlockchainEngineFixture

    mod._init_fill_worker("Amsterdam")
    for seed in range(3):
        fixture = mod.fill_case(
            generate_fuzzer_output(Amsterdam, seed),
            Amsterdam,
            mod._FILL["eels"],
            fixture_format=BlockchainEngineFixture,
        )
        result = import_fixture(fixture, "amsterdam")
        assert result.agreed, result.reason


def test_a_payload_that_does_not_hash_to_its_block_hash_is_refused() -> None:
    """
    The rebuilt header is checked against `blockHash`: a payload with any
    field changed after the fact is refused before it is executed.
    """
    from execution_testing.fixtures import BlockchainEngineFixture

    mod._init_fill_worker("Amsterdam")
    fixture = mod.fill_case(
        generate_fuzzer_output(Amsterdam, 0),
        Amsterdam,
        mod._FILL["eels"],
        fixture_format=BlockchainEngineFixture,
    )
    payload = fixture["engineNewPayloads"][0]["params"][0]
    payload["extraData"] = "0x01"
    result = import_fixture(fixture, "amsterdam")
    assert not result.agreed
    assert "refused as BlockException.INVALID_BLOCK_HASH" in result.reason


def test_a_self_checked_slice_reports_every_case_checked(
    tmp_path: Any, monkeypatch: Any
) -> None:
    """
    A slice the campaign samples fills each case again on a plain EELS
    tool and imports it back: clean cases come back checked and agreeing,
    and a disagreement comes back named by its case.
    """
    from ..fuzzer_bridge import eels_import
    from ..fuzzer_bridge.eels_import import ImportResult

    mod._init_fill_worker("Amsterdam")
    clean = mod._fill_slice(([0, 1], str(tmp_path), True))
    assert clean["self_checked"] == 2 and clean["self_checks"] == {}
    unsampled = mod._fill_slice(([0], str(tmp_path)))
    assert unsampled["self_checked"] == 0

    monkeypatch.setattr(
        eels_import,
        "import_fixture",
        lambda *_: ImportResult(False, "block 1 expected valid, refused"),
    )
    refused = mod._fill_slice(([0], str(tmp_path), True))
    assert refused["self_checks"] == {
        "seed_0": "block 1 expected valid, refused"
    }


def test_a_negative_is_witnessed_in_every_slice_and_dropped_on_failure(
    tmp_path: Any, monkeypatch: Any
) -> None:
    """
    An engine campaign self-checks a negative case even in a slice it does
    not sample, and a negative EELS does not refuse as named is not written
    for the clients.
    """
    from ..fuzzer_bridge import eels_import
    from ..fuzzer_bridge.campaign import shard_path
    from ..fuzzer_bridge.eels_import import ImportResult

    mod._init_fill_worker("Amsterdam", fixture_format="blockchain_test_engine")
    seed = next(
        s
        for s in range(100)
        if generate_fuzzer_output(Amsterdam, s).negative is not None
    )
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    witnessed = mod._fill_slice(([seed], str(tmp_path / "a")))
    assert witnessed["self_checked"] == 1
    assert witnessed["self_checks"] == {}
    assert shard_path(tmp_path / "a", [seed]).exists()

    monkeypatch.setattr(
        eels_import,
        "import_fixture",
        lambda *_: ImportResult(False, "block 1 expected X, imported"),
    )
    refused = mod._fill_slice(([seed], str(tmp_path / "b")))
    assert refused["self_checks"] == {
        f"seed_{seed}": "block 1 expected X, imported"
    }
    assert not shard_path(tmp_path / "b", [seed]).exists()
    mod._init_fill_worker("Amsterdam")
