"""Tests for whole-file runner output parsing."""

from ..fuzzer_bridge.runners import (
    Verdict,
    parse_besu_summary,
    parse_gtest_report,
    parse_json_array,
    strip_nethermind_suffix,
    summarize_gtest_failure,
)


def test_parse_json_array_from_noisy_stdout() -> None:
    """A JSON result list is found even after log lines."""
    out = (
        "INFO something\n"
        '[{"name": "seed_1", "pass": true}, '
        '{"name": "seed_2", "pass": false, "error": "root mismatch"}]\n'
    )
    verdicts = parse_json_array(out)
    assert verdicts["seed_1"].passed and verdicts["seed_1"].error == ""
    assert not verdicts["seed_2"].passed
    assert verdicts["seed_2"].error == "root mismatch"


def test_parse_json_array_without_results_is_empty() -> None:
    """Garbage output yields no verdicts rather than an exception."""
    assert parse_json_array("boom") == {}


def test_parse_gtest_report_maps_failures() -> None:
    """Gtest's report becomes per-test verdicts with the failure text."""
    report = {
        "testsuites": [
            {
                "testsuite": [
                    {"name": "seed_1"},
                    {"name": "seed_2", "failures": [{"failure": "bad root"}]},
                ]
            }
        ]
    }
    verdicts = parse_gtest_report(report)
    assert verdicts["seed_1"].passed
    assert (
        not verdicts["seed_2"].passed
        and "bad root" in verdicts["seed_2"].error
    )


def test_parse_besu_summary_attributes_failures_by_name() -> None:
    """`Running` lines name the tests; the summary names the failed ones."""
    stdout = (
        "Running iteration 0\nRunning seed_1\n"
        "Block 1 (0xab) Imported in 1.0 ms (2.0 MGas/s)\nRunning seed_2\n"
        "\n====\nTEST SUMMARY\n====\nTotal tests:  2\nPassed:       1\n"
        "Failed:       1\n\nFailed tests:\n  - seed_2: bad state root\n====\n"
    )
    verdicts = parse_besu_summary(stdout)
    assert verdicts == {
        "seed_1": Verdict(True),
        "seed_2": Verdict(False, "bad state root"),
    }
    assert "iteration" not in verdicts


def test_strip_nethermind_suffix() -> None:
    """Nethtest reports names with a `_d0g0v0_` suffix."""
    assert strip_nethermind_suffix("seed_7_d0g0v0_") == "seed_7"
    assert strip_nethermind_suffix("seed_7") == "seed_7"


def test_gtest_failure_summary_names_the_mismatched_fields() -> None:
    """The signature line says what differed, not where gtest asserted."""
    text = (
        "/src/blockchaintest.cpp:25\nFailed\nseed_0:\n  Amsterdam/0/0:\n"
        "    state root:\n      actual   0xaa\n      expected 0xbb\n"
        "    gas used:\n      actual   1\n      expected 2\n"
        "    Result state:\n"
    )
    summary = summarize_gtest_failure(text)
    assert summary.startswith("mismatch: state root, gas used\n")
    assert summarize_gtest_failure("plain error") == "plain error"
