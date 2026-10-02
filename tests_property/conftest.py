"""
Hypothesis profiles and per-fork fixtures for the property suite.

The `ci` profile is the default and is derandomized, so a failure reproduces
from its printed blob. `dev` explores randomly and `nightly` runs a larger
budget; select one with `--hypothesis-profile`.
"""

import importlib
from types import ModuleType

import pytest
from hypothesis import HealthCheck, settings

from .forks import PROPERTY_TEST_FORKS

# Spec code is slow and its timing varies between runs and interpreters, so
# no profile enforces a per-example deadline.
settings.register_profile(
    "dev",
    max_examples=200,
    deadline=None,
    print_blob=True,
)
settings.register_profile(
    "ci",
    parent=settings.get_profile("dev"),
    derandomize=True,
)
settings.register_profile(
    "nightly",
    parent=settings.get_profile("dev"),
    max_examples=5000,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("ci")


@pytest.fixture(scope="session", params=PROPERTY_TEST_FORKS)
def fork_name(request: pytest.FixtureRequest) -> str:
    """Return the name of the fork package under test."""
    return str(request.param)


@pytest.fixture(scope="session")
def transactions(fork_name: str) -> ModuleType:
    """Return the transactions module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.transactions")


@pytest.fixture(scope="session")
def gas(fork_name: str) -> ModuleType:
    """Return the gas module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.vm.gas")


@pytest.fixture(scope="session")
def tracker(fork_name: str) -> ModuleType:
    """Return the state tracker module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.state_tracker")
