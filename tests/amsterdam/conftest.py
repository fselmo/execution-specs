"""
Minimal conftest for amsterdam Block Access List tests.
"""
from typing import Any


def pytest_configure(config: Any) -> None:
    """Configure custom markers."""
    config.addinivalue_line("markers", "block_access_list: mark test as Block Access List-related")
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
