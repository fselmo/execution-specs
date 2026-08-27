"""Restore mutated spec sources even when the process is signalled."""

import os
import signal
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator


@contextmanager
def restore_on_signal(originals: Dict[Path, str]) -> Iterator[None]:
    """
    Restore every file in ``originals`` if the process is signalled mid-run.

    A ``finally`` handles exceptions and SIGINT (which raises), but a plain
    SIGTERM (e.g. from ``timeout``) would kill the process before the sources
    are restored, leaving mutants on disk. Restore in a SIGTERM handler too.
    """

    def handler(signum: int, _frame: object) -> None:
        for path, text in originals.items():
            path.write_text(text)
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    previous = signal.signal(signal.SIGTERM, handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)
