"""Test running client CLIs on the host or in a container."""

import os
import stat
import sys
from pathlib import Path

import pytest

from execution_testing.client_clis import (
    ErigonFixtureConsumer,
    FixtureConsumerTool,
    GethFixtureConsumer,
)
from execution_testing.client_clis.ethereum_cli import (
    DockerImage,
    command_line,
    parse_executable,
    run_command,
)

# Stands in for `docker run`: skips the options up to the image, then runs
# `<images>/<image>`, or `<images>/<entrypoint>` when one is given.
FAKE_DOCKER = """#!{python}
import os, sys
args = sys.argv[2:]
program = None
while args[0].startswith("--"):
    if args[0] in ("--rm", "--quiet"):
        args = args[1:]
        continue
    if args[0] == "--entrypoint":
        program = args[1]
    args = args[2:]
image, args = args[0], args[1:]
program = os.path.join({images!r}, program or image.replace("/", "_"))
os.execv(program, [program, *args])
"""


def write_script(path: Path, text: str) -> Path:
    """Write an executable script."""
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


@pytest.fixture
def images(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Put a fake `docker` on `PATH` whose images are scripts in a folder."""
    images = tmp_path / "images"
    images.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_script(
        bin_dir / "docker",
        FAKE_DOCKER.format(python=sys.executable, images=str(images)),
    )
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return images


@pytest.mark.parametrize(
    "value,expected",
    [
        pytest.param("/opt/evm", Path("/opt/evm"), id="host_path"),
        pytest.param(
            "docker:ethpandaops/besu:main",
            DockerImage("ethpandaops/besu:main"),
            id="image_entrypoint",
        ),
        pytest.param(
            "docker:localhost:5000/besu:main#evmtool",
            DockerImage("localhost:5000/besu:main", entrypoint="evmtool"),
            id="image_binary",
        ),
    ],
)
def test_parse_executable(value: str, expected: object) -> None:
    """`--bin` takes a host path or `docker:<image>[#<binary>]`."""
    executable = parse_executable(value)
    assert executable == expected
    assert str(executable) == value


def test_parse_executable_needs_an_image() -> None:
    """`docker:` alone names no image."""
    with pytest.raises(ValueError, match="No image"):
        parse_executable("docker:#evm")


def test_command_line_on_host() -> None:
    """A host binary runs as is, and mounts mean nothing."""
    assert command_line(
        Path("/opt/evm"), ["blocktest", "x.json"], read_only=[Path("/f")]
    ) == ["/opt/evm", "blocktest", "x.json"]


def test_command_line_in_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A container runs without network, with each path mounted where the host
    has it: fixtures read-only, dump directories writable.
    """
    monkeypatch.chdir(tmp_path)
    fixture = Path("fixtures/x.json")
    dump = tmp_path / "dump"
    assert command_line(
        DockerImage("ethpandaops/besu:main", entrypoint="evmtool"),
        ["block-test", str(fixture)],
        read_only=[fixture, dump, None],
        writable=[dump, None],
    ) == [
        "docker",
        "run",
        "--rm",
        "--quiet",
        "--network",
        "none",
        "--hostname",
        "localhost",
        "--workdir",
        str(tmp_path),
        "--volume",
        f"{tmp_path / fixture}:{tmp_path / fixture}:ro",
        "--volume",
        f"{dump}:{dump}:rw",
        "--entrypoint",
        "evmtool",
        "ethpandaops/besu:main",
        "block-test",
        "fixtures/x.json",
    ]


def test_run_command_captures_text(tmp_path: Path) -> None:
    """The output of a host binary comes back as text."""
    runner = write_script(
        tmp_path / "runner",
        '#!/bin/sh\necho out "$@"\necho err >&2\nexit 3\n',
    )
    result = run_command(runner, ["a", "b"])
    assert (result.returncode, result.stdout, result.stderr) == (
        3,
        "out a b\n",
        "err\n",
    )


def test_run_command_creates_writable_mounts(
    images: Path, tmp_path: Path
) -> None:
    """
    A missing writable path is created before the container starts, so it
    is owned by the user, not by Docker.
    """
    write_script(images / "runner", "#!/bin/sh\necho ran\n")
    dump = tmp_path / "dump" / "nested"
    result = run_command(DockerImage("runner"), [], writable=[dump])
    assert result.stdout == "ran\n"
    assert dump.is_dir()


@pytest.mark.parametrize(
    "help_text,expected_class",
    [
        pytest.param("COMMANDS: blocktest", GethFixtureConsumer, id="geth"),
        pytest.param(
            "COMMANDS: blocktest enginextest",
            ErigonFixtureConsumer,
            id="erigon",
        ),
    ],
)
def test_detection_through_a_container(
    images: Path, help_text: str, expected_class: type[FixtureConsumerTool]
) -> None:
    """
    The client is detected from the image's runner exactly as from a host
    binary, including Erigon's probe of `--help`.
    """
    write_script(
        images / "evm",
        '#!/bin/sh\nif [ "$1" = --help ]; then echo "'
        + help_text
        + '"; else echo "evm version 1.0.0"; fi\n',
    )
    image = DockerImage("ethereum/client-go:alltools", entrypoint="evm")
    tool = FixtureConsumerTool.from_binary_path(binary_path=image)
    assert type(tool) is expected_class
    assert tool.binary == image
