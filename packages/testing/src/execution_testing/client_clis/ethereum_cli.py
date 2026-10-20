"""Abstract base class to help create Python interfaces to Ethereum CLIs."""

import csv
import io
import os
import shutil
import subprocess
from dataclasses import dataclass
from functools import cache
from itertools import groupby
from pathlib import Path
from re import Pattern
from typing import Any, ClassVar, Iterable, List, Optional, Sequence, Type

from execution_testing.logging import (
    get_logger,
)

logger = get_logger(__name__)


class UnknownCLIError(Exception):
    """Exception raised if an unknown CLI is encountered."""

    pass


class CLINotFoundInPathError(Exception):
    """Exception raised if the specified CLI binary isn't found in the path."""

    def __init__(
        self,
        message: str = "The CLI binary was not found in the path",
        binary: Path | None = None,
    ) -> None:
        """Initialize the exception."""
        if binary:
            message = f"{message} ({binary})"
        super().__init__(message)


@dataclass(frozen=True)
class DockerImage:
    """
    A client binary inside a container image.

    `--bin` takes it as `docker:<image>` to run the image's entrypoint, or as
    `docker:<image>#<binary>` to run another binary in the image. `#` cannot
    appear in an image reference, whose tag already uses `:`, so the split
    is never ambiguous.
    """

    PREFIX: ClassVar[str] = "docker:"

    image: str
    entrypoint: str | None = None

    @classmethod
    def parse(cls, value: str) -> "DockerImage":
        """Parse `docker:<image>[#<binary>]`."""
        assert value.startswith(cls.PREFIX), value
        image, _, entrypoint = value.removeprefix(cls.PREFIX).partition("#")
        if not image:
            raise ValueError(f"No image given in '{value}'")
        return cls(image=image, entrypoint=entrypoint or None)

    def __str__(self) -> str:
        """Return the `--bin` spelling of the image."""
        if self.entrypoint is None:
            return f"{self.PREFIX}{self.image}"
        return f"{self.PREFIX}{self.image}#{self.entrypoint}"


Executable = Path | DockerImage
"""A binary on the host, or a binary in a container image."""


def parse_executable(value: str) -> Executable:
    """Parse a `--bin` value: a host path, or `docker:<image>[#<binary>]`."""
    if value.startswith(DockerImage.PREFIX):
        return DockerImage.parse(value)
    return Path(value)


def command_line(
    executable: Executable,
    args: Sequence[str],
    *,
    read_only: Iterable[Path | None] = (),
    writable: Iterable[Path | None] = (),
) -> List[str]:
    """
    Return the command that runs `executable` with `args`.

    A container sees the `read_only` and `writable` paths (`None` entries are
    skipped) at the same paths as the host, so `args` never need rewriting,
    and it has no network.
    """
    if not isinstance(executable, DockerImage):
        return [str(executable), *args]
    command = [
        "docker",
        "run",
        "--rm",
        "--quiet",
        "--network",
        "none",
        # Java runners look up their own host name, which fails without a
        # network unless it is one /etc/hosts already knows.
        "--hostname",
        "localhost",
        "--workdir",
        str(Path.cwd()),
    ]
    mounts: dict[Path, str] = {}
    for path in read_only:
        if path is not None:
            mounts.setdefault(path.absolute(), "ro")
    for path in writable:
        if path is not None:
            mounts[path.absolute()] = "rw"
    for path, mode in mounts.items():
        command += ["--mount", bind_mount(path, read_only=mode == "ro")]
    if executable.entrypoint is not None:
        command += ["--entrypoint", executable.entrypoint]
    return [*command, executable.image, *args]


def bind_mount(path: Path, *, read_only: bool) -> str:
    """
    Return a `--mount` value binding `path` at the same path.

    `--volume` splits on `:`, which test ids put in dump and fixture paths;
    `--mount` reads CSV, so a field with a comma is quoted.
    """
    fields = ["type=bind", f"source={path}", f"target={path}"]
    if read_only:
        fields.append("readonly")
    line = io.StringIO()
    csv.writer(line, lineterminator="").writerow(fields)
    return line.getvalue()


def run_command(
    executable: Executable,
    args: Sequence[str],
    *,
    read_only: Iterable[Path | None] = (),
    writable: Iterable[Path | None] = (),
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """
    Run `executable` with `args`, on the host or in a container, and capture
    its output as text.

    Writable paths are created first: Docker would otherwise create a missing
    one owned by root.
    """
    writable = list(writable)
    if isinstance(executable, DockerImage):
        for path in writable:
            if path is not None and not path.exists():
                path.mkdir(parents=True)
    return subprocess.run(
        command_line(executable, args, read_only=read_only, writable=writable),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


class EthereumCLI:
    """
    Abstract base class to help create Python interfaces to Ethereum CLIs.

    This base class helps handle the special case of EVM subcommands, such as
    the EVM transition tool `t8n`, which have multiple implementations, one
    from each client team. In the case of these tools, this class mainly serves
    to help instantiate the correct subclass based on the output of the CLI's
    version flag.
    """

    registered_tools: List[Type[Any]] = []
    default_tool: Optional[Type[Any]] = None
    binary: Executable
    default_binary: Path
    detect_binary_pattern: Pattern
    version_flag: str = "-v"
    cached_version: Optional[str] = None

    def __init__(self, *, binary: Optional[Path] = None):
        """Abstract init method that all subclasses must implement."""
        if binary is None:
            binary = self.default_binary
        else:
            # improve behavior of which by resolving the path:
            # ~/relative paths don't work
            resolved_path = Path(os.path.expanduser(binary)).resolve()
            if resolved_path.exists():
                binary = resolved_path
        binary = shutil.which(binary)  # type: ignore
        if not binary:
            raise CLINotFoundInPathError(binary=binary)
        self.binary = Path(binary)

    @classmethod
    def register_tool(cls, tool_subclass: Type[Any]) -> None:
        """Register a given subclass as tool option."""
        cls.registered_tools.append(tool_subclass)  # raise NotImplementedError

    @classmethod
    def set_default_tool(cls, tool_subclass: Type[Any]) -> None:
        """Register the default tool subclass."""
        cls.default_tool = tool_subclass

    @classmethod
    def from_binary_path(
        cls, *, binary_path: Optional[Executable] = None, **kwargs: Any
    ) -> Any:
        """
        Instantiate the appropriate CLI subclass derived from the
        CLI's `binary_path`.

        This method will attempt to detect the CLI version and instantiate
        the appropriate subclass based on the version output by running
        the CLI with the version flag.
        """
        assert cls.default_tool is not None, (
            "default CLI implementation was never set"
        )

        # ensure provided t8n binary can be found and used
        if binary_path is None:
            logger.debug("Binary path of provided t8n is None!")
            return cls.default_tool(binary=binary_path, **kwargs)

        binary: Executable
        if isinstance(binary_path, DockerImage):
            binary = binary_path
        else:
            binary = cls._resolve_binary_path(binary_path)

        # Group the tools by version flag, so we only have to call the tool
        # once for all the classes that share the same version flag
        for version_flag, subclasses in groupby(
            cls.registered_tools, key=lambda x: x.version_flag
        ):
            logger.debug(
                f"\n{'-' * 120}\nTrying this `version` flag to determine "
                f"if t8n supported: {version_flag}"
            )
            # adding more logging reveals we check for `-v` twice..

            matched = None
            try:
                result = run_command(binary, [version_flag])
                logger.debug(
                    f"Subprocess:\n\tstdout: {result.stdout!r}\n\n\n\t"
                    f"stderr: {result.stderr!r}\n\n\n"
                )

                if result.returncode != 0:
                    logger.debug(
                        "Subprocess returncode is not 0! "
                        f"It is: {result.returncode}"
                    )
                    # don't raise exception, you are supposed to keep trying
                    # different version flags
                    continue

                # if there is a breaking error try sth else
                if result.stderr:
                    if EthereumCLI.stderr_is_breaking(stderr=result.stderr):
                        logger.debug(f"Stderr detected: {result.stderr}")
                        continue

                binary_output = result.stdout.strip()
                logger.debug(f"Stripped subprocess stdout: {binary_output}")

                for subclass in subclasses:
                    logger.debug(f"Trying subclass {subclass}")
                    try:
                        detected = subclass.detect_binary(
                            binary_output, binary
                        )
                    except Exception as e:
                        logger.debug(f"{subclass} cannot detect: {e}")
                        continue
                    if detected:
                        matched = subclass
                        break

                    logger.debug(
                        f"T8n with version {binary_output} does not "
                        f"belong to subclass {subclass}"
                    )

            except Exception as e:
                logger.debug(
                    f"Trying to determine t8n version with flag "
                    f"`{version_flag}` failed: {e}"
                )
                continue

            # Built outside the try blocks, so a matched tool that can't be
            # constructed raises its own error instead of Unknown CLI.
            if matched is not None:
                return matched(binary=binary, **kwargs)

        raise UnknownCLIError(f"Unknown CLI: {binary}")

    @staticmethod
    def _resolve_binary_path(binary_path: Path) -> Path:
        """Resolve a host binary path, falling back to a `PATH` lookup."""
        expanded_path = Path(os.path.expanduser(binary_path))
        logger.debug(f"Expanded path of provided t8n: {expanded_path}")

        resolved_path = expanded_path.resolve()
        logger.debug(f"Resolved path of provided t8n: {resolved_path}")

        if resolved_path.exists():
            logger.debug("Resolved path exists")
            binary = Path(resolved_path)
        else:
            logger.debug(
                f"Resolved path does not exist: {resolved_path}\n"
                "Trying to find it via `which`"
            )

            # it might be that the provided binary exists in path
            filename = os.path.basename(resolved_path)
            binary = shutil.which(filename)  # type: ignore
            logger.debug(f"Output of 'which {binary_path}': {binary}")

            if binary is None:
                logger.error(
                    f"Resolved t8n binary path does not exist: {resolved_path}"
                )
                raise CLINotFoundInPathError(binary=resolved_path)

            assert binary is not None
            logger.debug(
                f"Successfully located the path of the t8n binary: {binary}"
            )
            binary = Path(binary)
        return binary

    @classmethod
    def detect_binary(
        cls,
        binary_output: str,
        binary: Optional[Executable] = None,  # noqa: ARG003
    ) -> bool:
        """
        Return True if a CLI's `binary_output` matches the
        class's expected output.

        `binary` is the resolved path to the tool being probed. Subclasses may
        use it to disambiguate tools that share a version banner by inspecting
        the binary itself (e.g. its subcommands), instead of relying on the
        version string alone.
        """
        logger.debug(f"Trying to detect binary for {binary_output}..")
        assert cls.detect_binary_pattern is not None

        logger.debug(
            f"Trying to match {binary_output} against this "
            f"pattern: {cls.detect_binary_pattern}"
        )
        match_result = cls.detect_binary_pattern.match(binary_output)
        match_successful: bool = match_result is not None

        return match_successful

    @classmethod
    def is_installed(cls, binary_path: Optional[Path] = None) -> bool:
        """Return whether the tool is installed in the current system."""
        if binary_path is None:
            binary_path = cls.default_binary
        else:
            resolved_path = Path(os.path.expanduser(binary_path)).resolve()
            if resolved_path.exists():
                binary_path = resolved_path
        binary = shutil.which(str(binary_path))
        return binary is not None

    @classmethod
    def stderr_is_breaking(cls, *, stderr: str) -> bool:
        """
        Process the stderr output and decide if the error is a
        breaking error for this specific tool.
        """
        # harmless java warning on certain systems (besu)
        if "SVE vector length" in stderr:
            return False

        return True

    def version(self) -> str:
        """
        Return the name and version of the CLI as reported by
        the CLI's version flag.
        """
        if self.cached_version is None:
            result = self._run_command([self.version_flag])

            if result.returncode != 0:
                raise Exception("failed to evaluate: " + result.stderr)

            self.cached_version = result.stdout.strip()

        return self.cached_version

    def _run_command(
        self,
        args: Sequence[str],
        *,
        read_only: Iterable[Path | None] = (),
        writable: Iterable[Path | None] = (),
    ) -> subprocess.CompletedProcess[str]:
        """Run this tool's binary with `args`; see `run_command`."""
        try:
            return run_command(
                self.binary, args, read_only=read_only, writable=writable
            )
        except Exception as e:
            raise Exception(
                f"Unexpected exception calling {self.binary}."
            ) from e

    @cache  # noqa
    def help(self, subcommand: str | None = None) -> str:
        """Return the help string, optionally for a subcommand."""
        args = [subcommand] if subcommand else []
        return self._run_command([*args, "--help"]).stdout
