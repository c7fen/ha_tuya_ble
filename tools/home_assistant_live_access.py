"""Fail-closed, local-only helpers for Home Assistant access orchestration.

This module deliberately contains no network client or command executor.  It
turns a private, declarative SSH recipe into a small owner-only interactive
wrapper and validates that wrapper without returning its target or contents.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import pty
import re
import select
import shlex
import stat
import subprocess
import sys
import termios
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, TextIO, TypeVar

REPAIRS_RESPONSE_SHAPE_INVALID = "REPAIRS_RESPONSE_SHAPE_INVALID"
ADMISSION_COLLECTOR = "ADMISSION_COLLECTOR"
ADMISSION_VALID = "ADMISSION_VALID"
PRIVATE_WRAPPER_BOOTSTRAPPED = "PRIVATE_WRAPPER_BOOTSTRAPPED"
PRIVATE_WRAPPER_VALID = "PRIVATE_WRAPPER_VALID"
PRIVATE_WRAPPER_INVALID = "PRIVATE_WRAPPER_INVALID"
HA_INTERACTIVE_SESSION_READY = "HA_INTERACTIVE_SESSION_READY"
PRIVATE_ROUTE_ID = "home-assistant-private-ssh"
SAFE_SSH_EXECUTABLES = frozenset({"ssh", "/usr/bin/ssh", "/bin/ssh"})
SAFE_PRIVATE_ALIAS = re.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMMAND_DONE_MARKER = "__HA_INTERACTIVE_COMMAND_DONE__"
_MAX_PTY_CAPTURE_BYTES = 64 * 1024


class RepairsGate(StrEnum):
    """The represented read-only gates that use the canonical decoder."""

    INITIAL = "initial"
    POST_ACTIVATION = "post_activation"
    POST_ROLLBACK = "post_rollback"


class BrokerState(StrEnum):
    """The explicit private session phases; no child output is public state."""

    SSH_CHILD_STARTED = "SSH_CHILD_STARTED"
    REMOTE_INTERACTIVE_READY = "REMOTE_INTERACTIVE_READY"
    LOGIN_SHELL_READY = "LOGIN_SHELL_READY"
    SESSION_ACTIVE = "SESSION_ACTIVE"
    CLOSED = "CLOSED"


class BrokerFailure(StrEnum):
    """Fixed, non-transcript failure classes for a private session."""

    CHILD_EXITED = "CHILD_EXITED"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    PROTOCOL = "PROTOCOL"
    TIMEOUT = "TIMEOUT"


class SessionBrokerError(RuntimeError):
    """A failure that intentionally never includes captured PTY bytes."""


CommandResult = TypeVar("CommandResult")


class StructuredSessionCommand(Protocol[CommandResult]):
    """A bounded command with a sanitizer, never a raw terminal passthrough."""

    def wire_command(self, completion_marker: str) -> str:
        """Return the reviewed shell command plus an internal completion marker."""

    def sanitize(self, private_output: bytes) -> CommandResult:
        """Return only the command's structured, allowlisted result."""


@dataclass(frozen=True)
class DecodedRepairs:
    """Internal strict decode result; invalid shapes never substitute an empty list."""

    shape_valid: bool
    issues: tuple[object, ...] | None


@dataclass(frozen=True)
class RepairsAggregate:
    """Sanitized Repairs evidence; no issue object is retained or emitted."""

    relevant_count: int
    critical_count: int


@dataclass(frozen=True)
class RepairsGateResult:
    """Internal fail-closed decision for one represented collector gate."""

    gate: RepairsGate
    shape_valid: bool
    classification: str
    code: str
    aggregate: RepairsAggregate | None


@dataclass(frozen=True)
class RepairsEvidence:
    """The exact retained/public Repairs evidence allowlist."""

    shape_valid: bool
    relevant_count: int | None
    critical_count: int | None


@dataclass(frozen=True)
class WrapperValidationResult:
    """Safe wrapper validation evidence that intentionally omits private data."""

    status: str
    reasons: tuple[str, ...]


def _invalid_repairs_result(gate: RepairsGate) -> RepairsGateResult:
    return RepairsGateResult(
        gate=gate,
        shape_valid=False,
        classification=ADMISSION_COLLECTOR,
        code=REPAIRS_RESPONSE_SHAPE_INVALID,
        aggregate=None,
    )


def decode_repairs_response(
    response: str,
) -> DecodedRepairs:
    """Decode only the complete Supervisor ``ha --raw-json`` envelope."""
    try:
        payload = json.loads(response)
    except (TypeError, json.JSONDecodeError):
        return DecodedRepairs(shape_valid=False, issues=None)

    if not isinstance(payload, dict):
        return DecodedRepairs(shape_valid=False, issues=None)
    if "result" not in payload or not isinstance(payload["result"], str):
        return DecodedRepairs(shape_valid=False, issues=None)
    if payload["result"] != "ok":
        return DecodedRepairs(shape_valid=False, issues=None)
    if "data" not in payload or not isinstance(payload["data"], dict):
        return DecodedRepairs(shape_valid=False, issues=None)
    data = payload["data"]
    if "issues" not in data or not isinstance(data["issues"], list):
        return DecodedRepairs(shape_valid=False, issues=None)

    return DecodedRepairs(shape_valid=True, issues=tuple(data["issues"]))


def aggregate_decoded_repairs(
    decoded: DecodedRepairs,
    is_relevant: Callable[[object], bool],
    is_critical: Callable[[object], bool],
) -> RepairsAggregate:
    """Reduce a valid internal decode to sanitized aggregate-only evidence."""
    if not decoded.shape_valid or decoded.issues is None:
        raise ValueError(REPAIRS_RESPONSE_SHAPE_INVALID)

    relevant_count = 0
    critical_count = 0
    for issue in decoded.issues:
        if is_relevant(issue):
            relevant_count += 1
            if is_critical(issue):
                critical_count += 1

    return RepairsAggregate(
        relevant_count=relevant_count,
        critical_count=critical_count,
    )


def collect_repairs_gate(
    gate: RepairsGate,
    response: str,
    is_relevant: Callable[[object], bool],
    is_critical: Callable[[object], bool],
) -> RepairsGateResult:
    """Classify malformed Repairs data as collector admission failure."""
    decoded = decode_repairs_response(response)
    if not decoded.shape_valid:
        return _invalid_repairs_result(gate)
    aggregate = aggregate_decoded_repairs(decoded, is_relevant, is_critical)

    return RepairsGateResult(
        gate=gate,
        shape_valid=True,
        classification=ADMISSION_VALID,
        code="REPAIRS_ADMISSION_VALID",
        aggregate=aggregate,
    )


def collect_represented_repairs_gates(
    responses: dict[RepairsGate, str],
    is_relevant: Callable[[object], bool],
    is_critical: Callable[[object], bool],
) -> tuple[RepairsGateResult, ...]:
    """Use the one strict decoder at initial, activation, and rollback gates."""
    return tuple(
        collect_repairs_gate(gate, responses[gate], is_relevant, is_critical)
        for gate in RepairsGate
    )


def repairs_evidence(result: RepairsGateResult) -> RepairsEvidence:
    """Cross the collector boundary with only the exact evidence allowlist."""
    if result.aggregate is None:
        return RepairsEvidence(
            shape_valid=result.shape_valid,
            relevant_count=None,
            critical_count=None,
        )
    return RepairsEvidence(
        shape_valid=result.shape_valid,
        relevant_count=result.aggregate.relevant_count,
        critical_count=result.aggregate.critical_count,
    )


def _extract_single_json_object(private_output: bytes) -> str | None:
    """Find one complete JSON object amid private PTY command echo and prompts."""
    try:
        text = private_output.decode("utf-8")
    except UnicodeDecodeError:
        return None

    decoder = json.JSONDecoder()
    objects: list[object] = []
    offset = 0
    while True:
        start = text.find("{", offset)
        if start == -1:
            break
        try:
            value, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            offset = start + 1
            continue
        objects.append(value)
        offset = start + end

    if len(objects) != 1 or not isinstance(objects[0], dict):
        return None
    return json.dumps(objects[0], separators=(",", ":"), sort_keys=True)


class ResolutionInfoCommand:
    """The one supported structured Repairs command; output is aggregate-only."""

    def __init__(
        self,
        gate: RepairsGate,
        is_relevant: Callable[[object], bool],
        is_critical: Callable[[object], bool],
    ) -> None:
        self._gate = gate
        self._is_relevant = is_relevant
        self._is_critical = is_critical

    def wire_command(self, completion_marker: str) -> str:
        return "ha resolution info --raw-json; " f"printf '%s\\n' '{completion_marker}'"

    def sanitize(self, private_output: bytes) -> RepairsEvidence:
        response = _extract_single_json_object(private_output)
        result = collect_repairs_gate(
            self._gate,
            response if response is not None else "",
            self._is_relevant,
            self._is_critical,
        )
        return repairs_evidence(result)


class PrivateInteractiveSessionBroker:
    """Privately broker one actual interactive PTY session through a wrapper.

    The wrapper argv and every byte emitted by its SSH child stay process-local.
    This class publishes only the fixed readiness sentinel and structured command
    adapter results. It intentionally provides no API for raw terminal output.
    """

    def __init__(
        self,
        wrapper_argv: list[str],
        *,
        remote_ready_marker: bytes,
        login_ready_marker: bytes,
        timeout_seconds: float = 15.0,
        max_capture_bytes: int = _MAX_PTY_CAPTURE_BYTES,
    ) -> None:
        if (
            not wrapper_argv
            or not remote_ready_marker
            or not login_ready_marker
            or timeout_seconds <= 0
            or max_capture_bytes <= 0
        ):
            raise ValueError("PRIVATE_SESSION_BROKER_CONFIGURATION_INVALID")
        self._wrapper_argv = tuple(wrapper_argv)
        self._remote_ready_marker = remote_ready_marker
        self._login_ready_marker = login_ready_marker
        self._timeout_seconds = timeout_seconds
        self._max_capture_bytes = max_capture_bytes
        self._master_fd: int | None = None
        self._child: subprocess.Popen[bytes] | None = None
        self._state = BrokerState.CLOSED

    def __repr__(self) -> str:
        """Never render the wrapper source, argv, target, or captured output."""
        return f"PrivateInteractiveSessionBroker(state={self._state.value!r})"

    @property
    def state(self) -> BrokerState:
        """Expose only the generic lifecycle state."""
        return self._state

    def _raise(self, failure: BrokerFailure) -> None:
        self.close()
        raise SessionBrokerError(f"PRIVATE_INTERACTIVE_SESSION_{failure.value}")

    def _write_private(self, value: str) -> None:
        if self._master_fd is None:
            self._raise(BrokerFailure.PROTOCOL)
        try:
            os.write(self._master_fd, value.encode("utf-8"))
        except OSError:
            self._raise(BrokerFailure.CHILD_EXITED)

    def _read_until(self, marker: bytes) -> bytes:
        """Read a bounded private exchange, discarding it once its adapter returns."""
        if self._master_fd is None or self._child is None:
            self._raise(BrokerFailure.PROTOCOL)
        captured = bytearray()
        deadline = time.monotonic() + self._timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._raise(BrokerFailure.TIMEOUT)
            readable, _, _ = select.select([self._master_fd], [], [], remaining)
            if not readable:
                self._raise(BrokerFailure.TIMEOUT)
            try:
                chunk = os.read(self._master_fd, 4096)
            except OSError:
                self._raise(BrokerFailure.CHILD_EXITED)
            if not chunk:
                self._raise(BrokerFailure.CHILD_EXITED)
            captured.extend(chunk)
            if len(captured) > self._max_capture_bytes:
                self._raise(BrokerFailure.OUTPUT_LIMIT)
            marker_index = captured.find(marker)
            if marker_index >= 0:
                return bytes(captured[:marker_index])

    def _drain_and_discard(self, duration_seconds: float) -> None:
        """Suppress startup/close output rather than preserving it for diagnostics."""
        if self._master_fd is None:
            return
        deadline = time.monotonic() + duration_seconds
        while time.monotonic() < deadline:
            readable, _, _ = select.select([self._master_fd], [], [], 0.01)
            if not readable:
                continue
            try:
                if not os.read(self._master_fd, 4096):
                    return
            except OSError:
                return

    def open(self) -> BrokerState:
        """Start the wrapper on a PTY and privately establish the login shell."""
        if self._state is not BrokerState.CLOSED or self._child is not None:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_ALREADY_OPEN")
        master_fd, slave_fd = pty.openpty()
        terminal_attributes = termios.tcgetattr(slave_fd)
        terminal_attributes[3] &= ~termios.ECHO
        termios.tcsetattr(slave_fd, termios.TCSANOW, terminal_attributes)
        try:
            self._child = subprocess.Popen(
                self._wrapper_argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
        except OSError as error:
            os.close(master_fd)
            os.close(slave_fd)
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_START_FAILED"
            ) from error
        os.close(slave_fd)
        self._master_fd = master_fd
        self._state = BrokerState.SSH_CHILD_STARTED
        self._read_until(self._remote_ready_marker)
        self._state = BrokerState.REMOTE_INTERACTIVE_READY
        self._write_private("exec bash -li\n")
        self._read_until(self._login_ready_marker)
        self._state = BrokerState.LOGIN_SHELL_READY
        self._state = BrokerState.SESSION_ACTIVE
        print(HA_INTERACTIVE_SESSION_READY)
        return self._state

    def execute(
        self, command: StructuredSessionCommand[CommandResult]
    ) -> CommandResult:
        """Run a reviewed bounded adapter and expose only its sanitized result."""
        if self._state is not BrokerState.SESSION_ACTIVE:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_NOT_ACTIVE")
        wire_command = command.wire_command(_COMMAND_DONE_MARKER)
        if "\n" in wire_command or "\r" in wire_command:
            raise ValueError("PRIVATE_INTERACTIVE_COMMAND_INVALID")
        self._write_private(wire_command + "\n")
        private_output = self._read_until(_COMMAND_DONE_MARKER.encode("ascii"))
        return command.sanitize(private_output)

    def close(self) -> None:
        """Close/terminate privately and discard the local SSH close message."""
        child = self._child
        master_fd = self._master_fd
        if child is not None and child.poll() is None and master_fd is not None:
            try:
                os.write(master_fd, b"exit\n")
            except OSError:
                pass
            self._drain_and_discard(0.1)
            try:
                child.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:
                    child.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=0.5)
        if master_fd is not None:
            self._drain_and_discard(0.05)
            try:
                os.close(master_fd)
            except OSError:
                pass
        self._master_fd = None
        self._child = None
        self._state = BrokerState.CLOSED


def _private_spec_from_stream(stream: TextIO) -> dict[str, object]:
    """Read a literal-only private recipe without rendering it anywhere."""
    try:
        tree = ast.parse(stream.read(), mode="exec")
    except (SyntaxError, UnicodeError) as error:
        raise ValueError("PRIVATE_WRAPPER_SPEC_INVALID") from error

    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Assign):
        raise ValueError("PRIVATE_WRAPPER_SPEC_INVALID")
    assignment = tree.body[0]
    if (
        len(assignment.targets) != 1
        or not isinstance(assignment.targets[0], ast.Name)
        or assignment.targets[0].id != "PRIVATE_WRAPPER"
    ):
        raise ValueError("PRIVATE_WRAPPER_SPEC_INVALID")
    try:
        spec = ast.literal_eval(assignment.value)
    except (ValueError, TypeError, MemoryError, RecursionError) as error:
        raise ValueError("PRIVATE_WRAPPER_SPEC_INVALID") from error
    if not isinstance(spec, dict):
        raise ValueError("PRIVATE_WRAPPER_SPEC_INVALID")
    return spec


def _validate_private_command(spec: dict[str, object]) -> list[str]:
    """Allow only the reviewed private interactive SSH command shape."""
    if set(spec) != {"route", "argv"} or spec["route"] != PRIVATE_ROUTE_ID:
        raise ValueError("PRIVATE_WRAPPER_ROUTE_INVALID")
    argv = spec["argv"]
    if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
        raise ValueError("PRIVATE_WRAPPER_COMMAND_INVALID")
    if len(argv) == 2:
        executable, target = argv
    elif len(argv) == 3 and argv[1] == "-tt":
        executable, _, target = argv
    else:
        raise ValueError("PRIVATE_WRAPPER_COMMAND_INVALID")
    if executable not in SAFE_SSH_EXECUTABLES or not SAFE_PRIVATE_ALIAS.fullmatch(
        target
    ):
        raise ValueError("PRIVATE_WRAPPER_COMMAND_INVALID")
    return argv


def _require_secure_directory(directory: Path) -> None:
    details = directory.lstat()
    if (
        not directory.is_dir()
        or stat.S_ISLNK(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_mode & 0o077
    ):
        raise ValueError("PRIVATE_WRAPPER_DIRECTORY_INVALID")


def bootstrap_private_wrapper(private_spec: TextIO, wrapper_path: Path) -> None:
    """Create a 0700 wrapper from a separate non-echoing literal-only recipe.

    This does not parse ``AGENTS.local.md``. A separately authorized local
    process supplies the small private recipe without sending its target through
    an agent transcript.
    """
    _require_secure_directory(wrapper_path.parent)
    if wrapper_path.exists() or wrapper_path.is_symlink():
        raise ValueError("PRIVATE_WRAPPER_DESTINATION_EXISTS")
    argv = _validate_private_command(_private_spec_from_stream(private_spec))
    wrapper_source = "#!/bin/sh\nexec " + shlex.join(argv) + "\n"
    descriptor = os.open(
        wrapper_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o700,
    )
    try:
        os.write(descriptor, wrapper_source.encode("utf-8"))
        os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)


def _wrapper_source_is_valid(source: str) -> bool:
    """Statically validate the sole allowed shell command without executing it."""
    lines = source.splitlines()
    if len(lines) != 2 or lines[0] != "#!/bin/sh" or not lines[1].startswith("exec "):
        return False
    try:
        argv = shlex.split(lines[1])
    except ValueError:
        return False
    try:
        return (
            _validate_private_command({"route": PRIVATE_ROUTE_ID, "argv": argv[1:]})
            == argv[1:]
        )
    except ValueError:
        return False


def validate_private_wrapper(wrapper_path: Path) -> WrapperValidationResult:
    """Return safe structural evidence; never return a target or wrapper text."""
    reasons: list[str] = []
    try:
        details = wrapper_path.lstat()
    except FileNotFoundError:
        return WrapperValidationResult(PRIVATE_WRAPPER_INVALID, ("MISSING",))

    if stat.S_ISLNK(details.st_mode):
        reasons.append("SYMLINK")
    if not stat.S_ISREG(details.st_mode):
        reasons.append("NOT_REGULAR")
    if details.st_uid != os.getuid():
        reasons.append("OWNER")
    if stat.S_IMODE(details.st_mode) != 0o700:
        reasons.append("MODE")
    try:
        _require_secure_directory(wrapper_path.parent)
    except ValueError:
        reasons.append("PARENT")

    if not reasons:
        try:
            source = wrapper_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            reasons.append("UNREADABLE")
        else:
            if not _wrapper_source_is_valid(source):
                reasons.append("COMMAND")

    if reasons:
        return WrapperValidationResult(PRIVATE_WRAPPER_INVALID, tuple(sorted(reasons)))
    return WrapperValidationResult(PRIVATE_WRAPPER_VALID, ())


def _write_safe_result(result: WrapperValidationResult) -> None:
    """Render only fixed status values and reason codes to the local operator."""
    print(json.dumps(asdict(result), sort_keys=True))


def main(arguments: Iterable[str] | None = None) -> int:
    """Run local-only bootstrap or static validation; never open a connection."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    bootstrap = subparsers.add_parser("bootstrap")
    bootstrap.add_argument("--private-spec", type=Path, required=True)
    bootstrap.add_argument("--wrapper", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--wrapper", type=Path, required=True)
    parsed = parser.parse_args(arguments)

    try:
        if parsed.command == "bootstrap":
            with parsed.private_spec.open(encoding="utf-8") as private_spec:
                bootstrap_private_wrapper(private_spec, parsed.wrapper)
            print(json.dumps({"status": PRIVATE_WRAPPER_BOOTSTRAPPED}))
            return 0
        result = validate_private_wrapper(parsed.wrapper)
        _write_safe_result(result)
        return 0 if result.status == PRIVATE_WRAPPER_VALID else 1
    except (OSError, ValueError):
        print(json.dumps({"status": PRIVATE_WRAPPER_INVALID}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
