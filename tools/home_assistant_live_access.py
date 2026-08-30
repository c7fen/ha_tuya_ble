"""Fail-closed, local-only helpers for Home Assistant access orchestration.

This module contains no network client and never exposes a raw remote terminal.
It creates/validates a private owner-only SSH wrapper, then can launch only that
validated path through a controlling PTY for fixed structured operations.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import pty
import re
import secrets
import select
import shlex
import signal
import stat
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, TextIO

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
_MAX_PTY_CAPTURE_BYTES = 64 * 1024
_MAX_SOURCE_BUNDLE_BYTES = 4 * 1024 * 1024
_MAX_SOURCE_FILES = 512
_TRANSFER_CHUNK_SIZE = 2048
_FRAME_START = b"\x1e"
_FRAME_END = b"\x1f"
PR45_CANDIDATE_COMMIT = "a382c08cd4e8613dc214505bcb8a6f59f8da3022"
PR45_CANDIDATE_TREE = "73246ecd71f0953c7bf8a73df78d6506bee29c8e"
PR41_RESTORE_COMMIT = "4f73a9b008dcb89134bc41001c486f06d6056867"
PR41_RESTORE_TREE = "463ed8553da01eae591de611e76e45392ad9e7bf"
_AUTHORITY_MANIFEST_DIGESTS = {
    "candidate": "4b7d4222c57377a29961d35a7427ebc1b6dd032a82a9274a63a0f0269e13a20e",
    "restore": "2d1dd79288b90f0d12c5c35449e6ed5d02c53433335dedd68377c81809731ac2",
}
_HELPER_FILES = frozenset(
    {
        "helper/phase_a_status_probe_helper.py",
        "helper/phase_a_status_probe_lib.py",
    }
)
_NONCE = re.compile(r"[0-9a-f]{16,32}\Z")
AUDIT_COUNTER_NAMES = (
    "connect_attempts",
    "gatt_sessions_claimed",
    "authenticated_sessions",
    "packets_sent_total",
    "device_status_requests",
    "device_info_requests",
    "pair_requests",
    "datapoint_write_operations",
    "datapoint_protocol_packets",
    "other_packets",
    "reconnect_schedules",
    "disconnects",
)


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


class SourceState(StrEnum):
    """The two exact repository authorities accepted by the control plane."""

    CANDIDATE = "candidate"
    RESTORE = "restore"


class BoundedOperation(StrEnum):
    """Every operation the private remote dispatcher can represent."""

    BACKUP = "backup"
    TRANSFER = "transfer"
    INSTALL = "install"
    SOURCE_INVENTORY = "source_inventory"
    CORE_CHECK = "core_check"
    RESTART_CORE = "restart_core"
    CORE_READINESS = "core_readiness"
    SERVICE_INVENTORY = "service_inventory"
    PHASE_A_HELPER = "phase_a_helper"
    RESTORE = "restore"
    RESTORE_BACKUP = "restore_backup"


class PhaseAOperation(StrEnum):
    """The BLE-free PR #45 helper operations admitted by this broker."""

    PREFLIGHT = "preflight"
    AUDIT = "audit"
    RECEIPT = "receipt"


class ServiceExpectation(StrEnum):
    """Whether all temporary Issue-37 services must exist or be absent."""

    PRESENT = "expected_present"
    ABSENT = "expected_absent"


class AuditLabel(StrEnum):
    """The fixed zero-I/O snapshots in the hardened preflight contract."""

    A0 = "A0"
    AP0 = "AP0"
    A1 = "A1"
    A2 = "A2"


class LifecycleState(StrEnum):
    """Exact controller-owned full-preflight and restoration stages."""

    BASELINE = "BASELINE"
    INITIAL_REPAIRS_PASS = "INITIAL_REPAIRS_PASS"
    BACKUP_VERIFIED = "BACKUP_VERIFIED"
    CANDIDATE_STAGED = "CANDIDATE_STAGED"
    CANDIDATE_INSTALLED = "CANDIDATE_INSTALLED"
    CANDIDATE_INVENTORY_VERIFIED = "CANDIDATE_INVENTORY_VERIFIED"
    CANDIDATE_CORE_CHECKED = "CANDIDATE_CORE_CHECKED"
    ACTIVATION_RESTART_CONSUMED = "ACTIVATION_RESTART_CONSUMED"
    CANDIDATE_READY = "CANDIDATE_READY"
    RESEARCH_SERVICES_PRESENT = "RESEARCH_SERVICES_PRESENT"
    POST_ACTIVATION_REPAIRS_PASS = "POST_ACTIVATION_REPAIRS_PASS"
    A0_COLLECTED = "A0_COLLECTED"
    P0_COMPLETED = "P0_COMPLETED"
    AP0_COLLECTED = "AP0_COLLECTED"
    NON_PROBE_PREFLIGHT_COMPLETED = "NON_PROBE_PREFLIGHT_COMPLETED"
    NON_PROBE_RECEIPT_COMPLETED = "NON_PROBE_RECEIPT_COMPLETED"
    A1_COLLECTED = "A1_COLLECTED"
    RESEARCH_FINAL_VALIDATED = "RESEARCH_FINAL_VALIDATED"
    A2_COLLECTED = "A2_COLLECTED"
    RESTORE_STAGED = "RESTORE_STAGED"
    PR41_RESTORED = "PR41_RESTORED"
    RESTORE_INVENTORY_VERIFIED = "RESTORE_INVENTORY_VERIFIED"
    RESTORE_CORE_CHECKED = "RESTORE_CORE_CHECKED"
    REMOVAL_RESTART_CONSUMED = "REMOVAL_RESTART_CONSUMED"
    PR41_READY = "PR41_READY"
    RESEARCH_SERVICES_ABSENT = "RESEARCH_SERVICES_ABSENT"
    POST_RESTORE_REPAIRS_PASS = "POST_RESTORE_REPAIRS_PASS"
    COMPLETE = "COMPLETE"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"

    @property
    def is_failure(self) -> bool:
        return self is LifecycleState.ROLLBACK_REQUIRED


class LifecycleAction(StrEnum):
    """One generation-bound permit for every represented controller stage."""

    INITIAL_REPAIRS = "initial_repairs"
    BACKUP = "backup"
    CANDIDATE_TRANSFER = "candidate_transfer"
    CANDIDATE_INSTALL = "candidate_install"
    CANDIDATE_INVENTORY = "candidate_inventory"
    CANDIDATE_CORE_CHECK_1 = "candidate_core_check_1"
    CANDIDATE_CORE_CHECK_2 = "candidate_core_check_2"
    ACTIVATION_RESTART = "activation_restart"
    CANDIDATE_READINESS = "candidate_readiness"
    SERVICES_PRESENT = "services_present"
    POST_ACTIVATION_REPAIRS = "post_activation_repairs"
    A0 = "a0"
    P0 = "p0"
    AP0 = "ap0"
    PREFLIGHT = "preflight"
    RECEIPT = "receipt"
    A1 = "a1"
    RESEARCH_FINAL = "research_final"
    A2 = "a2"
    RESTORE_TRANSFER = "restore_transfer"
    RESTORE_INSTALL = "restore_install"
    RESTORE_INVENTORY = "restore_inventory"
    RESTORE_CORE_CHECK_1 = "restore_core_check_1"
    RESTORE_CORE_CHECK_2 = "restore_core_check_2"
    REMOVAL_RESTART = "removal_restart"
    RESTORE_READINESS = "restore_readiness"
    SERVICES_ABSENT = "services_absent"
    POST_RESTORE_REPAIRS = "post_restore_repairs"
    FINAL_ACCEPTANCE = "final_acceptance"
    AMBIGUOUS_RECEIPT = "ambiguous_receipt"
    BACKUP_FALLBACK = "backup_fallback"


_ROLLBACK_REBIND_ACTIONS = frozenset(
    {
        LifecycleAction.RESTORE_TRANSFER,
        LifecycleAction.RESTORE_INSTALL,
        LifecycleAction.RESTORE_INVENTORY,
        LifecycleAction.RESTORE_CORE_CHECK_1,
        LifecycleAction.RESTORE_CORE_CHECK_2,
        LifecycleAction.REMOVAL_RESTART,
        LifecycleAction.RESTORE_READINESS,
        LifecycleAction.SERVICES_ABSENT,
        LifecycleAction.POST_RESTORE_REPAIRS,
        LifecycleAction.FINAL_ACCEPTANCE,
        LifecycleAction.AMBIGUOUS_RECEIPT,
        LifecycleAction.BACKUP_FALLBACK,
    }
)

_ROLLBACK_BROKER_ADAPTERS = (
    "_transfer_source_bundle",
    "_install_staged_restore",
    "_verify_source_inventory",
    "_check_core",
    "_restart_core",
    "_wait_for_core_readiness",
    "_inventory_temporary_services",
    "_collect_resolution_info",
    "_invoke_phase_a",
    "_restore_private_backup",
)


class SessionBrokerError(RuntimeError):
    """A failure that intentionally never includes captured PTY bytes."""


class SourceBundleError(ValueError):
    """A fixed source-admission failure without paths or content."""


class LifecycleControllerError(RuntimeError):
    """A fixed lifecycle failure that contains no private operation data."""


@dataclass(frozen=True)
class SourceManifestEntry:
    """One trusted repository-relative regular-file digest."""

    relative_path: str = field(repr=False)
    size: int
    sha256: str = field(repr=False)


@dataclass(frozen=True)
class SourceManifest:
    """An exact aggregate source contract bound to one reviewed Git object."""

    state: SourceState
    entries: tuple[SourceManifestEntry, ...] = field(repr=False)

    def __repr__(self) -> str:
        return f"SourceManifest(state={self.state.value!r}, file_count={len(self.entries)})"

    @property
    def authority_commit(self) -> str:
        return (
            PR45_CANDIDATE_COMMIT
            if self.state is SourceState.CANDIDATE
            else PR41_RESTORE_COMMIT
        )

    @property
    def authority_tree(self) -> str:
        return (
            PR45_CANDIDATE_TREE
            if self.state is SourceState.CANDIDATE
            else PR41_RESTORE_TREE
        )


@dataclass(frozen=True)
class SourceBundleFile:
    """One local repository file; content and name are never rendered."""

    relative_path: str = field(repr=False)
    content: bytes = field(repr=False)
    regular_file: bool = True


@dataclass(frozen=True)
class SourceBundle:
    """A locally verified bundle for one fixed deployment state."""

    state: SourceState
    files: tuple[SourceBundleFile, ...] = field(repr=False)
    manifest: SourceManifest = field(repr=False)

    def __repr__(self) -> str:
        return f"SourceBundle(state={self.state.value!r}, file_count={len(self.files)})"


@dataclass(frozen=True)
class BackupResult:
    success: bool
    file_count: int
    manifest_match: bool
    regular_files_only: bool


@dataclass(frozen=True)
class TransferResult:
    success: bool
    file_count: int
    manifest_match: bool
    regular_files_only: bool


@dataclass(frozen=True)
class InstallResult:
    installation_success: bool
    expected_file_count: int
    installed_file_count: int
    manifest_match: bool


@dataclass(frozen=True)
class SourceInventoryResult:
    expected_count: int
    observed_count: int
    manifest_match: bool
    unexpected_count: int
    missing_count: int


@dataclass(frozen=True)
class CoreCheckResult:
    attempt_ordinal: int
    http_status: int | None
    result: str | None
    check_passed: bool
    error_class: str | None


@dataclass(frozen=True)
class RestartResult:
    submitted: bool
    accepted: bool


@dataclass(frozen=True)
class CoreReadinessResult:
    core_reachable: bool
    core_running: bool
    integration_loaded: bool
    timed_out: bool


@dataclass(frozen=True)
class ServiceInventoryResult:
    expected_present_count: int
    observed_present_count: int
    all_expected_present: bool
    expected_absent_count: int
    observed_absent_count: int
    all_expected_absent: bool


@dataclass(frozen=True)
class AuditEvent:
    event_ordinal: int
    kind: str
    monotonic_ms: int
    protocol_category: str | None


@dataclass(frozen=True)
class AuditSnapshot:
    protocol_version: int
    audit_instance_token: str = field(repr=False)
    event_ordinal: int
    history_overflow: bool
    runtime_ms: int
    counters: tuple[tuple[str, int], ...]
    events: tuple[AuditEvent, ...] = field(repr=False)
    nonce: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class AuditComparison:
    same_instance: bool
    ordinal_unchanged: bool
    counters_unchanged: bool
    events_unchanged: bool
    no_overflow: bool

    @property
    def zero_io_unchanged(self) -> bool:
        return (
            self.same_instance
            and self.ordinal_unchanged
            and self.counters_unchanged
            and self.events_unchanged
            and self.no_overflow
        )


@dataclass(frozen=True)
class PhaseAResult:
    operation: PhaseAOperation
    exit_code: int
    outcome: str
    nonce: str | None = field(default=None, repr=False)
    http_handoff: bool | None = None
    audit: AuditSnapshot | None = None


@dataclass
class _InvocationPermit:
    """A non-replayable action capability bound to one session and lifecycle."""

    action: LifecycleAction
    lifecycle_generation: object = field(repr=False)
    session_generation: object = field(repr=False)
    consumed: bool = False

    def consume(
        self,
        lifecycle_generation: object,
        session_generation: object,
        action: LifecycleAction,
    ) -> None:
        if (
            self.consumed
            or lifecycle_generation is not self.lifecycle_generation
            or session_generation is not self.session_generation
            or action is not self.action
        ):
            raise LifecycleControllerError("LIFECYCLE_PERMIT_CONSUMED") from None
        self.consumed = True


@dataclass(frozen=True)
class FinalRestoreProof:
    """No-default final restoration predicates assembled by the controller."""

    source_manifest_match: bool
    research_files_absent: bool
    core_check_passed: bool
    restart_consumed: bool
    restart_dispatched: bool
    restart_submitted: bool
    restart_accepted: bool
    core_reachable: bool
    core_running: bool
    integration_loaded: bool
    core_not_timed_out: bool
    research_services_absent: bool
    repairs_shape_valid: bool
    repairs_relevant_zero: bool
    repairs_critical_zero: bool

    @property
    def complete(self) -> bool:
        """Require every named predicate explicitly; no dynamic defaults exist."""
        return (
            self.source_manifest_match
            and self.research_files_absent
            and self.core_check_passed
            and self.restart_consumed
            and self.restart_dispatched
            and self.restart_submitted
            and self.restart_accepted
            and self.core_reachable
            and self.core_running
            and self.integration_loaded
            and self.core_not_timed_out
            and self.research_services_absent
            and self.repairs_shape_valid
            and self.repairs_relevant_zero
            and self.repairs_critical_zero
        )


def _source_path_allowed(path: object, state: SourceState) -> bool:
    if not isinstance(path, str) or not path or "\\" in path:
        return False
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        return False
    if path in _HELPER_FILES:
        return state is SourceState.CANDIDATE
    return len(pure.parts) >= 2 and pure.parts[0] == "integration"


def _source_manifest_digest(entries: Iterable[SourceManifestEntry]) -> str:
    canonical = "".join(
        f"{entry.relative_path}\0{entry.size}\0{entry.sha256}\n"
        for entry in sorted(entries, key=lambda item: item.relative_path)
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_source_bundle(
    state: SourceState,
    files: Iterable[SourceBundleFile],
    expected_manifest: SourceManifest,
) -> SourceBundle:
    """Admit only a complete bounded bundle matching the trusted manifest."""
    if not isinstance(state, SourceState) or expected_manifest.state is not state:
        raise SourceBundleError("SOURCE_BUNDLE_AUTHORITY_MISMATCH") from None
    file_items = tuple(files)
    if not file_items or len(file_items) > _MAX_SOURCE_FILES:
        raise SourceBundleError("SOURCE_BUNDLE_SIZE_INVALID") from None
    paths = [item.relative_path for item in file_items]
    if len(paths) != len(set(paths)):
        raise SourceBundleError("SOURCE_BUNDLE_DUPLICATE_FILE") from None
    if any(not _source_path_allowed(path, state) for path in paths):
        raise SourceBundleError("SOURCE_BUNDLE_UNEXPECTED_FILE") from None
    if any(
        not isinstance(item, SourceBundleFile)
        or not item.regular_file
        or not isinstance(item.content, bytes)
        for item in file_items
    ):
        raise SourceBundleError("SOURCE_BUNDLE_REGULAR_FILES_ONLY") from None
    if sum(len(item.content) for item in file_items) > _MAX_SOURCE_BUNDLE_BYTES:
        raise SourceBundleError("SOURCE_BUNDLE_SIZE_INVALID") from None
    entries = expected_manifest.entries
    manifest_paths = [entry.relative_path for entry in entries]
    if len(manifest_paths) != len(set(manifest_paths)):
        raise SourceBundleError("SOURCE_BUNDLE_DUPLICATE_FILE") from None
    if any(not _source_path_allowed(path, state) for path in manifest_paths):
        raise SourceBundleError("SOURCE_BUNDLE_UNEXPECTED_FILE") from None
    if state is SourceState.CANDIDATE and not _HELPER_FILES.issubset(paths):
        raise SourceBundleError("SOURCE_BUNDLE_MANIFEST_MISMATCH") from None
    if _source_manifest_digest(entries) != _AUTHORITY_MANIFEST_DIGESTS[state.value]:
        raise SourceBundleError("SOURCE_BUNDLE_AUTHORITY_MISMATCH") from None
    actual = {
        item.relative_path: (
            len(item.content),
            hashlib.sha256(item.content).hexdigest(),
        )
        for item in file_items
    }
    expected = {
        entry.relative_path: (entry.size, entry.sha256)
        for entry in entries
        if isinstance(entry.size, int)
        and entry.size >= 0
        and isinstance(entry.sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", entry.sha256)
    }
    if len(expected) != len(entries) or actual != expected:
        raise SourceBundleError("SOURCE_BUNDLE_MANIFEST_MISMATCH") from None
    return SourceBundle(state, file_items, expected_manifest)


def validate_source_bundle(bundle: SourceBundle) -> None:
    """Revalidate a bundle immediately before any PTY write."""
    if not isinstance(bundle, SourceBundle):
        raise SourceBundleError("SOURCE_BUNDLE_INVALID") from None
    build_source_bundle(bundle.state, bundle.files, bundle.manifest)


def _manifest_payload(manifest: SourceManifest) -> dict[str, object]:
    return {
        "state": manifest.state.value,
        "authority_commit": manifest.authority_commit,
        "authority_tree": manifest.authority_tree,
        "entries": [
            {
                "path": entry.relative_path,
                "size": entry.size,
                "sha256": entry.sha256,
            }
            for entry in manifest.entries
        ],
    }


def _bundle_payload(bundle: SourceBundle) -> dict[str, object]:
    return {
        "manifest": _manifest_payload(bundle.manifest),
        "files": [
            {
                "path": item.relative_path,
                "content": base64.b64encode(item.content).decode("ascii"),
            }
            for item in bundle.files
        ],
    }


def _exact_payload(private_output: bytes) -> dict[str, Any]:
    extracted = _extract_exact_framed_json_object(private_output)
    if extracted is None:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    payload = json.loads(extracted)
    if not isinstance(payload, dict) or "error_class" in payload:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return payload


def _exact_core_check_payload(private_output: bytes) -> dict[str, Any]:
    """Decode only the Core-check allowlist, including a generic error class."""
    extracted = _extract_exact_framed_json_object(private_output)
    if extracted is None:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    try:
        payload = json.loads(extracted)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    allowed = {"http_status", "result", "check_passed", "error_class"}
    error_class = (
        payload["error_class"]
        if isinstance(payload, dict) and "error_class" in payload
        else None
    )
    if (
        not isinstance(payload, dict)
        or not set(payload).issubset(allowed)
        or error_class is not None
        and (
            not isinstance(error_class, str)
            or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", error_class)
        )
    ):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return payload


def _bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError
    return value


def _count(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError
    return value


def _parse_source_inventory_result(payload: object) -> SourceInventoryResult:
    try:
        if not isinstance(payload, dict) or set(payload) != {
            "expected_count",
            "observed_count",
            "manifest_match",
            "unexpected_count",
            "missing_count",
        }:
            raise ValueError
        expected_count = _count(payload["expected_count"])
        observed_count = _count(payload["observed_count"])
        manifest_match = _bool(payload["manifest_match"])
        unexpected_count = _count(payload["unexpected_count"])
        missing_count = _count(payload["missing_count"])
        if manifest_match != (
            expected_count == observed_count
            and unexpected_count == 0
            and missing_count == 0
        ):
            raise ValueError
        return SourceInventoryResult(
            expected_count,
            observed_count,
            manifest_match,
            unexpected_count,
            missing_count,
        )
    except (KeyError, TypeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None


def _parse_core_check_result(value: object, *, attempt_ordinal: int) -> CoreCheckResult:
    if attempt_ordinal not in {1, 2}:
        raise SessionBrokerError("CORE_CHECK_ATTEMPT_INVALID") from None
    invalid = CoreCheckResult(attempt_ordinal, None, None, False, "INVALID_RESPONSE")
    if not isinstance(value, dict) or not set(value).issubset(
        {"http_status", "result", "check_passed", "error_class"}
    ):
        return invalid
    status = value.get("http_status")
    result = value.get("result")
    passed = value.get("check_passed")
    error_class = value.get("error_class")
    if (
        not isinstance(status, int)
        or isinstance(status, bool)
        or not isinstance(result, str)
        or error_class is not None
        and not isinstance(error_class, str)
    ):
        return invalid
    exact_pass = (
        200 <= status < 300
        and result == "ok"
        and passed is True
        and error_class is None
    )
    return CoreCheckResult(
        attempt_ordinal,
        status,
        result,
        exact_pass,
        None if exact_pass else error_class or "CHECK_FAILED",
    )


def _parse_service_inventory_result(payload: object) -> ServiceInventoryResult:
    keys = {
        "expected_present_count",
        "observed_present_count",
        "all_expected_present",
        "expected_absent_count",
        "observed_absent_count",
        "all_expected_absent",
    }
    try:
        if not isinstance(payload, dict) or set(payload) != keys:
            raise ValueError
        return ServiceInventoryResult(
            _count(payload["expected_present_count"]),
            _count(payload["observed_present_count"]),
            _bool(payload["all_expected_present"]),
            _count(payload["expected_absent_count"]),
            _count(payload["observed_absent_count"]),
            _bool(payload["all_expected_absent"]),
        )
    except (KeyError, TypeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None


def _parse_audit_snapshot(value: object) -> AuditSnapshot:
    required = {
        "protocol_version",
        "audit_instance_token",
        "event_ordinal",
        "history_overflow",
        "runtime_ms",
        "counters",
        "events",
    }
    try:
        if not isinstance(value, dict) or set(value) not in (
            required,
            required | {"nonce"},
        ):
            raise ValueError
        token = value["audit_instance_token"]
        nonce = value.get("nonce")
        counters = value["counters"]
        events = value["events"]
        if (
            value["protocol_version"] != 1
            or not isinstance(token, str)
            or not _NONCE.fullmatch(token)
            or nonce is not None
            and (not isinstance(nonce, str) or not _NONCE.fullmatch(nonce))
            or not isinstance(counters, dict)
            or set(counters) != set(AUDIT_COUNTER_NAMES)
            or not isinstance(events, list)
            or len(events) > 128
        ):
            raise ValueError
        counter_items = tuple(
            (name, _count(counters[name])) for name in AUDIT_COUNTER_NAMES
        )
        clean_events = []
        event_keys = {
            "event_ordinal",
            "kind",
            "monotonic_ms",
            "protocol_category",
        }
        event_kinds = {
            "CONNECT_ATTEMPT",
            "GATT_SESSION_CLAIMED",
            "AUTHENTICATED_SESSION",
            "PACKET_SENT",
            "DATAPOINT_WRITE",
            "RECONNECT_SCHEDULED",
            "DISCONNECT",
        }
        protocol_categories = {
            None,
            "DEVICE_STATUS",
            "DEVICE_INFO",
            "PAIR",
            "DATAPOINT",
            "OTHER",
        }
        for event in events:
            if (
                not isinstance(event, dict)
                or set(event) != event_keys
                or event["kind"] not in event_kinds
                or event["protocol_category"] not in protocol_categories
            ):
                raise ValueError
            clean_events.append(
                AuditEvent(
                    _count(event["event_ordinal"]),
                    event["kind"],
                    _count(event["monotonic_ms"]),
                    event["protocol_category"],
                )
            )
        return AuditSnapshot(
            1,
            token,
            _count(value["event_ordinal"]),
            _bool(value["history_overflow"]),
            _count(value["runtime_ms"]),
            counter_items,
            tuple(clean_events),
            nonce,
        )
    except (KeyError, TypeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None


def _parse_phase_a_result(
    operation: PhaseAOperation,
    private_output: bytes,
    *,
    expected_nonce: str | None = None,
) -> PhaseAResult:
    if not isinstance(operation, PhaseAOperation):
        raise SessionBrokerError("PHASE_A_HELPER_OPERATION_INVALID") from None
    value = _exact_payload(private_output)
    allowed = {"exit_code", "outcome", "nonce", "http_handoff", "audit"}
    if not set(value).issubset(allowed) or not {"exit_code", "outcome"}.issubset(value):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    exit_code = value["exit_code"]
    outcome = value["outcome"]
    nonce = value.get("nonce")
    handoff = value.get("http_handoff")
    if (
        exit_code not in {0, 65, 66, 67, 78}
        or not isinstance(outcome, str)
        or nonce is not None
        and (not isinstance(nonce, str) or not _NONCE.fullmatch(nonce))
        or handoff is not None
        and not isinstance(handoff, bool)
    ):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    successful_outcomes = {
        PhaseAOperation.PREFLIGHT: "preflight_ok",
        PhaseAOperation.AUDIT: "audit_snapshot",
        PhaseAOperation.RECEIPT: "receipt",
    }
    valid = (
        exit_code == 0
        and outcome == successful_outcomes[operation]
        or exit_code == 65
        and outcome == "not_submitted"
        or exit_code == 66
        and operation is PhaseAOperation.RECEIPT
        and outcome == "receipt"
        or exit_code == 67
        and outcome in {"schema_invalid", "nonce_mismatch", "evidence_write_failed"}
        or exit_code == 78
        and outcome == "transport_ambiguous"
    )
    if not valid:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    if exit_code != 65 and nonce is None:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    if expected_nonce is not None and nonce != expected_nonce:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    audit = None
    if operation is PhaseAOperation.AUDIT:
        if exit_code == 0 and "audit" not in value:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        if "audit" in value:
            audit = _parse_audit_snapshot(value["audit"])
            if audit.nonce != nonce:
                raise SessionBrokerError(
                    "PRIVATE_INTERACTIVE_SESSION_PROTOCOL"
                ) from None
    elif "audit" in value:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return PhaseAResult(operation, exit_code, outcome, nonce, handoff, audit)


def compare_audit_snapshots(
    before: AuditSnapshot, after: AuditSnapshot
) -> AuditComparison:
    """Compare exact retained I/O fields without semantic equivalence guesses."""
    if not isinstance(before, AuditSnapshot) or not isinstance(after, AuditSnapshot):
        raise TypeError("AUDIT_SNAPSHOT_INVALID")
    return AuditComparison(
        same_instance=before.audit_instance_token == after.audit_instance_token,
        ordinal_unchanged=before.event_ordinal == after.event_ordinal,
        counters_unchanged=before.counters == after.counters,
        events_unchanged=before.events == after.events,
        no_overflow=not before.history_overflow and not after.history_overflow,
    )


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


def _extract_exact_framed_json_object(private_output: bytes) -> str | None:
    """Decode exactly one JSON object from a broker-bounded private payload."""
    try:
        text = private_output.decode("utf-8").strip(" \t\r\n")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(value, dict):
        return None
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


_REMOTE_CONTROL_PROGRAM = r"""
import base64
import ctypes
import errno
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path('/config')
INTEGRATION = ROOT / 'custom_components' / 'tuya_ble'
HELPER = INTEGRATION / '.phase_a_tools'
STAGE = ROOT / '.ha_tuya_ble_r30_stage'
BACKUP = ROOT / '.ha_tuya_ble_r30_backup'
BACKUP_CONSUMED = ROOT / '.ha_tuya_ble_r30_backup.consumed'
EVIDENCE = Path('/var/lib/phase-a-status-probe')
SERVICES = {'preflight', 'probe', 'receipt', 'audit'}
COUNTERS = {
    'connect_attempts', 'gatt_sessions_claimed', 'authenticated_sessions',
    'packets_sent_total', 'device_status_requests', 'device_info_requests',
    'pair_requests', 'datapoint_write_operations',
    'datapoint_protocol_packets', 'other_packets', 'reconnect_schedules',
    'disconnects',
}

def receive():
    count = int(sys.stdin.readline())
    if count < 1 or count > 4096:
        raise ValueError('chunks')
    encoded = ''.join(sys.stdin.readline().strip() for _ in range(count))
    if len(encoded) > 6 * 1024 * 1024:
        raise ValueError('size')
    value = json.loads(base64.b64decode(encoded, validate=True))
    if not isinstance(value, dict):
        raise ValueError('payload')
    return value

def safe_path(value, state):
    if not isinstance(value, str) or not value or '\\' in value:
        raise ValueError('path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {'', '.', '..'} for part in path.parts):
        raise ValueError('path')
    if path.parts[0] == 'integration' and len(path.parts) >= 2:
        return path
    if state == 'candidate' and value in {
        'helper/phase_a_status_probe_helper.py',
        'helper/phase_a_status_probe_lib.py',
    }:
        return path
    raise ValueError('path')

def expected_manifest(value):
    manifest = value['manifest']
    state = manifest['state']
    authorities = {
        'candidate': (
            'a382c08cd4e8613dc214505bcb8a6f59f8da3022',
            '73246ecd71f0953c7bf8a73df78d6506bee29c8e',
        ),
        'restore': (
            '4f73a9b008dcb89134bc41001c486f06d6056867',
            '463ed8553da01eae591de611e76e45392ad9e7bf',
        ),
    }
    if state not in authorities or (
        manifest.get('authority_commit'), manifest.get('authority_tree')
    ) != authorities[state]:
        raise ValueError('authority')
    expected = {}
    for entry in manifest['entries']:
        path = str(safe_path(entry['path'], state))
        size = entry['size']
        digest = entry['sha256']
        if path in expected or not isinstance(size, int) or size < 0:
            raise ValueError('manifest')
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError('manifest')
        expected[path] = (size, digest)
    helper_names = {
        'helper/phase_a_status_probe_helper.py',
        'helper/phase_a_status_probe_lib.py',
    }
    if state == 'candidate' and not helper_names.issubset(expected):
        raise ValueError('helper')
    canonical = ''.join(
        path + '\0' + str(size) + '\0' + digest + '\n'
        for path, (size, digest) in sorted(expected.items())
    ).encode()
    fingerprints = {
        'candidate': '4b7d4222c57377a29961d35a7427ebc1b6dd032a82a9274a63a0f0269e13a20e',
        'restore': '2d1dd79288b90f0d12c5c35449e6ed5d02c53433335dedd68377c81809731ac2',
    }
    if hashlib.sha256(canonical).hexdigest() != fingerprints[state]:
        raise ValueError('fingerprint')
    return state, expected

def remove(path):
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.exists():
        shutil.rmtree(path)

def inventory_root(root, prefix, excluded_top=None):
    observed = {}
    if not root.exists():
        return observed
    if root.is_symlink() or not root.is_dir():
        raise ValueError('root')
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        if base == root and excluded_top in names:
            names.remove(excluded_top)
        if any((base / name).is_symlink() for name in names):
            raise ValueError('symlink')
        for name in files:
            path = base / name
            if path.is_symlink() or not path.is_file():
                raise ValueError('regular')
            logical = prefix + '/' + path.relative_to(root).as_posix()
            content = path.read_bytes()
            observed[logical] = (
                len(content), hashlib.sha256(content).hexdigest()
            )
    return observed

def inventory_targets():
    return {
        **inventory_root(INTEGRATION, 'integration', '.phase_a_tools'),
        **inventory_root(HELPER, 'helper'),
    }

def inventory_deployment(root):
    return {
        **inventory_root(root, 'integration', '.phase_a_tools'),
        **inventory_root(root / '.phase_a_tools', 'helper'),
    }

def inventory_stage():
    return {
        **inventory_root(STAGE / 'integration', 'integration'),
        **inventory_root(STAGE / 'helper', 'helper'),
    }

def inventory_result(expected, observed):
    return {
        'expected_count': len(expected),
        'observed_count': len(observed),
        'manifest_match': expected == observed,
        'unexpected_count': len(set(observed) - set(expected)),
        'missing_count': len(set(expected) - set(observed)),
    }

def backup():
    before = inventory_targets()
    if not before:
        raise ValueError('empty_source')
    pending = BACKUP.with_name(BACKUP.name + '.pending')
    remove(pending)
    pending.mkdir(mode=0o700)
    shutil.copytree(INTEGRATION, pending / 'integration', symlinks=True)
    after = inventory_deployment(pending / 'integration')
    if before != after:
        remove(pending)
        raise ValueError('backup_manifest')
    if BACKUP.exists():
        exchange(pending, BACKUP)
        remove(pending)
    else:
        os.replace(pending, BACKUP)
    BACKUP_CONSUMED.unlink(missing_ok=True)
    return {
        'success': before == after,
        'file_count': len(after),
        'manifest_match': before == after,
        'regular_files_only': True,
    }

def transfer(value):
    state, expected = expected_manifest(value)
    files = value['files']
    if not isinstance(files, list) or len(files) != len(expected):
        raise ValueError('files')
    pending = STAGE.with_name(STAGE.name + '.pending')
    remove(pending)
    pending.mkdir(mode=0o700)
    seen = set()
    for item in files:
        logical = str(safe_path(item['path'], state))
        if logical in seen:
            raise ValueError('duplicate')
        seen.add(logical)
        content = base64.b64decode(item['content'], validate=True)
        destination = pending.joinpath(*PurePosixPath(logical).parts)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
    observed = {
        **inventory_root(pending / 'integration', 'integration'),
        **inventory_root(pending / 'helper', 'helper'),
    }
    if observed != expected:
        remove(pending)
        raise ValueError('manifest')
    remove(STAGE)
    os.replace(pending, STAGE)
    return {
        'success': True,
        'file_count': len(observed),
        'manifest_match': True,
        'regular_files_only': True,
    }

def exchange(left, right):
    function = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    if function is None:
        raise OSError(errno.ENOSYS, 'atomic_exchange')
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(-100, os.fsencode(left), -100, os.fsencode(right), 2) != 0:
        code = ctypes.get_errno()
        raise OSError(code, 'atomic_exchange')

def mark_backup_consumed():
    descriptor = os.open(
        BACKUP_CONSUMED,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    os.close(descriptor)

def activate(value, restoring=False):
    state, expected = expected_manifest(value)
    if restoring != (state == 'restore') or inventory_stage() != expected:
        raise ValueError('stage')
    staged = STAGE / 'integration'
    if not restoring:
        os.replace(STAGE / 'helper', staged / '.phase_a_tools')
    if inventory_deployment(staged) != expected:
        raise ValueError('assembled')
    backup_marked = False
    if restoring:
        mark_backup_consumed()
        backup_marked = True
    exchanged = INTEGRATION.exists()
    mutated = False
    try:
        if exchanged:
            exchange(staged, INTEGRATION)
        else:
            os.replace(staged, INTEGRATION)
        mutated = True
        installed = inventory_targets()
        if installed != expected:
            raise ValueError('installed')
    except Exception:
        if mutated and exchanged:
            exchange(staged, INTEGRATION)
        elif mutated:
            os.replace(INTEGRATION, staged)
        if backup_marked:
            BACKUP_CONSUMED.unlink(missing_ok=True)
        raise
    remove(STAGE)
    if restoring:
        try:
            remove(BACKUP)
        except OSError:
            pass
    return {
        'installation_success': True,
        'expected_file_count': len(expected),
        'installed_file_count': len(installed),
        'manifest_match': True,
    }

def headers():
    token = os.environ.get('SUPERVISOR_TOKEN')
    if not token:
        raise ValueError('context')
    return {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
    }

def request_json(url, method='GET', timeout=30):
    request = urllib.request.Request(
        url,
        data=b'' if method == 'POST' else None,
        headers=headers(),
        method=method,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.getcode(), json.load(response)

def core_check():
    try:
        status, body = request_json('http://supervisor/core/check', 'POST')
        result = body.get('result') if isinstance(body, dict) else None
        authoritative = body.get('check_passed') if isinstance(body, dict) else None
        authoritative_field = (
            {'check_passed': authoritative}
            if isinstance(body, dict) and 'check_passed' in body
            else {}
        )
        return {
            'http_status': status,
            'result': result,
            **authoritative_field,
        }
    except Exception:
        return {
            'http_status': 0,
            'result': 'error',
            'error_class': 'REQUEST_FAILED',
        }

def restart_core():
    try:
        status, _ = request_json('http://supervisor/core/restart', 'POST')
        return {'submitted': True, 'accepted': 200 <= status < 300}
    except Exception:
        return {'submitted': False, 'accepted': False}

def service_names():
    status, body = request_json('http://supervisor/core/api/services')
    if not 200 <= status < 300 or not isinstance(body, list):
        raise ValueError('services')
    for domain in body:
        if isinstance(domain, dict) and domain.get('domain') == 'tuya_ble':
            services = domain.get('services')
            if isinstance(services, dict):
                return set(services)
    return set()

def service_inventory(expectation):
    observed = SERVICES & service_names()
    present = expectation == 'expected_present'
    return {
        'expected_present_count': len(SERVICES) if present else 0,
        'observed_present_count': len(observed) if present else 0,
        'all_expected_present': not present or observed == SERVICES,
        'expected_absent_count': 0 if present else len(SERVICES),
        'observed_absent_count': 0 if present else len(SERVICES - observed),
        'all_expected_absent': present or not observed,
    }

def readiness():
    deadline = time.monotonic() + 120
    reachable = running = loaded = False
    while time.monotonic() < deadline:
        try:
            remaining = deadline - time.monotonic()
            status, body = request_json(
                'http://supervisor/core/api/', timeout=min(5, remaining)
            )
            reachable = 200 <= status < 300
            running = (
                reachable
                and isinstance(body, dict)
                and body.get('message') == 'API running.'
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            config_status, config = request_json(
                'http://supervisor/core/api/config',
                timeout=min(5, remaining),
            )
            components = config.get('components') if isinstance(config, dict) else None
            loaded = (
                200 <= config_status < 300
                and isinstance(components, list)
                and 'tuya_ble' in components
            )
            if reachable and running and loaded:
                return {
                    'core_reachable': True,
                    'core_running': True,
                    'integration_loaded': True,
                    'timed_out': False,
                }
        except Exception:
            pass
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    return {
        'core_reachable': reachable,
        'core_running': running,
        'integration_loaded': loaded,
        'timed_out': True,
    }

def invoke_helper(value):
    operation = value['helper_operation']
    if operation not in {'preflight', 'audit', 'receipt'}:
        raise ValueError('helper_operation')
    runner = __import__('sub' + 'process')
    command = [
        sys.executable,
        '-S',
        str(HELPER / 'phase_a_status_probe_helper.py'),
        operation,
    ]
    invalid = value.get('invalid_nonce') is True
    if invalid:
        command += ['--nonce', 'invalid-nonce']
    elif value.get('nonce') is not None:
        command += ['--nonce', value['nonce']]
    label = value.get('evidence_label')
    if label is not None:
        command += ['--evidence-label', label]
    completed = runner.run(
        command, capture_output=True, check=False, timeout=190
    )
    if completed.stderr or completed.returncode not in {0, 65, 66, 67, 78}:
        raise ValueError('helper_exit')
    output = json.loads(completed.stdout)
    if not isinstance(output, dict) or not isinstance(output.get('outcome'), str):
        raise ValueError('helper_output')
    result = {
        'exit_code': completed.returncode,
        'outcome': output['outcome'],
    }
    if 'nonce' in output:
        result['nonce'] = output['nonce']
    if invalid:
        if completed.returncode != 65 or output != {'outcome': 'not_submitted'}:
            raise ValueError('invalid_nonce')
        result['http_handoff'] = False
    if operation == 'audit' and completed.returncode == 0:
        evidence = EVIDENCE / ('audit-' + label + '.json')
        audit = json.loads(evidence.read_bytes())
        if not isinstance(audit, dict) or set(audit.get('counters', {})) != COUNTERS:
            raise ValueError('audit')
        result['audit'] = audit
    return result

def restore_backup():
    mark_backup_consumed()
    source = BACKUP / 'integration'
    integration_existed = INTEGRATION.exists()
    mutated = False
    try:
        expected = inventory_deployment(source)
        if not expected:
            raise ValueError('backup')
        if integration_existed:
            exchange(source, INTEGRATION)
        else:
            os.replace(source, INTEGRATION)
        mutated = True
        installed = inventory_targets()
        if installed != expected:
            raise ValueError('backup_restore')
    except Exception:
        if mutated and integration_existed:
            exchange(source, INTEGRATION)
        elif mutated:
            os.replace(INTEGRATION, source)
        BACKUP_CONSUMED.unlink(missing_ok=True)
        raise
    try:
        remove(BACKUP)
    except OSError:
        pass
    return {
        'installation_success': True,
        'expected_file_count': len(expected),
        'installed_file_count': len(installed),
        'manifest_match': True,
    }

value = receive()
operation = sys.argv[1]
try:
    if operation == 'backup':
        result = backup()
    elif operation == 'transfer':
        result = transfer(value)
    elif operation == 'install':
        result = activate(value)
    elif operation == 'source_inventory':
        _, expected = expected_manifest(value)
        result = inventory_result(expected, inventory_targets())
    elif operation == 'core_check':
        result = core_check()
    elif operation == 'restart_core':
        result = restart_core()
    elif operation == 'core_readiness':
        result = readiness()
    elif operation == 'service_inventory':
        result = service_inventory(value['expectation'])
    elif operation == 'phase_a_helper':
        result = invoke_helper(value)
    elif operation == 'restore':
        result = activate(value, restoring=True)
    elif operation == 'restore_backup':
        result = restore_backup()
    else:
        raise ValueError('operation')
except Exception:
    result = {'error_class': 'OPERATION_FAILED'}
print(json.dumps(result, separators=(',', ':'), sort_keys=True), flush=True)
"""


def _spawn_private_wrapper(wrapper_path: Path) -> tuple[int, int]:
    """Fork a controlling PTY and execute exactly the pre-validated wrapper path."""
    child_pid, master_fd = pty.fork()
    if child_pid == 0:
        try:
            os.execv(str(wrapper_path), [str(wrapper_path)])
        except OSError:
            os._exit(127)
    return child_pid, master_fd


class PrivateInteractiveSessionBroker:
    """A private controlling-PTY broker for fixed structured operations only.

    It accepts a validated wrapper path, not an argv or external readiness data.
    Fresh broker-owned control frames prove each shell transition and bound the
    permitted typed results. Raw child terminal output never escapes.
    """

    def __init__(
        self,
        wrapper_path: Path,
        *,
        timeout_seconds: float = 15.0,
        max_capture_bytes: int = _MAX_PTY_CAPTURE_BYTES,
    ) -> None:
        if (
            not isinstance(wrapper_path, Path)
            or timeout_seconds <= 0
            or max_capture_bytes <= 0
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_CONFIGURATION_INVALID"
            ) from None
        self._require_valid_wrapper(wrapper_path)
        self._wrapper_path = wrapper_path
        self._timeout_seconds = timeout_seconds
        self._max_capture_bytes = max_capture_bytes
        self._master_fd: int | None = None
        self._child_pid: int | None = None
        self._residual = bytearray()
        self._state = BrokerState.CLOSED
        self._echo_disabled = False
        self._session_generation: object | None = None
        self._active_source_state: SourceState | None = None
        self._restarted_states: set[SourceState] = set()
        self._backup_restore_attempted = False

    def __repr__(self) -> str:
        """Never render the wrapper path, target, argv, or captured output."""
        return f"PrivateInteractiveSessionBroker(state={self._state.value!r})"

    @property
    def state(self) -> BrokerState:
        """Expose only the generic lifecycle state."""
        return self._state

    @staticmethod
    def _new_frame(phase: str) -> tuple[str, bytes]:
        payload = f"HA_BROKER_{phase}:{secrets.token_hex(16)}"
        return payload, _FRAME_START + payload.encode("ascii") + _FRAME_END

    @staticmethod
    def _require_valid_wrapper(wrapper_path: Path) -> None:
        validation_failed = False
        try:
            validation = validate_private_wrapper(wrapper_path)
        except (OSError, RuntimeError, ValueError):
            validation_failed = True
            validation = None
        if (
            validation_failed
            or validation is None
            or validation.status != PRIVATE_WRAPPER_VALID
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_WRAPPER_INVALID"
            ) from None

    @staticmethod
    def _frame_printf(payload: str) -> str:
        """Use textual escapes so terminal echo cannot produce a control frame."""
        return f"printf '\\036%s\\037' '{payload}'"

    def _fail(self, failure: BrokerFailure) -> None:
        self.close()
        raise SessionBrokerError(
            f"PRIVATE_INTERACTIVE_SESSION_{failure.value}"
        ) from None

    def _is_reaped(self) -> bool:
        if self._child_pid is None:
            return True
        try:
            waited_pid, _ = os.waitpid(self._child_pid, os.WNOHANG)
        except ChildProcessError:
            waited_pid = self._child_pid
        if waited_pid == self._child_pid:
            self._child_pid = None
            return True
        return False

    def _write_private(self, value: str) -> None:
        if self._master_fd is None:
            self._fail(BrokerFailure.PROTOCOL)
        encoded = value.encode("ascii")
        offset = 0
        try:
            while offset < len(encoded):
                written = os.write(self._master_fd, encoded[offset:])
                if written <= 0:
                    raise OSError
                offset += written
        except OSError:
            self._fail(BrokerFailure.CHILD_EXITED)

    def _read_until(
        self, frame: bytes, *, timeout_seconds: float | None = None
    ) -> bytes:
        """Consume through one exact private frame and preserve trailing residual bytes."""
        if self._master_fd is None or self._child_pid is None:
            self._fail(BrokerFailure.PROTOCOL)
        captured = self._residual
        self._residual = bytearray()
        deadline = time.monotonic() + (
            self._timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        while True:
            if len(captured) > self._max_capture_bytes:
                self._fail(BrokerFailure.OUTPUT_LIMIT)
            frame_index = captured.find(frame)
            if frame_index >= 0:
                self._residual.extend(captured[frame_index + len(frame) :])
                return bytes(captured[:frame_index])
            if self._is_reaped():
                self._fail(BrokerFailure.CHILD_EXITED)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail(BrokerFailure.TIMEOUT)
            select_failed = False
            try:
                readable, _, _ = select.select([self._master_fd], [], [], remaining)
            except (OSError, ValueError):
                select_failed = True
                readable = []
            if select_failed:
                self._fail(BrokerFailure.CHILD_EXITED)
            if not readable:
                self._fail(BrokerFailure.TIMEOUT)
            read_failed = False
            try:
                chunk = os.read(self._master_fd, 4096)
            except OSError:
                read_failed = True
                chunk = b""
            if read_failed:
                self._fail(BrokerFailure.CHILD_EXITED)
            if not chunk:
                self._fail(BrokerFailure.CHILD_EXITED)
            captured.extend(chunk)

    def _challenge(self, phase: str) -> None:
        payload, frame = self._new_frame(phase)
        self._write_private(self._frame_printf(payload) + "\n")
        self._read_until(frame)

    def _verify_interactive_login_bash(self) -> None:
        """Prove post-``exec`` Bash, interactive mode, and login-shell mode together."""
        payload, frame = self._new_frame("LOGIN")
        command = (
            'if [ -n "${BASH_VERSION-}" ] && '
            "case $- in *i*) true ;; *) false ;; esac && "
            f"shopt -q login_shell; then {self._frame_printf(payload)}; fi\n"
        )
        self._write_private(command)
        self._read_until(frame)

    def _drain_and_discard(self, duration_seconds: float) -> None:
        if self._master_fd is None:
            return
        deadline = time.monotonic() + duration_seconds
        while time.monotonic() < deadline:
            try:
                readable, _, _ = select.select([self._master_fd], [], [], 0.01)
                if readable:
                    os.read(self._master_fd, 4096)
            except (OSError, ValueError):
                return

    def _signal_process_group(self, signal_number: int) -> None:
        if self._child_pid is None:
            return
        try:
            os.killpg(self._child_pid, signal_number)
        except OSError:
            try:
                os.kill(self._child_pid, signal_number)
            except OSError:
                return

    def open(self) -> BrokerState:
        """Spawn the validated wrapper, challenge both shells, and publish readiness."""
        if self._state is not BrokerState.CLOSED or self._child_pid is not None:
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_ALREADY_OPEN"
            ) from None
        self._require_valid_wrapper(self._wrapper_path)
        spawn_failed = False
        try:
            self._child_pid, self._master_fd = _spawn_private_wrapper(
                self._wrapper_path
            )
        except OSError:
            spawn_failed = True
        if spawn_failed:
            self.close()
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_START_FAILED"
            ) from None
        self._state = BrokerState.SSH_CHILD_STARTED
        self._challenge("REMOTE")
        self._state = BrokerState.REMOTE_INTERACTIVE_READY
        self._write_private("exec bash -li\n")
        self._verify_interactive_login_bash()
        self._state = BrokerState.LOGIN_SHELL_READY
        self._session_generation = object()
        self._state = BrokerState.SESSION_ACTIVE
        print(HA_INTERACTIVE_SESSION_READY)
        return self._state

    def _collect_resolution_info(
        self,
        gate: RepairsGate,
        is_relevant: Callable[[object], bool],
        is_critical: Callable[[object], bool],
    ) -> RepairsEvidence:
        """Collect only fixed ``ha resolution info --raw-json`` aggregate evidence."""
        if self._state is not BrokerState.SESSION_ACTIVE:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_NOT_ACTIVE") from None
        start_payload, start_frame = self._new_frame("RESULT_START")
        end_payload, end_frame = self._new_frame("RESULT_END")
        command = (
            f"{self._frame_printf(start_payload)}; ha resolution info --raw-json; "
            f"{self._frame_printf(end_payload)}\n"
        )
        self._write_private(command)
        self._read_until(start_frame)
        private_output = self._read_until(end_frame)
        response = _extract_exact_framed_json_object(private_output)
        result = collect_repairs_gate(
            gate,
            response if response is not None else "",
            is_relevant,
            is_critical,
        )
        return repairs_evidence(result)

    def _ensure_echo_disabled(self) -> None:
        if self._echo_disabled:
            return
        payload, frame = self._new_frame("ECHO_OFF")
        self._write_private(f"stty -echo && {self._frame_printf(payload)}\n")
        self._read_until(frame)
        self._echo_disabled = True

    def _execute_bounded_operation(
        self,
        operation: BoundedOperation,
        value: dict[str, object],
        *,
        detail: str = "fixed",
    ) -> bytes:
        """Run one enum operation with bounded chunks and exact private frames."""
        if not isinstance(operation, BoundedOperation):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_OPERATION_INVALID"
            ) from None
        if self._state is not BrokerState.SESSION_ACTIVE:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_NOT_ACTIVE") from None
        if not isinstance(value, dict) or not re.fullmatch(r"[a-z0-9_]+", detail):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_OPERATION_INVALID"
            ) from None
        encoded_payload = base64.b64encode(
            json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii")
        chunks = tuple(
            encoded_payload[index : index + _TRANSFER_CHUNK_SIZE]
            for index in range(0, len(encoded_payload), _TRANSFER_CHUNK_SIZE)
        )
        if not chunks or len(chunks) > 4096:
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_OPERATION_INVALID"
            ) from None
        self._ensure_echo_disabled()
        start_payload, start_frame = self._new_frame("OPERATION_START")
        end_payload, end_frame = self._new_frame("OPERATION_END")
        encoded_program = base64.b64encode(
            _REMOTE_CONTROL_PROGRAM.encode("utf-8")
        ).decode("ascii")
        program_chunks = tuple(
            encoded_program[index : index + _TRANSFER_CHUNK_SIZE]
            for index in range(0, len(encoded_program), _TRANSFER_CHUNK_SIZE)
        )
        if not program_chunks or len(program_chunks) > 256:
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_OPERATION_INVALID"
            ) from None
        bootstrap = (
            "import base64,sys;"
            "count=int(sys.stdin.readline());"
            "source=''.join(sys.stdin.readline().strip() for _ in range(count));"
            "exec(base64.b64decode(source))"
        )
        command = (
            f"{self._frame_printf(start_payload)}; "
            f"HA_R30_OPERATION={operation.value} HA_R30_DETAIL={detail} "
            f"python3 -c {shlex.quote(bootstrap)} {operation.value}; "
            f"{self._frame_printf(end_payload)}\n"
        )
        self._write_private(command)
        self._read_until(start_frame)
        self._write_private(str(len(program_chunks)) + "\n")
        for chunk in program_chunks:
            self._write_private(chunk + "\n")
        self._write_private(str(len(chunks)) + "\n")
        for chunk in chunks:
            self._write_private(chunk + "\n")
        deadlines = {
            BoundedOperation.TRANSFER: 90.0,
            BoundedOperation.INSTALL: 90.0,
            BoundedOperation.RESTORE: 90.0,
            BoundedOperation.CORE_CHECK: 40.0,
            BoundedOperation.CORE_READINESS: 130.0,
            BoundedOperation.PHASE_A_HELPER: 200.0,
        }
        return self._read_until(
            end_frame,
            timeout_seconds=max(self._timeout_seconds, deadlines.get(operation, 40.0)),
        )

    @staticmethod
    def _simple_result(
        private_output: bytes,
        result_type: type[Any],
        keys: tuple[str, ...],
    ) -> Any:
        value = _exact_payload(private_output)
        if set(value) != set(keys):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        boolean_keys = {
            "success",
            "manifest_match",
            "regular_files_only",
            "installation_success",
            "submitted",
            "accepted",
            "core_reachable",
            "core_running",
            "integration_loaded",
            "timed_out",
        }
        try:
            values = tuple(
                _bool(value[key]) if key in boolean_keys else _count(value[key])
                for key in keys
            )
            return result_type(*values)
        except (KeyError, TypeError, ValueError):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None

    def _create_private_backup(self) -> BackupResult:
        output = self._execute_bounded_operation(BoundedOperation.BACKUP, {})
        return self._simple_result(
            output,
            BackupResult,
            ("success", "file_count", "manifest_match", "regular_files_only"),
        )

    def _transfer_source_bundle(self, bundle: SourceBundle) -> TransferResult:
        validate_source_bundle(bundle)
        output = self._execute_bounded_operation(
            BoundedOperation.TRANSFER,
            _bundle_payload(bundle),
            detail=bundle.state.value,
        )
        return self._simple_result(
            output,
            TransferResult,
            ("success", "file_count", "manifest_match", "regular_files_only"),
        )

    def _install_staged_source(self, manifest: SourceManifest) -> InstallResult:
        if (
            not isinstance(manifest, SourceManifest)
            or manifest.state is not SourceState.CANDIDATE
        ):
            raise SourceBundleError("CANDIDATE_MANIFEST_REQUIRED") from None
        output = self._execute_bounded_operation(
            BoundedOperation.INSTALL,
            {"manifest": _manifest_payload(manifest)},
            detail=manifest.state.value,
        )
        result = self._simple_result(
            output,
            InstallResult,
            (
                "installation_success",
                "expected_file_count",
                "installed_file_count",
                "manifest_match",
            ),
        )
        if result.installation_success and result.manifest_match:
            self._active_source_state = SourceState.CANDIDATE
        return result

    def _verify_source_inventory(
        self, manifest: SourceManifest
    ) -> SourceInventoryResult:
        if not isinstance(manifest, SourceManifest):
            raise SourceBundleError("SOURCE_MANIFEST_INVALID") from None
        output = self._execute_bounded_operation(
            BoundedOperation.SOURCE_INVENTORY,
            {"manifest": _manifest_payload(manifest)},
            detail=manifest.state.value,
        )
        return _parse_source_inventory_result(_exact_payload(output))

    def _check_core(self, attempt_ordinal: int) -> CoreCheckResult:
        if attempt_ordinal not in {1, 2}:
            raise SessionBrokerError("CORE_CHECK_ATTEMPT_INVALID") from None
        output = self._execute_bounded_operation(BoundedOperation.CORE_CHECK, {})
        return _parse_core_check_result(
            _exact_core_check_payload(output), attempt_ordinal=attempt_ordinal
        )

    def _restart_core(self) -> RestartResult:
        state = self._active_source_state
        if state is None:
            raise SessionBrokerError("CORE_RESTART_SOURCE_STATE_REQUIRED") from None
        if state in self._restarted_states:
            raise SessionBrokerError("CORE_RESTART_ALREADY_SUBMITTED") from None
        self._restarted_states.add(state)
        output = self._execute_bounded_operation(BoundedOperation.RESTART_CORE, {})
        result = self._simple_result(output, RestartResult, ("submitted", "accepted"))
        return result

    def _wait_for_core_readiness(self) -> CoreReadinessResult:
        if self._active_source_state is None:
            raise SessionBrokerError("CORE_READINESS_SOURCE_STATE_REQUIRED") from None
        output = self._execute_bounded_operation(
            BoundedOperation.CORE_READINESS,
            {"source_state": self._active_source_state.value},
        )
        return self._simple_result(
            output,
            CoreReadinessResult,
            ("core_reachable", "core_running", "integration_loaded", "timed_out"),
        )

    def _inventory_temporary_services(
        self, expectation: ServiceExpectation
    ) -> ServiceInventoryResult:
        if not isinstance(expectation, ServiceExpectation):
            raise SessionBrokerError("SERVICE_EXPECTATION_INVALID") from None
        output = self._execute_bounded_operation(
            BoundedOperation.SERVICE_INVENTORY,
            {"expectation": expectation.value},
            detail=expectation.value,
        )
        return _parse_service_inventory_result(_exact_payload(output))

    def _invoke_phase_a(
        self,
        operation: PhaseAOperation,
        *,
        nonce: str | None = None,
        evidence_label: AuditLabel | None = None,
    ) -> PhaseAResult:
        if not isinstance(operation, PhaseAOperation):
            raise SessionBrokerError("PHASE_A_HELPER_OPERATION_INVALID") from None
        if nonce is not None and (
            not isinstance(nonce, str) or not _NONCE.fullmatch(nonce)
        ):
            raise SessionBrokerError("PHASE_A_HELPER_NONCE_INVALID") from None
        if evidence_label is not None and not isinstance(evidence_label, AuditLabel):
            raise SessionBrokerError("PHASE_A_HELPER_LABEL_INVALID") from None
        if operation is PhaseAOperation.AUDIT and evidence_label is None:
            raise SessionBrokerError("PHASE_A_HELPER_LABEL_REQUIRED") from None
        if operation is not PhaseAOperation.AUDIT and evidence_label is not None:
            raise SessionBrokerError("PHASE_A_HELPER_LABEL_INVALID") from None
        if operation is PhaseAOperation.RECEIPT and nonce is None:
            raise SessionBrokerError("PHASE_A_HELPER_NONCE_REQUIRED") from None
        submitted_nonce = nonce or secrets.token_hex(16)
        value: dict[str, object] = {
            "helper_operation": operation.value,
            "nonce": submitted_nonce,
        }
        if evidence_label is not None:
            value["evidence_label"] = evidence_label.value
        output = self._execute_bounded_operation(
            BoundedOperation.PHASE_A_HELPER,
            value,
            detail=operation.value,
        )
        return _parse_phase_a_result(operation, output, expected_nonce=submitted_nonce)

    def _run_invalid_nonce_preflight(self) -> PhaseAResult:
        output = self._execute_bounded_operation(
            BoundedOperation.PHASE_A_HELPER,
            {
                "helper_operation": PhaseAOperation.PREFLIGHT.value,
                "invalid_nonce": True,
            },
            detail="invalid_nonce",
        )
        result = _parse_phase_a_result(PhaseAOperation.PREFLIGHT, output)
        if (
            result.exit_code != 65
            or result.outcome != "not_submitted"
            or result.http_handoff is not False
        ):
            self._fail(BrokerFailure.PROTOCOL)
        return result

    def _install_staged_restore(self, manifest: SourceManifest) -> InstallResult:
        """Activate one already-staged exact PR #41 source bundle."""
        if (
            not isinstance(manifest, SourceManifest)
            or manifest.state is not SourceState.RESTORE
        ):
            raise SourceBundleError("RESTORE_MANIFEST_REQUIRED") from None
        output = self._execute_bounded_operation(
            BoundedOperation.RESTORE,
            {"manifest": _manifest_payload(manifest)},
            detail=manifest.state.value,
        )
        result = self._simple_result(
            output,
            InstallResult,
            (
                "installation_success",
                "expected_file_count",
                "installed_file_count",
                "manifest_match",
            ),
        )
        if result.installation_success and result.manifest_match:
            self._active_source_state = SourceState.RESTORE
        return result

    def _restore_source(self, bundle: SourceBundle) -> InstallResult:
        if (
            not isinstance(bundle, SourceBundle)
            or bundle.state is not SourceState.RESTORE
        ):
            raise SourceBundleError("RESTORE_MANIFEST_REQUIRED") from None
        validate_source_bundle(bundle)
        transfer = self._transfer_source_bundle(bundle)
        if not transfer.success or not transfer.manifest_match:
            self._fail(BrokerFailure.PROTOCOL)
        return self._install_staged_restore(bundle.manifest)

    def _restore_private_backup(self) -> InstallResult:
        """Use the fixed verified private backup only as a restoration fallback."""
        if (
            self._active_source_state is SourceState.RESTORE
            or self._backup_restore_attempted
        ):
            raise SourceBundleError("PRIVATE_BACKUP_ALREADY_CONSUMED") from None
        self._backup_restore_attempted = True
        output = self._execute_bounded_operation(BoundedOperation.RESTORE_BACKUP, {})
        result = self._simple_result(
            output,
            InstallResult,
            (
                "installation_success",
                "expected_file_count",
                "installed_file_count",
                "manifest_match",
            ),
        )
        if result.installation_success and result.manifest_match:
            self._active_source_state = SourceState.RESTORE
        return result

    def close(self) -> None:
        """Close the child process group privately and suppress every close message."""
        try:
            if self._master_fd is not None and not self._is_reaped():
                try:
                    os.write(self._master_fd, b"exit\n")
                except OSError:
                    pass
                self._drain_and_discard(0.05)
                deadline = time.monotonic() + 0.25
                while time.monotonic() < deadline and not self._is_reaped():
                    time.sleep(0.01)
                if not self._is_reaped():
                    self._signal_process_group(signal.SIGTERM)
                    deadline = time.monotonic() + 0.25
                    while time.monotonic() < deadline and not self._is_reaped():
                        time.sleep(0.01)
                if not self._is_reaped():
                    self._signal_process_group(signal.SIGKILL)
                    self._is_reaped()
        except (ChildProcessError, OSError, ValueError):
            pass
        finally:
            if self._master_fd is not None:
                self._drain_and_discard(0.02)
                try:
                    os.close(self._master_fd)
                except OSError:
                    pass
            self._master_fd = None
            self._child_pid = None
            self._residual.clear()
            self._state = BrokerState.CLOSED
            self._echo_disabled = False
            self._session_generation = None
            self._active_source_state = None
            self._restarted_states.clear()
            self._backup_restore_attempted = False


class FullPreflightLifecycleController:
    """The sole public live-capable, ordered full-preflight control surface."""

    def __init__(
        self,
        broker: Any,
        *,
        is_relevant: Callable[[object], bool],
        is_critical: Callable[[object], bool],
    ) -> None:
        if (
            getattr(broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(broker, "_session_generation", None) is None
            or not callable(is_relevant)
            or not callable(is_critical)
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        self._broker = broker
        self._is_relevant = is_relevant
        self._is_critical = is_critical
        self._state = LifecycleState.BASELINE
        self._session_generation = broker._session_generation
        self._seen_session_generations = [self._session_generation]
        self._lifecycle_generation = object()
        self._permits = {
            action: _InvocationPermit(
                action, self._lifecycle_generation, self._session_generation
            )
            for action in LifecycleAction
        }
        self._candidate_bundle: SourceBundle | None = None
        self._candidate_manifest: SourceManifest | None = None
        self._restore_bundle: SourceBundle | None = None
        self._restore_manifest: SourceManifest | None = None
        self._candidate_activation_generation: object | None = None
        self._snapshots: dict[AuditLabel, AuditSnapshot] = {}
        self._snapshot_generations: dict[AuditLabel, object] = {}
        self._audit_comparisons: dict[
            tuple[AuditLabel, AuditLabel], AuditComparison
        ] = {}
        self._preflight_result: PhaseAResult | None = None
        self._receipt_result: PhaseAResult | None = None
        self._preflight_nonce: str | None = None
        self._ambiguous_nonce: str | None = None
        self._core_transport_ambiguous: dict[SourceState, bool] = {
            SourceState.CANDIDATE: False,
            SourceState.RESTORE: False,
        }
        self._restore_inventory: SourceInventoryResult | None = None
        self._restore_core_check: CoreCheckResult | None = None
        self._removal_restart: RestartResult | None = None
        self._restart_dispatched: set[SourceState] = set()
        self._restore_readiness: CoreReadinessResult | None = None
        self._restore_services: ServiceInventoryResult | None = None
        self._restore_repairs: RepairsEvidence | None = None

    @property
    def state(self) -> LifecycleState:
        return self._state

    def _assert_session_binding(self) -> None:
        if (
            getattr(self._broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(self._broker, "_session_generation", None)
            is not self._session_generation
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_CHANGED") from None

    def _require_state(self, *states: LifecycleState) -> None:
        if self._state not in states:
            raise LifecycleControllerError("LIFECYCLE_TRANSITION_INVALID") from None

    def bind_rollback_session(self, broker: PrivateInteractiveSessionBroker) -> None:
        """Explicitly bind unused rollback-only permits to one fresh session."""
        self._require_state(LifecycleState.ROLLBACK_REQUIRED)
        new_session_generation = getattr(broker, "_session_generation", None)
        current_binding_still_active = (
            getattr(self._broker, "state", None) is BrokerState.SESSION_ACTIVE
            and getattr(self._broker, "_session_generation", None)
            is self._session_generation
        )
        if (
            broker is self._broker
            or current_binding_still_active
            or getattr(broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or new_session_generation is None
            or any(
                new_session_generation is seen
                for seen in self._seen_session_generations
            )
            or not all(
                callable(getattr(broker, name, None))
                for name in _ROLLBACK_BROKER_ADAPTERS
            )
        ):
            raise LifecycleControllerError(
                "LIFECYCLE_ROLLBACK_BINDING_INVALID"
            ) from None

        permits_to_rebind = tuple(
            self._permits[action]
            for action in _ROLLBACK_REBIND_ACTIONS
            if not self._permits[action].consumed
        )
        if any(
            permit.lifecycle_generation is not self._lifecycle_generation
            or permit.session_generation is not self._session_generation
            for permit in permits_to_rebind
        ):
            raise LifecycleControllerError(
                "LIFECYCLE_ROLLBACK_BINDING_INVALID"
            ) from None

        for permit in permits_to_rebind:
            permit.session_generation = new_session_generation
        self._broker = broker
        self._session_generation = new_session_generation
        self._seen_session_generations.append(new_session_generation)

    def _dispatch(self, action: LifecycleAction, callback: Callable[[], Any]) -> Any:
        self._assert_session_binding()
        permit = self._permits[action]
        if permit.consumed:
            raise LifecycleControllerError("LIFECYCLE_PERMIT_CONSUMED") from None
        permit.consume(
            self._lifecycle_generation,
            self._session_generation,
            action,
        )
        return callback()

    def _rollback(self) -> None:
        self._state = LifecycleState.ROLLBACK_REQUIRED
        raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None

    @staticmethod
    def _repairs_pass(evidence: object) -> bool:
        return evidence == RepairsEvidence(True, 0, 0)

    @staticmethod
    def _bundle_result_pass(
        result: object, expected_count: int, result_type: type[Any]
    ) -> bool:
        if not isinstance(result, result_type):
            return False
        if isinstance(result, TransferResult):
            return (
                result.success
                and result.file_count == expected_count
                and result.manifest_match
                and result.regular_files_only
            )
        if isinstance(result, InstallResult):
            return (
                result.installation_success
                and result.expected_file_count == expected_count
                and result.installed_file_count == expected_count
                and result.manifest_match
            )
        return False

    @staticmethod
    def _inventory_pass(result: object, expected_count: int) -> bool:
        return (
            isinstance(result, SourceInventoryResult)
            and result.expected_count == expected_count
            and result.observed_count == expected_count
            and result.manifest_match
            and result.unexpected_count == 0
            and result.missing_count == 0
        )

    @staticmethod
    def _readiness_pass(result: object) -> bool:
        return (
            isinstance(result, CoreReadinessResult)
            and result.core_reachable
            and result.core_running
            and result.integration_loaded
            and not result.timed_out
        )

    @staticmethod
    def _services_present_pass(result: object) -> bool:
        return (
            isinstance(result, ServiceInventoryResult)
            and result.expected_present_count == 4
            and result.observed_present_count == 4
            and result.all_expected_present
            and result.expected_absent_count == 0
            and result.observed_absent_count == 0
            and result.all_expected_absent
        )

    @staticmethod
    def _services_absent_pass(result: object) -> bool:
        return (
            isinstance(result, ServiceInventoryResult)
            and result.expected_present_count == 0
            and result.observed_present_count == 0
            and result.all_expected_present
            and result.expected_absent_count == 4
            and result.observed_absent_count == 4
            and result.all_expected_absent
        )

    @staticmethod
    def _outer_transport_ambiguity(error: SessionBrokerError) -> bool:
        return str(error).endswith(("_TIMEOUT", "_CHILD_EXITED", "_OUTPUT_LIMIT"))

    def admit_initial_repairs(self) -> RepairsEvidence:
        self._require_state(LifecycleState.BASELINE)
        try:
            evidence = self._dispatch(
                LifecycleAction.INITIAL_REPAIRS,
                lambda: self._broker._collect_resolution_info(
                    RepairsGate.INITIAL, self._is_relevant, self._is_critical
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            raise LifecycleControllerError("INITIAL_REPAIRS_ADMISSION_FAILED") from None
        if not self._repairs_pass(evidence):
            raise LifecycleControllerError("INITIAL_REPAIRS_ADMISSION_FAILED") from None
        self._state = LifecycleState.INITIAL_REPAIRS_PASS
        return evidence

    def create_backup(self) -> BackupResult:
        self._require_state(LifecycleState.INITIAL_REPAIRS_PASS)
        try:
            result = self._dispatch(
                LifecycleAction.BACKUP, self._broker._create_private_backup
            )
        except (SessionBrokerError, TypeError, ValueError):
            raise LifecycleControllerError("BACKUP_VERIFICATION_FAILED") from None
        if not (
            isinstance(result, BackupResult)
            and result.success
            and result.file_count > 0
            and result.manifest_match
            and result.regular_files_only
        ):
            raise LifecycleControllerError("BACKUP_VERIFICATION_FAILED") from None
        self._state = LifecycleState.BACKUP_VERIFIED
        return result

    def stage_candidate(self, bundle: SourceBundle) -> TransferResult:
        self._require_state(LifecycleState.BACKUP_VERIFIED)
        if (
            not isinstance(bundle, SourceBundle)
            or bundle.state is not SourceState.CANDIDATE
        ):
            raise LifecycleControllerError("CANDIDATE_BUNDLE_INVALID") from None
        try:
            validate_source_bundle(bundle)
        except SourceBundleError:
            raise LifecycleControllerError("CANDIDATE_BUNDLE_INVALID") from None
        try:
            result = self._dispatch(
                LifecycleAction.CANDIDATE_TRANSFER,
                lambda: self._broker._transfer_source_bundle(bundle),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError("CANDIDATE_TRANSFER_FAILED") from None
        if not self._bundle_result_pass(result, len(bundle.files), TransferResult):
            raise LifecycleControllerError("CANDIDATE_TRANSFER_FAILED") from None
        self._candidate_bundle = bundle
        self._candidate_manifest = bundle.manifest
        self._state = LifecycleState.CANDIDATE_STAGED
        return result

    def install_candidate(self, manifest: SourceManifest) -> InstallResult:
        self._require_state(LifecycleState.CANDIDATE_STAGED)
        if (
            manifest != self._candidate_manifest
            or manifest.state is not SourceState.CANDIDATE
        ):
            raise LifecycleControllerError("CANDIDATE_MANIFEST_INVALID") from None
        try:
            result = self._dispatch(
                LifecycleAction.CANDIDATE_INSTALL,
                lambda: self._broker._install_staged_source(manifest),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._rollback()
        if not self._bundle_result_pass(result, len(manifest.entries), InstallResult):
            self._rollback()
        self._candidate_activation_generation = object()
        self._state = LifecycleState.CANDIDATE_INSTALLED
        return result

    def verify_candidate_inventory(
        self, manifest: SourceManifest
    ) -> SourceInventoryResult:
        self._require_state(LifecycleState.CANDIDATE_INSTALLED)
        if manifest != self._candidate_manifest:
            raise LifecycleControllerError("CANDIDATE_MANIFEST_INVALID") from None
        try:
            result = self._dispatch(
                LifecycleAction.CANDIDATE_INVENTORY,
                lambda: self._broker._verify_source_inventory(manifest),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._rollback()
        if not self._inventory_pass(result, len(manifest.entries)):
            self._rollback()
        self._state = LifecycleState.CANDIDATE_INVENTORY_VERIFIED
        return result

    def _check_core_for(
        self,
        source_state: SourceState,
        first_action: LifecycleAction,
        second_action: LifecycleAction,
    ) -> CoreCheckResult:
        attempt = 2 if self._core_transport_ambiguous[source_state] else 1
        action = first_action if attempt == 1 else second_action
        try:
            result = self._dispatch(action, lambda: self._broker._check_core(attempt))
        except SessionBrokerError as error:
            if attempt == 1 and self._outer_transport_ambiguity(error):
                session_survived = (
                    getattr(self._broker, "state", None) is BrokerState.SESSION_ACTIVE
                    and getattr(self._broker, "_session_generation", None)
                    is self._session_generation
                )
                if session_survived:
                    self._core_transport_ambiguous[source_state] = True
                    raise LifecycleControllerError(
                        "CORE_CHECK_TRANSPORT_AMBIGUOUS"
                    ) from None
                self._rollback()
            self._rollback()
        except (TypeError, ValueError):
            self._rollback()
        if not isinstance(result, CoreCheckResult) or not result.check_passed:
            self._rollback()
        return result

    def check_candidate_core(self) -> CoreCheckResult:
        self._require_state(LifecycleState.CANDIDATE_INVENTORY_VERIFIED)
        result = self._check_core_for(
            SourceState.CANDIDATE,
            LifecycleAction.CANDIDATE_CORE_CHECK_1,
            LifecycleAction.CANDIDATE_CORE_CHECK_2,
        )
        self._state = LifecycleState.CANDIDATE_CORE_CHECKED
        return result

    def _restart(
        self, source_state: SourceState, action: LifecycleAction
    ) -> RestartResult:
        def dispatch_restart() -> RestartResult:
            self._restart_dispatched.add(source_state)
            return self._broker._restart_core()

        try:
            result = self._dispatch(action, dispatch_restart)
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not (
            isinstance(result, RestartResult) and result.submitted and result.accepted
        ):
            self._rollback()
        return result

    def restart_for_candidate(self) -> RestartResult:
        self._require_state(LifecycleState.CANDIDATE_CORE_CHECKED)
        result = self._restart(
            SourceState.CANDIDATE, LifecycleAction.ACTIVATION_RESTART
        )
        self._state = LifecycleState.ACTIVATION_RESTART_CONSUMED
        return result

    def await_candidate_readiness(self) -> CoreReadinessResult:
        self._require_state(LifecycleState.ACTIVATION_RESTART_CONSUMED)
        try:
            result = self._dispatch(
                LifecycleAction.CANDIDATE_READINESS,
                self._broker._wait_for_core_readiness,
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._readiness_pass(result):
            self._rollback()
        self._state = LifecycleState.CANDIDATE_READY
        return result

    def verify_research_services_present(self) -> ServiceInventoryResult:
        self._require_state(LifecycleState.CANDIDATE_READY)
        try:
            result = self._dispatch(
                LifecycleAction.SERVICES_PRESENT,
                lambda: self._broker._inventory_temporary_services(
                    ServiceExpectation.PRESENT
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._services_present_pass(result):
            self._rollback()
        self._state = LifecycleState.RESEARCH_SERVICES_PRESENT
        return result

    def admit_post_activation_repairs(self) -> RepairsEvidence:
        self._require_state(LifecycleState.RESEARCH_SERVICES_PRESENT)
        try:
            evidence = self._dispatch(
                LifecycleAction.POST_ACTIVATION_REPAIRS,
                lambda: self._broker._collect_resolution_info(
                    RepairsGate.POST_ACTIVATION,
                    self._is_relevant,
                    self._is_critical,
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._repairs_pass(evidence):
            self._rollback()
        self._state = LifecycleState.POST_ACTIVATION_REPAIRS_PASS
        return evidence

    def _collect_audit(
        self,
        audit_label: AuditLabel,
        action: LifecycleAction,
    ) -> AuditSnapshot:
        nonce = secrets.token_hex(16)
        try:
            result = self._dispatch(
                action,
                lambda: self._broker._invoke_phase_a(
                    PhaseAOperation.AUDIT,
                    nonce=nonce,
                    evidence_label=audit_label,
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if (
            not isinstance(result, PhaseAResult)
            or result.operation is not PhaseAOperation.AUDIT
            or result.exit_code != 0
            or result.outcome != "audit_snapshot"
            or result.nonce != nonce
            or result.audit is None
            or result.audit.nonce != nonce
            or result.audit.history_overflow
        ):
            self._rollback()
        snapshot = result.audit
        self._snapshots[audit_label] = snapshot
        if self._candidate_activation_generation is not None:
            self._snapshot_generations[audit_label] = (
                self._candidate_activation_generation
            )
        return snapshot

    def collect_a0(self) -> AuditSnapshot:
        self._require_state(LifecycleState.POST_ACTIVATION_REPAIRS_PASS)
        snapshot = self._collect_audit(AuditLabel.A0, LifecycleAction.A0)
        self._state = LifecycleState.A0_COLLECTED
        return snapshot

    def run_p0(self) -> PhaseAResult:
        self._require_state(LifecycleState.A0_COLLECTED)
        try:
            result = self._dispatch(
                LifecycleAction.P0,
                self._broker._run_invalid_nonce_preflight,
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if (
            not isinstance(result, PhaseAResult)
            or result.operation is not PhaseAOperation.PREFLIGHT
            or result.exit_code != 65
            or result.outcome != "not_submitted"
            or result.http_handoff is not False
        ):
            self._rollback()
        self._state = LifecycleState.P0_COMPLETED
        return result

    def collect_ap0(self) -> AuditSnapshot:
        self._require_state(LifecycleState.P0_COMPLETED)
        snapshot = self._collect_audit(AuditLabel.AP0, LifecycleAction.AP0)
        comparison = compare_audit_snapshots(self._snapshots[AuditLabel.A0], snapshot)
        if not comparison.zero_io_unchanged:
            self._rollback()
        self._audit_comparisons[(AuditLabel.A0, AuditLabel.AP0)] = comparison
        self._state = LifecycleState.AP0_COLLECTED
        return snapshot

    def run_non_probe_preflight(self) -> PhaseAResult:
        self._require_state(LifecycleState.AP0_COLLECTED)
        nonce = secrets.token_hex(16)
        self._preflight_nonce = nonce
        try:
            result = self._dispatch(
                LifecycleAction.PREFLIGHT,
                lambda: self._broker._invoke_phase_a(
                    PhaseAOperation.PREFLIGHT, nonce=nonce
                ),
            )
        except SessionBrokerError:
            self._ambiguous_nonce = nonce
            self._rollback()
        except (TypeError, ValueError):
            self._rollback()
        if (
            not isinstance(result, PhaseAResult)
            or result.operation is not PhaseAOperation.PREFLIGHT
            or result.nonce != nonce
            or result.exit_code != 0
            or result.outcome != "preflight_ok"
        ):
            if isinstance(result, PhaseAResult) and result.exit_code == 78:
                self._ambiguous_nonce = nonce
            self._rollback()
        self._preflight_result = result
        self._state = LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED
        return result

    @staticmethod
    def _receipt_pass(result: object, expected_nonce: str) -> bool:
        return (
            isinstance(result, PhaseAResult)
            and result.operation is PhaseAOperation.RECEIPT
            and result.nonce == expected_nonce
            and result.exit_code in {0, 66}
            and result.outcome == "receipt"
        )

    def lookup_non_probe_receipt(self) -> PhaseAResult:
        self._require_state(LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED)
        if self._preflight_nonce is None:
            raise LifecycleControllerError("LIFECYCLE_TRANSITION_INVALID") from None
        nonce = self._preflight_nonce
        try:
            result = self._dispatch(
                LifecycleAction.RECEIPT,
                lambda: self._broker._invoke_phase_a(
                    PhaseAOperation.RECEIPT, nonce=nonce
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._receipt_pass(result, nonce):
            self._rollback()
        self._receipt_result = result
        self._state = LifecycleState.NON_PROBE_RECEIPT_COMPLETED
        return result

    def lookup_ambiguous_receipt(self) -> PhaseAResult:
        self._require_state(LifecycleState.ROLLBACK_REQUIRED)
        if self._ambiguous_nonce is None:
            raise LifecycleControllerError("LIFECYCLE_TRANSITION_INVALID") from None
        nonce = self._ambiguous_nonce
        try:
            result = self._dispatch(
                LifecycleAction.AMBIGUOUS_RECEIPT,
                lambda: self._broker._invoke_phase_a(
                    PhaseAOperation.RECEIPT, nonce=nonce
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        if not self._receipt_pass(result, nonce):
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        return result

    def collect_a1(self) -> AuditSnapshot:
        self._require_state(LifecycleState.NON_PROBE_RECEIPT_COMPLETED)
        snapshot = self._collect_audit(AuditLabel.A1, LifecycleAction.A1)
        comparison = compare_audit_snapshots(self._snapshots[AuditLabel.AP0], snapshot)
        if not comparison.zero_io_unchanged:
            self._rollback()
        self._audit_comparisons[(AuditLabel.AP0, AuditLabel.A1)] = comparison
        self._state = LifecycleState.A1_COLLECTED
        return snapshot

    def validate_research_final(self) -> None:
        self._require_state(LifecycleState.A1_COLLECTED)

        def validate() -> None:
            generation = self._candidate_activation_generation
            required_labels = {AuditLabel.A0, AuditLabel.AP0, AuditLabel.A1}
            if (
                generation is None
                or set(self._snapshots) != required_labels
                or any(
                    self._snapshot_generations.get(label) is not generation
                    for label in required_labels
                )
                or self._preflight_result is None
                or self._receipt_result is None
                or not self._audit_comparisons[
                    (AuditLabel.A0, AuditLabel.AP0)
                ].zero_io_unchanged
                or not self._audit_comparisons[
                    (AuditLabel.AP0, AuditLabel.A1)
                ].zero_io_unchanged
            ):
                self._rollback()

        self._dispatch(LifecycleAction.RESEARCH_FINAL, validate)
        self._state = LifecycleState.RESEARCH_FINAL_VALIDATED

    def collect_a2(self) -> AuditSnapshot:
        self._require_state(LifecycleState.RESEARCH_FINAL_VALIDATED)
        snapshot = self._collect_audit(AuditLabel.A2, LifecycleAction.A2)
        adjacent = compare_audit_snapshots(self._snapshots[AuditLabel.A1], snapshot)
        cumulative = compare_audit_snapshots(self._snapshots[AuditLabel.A0], snapshot)
        if not adjacent.zero_io_unchanged or not cumulative.zero_io_unchanged:
            self._rollback()
        self._audit_comparisons[(AuditLabel.A1, AuditLabel.A2)] = adjacent
        self._audit_comparisons[(AuditLabel.A0, AuditLabel.A2)] = cumulative
        self._state = LifecycleState.A2_COLLECTED
        return snapshot

    def stage_restore(self, bundle: SourceBundle) -> TransferResult:
        self._require_state(
            LifecycleState.A2_COLLECTED, LifecycleState.ROLLBACK_REQUIRED
        )
        if (
            not isinstance(bundle, SourceBundle)
            or bundle.state is not SourceState.RESTORE
        ):
            raise LifecycleControllerError("RESTORE_BUNDLE_INVALID") from None
        try:
            validate_source_bundle(bundle)
        except SourceBundleError:
            raise LifecycleControllerError("RESTORE_BUNDLE_INVALID") from None
        try:
            result = self._dispatch(
                LifecycleAction.RESTORE_TRANSFER,
                lambda: self._broker._transfer_source_bundle(bundle),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._state = LifecycleState.ROLLBACK_REQUIRED
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        if not self._bundle_result_pass(result, len(bundle.files), TransferResult):
            self._state = LifecycleState.ROLLBACK_REQUIRED
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        self._restore_bundle = bundle
        self._restore_manifest = bundle.manifest
        self._state = LifecycleState.RESTORE_STAGED
        return result

    def restore_pr41(self, manifest: SourceManifest) -> InstallResult:
        self._require_state(LifecycleState.RESTORE_STAGED)
        if (
            manifest != self._restore_manifest
            or manifest.state is not SourceState.RESTORE
        ):
            raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
        try:
            result = self._dispatch(
                LifecycleAction.RESTORE_INSTALL,
                lambda: self._broker._install_staged_restore(manifest),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._rollback()
        if not self._bundle_result_pass(result, len(manifest.entries), InstallResult):
            self._rollback()
        self._state = LifecycleState.PR41_RESTORED
        return result

    def verify_restore_inventory(
        self, manifest: SourceManifest
    ) -> SourceInventoryResult:
        self._require_state(LifecycleState.PR41_RESTORED)
        if manifest != self._restore_manifest:
            raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
        try:
            result = self._dispatch(
                LifecycleAction.RESTORE_INVENTORY,
                lambda: self._broker._verify_source_inventory(manifest),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._rollback()
        if not self._inventory_pass(result, len(manifest.entries)):
            self._rollback()
        self._restore_inventory = result
        self._state = LifecycleState.RESTORE_INVENTORY_VERIFIED
        return result

    def check_restore_core(self) -> CoreCheckResult:
        self._require_state(LifecycleState.RESTORE_INVENTORY_VERIFIED)
        result = self._check_core_for(
            SourceState.RESTORE,
            LifecycleAction.RESTORE_CORE_CHECK_1,
            LifecycleAction.RESTORE_CORE_CHECK_2,
        )
        self._restore_core_check = result
        self._state = LifecycleState.RESTORE_CORE_CHECKED
        return result

    def restart_for_restore(self) -> RestartResult:
        self._require_state(LifecycleState.RESTORE_CORE_CHECKED)
        result = self._restart(SourceState.RESTORE, LifecycleAction.REMOVAL_RESTART)
        self._removal_restart = result
        self._state = LifecycleState.REMOVAL_RESTART_CONSUMED
        return result

    def await_restore_readiness(self) -> CoreReadinessResult:
        self._require_state(LifecycleState.REMOVAL_RESTART_CONSUMED)
        try:
            result = self._dispatch(
                LifecycleAction.RESTORE_READINESS,
                self._broker._wait_for_core_readiness,
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._readiness_pass(result):
            self._rollback()
        self._restore_readiness = result
        self._state = LifecycleState.PR41_READY
        return result

    def verify_research_services_absent(self) -> ServiceInventoryResult:
        self._require_state(LifecycleState.PR41_READY)
        try:
            result = self._dispatch(
                LifecycleAction.SERVICES_ABSENT,
                lambda: self._broker._inventory_temporary_services(
                    ServiceExpectation.ABSENT
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._services_absent_pass(result):
            self._rollback()
        self._restore_services = result
        self._state = LifecycleState.RESEARCH_SERVICES_ABSENT
        return result

    def admit_post_restore_repairs(self) -> RepairsEvidence:
        self._require_state(LifecycleState.RESEARCH_SERVICES_ABSENT)
        try:
            evidence = self._dispatch(
                LifecycleAction.POST_RESTORE_REPAIRS,
                lambda: self._broker._collect_resolution_info(
                    RepairsGate.POST_ROLLBACK,
                    self._is_relevant,
                    self._is_critical,
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._repairs_pass(evidence):
            self._rollback()
        self._restore_repairs = evidence
        self._state = LifecycleState.POST_RESTORE_REPAIRS_PASS
        return evidence

    def _final_restore_proof(self) -> FinalRestoreProof:
        inventory = self._restore_inventory
        core = self._restore_core_check
        restart = self._removal_restart
        readiness = self._restore_readiness
        services = self._restore_services
        repairs = self._restore_repairs
        restart_permit = self._permits[LifecycleAction.REMOVAL_RESTART]
        return FinalRestoreProof(
            source_manifest_match=(
                inventory is not None
                and self._restore_manifest is not None
                and self._inventory_pass(inventory, len(self._restore_manifest.entries))
            ),
            research_files_absent=(
                inventory is not None
                and inventory.unexpected_count == 0
                and inventory.missing_count == 0
            ),
            core_check_passed=(core is not None and core.check_passed),
            restart_consumed=restart_permit.consumed,
            restart_dispatched=SourceState.RESTORE in self._restart_dispatched,
            restart_submitted=restart is not None and restart.submitted,
            restart_accepted=restart is not None and restart.accepted,
            core_reachable=readiness is not None and readiness.core_reachable,
            core_running=readiness is not None and readiness.core_running,
            integration_loaded=readiness is not None and readiness.integration_loaded,
            core_not_timed_out=readiness is not None and not readiness.timed_out,
            research_services_absent=self._services_absent_pass(services),
            repairs_shape_valid=repairs is not None and repairs.shape_valid,
            repairs_relevant_zero=(repairs is not None and repairs.relevant_count == 0),
            repairs_critical_zero=(repairs is not None and repairs.critical_count == 0),
        )

    def complete(self) -> FinalRestoreProof:
        self._require_state(LifecycleState.POST_RESTORE_REPAIRS_PASS)
        proof = self._dispatch(
            LifecycleAction.FINAL_ACCEPTANCE, self._final_restore_proof
        )
        if not isinstance(proof, FinalRestoreProof) or not proof.complete:
            self._rollback()
        self._state = LifecycleState.COMPLETE
        return proof

    def restore_private_backup_fallback(self) -> InstallResult:
        """Consume the fixed fallback once without treating it as PR #41 proof."""
        self._require_state(LifecycleState.ROLLBACK_REQUIRED)
        try:
            result = self._dispatch(
                LifecycleAction.BACKUP_FALLBACK,
                self._broker._restore_private_backup,
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        if not isinstance(result, InstallResult):
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        return result


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
