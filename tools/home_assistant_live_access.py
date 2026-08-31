"""Fail-closed, local-only helpers for Home Assistant access orchestration.

This module contains no network client and never exposes a raw remote terminal.
It creates/validates a private owner-only SSH wrapper, then can launch only that
validated path through a controlling PTY for fixed structured operations.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import errno
import fcntl
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
from itertools import pairwise
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Self, TextIO

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
_LIFECYCLE_JOURNAL_SCHEMA = 1
_MAX_LIFECYCLE_JOURNAL_BYTES = 128 * 1024
_LIFECYCLE_STATE_ROOT: Path | None = None
_LIFECYCLE_ANCHOR_NAME = "anchor.json"
_LIFECYCLE_JOURNAL_NAME = "journal.json"
_LIFECYCLE_LOCK_NAME = "journal.lock"
_DISABLE_DURABLE_LIFECYCLE_FOR_TESTS = False
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
    RECONCILE_BACKUP = "reconcile_backup"
    RECONCILE_BACKUP_CREATION = "reconcile_backup_creation"


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


class FallbackPhase(StrEnum):
    """Monotonic durable fallback/reconciliation phases."""

    AVAILABLE = "available"
    INTENT_DURABLE = "intent_recorded"
    DISPATCH_POSSIBLE = "dispatch_possible"
    RECONCILIATION_REQUIRED = "possibly_applied"
    RECONCILED_PR41 = "reconciled"
    RECONCILED_CANDIDATE = "reconciled_candidate"
    RECONCILED_UNKNOWN = "reconciled_unknown"


_FALLBACK_PHASE_SUCCESSORS = MappingProxyType(
    {
        FallbackPhase.AVAILABLE: frozenset({FallbackPhase.INTENT_DURABLE}),
        FallbackPhase.INTENT_DURABLE: frozenset({FallbackPhase.DISPATCH_POSSIBLE}),
        FallbackPhase.DISPATCH_POSSIBLE: frozenset(
            {FallbackPhase.RECONCILIATION_REQUIRED}
        ),
        FallbackPhase.RECONCILIATION_REQUIRED: frozenset(
            {
                FallbackPhase.RECONCILED_PR41,
                FallbackPhase.RECONCILED_CANDIDATE,
                FallbackPhase.RECONCILED_UNKNOWN,
            }
        ),
        FallbackPhase.RECONCILED_PR41: frozenset(),
        FallbackPhase.RECONCILED_CANDIDATE: frozenset(),
        FallbackPhase.RECONCILED_UNKNOWN: frozenset(),
    }
)


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
    COMPLETE_NORMAL = "COMPLETE_NORMAL"
    COMPLETE = "COMPLETE_NORMAL"
    RESTORED_AFTER_ABORT = "RESTORED_AFTER_ABORT"
    RESTORE_FAILED = "RESTORE_FAILED"
    MANUAL_RECOVERY_REQUIRED = "MANUAL_RECOVERY_REQUIRED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"

    @property
    def is_failure(self) -> bool:
        return self in {
            LifecycleState.ROLLBACK_REQUIRED,
            LifecycleState.RESTORE_FAILED,
            LifecycleState.MANUAL_RECOVERY_REQUIRED,
            LifecycleState.RECOVERY_REQUIRED,
        }


class LifecycleAction(StrEnum):
    """One generation-bound permit for every represented controller stage."""

    INITIAL_REPAIRS = "initial_repairs"
    BACKUP = "backup"
    BACKUP_RECONCILE = "backup_reconcile"
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
    BACKUP_FALLBACK = "backup_fallback"
    BACKUP_FALLBACK_RECONCILE = "backup_fallback_reconcile"


_LIFECYCLE_ACTION_PREDECESSORS = MappingProxyType(
    {
        LifecycleAction.INITIAL_REPAIRS: frozenset({LifecycleState.BASELINE}),
        LifecycleAction.BACKUP: frozenset({LifecycleState.INITIAL_REPAIRS_PASS}),
        LifecycleAction.BACKUP_RECONCILE: frozenset({LifecycleState.RECOVERY_REQUIRED}),
        LifecycleAction.CANDIDATE_TRANSFER: frozenset({LifecycleState.BACKUP_VERIFIED}),
        LifecycleAction.CANDIDATE_INSTALL: frozenset({LifecycleState.CANDIDATE_STAGED}),
        LifecycleAction.CANDIDATE_INVENTORY: frozenset(
            {LifecycleState.CANDIDATE_INSTALLED}
        ),
        LifecycleAction.CANDIDATE_CORE_CHECK_1: frozenset(
            {LifecycleState.CANDIDATE_INVENTORY_VERIFIED}
        ),
        LifecycleAction.CANDIDATE_CORE_CHECK_2: frozenset(
            {LifecycleState.CANDIDATE_INVENTORY_VERIFIED}
        ),
        LifecycleAction.ACTIVATION_RESTART: frozenset(
            {LifecycleState.CANDIDATE_CORE_CHECKED}
        ),
        LifecycleAction.CANDIDATE_READINESS: frozenset(
            {LifecycleState.ACTIVATION_RESTART_CONSUMED}
        ),
        LifecycleAction.SERVICES_PRESENT: frozenset({LifecycleState.CANDIDATE_READY}),
        LifecycleAction.POST_ACTIVATION_REPAIRS: frozenset(
            {LifecycleState.RESEARCH_SERVICES_PRESENT}
        ),
        LifecycleAction.A0: frozenset({LifecycleState.POST_ACTIVATION_REPAIRS_PASS}),
        LifecycleAction.P0: frozenset({LifecycleState.A0_COLLECTED}),
        LifecycleAction.AP0: frozenset({LifecycleState.P0_COMPLETED}),
        LifecycleAction.PREFLIGHT: frozenset({LifecycleState.AP0_COLLECTED}),
        LifecycleAction.A1: frozenset({LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED}),
        LifecycleAction.RESEARCH_FINAL: frozenset({LifecycleState.A1_COLLECTED}),
        LifecycleAction.A2: frozenset({LifecycleState.RESEARCH_FINAL_VALIDATED}),
        LifecycleAction.RESTORE_TRANSFER: frozenset(
            {
                LifecycleState.A2_COLLECTED,
                LifecycleState.ROLLBACK_REQUIRED,
                LifecycleState.RECOVERY_REQUIRED,
            }
        ),
        LifecycleAction.RESTORE_INSTALL: frozenset({LifecycleState.RESTORE_STAGED}),
        LifecycleAction.RESTORE_INVENTORY: frozenset({LifecycleState.PR41_RESTORED}),
        LifecycleAction.RESTORE_CORE_CHECK_1: frozenset(
            {LifecycleState.RESTORE_INVENTORY_VERIFIED}
        ),
        LifecycleAction.RESTORE_CORE_CHECK_2: frozenset(
            {LifecycleState.RESTORE_INVENTORY_VERIFIED}
        ),
        LifecycleAction.REMOVAL_RESTART: frozenset(
            {LifecycleState.RESTORE_CORE_CHECKED}
        ),
        LifecycleAction.RESTORE_READINESS: frozenset(
            {LifecycleState.REMOVAL_RESTART_CONSUMED}
        ),
        LifecycleAction.SERVICES_ABSENT: frozenset({LifecycleState.PR41_READY}),
        LifecycleAction.POST_RESTORE_REPAIRS: frozenset(
            {LifecycleState.RESEARCH_SERVICES_ABSENT}
        ),
        LifecycleAction.FINAL_ACCEPTANCE: frozenset(
            {LifecycleState.POST_RESTORE_REPAIRS_PASS}
        ),
        LifecycleAction.BACKUP_FALLBACK: frozenset({LifecycleState.ROLLBACK_REQUIRED}),
        LifecycleAction.BACKUP_FALLBACK_RECONCILE: frozenset(
            {LifecycleState.ROLLBACK_REQUIRED, LifecycleState.RECOVERY_REQUIRED}
        ),
    }
)

_LIFECYCLE_ACTION_SUCCESSORS = MappingProxyType(
    {
        LifecycleAction.INITIAL_REPAIRS: frozenset(
            {LifecycleState.INITIAL_REPAIRS_PASS}
        ),
        LifecycleAction.BACKUP: frozenset({LifecycleState.BACKUP_VERIFIED}),
        LifecycleAction.BACKUP_RECONCILE: frozenset({LifecycleState.BACKUP_VERIFIED}),
        LifecycleAction.CANDIDATE_TRANSFER: frozenset(
            {LifecycleState.CANDIDATE_STAGED}
        ),
        LifecycleAction.CANDIDATE_INSTALL: frozenset(
            {LifecycleState.CANDIDATE_INSTALLED}
        ),
        LifecycleAction.CANDIDATE_INVENTORY: frozenset(
            {LifecycleState.CANDIDATE_INVENTORY_VERIFIED}
        ),
        LifecycleAction.CANDIDATE_CORE_CHECK_1: frozenset(
            {LifecycleState.CANDIDATE_CORE_CHECKED}
        ),
        LifecycleAction.CANDIDATE_CORE_CHECK_2: frozenset(
            {LifecycleState.CANDIDATE_CORE_CHECKED}
        ),
        LifecycleAction.ACTIVATION_RESTART: frozenset(
            {LifecycleState.ACTIVATION_RESTART_CONSUMED}
        ),
        LifecycleAction.CANDIDATE_READINESS: frozenset(
            {LifecycleState.CANDIDATE_READY}
        ),
        LifecycleAction.SERVICES_PRESENT: frozenset(
            {LifecycleState.RESEARCH_SERVICES_PRESENT}
        ),
        LifecycleAction.POST_ACTIVATION_REPAIRS: frozenset(
            {LifecycleState.POST_ACTIVATION_REPAIRS_PASS}
        ),
        LifecycleAction.A0: frozenset({LifecycleState.A0_COLLECTED}),
        LifecycleAction.P0: frozenset({LifecycleState.P0_COMPLETED}),
        LifecycleAction.AP0: frozenset({LifecycleState.AP0_COLLECTED}),
        LifecycleAction.PREFLIGHT: frozenset(
            {LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED}
        ),
        LifecycleAction.A1: frozenset({LifecycleState.A1_COLLECTED}),
        LifecycleAction.RESEARCH_FINAL: frozenset(
            {LifecycleState.RESEARCH_FINAL_VALIDATED}
        ),
        LifecycleAction.A2: frozenset({LifecycleState.A2_COLLECTED}),
        LifecycleAction.RESTORE_TRANSFER: frozenset({LifecycleState.RESTORE_STAGED}),
        LifecycleAction.RESTORE_INSTALL: frozenset({LifecycleState.PR41_RESTORED}),
        LifecycleAction.RESTORE_INVENTORY: frozenset(
            {LifecycleState.RESTORE_INVENTORY_VERIFIED}
        ),
        LifecycleAction.RESTORE_CORE_CHECK_1: frozenset(
            {LifecycleState.RESTORE_CORE_CHECKED}
        ),
        LifecycleAction.RESTORE_CORE_CHECK_2: frozenset(
            {LifecycleState.RESTORE_CORE_CHECKED}
        ),
        LifecycleAction.REMOVAL_RESTART: frozenset(
            {LifecycleState.REMOVAL_RESTART_CONSUMED}
        ),
        LifecycleAction.RESTORE_READINESS: frozenset({LifecycleState.PR41_READY}),
        LifecycleAction.SERVICES_ABSENT: frozenset(
            {LifecycleState.RESEARCH_SERVICES_ABSENT}
        ),
        LifecycleAction.POST_RESTORE_REPAIRS: frozenset(
            {LifecycleState.POST_RESTORE_REPAIRS_PASS}
        ),
        LifecycleAction.FINAL_ACCEPTANCE: frozenset(
            {
                LifecycleState.COMPLETE_NORMAL,
                LifecycleState.RESTORED_AFTER_ABORT,
            }
        ),
        LifecycleAction.BACKUP_FALLBACK: frozenset({LifecycleState.ROLLBACK_REQUIRED}),
        LifecycleAction.BACKUP_FALLBACK_RECONCILE: frozenset(
            {
                LifecycleState.PR41_RESTORED,
                LifecycleState.ROLLBACK_REQUIRED,
                LifecycleState.RECOVERY_REQUIRED,
                LifecycleState.MANUAL_RECOVERY_REQUIRED,
            }
        ),
    }
)

_NORMAL_LIFECYCLE_HISTORY = (
    LifecycleState.BASELINE,
    LifecycleState.INITIAL_REPAIRS_PASS,
    LifecycleState.BACKUP_VERIFIED,
    LifecycleState.CANDIDATE_STAGED,
    LifecycleState.CANDIDATE_INSTALLED,
    LifecycleState.CANDIDATE_INVENTORY_VERIFIED,
    LifecycleState.CANDIDATE_CORE_CHECKED,
    LifecycleState.ACTIVATION_RESTART_CONSUMED,
    LifecycleState.CANDIDATE_READY,
    LifecycleState.RESEARCH_SERVICES_PRESENT,
    LifecycleState.POST_ACTIVATION_REPAIRS_PASS,
    LifecycleState.A0_COLLECTED,
    LifecycleState.P0_COMPLETED,
    LifecycleState.AP0_COLLECTED,
    LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED,
    LifecycleState.A1_COLLECTED,
    LifecycleState.RESEARCH_FINAL_VALIDATED,
    LifecycleState.A2_COLLECTED,
    LifecycleState.RESTORE_STAGED,
    LifecycleState.PR41_RESTORED,
    LifecycleState.RESTORE_INVENTORY_VERIFIED,
    LifecycleState.RESTORE_CORE_CHECKED,
    LifecycleState.REMOVAL_RESTART_CONSUMED,
    LifecycleState.PR41_READY,
    LifecycleState.RESEARCH_SERVICES_ABSENT,
    LifecycleState.POST_RESTORE_REPAIRS_PASS,
)

_RECONSTRUCTABLE_RESTORE_STAGES = frozenset(
    {
        LifecycleState.RESTORE_STAGED,
        LifecycleState.PR41_RESTORED,
        LifecycleState.RESTORE_INVENTORY_VERIFIED,
        LifecycleState.RESTORE_CORE_CHECKED,
        LifecycleState.REMOVAL_RESTART_CONSUMED,
        LifecycleState.PR41_READY,
        LifecycleState.RESEARCH_SERVICES_ABSENT,
        LifecycleState.POST_RESTORE_REPAIRS_PASS,
    }
)

_RESTORE_ACTIVE_SOURCE_STAGES = _RECONSTRUCTABLE_RESTORE_STAGES - {
    LifecycleState.RESTORE_STAGED
}

_RESTORE_RESTARTED_STAGES = frozenset(
    {
        LifecycleState.REMOVAL_RESTART_CONSUMED,
        LifecycleState.PR41_READY,
        LifecycleState.RESEARCH_SERVICES_ABSENT,
        LifecycleState.POST_RESTORE_REPAIRS_PASS,
    }
)

_CANDIDATE_SOURCE_ACTIONS = frozenset(
    {
        LifecycleAction.CANDIDATE_TRANSFER,
        LifecycleAction.CANDIDATE_INSTALL,
        LifecycleAction.CANDIDATE_INVENTORY,
        LifecycleAction.CANDIDATE_CORE_CHECK_1,
        LifecycleAction.CANDIDATE_CORE_CHECK_2,
        LifecycleAction.ACTIVATION_RESTART,
        LifecycleAction.CANDIDATE_READINESS,
        LifecycleAction.SERVICES_PRESENT,
        LifecycleAction.POST_ACTIVATION_REPAIRS,
        LifecycleAction.A0,
        LifecycleAction.P0,
        LifecycleAction.AP0,
        LifecycleAction.PREFLIGHT,
        LifecycleAction.A1,
        LifecycleAction.RESEARCH_FINAL,
        LifecycleAction.A2,
    }
)

_RESTORE_SOURCE_ACTIONS = frozenset(
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
    }
)

_PR41_BOUND_ACTIONS = _RESTORE_SOURCE_ACTIONS | {
    LifecycleAction.BACKUP,
    LifecycleAction.BACKUP_RECONCILE,
    LifecycleAction.BACKUP_FALLBACK,
    LifecycleAction.BACKUP_FALLBACK_RECONCILE,
}


_BOUNDED_OPERATION_ACTIONS = {
    BoundedOperation.BACKUP: frozenset({LifecycleAction.BACKUP}),
    BoundedOperation.RECONCILE_BACKUP_CREATION: frozenset(
        {LifecycleAction.BACKUP_RECONCILE}
    ),
    BoundedOperation.TRANSFER: frozenset(
        {LifecycleAction.CANDIDATE_TRANSFER, LifecycleAction.RESTORE_TRANSFER}
    ),
    BoundedOperation.INSTALL: frozenset({LifecycleAction.CANDIDATE_INSTALL}),
    BoundedOperation.SOURCE_INVENTORY: frozenset(
        {LifecycleAction.CANDIDATE_INVENTORY, LifecycleAction.RESTORE_INVENTORY}
    ),
    BoundedOperation.CORE_CHECK: frozenset(
        {
            LifecycleAction.CANDIDATE_CORE_CHECK_1,
            LifecycleAction.CANDIDATE_CORE_CHECK_2,
            LifecycleAction.RESTORE_CORE_CHECK_1,
            LifecycleAction.RESTORE_CORE_CHECK_2,
        }
    ),
    BoundedOperation.RESTART_CORE: frozenset(
        {LifecycleAction.ACTIVATION_RESTART, LifecycleAction.REMOVAL_RESTART}
    ),
    BoundedOperation.CORE_READINESS: frozenset(
        {LifecycleAction.CANDIDATE_READINESS, LifecycleAction.RESTORE_READINESS}
    ),
    BoundedOperation.SERVICE_INVENTORY: frozenset(
        {LifecycleAction.SERVICES_PRESENT, LifecycleAction.SERVICES_ABSENT}
    ),
    BoundedOperation.PHASE_A_HELPER: frozenset(
        {
            LifecycleAction.A0,
            LifecycleAction.P0,
            LifecycleAction.AP0,
            LifecycleAction.PREFLIGHT,
            LifecycleAction.A1,
            LifecycleAction.A2,
        }
    ),
    BoundedOperation.RESTORE: frozenset({LifecycleAction.RESTORE_INSTALL}),
    BoundedOperation.RESTORE_BACKUP: frozenset({LifecycleAction.BACKUP_FALLBACK}),
    BoundedOperation.RECONCILE_BACKUP: frozenset(
        {LifecycleAction.BACKUP_FALLBACK_RECONCILE}
    ),
}


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
        LifecycleAction.BACKUP_FALLBACK,
        LifecycleAction.BACKUP_FALLBACK_RECONCILE,
        LifecycleAction.BACKUP_RECONCILE,
    }
)

_ROLLBACK_BROKER_ADAPTERS = (
    "_register_lifecycle_controller",
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
    "_reconcile_private_backup",
    "_reconcile_private_backup_creation",
)


class SessionBrokerError(RuntimeError):
    """A failure that intentionally never includes captured PTY bytes."""


class SourceBundleError(ValueError):
    """A fixed source-admission failure without paths or content."""


class LifecycleControllerError(RuntimeError):
    """A fixed lifecycle failure that contains no private operation data."""


@dataclass(frozen=True, slots=True)
class _CapabilityIssuer:
    """Shared identity ledgers proving controller issuance and broker consumption."""

    identity: object
    issued: list[object]
    consumed: list[object]


@dataclass(frozen=True, slots=True)
class _ControllerBinding:
    """One exact controller/lifecycle/session registration held by a broker."""

    controller: object
    issuer: _CapabilityIssuer
    lifecycle_generation: object
    session_generation: object


@dataclass(frozen=True, slots=True)
class _PrivateWirePacket:
    """One internally issued ASCII packet for the name-mangled PTY sink."""

    payload: bytes = field(repr=False)
    issuer: object = field(repr=False)


@dataclass(frozen=True, slots=True)
class _LifecycleCapability:
    """A controller-minted, broker-validated, one-shot action capability."""

    controller: object
    issuer: object
    lifecycle_generation: object
    source_generation: object
    session_generation: object
    action: LifecycleAction
    issuance_identity: object
    backup_identity: object = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class _EvidenceOrigin:
    """Internal provenance for one sanitized evidence object."""

    evidence: object = field(repr=False)
    controller: object = field(repr=False)
    lifecycle_generation: object = field(repr=False)
    source_generation: object = field(repr=False)
    action: LifecycleAction
    session_generation: object = field(repr=False)
    issuance_identity: object = field(repr=False)
    audit_instance: str | None = field(default=None, repr=False)
    nonce: str | None = field(default=None, repr=False)


_EVIDENCE_ORIGIN_LEDGER: dict[int, _EvidenceOrigin] = {}
_CLAIMED_EVIDENCE: set[int] = set()


def _bind_evidence_origin(evidence: object, capability: _LifecycleCapability) -> object:
    """Bind a newly parsed sanitized result to its exact broker capability."""
    identity = id(evidence)
    existing = _EVIDENCE_ORIGIN_LEDGER.get(identity)
    if existing is not None:
        raise SessionBrokerError(
            "PRIVATE_INTERACTIVE_SESSION_EVIDENCE_REUSED"
        ) from None
    audit = evidence.audit if isinstance(evidence, PhaseAResult) else None
    _EVIDENCE_ORIGIN_LEDGER[identity] = _EvidenceOrigin(
        evidence=evidence,
        controller=capability.controller,
        lifecycle_generation=capability.lifecycle_generation,
        source_generation=capability.source_generation,
        action=capability.action,
        session_generation=capability.session_generation,
        issuance_identity=capability.issuance_identity,
        audit_instance=(
            audit.audit_instance_token if isinstance(audit, AuditSnapshot) else None
        ),
        nonce=evidence.nonce if isinstance(evidence, PhaseAResult) else None,
    )
    return evidence


def _claim_evidence_origin(
    evidence: object, capability: _LifecycleCapability
) -> _EvidenceOrigin | None:
    """Claim evidence once when every immutable issuance dimension matches."""
    identity = id(evidence)
    origin = _EVIDENCE_ORIGIN_LEDGER.get(identity)
    if (
        origin is None
        or origin.evidence is not evidence
        or identity in _CLAIMED_EVIDENCE
        or origin.controller is not capability.controller
        or origin.lifecycle_generation is not capability.lifecycle_generation
        or origin.source_generation is not capability.source_generation
        or origin.action is not capability.action
        or origin.session_generation is not capability.session_generation
        or origin.issuance_identity is not capability.issuance_identity
    ):
        return None
    _CLAIMED_EVIDENCE.add(identity)
    return origin


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
    lifecycle_generation: str = field(default="", repr=False)
    source_generation: str = field(default="", repr=False)
    backup_generation: str = field(default="", repr=False)
    manifest_identity: str = field(default="", repr=False)
    backup_digest: str = field(default="", repr=False)


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
class FallbackReconciliationResult:
    phase: str
    restoration_applied: bool
    manifest_match: bool
    file_count: int


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
class PreflightResponse:
    """Exact successful PR #45 PREFLIGHT service response."""

    result: str
    protocol_version: int
    nonce: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ReceiptResponse:
    """Exact shared PR #45 RECEIPT projection; never lifecycle authority."""

    nonce: str = field(repr=False)
    known: bool
    service_entered: bool
    request_handed_to_transport: bool
    terminal_class: str | None
    response_available: bool


@dataclass(frozen=True)
class PhaseAResult:
    operation: PhaseAOperation
    exit_code: int
    outcome: str
    nonce: str | None = field(default=None, repr=False)
    preflight: PreflightResponse | None = None
    receipt: ReceiptResponse | None = None
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
        return all(
            value is True
            for value in (
                self.source_manifest_match,
                self.research_files_absent,
                self.core_check_passed,
                self.restart_consumed,
                self.restart_dispatched,
                self.restart_submitted,
                self.restart_accepted,
                self.core_reachable,
                self.core_running,
                self.integration_loaded,
                self.core_not_timed_out,
                self.research_services_absent,
                self.repairs_shape_valid,
                self.repairs_relevant_zero,
                self.repairs_critical_zero,
            )
        )


def _exact_non_bool_int(
    value: object, *, minimum: int = 0, maximum: int | None = None
) -> bool:
    """Accept an integer only when bool-subclass confusion is impossible."""
    return (
        type(value) is int
        and value >= minimum
        and (maximum is None or value <= maximum)
    )


def _strict_json_object(raw: bytes) -> dict[str, object]:
    """Decode one bounded JSON object while rejecting duplicate keys."""

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError):
        raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
    if type(decoded) is not dict:
        raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
    return decoded


def _fixed_lifecycle_state_root() -> Path:
    """Resolve one owner-private location shared by this repository's worktrees."""
    if _LIFECYCLE_STATE_ROOT is not None:
        return _LIFECYCLE_STATE_ROOT

    repository = Path(__file__).absolute().parent.parent
    dot_git = repository / ".git"
    try:
        metadata = dot_git.lstat()
    except OSError:
        raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None

    if stat.S_ISDIR(metadata.st_mode):
        common = dot_git
    elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
        try:
            raw = dot_git.read_bytes()
        except OSError:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        if len(raw) > 4096:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        try:
            line = raw.decode("utf-8").strip()
        except UnicodeError:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        if not line.startswith("gitdir: ") or "\n" in line or "\r" in line:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        candidate = Path(line.removeprefix("gitdir: "))
        if not candidate.is_absolute():
            candidate = repository / candidate
        git_dir = Path(os.path.abspath(candidate))
        if git_dir.parent.name != "worktrees":
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        common = git_dir.parent.parent
    else:
        raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None

    try:
        common_metadata = common.lstat()
    except OSError:
        raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
    if (
        not stat.S_ISDIR(common_metadata.st_mode)
        or common_metadata.st_uid != os.getuid()
    ):
        raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
    return common / "ha_tuya_ble_issue_37_lifecycle_v1"


def _lifecycle_anchor_path(root: Path) -> Path:
    """Return the independently retained anchor beside one lifecycle root."""
    return root.parent / f".{root.name}.{_LIFECYCLE_ANCHOR_NAME}"


class _DurableLifecycleJournal:
    """Fixed-path, locked, atomic continuity record for one Issue-37 lifecycle."""

    _TOP_LEVEL_KEYS = frozenset(
        {
            "schema_version",
            "revision",
            "lifecycle_generation",
            "active",
            "terminal",
            "stage",
            "research_succeeded",
            "rollback_mode",
            "recovery_mode",
            "pr45_source",
            "pr41_restore",
            "source_generation",
            "consumed_operations",
            "helper_tombstones",
            "restart_tombstones",
            "core_check_attempts",
            "ambiguous_operation",
            "known_nonce",
            "evidence_generation",
            "evidence_identities",
            "transitions",
            "operations",
            "fallback_phase",
            "fallback_reconciliation_attempts",
            "baseline_backup_identity",
        }
    )
    _RISKY_ACTIONS = frozenset(
        {
            LifecycleAction.BACKUP.value,
            LifecycleAction.BACKUP_RECONCILE.value,
            LifecycleAction.CANDIDATE_TRANSFER.value,
            LifecycleAction.CANDIDATE_INSTALL.value,
            LifecycleAction.ACTIVATION_RESTART.value,
            LifecycleAction.P0.value,
            LifecycleAction.PREFLIGHT.value,
            LifecycleAction.A0.value,
            LifecycleAction.AP0.value,
            LifecycleAction.A1.value,
            LifecycleAction.A2.value,
            LifecycleAction.RESTORE_TRANSFER.value,
            LifecycleAction.RESTORE_INSTALL.value,
            LifecycleAction.REMOVAL_RESTART.value,
            LifecycleAction.BACKUP_FALLBACK.value,
            LifecycleAction.BACKUP_FALLBACK_RECONCILE.value,
        }
    )

    def __init__(self) -> None:
        self._directory = _fixed_lifecycle_state_root()
        self._anchor_name = _lifecycle_anchor_path(self._directory).name
        self._parent_fd: int | None = None
        self._root_fd: int | None = None
        self._lock_fd: int | None = None
        self._closed = False
        try:
            self._secure_directory()
            self._acquire_lock()
            newly_created = False
            anchor = self._read_anchor()
            record = self._read_record()
            if record is None:
                if anchor is not None:
                    raise LifecycleControllerError(
                        "RECOVERY_REQUIRED_MISSING_JOURNAL"
                    ) from None
                record = self._new_record()
                self._write_anchor(self._new_anchor(record))
                self._write_record(record)
                newly_created = True
            elif anchor is None:
                raise LifecycleControllerError("LIFECYCLE_ANCHOR_MISSING") from None
            else:
                self._validate_anchor(anchor, record)
                self._reconcile_anchor_revision(anchor, record)
            self._anchor = anchor if anchor is not None else self._read_anchor()
            self._record = record
            if not newly_created and record["active"] is not True:
                raise LifecycleControllerError("LIFECYCLE_TERMINAL_RETAINED") from None
            if not newly_created:
                consumed = set(record["consumed_operations"])
                if not consumed.intersection(self._RISKY_ACTIONS):
                    raise LifecycleControllerError(
                        "LIFECYCLE_PREPARATION_ABANDONED"
                    ) from None
                record = copy.deepcopy(record)
                record["recovery_mode"] = True
                record["rollback_mode"] = True
                incomplete_restore = any(
                    operation["action"]
                    in {action.value for action in _RESTORE_SOURCE_ACTIONS}
                    and operation["phase"] != "transition_committed"
                    for operation in record["operations"]
                )
                stage = LifecycleState(record["stage"])
                if incomplete_restore:
                    restore_generation = record["pr41_restore"]["generation"]
                    record["active"] = False
                    record["terminal"] = LifecycleState.RESTORE_FAILED.value
                    record["stage"] = LifecycleState.RESTORE_FAILED.value
                    record["source_generation"] = restore_generation
                    record["transitions"].append(
                        {
                            "sequence": len(record["transitions"]),
                            "stage": LifecycleState.RESTORE_FAILED.value,
                            "action": None,
                            "source_generation": restore_generation,
                            "evidence_generation": None,
                        }
                    )
                elif stage not in _RECONSTRUCTABLE_RESTORE_STAGES:
                    record["stage"] = LifecycleState.RECOVERY_REQUIRED.value
                    record["transitions"].append(
                        {
                            "sequence": len(record["transitions"]),
                            "stage": LifecycleState.RECOVERY_REQUIRED.value,
                            "action": None,
                            "source_generation": record["source_generation"],
                            "evidence_generation": None,
                        }
                    )
                record["revision"] += 1
                self._write_record(record)
                self._advance_anchor_revision(record["revision"])
            self._record = record
        except BaseException:
            try:
                self.close()
            except OSError as cleanup_error:
                _ = cleanup_error
            raise

    @staticmethod
    def _token() -> str:
        return secrets.token_hex(16)

    @staticmethod
    def _safe_stat(value: os.stat_result, *, mode: int, directory: bool) -> bool:
        expected_type = (
            stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
        )
        return (
            expected_type
            and value.st_uid == os.getuid()
            and stat.S_IMODE(value.st_mode) == mode
            and (directory or value.st_nlink == 1)
        )

    def _secure_directory(self) -> None:
        parent_descriptor: int | None = None
        descriptor: int | None = None
        try:
            self._directory.parent.mkdir(parents=True, exist_ok=True)
            parent_descriptor = os.open(
                self._directory.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            parent_metadata = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != os.getuid()
            ):
                raise OSError
            try:
                os.mkdir(self._directory.name, mode=0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                pass
            descriptor = os.open(
                self._directory.name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
            metadata = os.fstat(descriptor)
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            if parent_descriptor is not None:
                os.close(parent_descriptor)
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        if not self._safe_stat(metadata, mode=0o700, directory=True):
            os.close(descriptor)
            os.close(parent_descriptor)
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        self._root_fd = descriptor
        self._parent_fd = parent_descriptor

    def _open_parent_regular(self, name: str, flags: int, mode: int = 0o600) -> int:
        if self._parent_fd is None or Path(name).name != name:
            raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                mode,
                dir_fd=self._parent_fd,
            )
            metadata = os.fstat(descriptor)
        except FileNotFoundError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None
        if not self._safe_stat(metadata, mode=0o600, directory=False):
            os.close(descriptor)
            raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None
        return descriptor

    def _open_regular(self, name: str, flags: int, mode: int = 0o600) -> int:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        close_on_exec = getattr(os, "O_CLOEXEC", 0)
        if self._root_fd is None or Path(name).name != name:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                flags | nofollow | close_on_exec,
                mode,
                dir_fd=self._root_fd,
            )
            metadata = os.fstat(descriptor)
        except FileNotFoundError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        if not self._safe_stat(metadata, mode=0o600, directory=False):
            os.close(descriptor)
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        return descriptor

    def _acquire_lock(self) -> None:
        if self._root_fd is None:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        try:
            fcntl.flock(self._root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise LifecycleControllerError("LIFECYCLE_OWNER_ACTIVE") from None
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        descriptor = self._open_regular(
            _LIFECYCLE_LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise LifecycleControllerError("LIFECYCLE_OWNER_ACTIVE") from None
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        self._lock_fd = descriptor

    def _read_record(self) -> dict[str, object] | None:
        if self._root_fd is None:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        try:
            descriptor = self._open_regular(_LIFECYCLE_JOURNAL_NAME, os.O_RDONLY)
        except FileNotFoundError:
            return None
        try:
            size = os.fstat(descriptor).st_size
            if size <= 0 or size > _MAX_LIFECYCLE_JOURNAL_BYTES:
                raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
            chunks: list[bytes] = []
            remaining = size
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    raise LifecycleControllerError(
                        "LIFECYCLE_JOURNAL_INVALID"
                    ) from None
                chunks.append(chunk)
                remaining -= len(chunk)
        except OSError:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        finally:
            os.close(descriptor)
        record = _strict_json_object(b"".join(chunks))
        self._validate_record(record)
        return record

    def _read_anchor(self) -> dict[str, object] | None:
        try:
            descriptor = self._open_parent_regular(self._anchor_name, os.O_RDONLY)
        except FileNotFoundError:
            return None
        try:
            size = os.fstat(descriptor).st_size
            if size <= 0 or size > 4096:
                raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None
            raw = bytearray()
            while len(raw) < size:
                chunk = os.read(descriptor, size - len(raw))
                if not chunk:
                    raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None
                raw.extend(chunk)
        except OSError:
            raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None
        finally:
            os.close(descriptor)
        try:
            return _strict_json_object(bytes(raw))
        except LifecycleControllerError:
            raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None

    def _new_anchor(self, record: dict[str, object]) -> dict[str, object]:
        if self._root_fd is None:
            raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None
        root_metadata = os.fstat(self._root_fd)
        return {
            "schema_version": 1,
            "state_root_generation": self._token(),
            "state_root_device": root_metadata.st_dev,
            "state_root_inode": root_metadata.st_ino,
            "original_lifecycle_generation": record["lifecycle_generation"],
            "pr41_commit": PR41_RESTORE_COMMIT,
            "pr41_tree": PR41_RESTORE_TREE,
            "baseline_backup_identity": None,
            "root_revision": 0,
        }

    def _validate_anchor(
        self, anchor: dict[str, object], record: dict[str, object]
    ) -> None:
        if self._root_fd is None:
            raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None
        root_metadata = os.fstat(self._root_fd)
        token = re.compile(r"[0-9a-f]{32}\Z")
        valid = (
            set(anchor)
            == {
                "schema_version",
                "state_root_generation",
                "state_root_device",
                "state_root_inode",
                "original_lifecycle_generation",
                "pr41_commit",
                "pr41_tree",
                "baseline_backup_identity",
                "root_revision",
            }
            and anchor.get("schema_version") == 1
            and isinstance(anchor.get("state_root_generation"), str)
            and token.fullmatch(anchor.get("state_root_generation", "")) is not None
            and _exact_non_bool_int(anchor.get("state_root_device"), minimum=1)
            and _exact_non_bool_int(anchor.get("state_root_inode"), minimum=1)
            and anchor.get("state_root_device") == root_metadata.st_dev
            and anchor.get("state_root_inode") == root_metadata.st_ino
            and anchor.get("original_lifecycle_generation")
            == record.get("lifecycle_generation")
            and anchor.get("pr41_commit") == PR41_RESTORE_COMMIT
            and anchor.get("pr41_tree") == PR41_RESTORE_TREE
            and (
                anchor.get("baseline_backup_identity") is None
                or self._backup_identity_valid(
                    anchor.get("baseline_backup_identity"),
                    record.get("lifecycle_generation"),
                    record,
                )
            )
            and _exact_non_bool_int(anchor.get("root_revision"), maximum=10_000_000)
        )
        if not valid:
            raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None

    def _write_anchor(
        self, anchor: dict[str, object], *, replace_existing: bool = False
    ) -> None:
        validation_record = getattr(
            self,
            "_record",
            {"lifecycle_generation": anchor["original_lifecycle_generation"]},
        )
        self._validate_anchor(
            anchor,
            validation_record,
        )
        payload = json.dumps(
            anchor, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        temporary = f".anchor-{self._token()}.tmp"
        descriptor: int | None = None
        try:
            descriptor = self._open_parent_regular(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            if self._parent_fd is None:
                raise OSError
            if replace_existing:
                os.replace(
                    temporary,
                    self._anchor_name,
                    src_dir_fd=self._parent_fd,
                    dst_dir_fd=self._parent_fd,
                )
            else:
                os.link(
                    temporary,
                    self._anchor_name,
                    src_dir_fd=self._parent_fd,
                    dst_dir_fd=self._parent_fd,
                    follow_symlinks=False,
                )
                os.unlink(temporary, dir_fd=self._parent_fd)
            os.fsync(self._parent_fd)
        except OSError:
            raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if self._parent_fd is not None:
                try:
                    os.unlink(temporary, dir_fd=self._parent_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None

    def _reconcile_anchor_revision(
        self, anchor: dict[str, object], record: dict[str, object]
    ) -> None:
        anchor_revision = anchor["root_revision"]
        journal_revision = record["revision"]
        if journal_revision == anchor_revision:
            if anchor.get("baseline_backup_identity") != record.get(
                "baseline_backup_identity"
            ):
                raise LifecycleControllerError(
                    "LIFECYCLE_BACKUP_IDENTITY_INVALID"
                ) from None
            return
        if journal_revision == anchor_revision + 1:
            repaired = copy.deepcopy(anchor)
            repaired["root_revision"] = journal_revision
            repaired["baseline_backup_identity"] = record.get(
                "baseline_backup_identity"
            )
            self._write_anchor(repaired, replace_existing=True)
            anchor.clear()
            anchor.update(repaired)
            return
        raise LifecycleControllerError("LIFECYCLE_JOURNAL_REVISION_INVALID") from None

    def _advance_anchor_revision(
        self, revision: int, backup_identity: dict[str, object] | None = None
    ) -> None:
        if self._anchor["root_revision"] + 1 != revision:
            raise LifecycleControllerError(
                "LIFECYCLE_JOURNAL_REVISION_INVALID"
            ) from None
        candidate = copy.deepcopy(self._anchor)
        candidate["root_revision"] = revision
        if backup_identity is not None:
            if candidate["baseline_backup_identity"] is not None:
                raise LifecycleControllerError(
                    "LIFECYCLE_BACKUP_ALREADY_VERIFIED"
                ) from None
            candidate["baseline_backup_identity"] = copy.deepcopy(backup_identity)
        self._write_anchor(candidate, replace_existing=True)
        self._anchor = candidate

    def _new_record(self) -> dict[str, object]:
        lifecycle = self._token()
        source = self._token()
        return {
            "schema_version": _LIFECYCLE_JOURNAL_SCHEMA,
            "revision": 0,
            "lifecycle_generation": lifecycle,
            "active": True,
            "terminal": None,
            "stage": LifecycleState.BASELINE.value,
            "research_succeeded": False,
            "rollback_mode": False,
            "recovery_mode": False,
            "pr45_source": {
                "commit": PR45_CANDIDATE_COMMIT,
                "tree": PR45_CANDIDATE_TREE,
                "generation": self._token(),
            },
            "pr41_restore": {
                "commit": PR41_RESTORE_COMMIT,
                "tree": PR41_RESTORE_TREE,
                "generation": self._token(),
            },
            "source_generation": source,
            "consumed_operations": [],
            "helper_tombstones": [],
            "restart_tombstones": [],
            "core_check_attempts": {"candidate": [], "restore": []},
            "ambiguous_operation": None,
            "known_nonce": None,
            "evidence_generation": 0,
            "evidence_identities": [],
            "transitions": [
                {
                    "sequence": 0,
                    "stage": LifecycleState.BASELINE.value,
                    "action": None,
                    "source_generation": source,
                    "evidence_generation": None,
                }
            ],
            "operations": [],
            "fallback_phase": FallbackPhase.AVAILABLE.value,
            "fallback_reconciliation_attempts": 0,
            "baseline_backup_identity": None,
        }

    @classmethod
    def _validate_record(cls, record: dict[str, object]) -> None:
        invalid = set(record) != cls._TOP_LEVEL_KEYS
        token = re.compile(r"[0-9a-f]{32}\Z")
        states = {item.value for item in LifecycleState}
        actions = {item.value for item in LifecycleAction}
        terminal_values = {
            LifecycleState.COMPLETE_NORMAL.value,
            LifecycleState.RESTORED_AFTER_ABORT.value,
            LifecycleState.RESTORE_FAILED.value,
            LifecycleState.MANUAL_RECOVERY_REQUIRED.value,
        }
        invalid = invalid or record.get("schema_version") != _LIFECYCLE_JOURNAL_SCHEMA
        invalid = invalid or not _exact_non_bool_int(
            record.get("revision"), maximum=10_000_000
        )
        invalid = invalid or not isinstance(record.get("lifecycle_generation"), str)
        invalid = (
            invalid or token.fullmatch(record.get("lifecycle_generation", "")) is None
        )
        invalid = invalid or type(record.get("active")) is not bool
        invalid = invalid or record.get("terminal") not in terminal_values | {None}
        invalid = invalid or record.get("stage") not in states
        invalid = invalid or type(record.get("research_succeeded")) is not bool
        invalid = invalid or type(record.get("rollback_mode")) is not bool
        invalid = invalid or type(record.get("recovery_mode")) is not bool
        invalid = invalid or not isinstance(record.get("source_generation"), str)
        invalid = (
            invalid or token.fullmatch(record.get("source_generation", "")) is None
        )
        for key, commit, tree in (
            ("pr45_source", PR45_CANDIDATE_COMMIT, PR45_CANDIDATE_TREE),
            ("pr41_restore", PR41_RESTORE_COMMIT, PR41_RESTORE_TREE),
        ):
            value = record.get(key)
            invalid = invalid or type(value) is not dict
            if type(value) is dict:
                invalid = invalid or set(value) != {"commit", "tree", "generation"}
                invalid = invalid or value.get("commit") != commit
                invalid = invalid or value.get("tree") != tree
                invalid = invalid or not isinstance(value.get("generation"), str)
                invalid = (
                    invalid or token.fullmatch(value.get("generation", "")) is None
                )
        for key in (
            "consumed_operations",
            "helper_tombstones",
            "restart_tombstones",
        ):
            value = record.get(key)
            invalid = invalid or type(value) is not list
            if type(value) is list:
                invalid = invalid or len(value) != len(set(value))
                invalid = invalid or any(item not in actions for item in value)
        core = record.get("core_check_attempts")
        invalid = invalid or type(core) is not dict
        if type(core) is dict:
            invalid = invalid or set(core) != {"candidate", "restore"}
            for attempts in core.values():
                invalid = invalid or type(attempts) is not list
                if type(attempts) is list:
                    invalid = invalid or any(
                        not _exact_non_bool_int(item, minimum=1, maximum=2)
                        for item in attempts
                    )
                    invalid = invalid or attempts not in ([], [1], [1, 2])
        ambiguous = record.get("ambiguous_operation")
        invalid = invalid or ambiguous not in actions | {None}
        nonce = record.get("known_nonce")
        invalid = invalid or (
            nonce is not None
            and (not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None)
        )
        invalid = invalid or not _exact_non_bool_int(
            record.get("evidence_generation"), maximum=1_000_000
        )
        identities = record.get("evidence_identities")
        transitions = record.get("transitions")
        operations = record.get("operations")
        invalid = invalid or type(identities) is not list
        invalid = invalid or type(transitions) is not list or not transitions
        invalid = invalid or type(operations) is not list
        if type(identities) is list:
            identity_generations: list[int] = []
            issuance_identities: list[str] = []
            for identity in identities:
                invalid = (
                    invalid
                    or type(identity) is not dict
                    or set(identity)
                    != {
                        "generation",
                        "lifecycle_generation",
                        "action",
                        "source_generation",
                        "session_generation",
                        "issuance_identity",
                        "audit_instance",
                        "nonce",
                    }
                )
                if type(identity) is dict:
                    invalid = invalid or not _exact_non_bool_int(
                        identity.get("generation"), minimum=1
                    )
                    if type(identity.get("generation")) is int:
                        identity_generations.append(identity["generation"])
                    invalid = invalid or identity.get("action") not in actions
                    invalid = invalid or any(
                        not isinstance(identity.get(name), str)
                        or token.fullmatch(identity.get(name, "")) is None
                        for name in (
                            "lifecycle_generation",
                            "source_generation",
                            "session_generation",
                            "issuance_identity",
                        )
                    )
                    invalid = invalid or identity.get(
                        "lifecycle_generation"
                    ) != record.get("lifecycle_generation")
                    if isinstance(identity.get("issuance_identity"), str):
                        issuance_identities.append(identity["issuance_identity"])
                    for name in ("audit_instance", "nonce"):
                        value = identity.get(name)
                        invalid = invalid or (
                            value is not None
                            and (
                                not isinstance(value, str)
                                or _NONCE.fullmatch(value) is None
                            )
                        )
            invalid = invalid or identity_generations != list(
                range(1, len(identity_generations) + 1)
            )
            invalid = invalid or len(issuance_identities) != len(
                set(issuance_identities)
            )
            invalid = invalid or len(identity_generations) != record.get(
                "evidence_generation"
            )
        if type(transitions) is list:
            for index, transition in enumerate(transitions):
                invalid = (
                    invalid
                    or type(transition) is not dict
                    or set(transition)
                    != {
                        "sequence",
                        "stage",
                        "action",
                        "source_generation",
                        "evidence_generation",
                    }
                )
                if type(transition) is dict:
                    invalid = invalid or transition.get("sequence") != index
                    invalid = invalid or transition.get("stage") not in states
                    invalid = invalid or transition.get("action") not in actions | {
                        None
                    }
                    invalid = invalid or not isinstance(
                        transition.get("source_generation"), str
                    )
                    evidence = transition.get("evidence_generation")
                    invalid = invalid or (
                        evidence is not None
                        and not _exact_non_bool_int(evidence, minimum=1)
                    )
            if transitions:
                first = transitions[0]
                invalid = invalid or first.get("sequence") != 0
                invalid = invalid or first.get("stage") != LifecycleState.BASELINE.value
                invalid = invalid or first.get("action") is not None
                for previous, transition in pairwise(transitions):
                    try:
                        previous_state = LifecycleState(previous.get("stage"))
                        next_state = LifecycleState(transition.get("stage"))
                        action_value = transition.get("action")
                        action = (
                            None
                            if action_value is None
                            else LifecycleAction(action_value)
                        )
                    except (TypeError, ValueError):
                        invalid = True
                        continue
                    if action is None:
                        invalid = invalid or next_state not in {
                            LifecycleState.ROLLBACK_REQUIRED,
                            LifecycleState.RECOVERY_REQUIRED,
                            LifecycleState.RESTORE_FAILED,
                        }
                    else:
                        invalid = (
                            invalid
                            or previous_state
                            not in _LIFECYCLE_ACTION_PREDECESSORS[action]
                            or next_state not in _LIFECYCLE_ACTION_SUCCESSORS[action]
                        )
        phases = {
            "intent_durable",
            "dispatch_started",
            "result_durable",
            "transition_committed",
            "ambiguous",
            "reconciled",
        }
        if type(operations) is list:
            seen: set[str] = set()
            for operation in operations:
                invalid = (
                    invalid
                    or type(operation) is not dict
                    or set(operation)
                    != {
                        "action",
                        "phase",
                        "source_generation",
                        "nonce",
                    }
                )
                if type(operation) is dict:
                    action = operation.get("action")
                    invalid = invalid or action not in actions or action in seen
                    if isinstance(action, str):
                        seen.add(action)
                    invalid = invalid or operation.get("phase") not in phases
                    invalid = invalid or not isinstance(
                        operation.get("source_generation"), str
                    )
                    invalid = (
                        invalid
                        or token.fullmatch(operation.get("source_generation", ""))
                        is None
                    )
                    operation_nonce = operation.get("nonce")
                    invalid = invalid or (
                        operation_nonce is not None
                        and (
                            not isinstance(operation_nonce, str)
                            or _NONCE.fullmatch(operation_nonce) is None
                        )
                    )
            if type(record.get("consumed_operations")) is list:
                invalid = invalid or seen != set(record["consumed_operations"])
            evidence_actions: list[object] = []
            if type(identities) is list:
                evidence_actions = [
                    identity.get("action")
                    for identity in identities
                    if type(identity) is dict
                ]
            result_actions = [
                operation.get("action")
                for operation in operations
                if type(operation) is dict
                and operation.get("phase")
                in {"result_durable", "transition_committed", "reconciled"}
            ]
            invalid = invalid or evidence_actions != result_actions
        helper_actions = {
            LifecycleAction.A0.value,
            LifecycleAction.P0.value,
            LifecycleAction.AP0.value,
            LifecycleAction.PREFLIGHT.value,
            LifecycleAction.A1.value,
            LifecycleAction.A2.value,
        }
        restart_actions = {
            LifecycleAction.ACTIVATION_RESTART.value,
            LifecycleAction.REMOVAL_RESTART.value,
        }
        consumed_values = record.get("consumed_operations")
        if type(consumed_values) is list:
            invalid = invalid or record.get("helper_tombstones") != [
                value for value in consumed_values if value in helper_actions
            ]
            invalid = invalid or record.get("restart_tombstones") != [
                value for value in consumed_values if value in restart_actions
            ]
            expected_candidate_attempts = [
                1 if value == LifecycleAction.CANDIDATE_CORE_CHECK_1.value else 2
                for value in consumed_values
                if value
                in {
                    LifecycleAction.CANDIDATE_CORE_CHECK_1.value,
                    LifecycleAction.CANDIDATE_CORE_CHECK_2.value,
                }
            ]
            expected_restore_attempts = [
                1 if value == LifecycleAction.RESTORE_CORE_CHECK_1.value else 2
                for value in consumed_values
                if value
                in {
                    LifecycleAction.RESTORE_CORE_CHECK_1.value,
                    LifecycleAction.RESTORE_CORE_CHECK_2.value,
                }
            ]
            if type(core) is dict:
                invalid = (
                    invalid or core.get("candidate") != expected_candidate_attempts
                )
                invalid = invalid or core.get("restore") != expected_restore_attempts
            if LifecycleAction.PREFLIGHT.value in consumed_values:
                invalid = invalid or record.get("known_nonce") is None
        if (
            record.get("ambiguous_operation") is not None
            and type(consumed_values) is list
        ):
            invalid = (
                invalid or record.get("ambiguous_operation") not in consumed_values
            )
        invalid = invalid or record.get("fallback_phase") not in {
            phase.value for phase in FallbackPhase
        }
        invalid = invalid or not _exact_non_bool_int(
            record.get("fallback_reconciliation_attempts"), maximum=8
        )
        backup_identity = record.get("baseline_backup_identity")
        invalid = invalid or (
            backup_identity is not None
            and not cls._backup_identity_valid(
                backup_identity, record.get("lifecycle_generation"), record
            )
        )
        if type(transitions) is list and transitions:
            invalid = invalid or transitions[-1].get("stage") != record.get("stage")
        terminal = record.get("terminal")
        invalid = invalid or ((terminal is None) == (record.get("active") is False))
        invalid = invalid or (terminal is not None and terminal != record.get("stage"))
        if terminal == LifecycleState.COMPLETE_NORMAL.value:
            invalid = invalid or record.get("research_succeeded") is not True
            invalid = invalid or record.get("recovery_mode") is not False
            invalid = invalid or record.get("rollback_mode") is not False
            if type(transitions) is list:
                observed = tuple(
                    LifecycleState(item["stage"])
                    for item in transitions
                    if type(item) is dict and item.get("stage") in states
                )
                position = 0
                for state in observed:
                    if (
                        position < len(_NORMAL_LIFECYCLE_HISTORY)
                        and state is _NORMAL_LIFECYCLE_HISTORY[position]
                    ):
                        position += 1
                invalid = invalid or position != len(_NORMAL_LIFECYCLE_HISTORY)
        if invalid:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None

    def _write_record(self, record: dict[str, object]) -> None:
        current = getattr(self, "_record", None)
        if current is not None and record.get("revision") != current["revision"] + 1:
            raise LifecycleControllerError(
                "LIFECYCLE_JOURNAL_REVISION_INVALID"
            ) from None
        self._validate_record(record)
        payload = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        if len(payload) > _MAX_LIFECYCLE_JOURNAL_BYTES:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        temporary = f".journal-{self._token()}.tmp"
        descriptor: int | None = None
        try:
            descriptor = self._open_regular(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            if self._root_fd is None:
                raise OSError
            os.replace(
                temporary,
                _LIFECYCLE_JOURNAL_NAME,
                src_dir_fd=self._root_fd,
                dst_dir_fd=self._root_fd,
            )
            os.fsync(self._root_fd)
        except OSError:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                if self._root_fd is not None:
                    os.unlink(temporary, dir_fd=self._root_fd)
            except FileNotFoundError:
                pass
            except OSError:
                raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None

    def _commit(self, mutate: Callable[[dict[str, object]], None]) -> None:
        candidate = copy.deepcopy(self._record)
        mutate(candidate)
        candidate["revision"] = self._record["revision"] + 1
        self._write_record(candidate)
        backup_identity = (
            candidate["baseline_backup_identity"]
            if self._record["baseline_backup_identity"] is None
            and candidate["baseline_backup_identity"] is not None
            else None
        )
        self._advance_anchor_revision(candidate["revision"], backup_identity)
        self._record = candidate

    @staticmethod
    def _backup_identity_valid(
        value: object, lifecycle_generation: object, record: dict[str, object]
    ) -> bool:
        return (
            type(value) is dict
            and set(value)
            == {
                "lifecycle_generation",
                "source_generation",
                "pr41_commit",
                "pr41_tree",
                "backup_generation",
                "manifest_identity",
                "backup_digest",
            }
            and value.get("lifecycle_generation") == lifecycle_generation
            and value.get("source_generation")
            == record.get("pr41_restore", {}).get("generation")
            and value.get("pr41_commit") == PR41_RESTORE_COMMIT
            and value.get("pr41_tree") == PR41_RESTORE_TREE
            and all(
                isinstance(value.get(name), str)
                and re.fullmatch(r"[0-9a-f]{32}", value[name]) is not None
                for name in (
                    "lifecycle_generation",
                    "source_generation",
                    "backup_generation",
                )
            )
            and all(
                isinstance(value.get(name), str)
                and re.fullmatch(r"[0-9a-f]{64}", value[name]) is not None
                for name in ("manifest_identity", "backup_digest")
            )
        )

    def bind_baseline_backup(self, result: BackupResult) -> None:
        identity = {
            "lifecycle_generation": result.lifecycle_generation,
            "source_generation": result.source_generation,
            "pr41_commit": PR41_RESTORE_COMMIT,
            "pr41_tree": PR41_RESTORE_TREE,
            "backup_generation": result.backup_generation,
            "manifest_identity": result.manifest_identity,
            "backup_digest": result.backup_digest,
        }
        if not self._backup_identity_valid(
            identity, self._record["lifecycle_generation"], self._record
        ):
            raise LifecycleControllerError(
                "LIFECYCLE_BACKUP_IDENTITY_INVALID"
            ) from None
        candidate = copy.deepcopy(self._record)
        if candidate["baseline_backup_identity"] is not None:
            raise LifecycleControllerError(
                "LIFECYCLE_BACKUP_ALREADY_VERIFIED"
            ) from None
        candidate["baseline_backup_identity"] = identity
        candidate["revision"] = self._record["revision"] + 1
        self._write_record(candidate)
        self._advance_anchor_revision(candidate["revision"], identity)
        self._record = candidate

    @property
    def lifecycle_generation(self) -> str:
        return self._record["lifecycle_generation"]

    @property
    def source_generation(self) -> str:
        return self._record["source_generation"]

    @property
    def baseline_backup_identity(self) -> dict[str, object] | None:
        value = self._record["baseline_backup_identity"]
        return None if value is None else copy.deepcopy(value)

    @property
    def state(self) -> LifecycleState:
        return LifecycleState(self._record["stage"])

    @property
    def recovery_mode(self) -> bool:
        return self._record["recovery_mode"] is True

    @property
    def research_succeeded(self) -> bool:
        return self._record["research_succeeded"] is True

    @property
    def consumed_actions(self) -> frozenset[LifecycleAction]:
        return frozenset(
            LifecycleAction(value) for value in self._record["consumed_operations"]
        )

    def action_transition_committed(self, action: LifecycleAction) -> bool:
        operation = next(
            (
                item
                for item in self._record["operations"]
                if item["action"] == action.value
            ),
            None,
        )
        return (
            operation is not None
            and operation["phase"] == "transition_committed"
            and any(
                transition["action"] == action.value
                and LifecycleState(transition["stage"])
                in _LIFECYCLE_ACTION_SUCCESSORS[action]
                for transition in self._record["transitions"]
            )
        )

    @property
    def transitions(self) -> tuple[dict[str, object], ...]:
        return tuple(copy.deepcopy(self._record["transitions"]))

    def record_intent(
        self,
        action: LifecycleAction,
        *,
        source_generation: str,
        nonce: str | None,
    ) -> None:
        def mutate(record: dict[str, object]) -> None:
            if (
                LifecycleState(record["stage"])
                not in _LIFECYCLE_ACTION_PREDECESSORS[action]
            ):
                raise LifecycleControllerError("LIFECYCLE_TRANSITION_INVALID") from None
            expected_source = record["source_generation"]
            if action in _CANDIDATE_SOURCE_ACTIONS:
                expected_source = record["pr45_source"]["generation"]
            elif action in _PR41_BOUND_ACTIONS:
                expected_source = record["pr41_restore"]["generation"]
            if source_generation != expected_source:
                raise LifecycleControllerError(
                    "LIFECYCLE_SOURCE_GENERATION_INVALID"
                ) from None
            if action.value in record["consumed_operations"]:
                raise LifecycleControllerError("LIFECYCLE_PERMIT_CONSUMED") from None
            record["consumed_operations"].append(action.value)
            if action in {
                LifecycleAction.A0,
                LifecycleAction.P0,
                LifecycleAction.AP0,
                LifecycleAction.PREFLIGHT,
                LifecycleAction.A1,
                LifecycleAction.A2,
            }:
                record["helper_tombstones"].append(action.value)
            if action in {
                LifecycleAction.ACTIVATION_RESTART,
                LifecycleAction.REMOVAL_RESTART,
            }:
                record["restart_tombstones"].append(action.value)
            if action in {
                LifecycleAction.CANDIDATE_CORE_CHECK_1,
                LifecycleAction.CANDIDATE_CORE_CHECK_2,
            }:
                record["core_check_attempts"]["candidate"].append(
                    1 if action is LifecycleAction.CANDIDATE_CORE_CHECK_1 else 2
                )
            if action in {
                LifecycleAction.RESTORE_CORE_CHECK_1,
                LifecycleAction.RESTORE_CORE_CHECK_2,
            }:
                record["core_check_attempts"]["restore"].append(
                    1 if action is LifecycleAction.RESTORE_CORE_CHECK_1 else 2
                )
            if action is LifecycleAction.PREFLIGHT:
                record["known_nonce"] = nonce
            if action is LifecycleAction.BACKUP_FALLBACK:
                record["fallback_phase"] = FallbackPhase.INTENT_DURABLE.value
            record["operations"].append(
                {
                    "action": action.value,
                    "phase": "intent_durable",
                    "source_generation": source_generation,
                    "nonce": nonce,
                }
            )

        self._commit(mutate)

    def _set_operation_phase(self, action: LifecycleAction, phase: str) -> None:
        def mutate(record: dict[str, object]) -> None:
            matches = [
                operation
                for operation in record["operations"]
                if operation["action"] == action.value
            ]
            if len(matches) != 1:
                raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
            matches[0]["phase"] = phase
            if action in {
                LifecycleAction.BACKUP_FALLBACK,
                LifecycleAction.BACKUP_FALLBACK_RECONCILE,
            }:
                if action is LifecycleAction.BACKUP_FALLBACK:
                    record["fallback_phase"] = {
                        "dispatch_started": FallbackPhase.DISPATCH_POSSIBLE.value,
                        "result_durable": (FallbackPhase.RECONCILIATION_REQUIRED.value),
                    }.get(phase, record["fallback_phase"])
                elif phase in {"result_durable", "reconciled"}:
                    record["fallback_phase"] = FallbackPhase.RECONCILED_PR41.value
            if (
                action is LifecycleAction.BACKUP_FALLBACK_RECONCILE
                and phase == "dispatch_started"
            ):
                attempts = record["fallback_reconciliation_attempts"]
                if not _exact_non_bool_int(attempts, maximum=7):
                    raise LifecycleControllerError(
                        "LIFECYCLE_RECONCILIATION_LIMIT"
                    ) from None
                record["fallback_reconciliation_attempts"] = attempts + 1

        self._commit(mutate)

    def record_dispatch_started(self, action: LifecycleAction) -> None:
        self._set_operation_phase(action, "dispatch_started")

    def record_ambiguous(self, action: LifecycleAction) -> None:
        def mutate(record: dict[str, object]) -> None:
            matches = [
                operation
                for operation in record["operations"]
                if operation["action"] == action.value
            ]
            if len(matches) != 1:
                raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
            matches[0]["phase"] = "ambiguous"
            record["ambiguous_operation"] = action.value
            record["recovery_mode"] = True
            record["rollback_mode"] = True
            if action in {
                LifecycleAction.BACKUP_FALLBACK,
                LifecycleAction.BACKUP_FALLBACK_RECONCILE,
            }:
                record["fallback_phase"] = FallbackPhase.RECONCILIATION_REQUIRED.value

        self._commit(mutate)

    def record_fallback_reconciled(self) -> None:
        self._set_operation_phase(
            LifecycleAction.BACKUP_FALLBACK_RECONCILE, "reconciled"
        )

    @property
    def fallback_reconciliation_resumable(self) -> bool:
        operation = next(
            (
                item
                for item in self._record["operations"]
                if item["action"] == LifecycleAction.BACKUP_FALLBACK_RECONCILE.value
            ),
            None,
        )
        return (
            self._record["fallback_phase"]
            == FallbackPhase.RECONCILIATION_REQUIRED.value
            and operation is not None
            and operation["phase"] == "ambiguous"
            and self._record["fallback_reconciliation_attempts"] < 8
        )

    def record_result(
        self,
        action: LifecycleAction,
        *,
        lifecycle_generation: str,
        source_generation: str,
        session_generation: str,
        issuance_identity: str,
        audit_instance: str | None,
        nonce: str | None,
        evidence: object = None,
    ) -> int:
        generation = self._record["evidence_generation"] + 1

        def mutate(record: dict[str, object]) -> None:
            matches = [
                operation
                for operation in record["operations"]
                if operation["action"] == action.value
            ]
            if len(matches) != 1:
                raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
            matches[0]["phase"] = (
                "reconciled"
                if action is LifecycleAction.BACKUP_FALLBACK_RECONCILE
                else "result_durable"
            )
            if action is LifecycleAction.BACKUP_FALLBACK_RECONCILE:
                if not (
                    isinstance(evidence, FallbackReconciliationResult)
                    and _exact_non_bool_int(evidence.file_count)
                    and (
                        evidence.phase == "reconciled"
                        and evidence.restoration_applied is True
                        and evidence.manifest_match is True
                        and evidence.file_count >= 1
                        or evidence.phase == "reconciled_candidate"
                        and evidence.restoration_applied is False
                        and evidence.manifest_match is False
                        and evidence.file_count >= 1
                        or evidence.phase == "reconciled_unknown"
                        and evidence.restoration_applied is False
                        and evidence.manifest_match is False
                    )
                ):
                    raise LifecycleControllerError(
                        "LIFECYCLE_FALLBACK_RECONCILIATION_INVALID"
                    ) from None
                try:
                    record["fallback_phase"] = {
                        "reconciled": FallbackPhase.RECONCILED_PR41,
                        "reconciled_candidate": FallbackPhase.RECONCILED_CANDIDATE,
                        "reconciled_unknown": FallbackPhase.RECONCILED_UNKNOWN,
                    }[evidence.phase].value
                except KeyError:
                    raise LifecycleControllerError(
                        "LIFECYCLE_FALLBACK_RECONCILIATION_INVALID"
                    ) from None
                matches[0]["phase"] = "transition_committed"
                if evidence.phase == "reconciled":
                    target = LifecycleState.PR41_RESTORED
                    record["source_generation"] = record["pr41_restore"]["generation"]
                elif evidence.phase == "reconciled_candidate":
                    target = LifecycleState(record["stage"])
                else:
                    target = LifecycleState.MANUAL_RECOVERY_REQUIRED
                    record["active"] = False
                    record["terminal"] = target.value
                record["stage"] = target.value
                record["recovery_mode"] = True
                record["rollback_mode"] = True
                record["ambiguous_operation"] = None
                record["transitions"].append(
                    {
                        "sequence": len(record["transitions"]),
                        "stage": target.value,
                        "action": action.value,
                        "source_generation": record["source_generation"],
                        "evidence_generation": generation,
                    }
                )
            record["evidence_generation"] = generation
            record["evidence_identities"].append(
                {
                    "generation": generation,
                    "lifecycle_generation": lifecycle_generation,
                    "action": action.value,
                    "source_generation": source_generation,
                    "session_generation": session_generation,
                    "issuance_identity": issuance_identity,
                    "audit_instance": audit_instance,
                    "nonce": nonce,
                }
            )
            if (
                action
                in {
                    LifecycleAction.BACKUP,
                    LifecycleAction.BACKUP_RECONCILE,
                }
                and evidence is not None
            ):
                if not isinstance(evidence, BackupResult):
                    raise LifecycleControllerError(
                        "LIFECYCLE_BACKUP_IDENTITY_INVALID"
                    ) from None
                identity = {
                    "lifecycle_generation": evidence.lifecycle_generation,
                    "source_generation": evidence.source_generation,
                    "pr41_commit": PR41_RESTORE_COMMIT,
                    "pr41_tree": PR41_RESTORE_TREE,
                    "backup_generation": evidence.backup_generation,
                    "manifest_identity": evidence.manifest_identity,
                    "backup_digest": evidence.backup_digest,
                }
                if not self._backup_identity_valid(
                    identity, record["lifecycle_generation"], record
                ):
                    raise LifecycleControllerError(
                        "LIFECYCLE_BACKUP_IDENTITY_INVALID"
                    ) from None
                record["baseline_backup_identity"] = identity
                matches[0]["phase"] = "transition_committed"
                record["stage"] = LifecycleState.BACKUP_VERIFIED.value
                record["source_generation"] = record["pr41_restore"]["generation"]
                record["recovery_mode"] = False
                record["rollback_mode"] = False
                record["ambiguous_operation"] = None
                record["transitions"].append(
                    {
                        "sequence": len(record["transitions"]),
                        "stage": LifecycleState.BACKUP_VERIFIED.value,
                        "action": action.value,
                        "source_generation": record["source_generation"],
                        "evidence_generation": generation,
                    }
                )

        self._commit(mutate)
        return generation

    def transition(
        self,
        state: LifecycleState,
        *,
        action: LifecycleAction | None,
        source_generation: str,
        evidence_generation: int | None,
        recovery: bool = False,
        terminal: bool = False,
    ) -> None:
        def mutate(record: dict[str, object]) -> None:
            if action is not None:
                matches = [
                    operation
                    for operation in record["operations"]
                    if operation["action"] == action.value
                ]
                if len(matches) != 1:
                    raise LifecycleControllerError(
                        "LIFECYCLE_JOURNAL_INVALID"
                    ) from None
                matches[0]["phase"] = "transition_committed"
            record["stage"] = state.value
            record["source_generation"] = source_generation
            record["recovery_mode"] = record["recovery_mode"] is True or recovery
            record["rollback_mode"] = record["rollback_mode"] is True or recovery
            if state is LifecycleState.A2_COLLECTED and not record["recovery_mode"]:
                record["research_succeeded"] = True
            record["transitions"].append(
                {
                    "sequence": len(record["transitions"]),
                    "stage": state.value,
                    "action": None if action is None else action.value,
                    "source_generation": source_generation,
                    "evidence_generation": evidence_generation,
                }
            )
            if terminal:
                record["terminal"] = state.value
                record["active"] = False

        self._commit(mutate)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        descriptor = self._lock_fd
        self._lock_fd = None
        failures: list[OSError] = []
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError as error:
                failures.append(error)
            try:
                os.close(descriptor)
            except OSError as error:
                failures.append(error)
        root_descriptor = self._root_fd
        self._root_fd = None
        if root_descriptor is not None:
            try:
                os.close(root_descriptor)
            except OSError as error:
                failures.append(error)
        parent_descriptor = self._parent_fd
        self._parent_fd = None
        if parent_descriptor is not None:
            try:
                os.close(parent_descriptor)
            except OSError as error:
                failures.append(error)
        if failures:
            raise failures[0]


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


def validate_source_manifest(manifest: SourceManifest) -> None:
    """Admit one exact authority-bound manifest without requiring file content."""
    if not isinstance(manifest, SourceManifest) or not isinstance(
        manifest.state, SourceState
    ):
        raise SourceBundleError("SOURCE_BUNDLE_MANIFEST_MISMATCH") from None
    entries = manifest.entries
    if type(entries) is not tuple or not entries or len(entries) > _MAX_SOURCE_FILES:
        raise SourceBundleError("SOURCE_BUNDLE_MANIFEST_MISMATCH") from None
    if any(type(entry) is not SourceManifestEntry for entry in entries):
        raise SourceBundleError("SOURCE_BUNDLE_MANIFEST_MISMATCH") from None
    paths = [entry.relative_path for entry in entries]
    if len(paths) != len(set(paths)):
        raise SourceBundleError("SOURCE_BUNDLE_DUPLICATE_FILE") from None
    if any(not _source_path_allowed(path, manifest.state) for path in paths):
        raise SourceBundleError("SOURCE_BUNDLE_UNEXPECTED_FILE") from None
    if manifest.state is SourceState.CANDIDATE and not _HELPER_FILES.issubset(paths):
        raise SourceBundleError("SOURCE_BUNDLE_MANIFEST_MISMATCH") from None
    if any(
        type(entry.size) is not int
        or entry.size < 0
        or not isinstance(entry.sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", entry.sha256) is None
        for entry in entries
    ):
        raise SourceBundleError("SOURCE_BUNDLE_MANIFEST_MISMATCH") from None
    if (
        _source_manifest_digest(entries)
        != _AUTHORITY_MANIFEST_DIGESTS[manifest.state.value]
    ):
        raise SourceBundleError("SOURCE_BUNDLE_AUTHORITY_MISMATCH") from None


def build_source_bundle(
    state: SourceState,
    files: Iterable[SourceBundleFile],
    expected_manifest: SourceManifest,
) -> SourceBundle:
    """Admit only a complete bounded bundle matching the trusted manifest."""
    if (
        not isinstance(state, SourceState)
        or not isinstance(expected_manifest, SourceManifest)
        or expected_manifest.state is not state
    ):
        raise SourceBundleError("SOURCE_BUNDLE_AUTHORITY_MISMATCH") from None
    validate_source_manifest(expected_manifest)
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


def _backup_context_payload(
    manifest: SourceManifest, capability: _LifecycleCapability
) -> dict[str, object]:
    if manifest.state is not SourceState.RESTORE:
        raise SourceBundleError("RESTORE_MANIFEST_REQUIRED") from None
    validate_source_manifest(manifest)
    payload = {
        "lifecycle_generation": str(capability.lifecycle_generation),
        "source_generation": str(capability.source_generation),
        "source_state": "PR41_BASELINE",
        "manifest": _manifest_payload(manifest),
    }
    if (
        capability.action
        in {
            LifecycleAction.BACKUP_FALLBACK,
            LifecycleAction.BACKUP_FALLBACK_RECONCILE,
        }
        and capability.backup_identity is not None
    ):
        identity = capability.backup_identity
        if not (
            type(identity) is dict
            and identity.get("lifecycle_generation")
            == str(capability.lifecycle_generation)
            and identity.get("source_generation") == str(capability.source_generation)
            and all(
                isinstance(identity.get(name), str)
                and re.fullmatch(pattern, identity[name]) is not None
                for name, pattern in (
                    ("backup_generation", r"[0-9a-f]{32}"),
                    ("manifest_identity", r"[0-9a-f]{64}"),
                    ("backup_digest", r"[0-9a-f]{64}"),
                )
            )
        ):
            raise SourceBundleError("BACKUP_IDENTITY_REQUIRED") from None
        payload.update(
            {
                "backup_generation": identity["backup_generation"],
                "manifest_identity": identity["manifest_identity"],
                "backup_digest": identity["backup_digest"],
            }
        )
    return payload


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object while rejecting duplicate member names."""
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_member")
        value[key] = item
    return value


def _strict_json_loads(value: str | bytes) -> Any:
    """Decode JSON without silently normalizing duplicate object members."""
    return json.loads(value, object_pairs_hook=_reject_duplicate_json_pairs)


def _exact_payload(private_output: bytes) -> dict[str, Any]:
    extracted = _extract_exact_framed_json_object(private_output)
    if extracted is None:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    try:
        payload = _strict_json_loads(extracted)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    if not isinstance(payload, dict) or "error_class" in payload:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return payload


def _parse_backup_result(private_output: bytes) -> BackupResult:
    value = _exact_payload(private_output)
    if set(value) != {
        "success",
        "file_count",
        "manifest_match",
        "regular_files_only",
        "lifecycle_generation",
        "source_generation",
        "backup_generation",
        "manifest_identity",
        "backup_digest",
    }:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    try:
        result = BackupResult(
            _bool(value["success"]),
            _count(value["file_count"]),
            _bool(value["manifest_match"]),
            _bool(value["regular_files_only"]),
            *(
                value[name]
                for name in (
                    "lifecycle_generation",
                    "source_generation",
                    "backup_generation",
                    "manifest_identity",
                    "backup_digest",
                )
            ),
        )
    except (KeyError, TypeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    if any(
        not isinstance(getattr(result, name), str)
        or re.fullmatch(r"[0-9a-f]{32}", getattr(result, name)) is None
        for name in (
            "lifecycle_generation",
            "source_generation",
            "backup_generation",
        )
    ) or any(
        not isinstance(getattr(result, name), str)
        or re.fullmatch(r"[0-9a-f]{64}", getattr(result, name)) is None
        for name in ("manifest_identity", "backup_digest")
    ):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return result


def _exact_core_check_payload(private_output: bytes) -> dict[str, Any]:
    """Decode only the Core-check allowlist, including a generic error class."""
    extracted = _extract_exact_framed_json_object(private_output)
    if extracted is None:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    try:
        payload = _strict_json_loads(extracted)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
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
        type(status) is not int
        or not isinstance(result, str)
        or "check_passed" in value
        and type(passed) is not bool
        or error_class is not None
        and (
            not isinstance(error_class, str)
            or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", error_class) is None
        )
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
        "result",
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
            value["result"] != "audit_snapshot"
            or type(value["protocol_version"]) is not int
            or value["protocol_version"] != 1
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
    if "exit_code" not in value or "outcome" not in value:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    exit_code = value["exit_code"]
    outcome = value["outcome"]
    nonce = value.get("nonce")
    if (
        type(exit_code) is not int
        or exit_code not in {0, 65, 66, 67, 78}
        or not isinstance(outcome, str)
        or nonce is not None
        and (not isinstance(nonce, str) or not _NONCE.fullmatch(nonce))
    ):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None

    preflight = None
    receipt = None
    audit = None
    if exit_code == 65:
        if set(value) != {"exit_code", "outcome"} or outcome != "not_submitted":
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    elif exit_code in {67, 78}:
        expected_outcomes = (
            {"schema_invalid", "nonce_mismatch", "evidence_write_failed"}
            if exit_code == 67
            else {"transport_ambiguous"}
        )
        if (
            set(value) != {"exit_code", "outcome", "nonce"}
            or nonce is None
            or outcome not in expected_outcomes
        ):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    elif operation is PhaseAOperation.PREFLIGHT:
        item = value.get("preflight")
        if (
            exit_code != 0
            or outcome != "preflight_ok"
            or set(value) != {"exit_code", "outcome", "nonce", "preflight"}
            or nonce is None
            or not isinstance(item, dict)
            or set(item) != {"result", "protocol_version", "nonce"}
            or item["result"] != "preflight_ok"
            or type(item["protocol_version"]) is not int
            or item["protocol_version"] != 1
            or item["nonce"] != nonce
        ):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        preflight = PreflightResponse("preflight_ok", 1, nonce)
    elif operation is PhaseAOperation.RECEIPT:
        item = value.get("receipt")
        receipt_keys = {
            "nonce",
            "known",
            "service_entered",
            "request_handed_to_transport",
            "terminal_class",
            "response_available",
        }
        if (
            exit_code not in {0, 66}
            or outcome != "receipt"
            or set(value) != {"exit_code", "outcome", "nonce", "receipt"}
            or nonce is None
            or not isinstance(item, dict)
            or set(item) != receipt_keys
            or item["nonce"] != nonce
            or any(
                type(item[key]) is not bool
                for key in (
                    "known",
                    "service_entered",
                    "request_handed_to_transport",
                    "response_available",
                )
            )
            or item["terminal_class"] is not None
            and (
                not isinstance(item["terminal_class"], str)
                or len(item["terminal_class"]) > 64
            )
            or exit_code == 0
            and item["known"] is not True
            or exit_code == 66
            and item
            != {
                "nonce": nonce,
                "known": False,
                "service_entered": False,
                "request_handed_to_transport": False,
                "terminal_class": None,
                "response_available": False,
            }
        ):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        receipt = ReceiptResponse(**item)
    elif operation is PhaseAOperation.AUDIT:
        if (
            exit_code != 0
            or outcome != "audit_snapshot"
            or set(value) != {"exit_code", "outcome", "nonce", "audit"}
            or nonce is None
        ):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        audit = _parse_audit_snapshot(value["audit"])
        if audit.nonce != nonce:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    else:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None

    if expected_nonce is not None and nonce != expected_nonce:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return PhaseAResult(
        operation=operation,
        exit_code=exit_code,
        outcome=outcome,
        nonce=nonce,
        preflight=preflight,
        receipt=receipt,
        audit=audit,
    )


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
        payload = _strict_json_loads(response)
    except (TypeError, json.JSONDecodeError, ValueError):
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


def _fixed_repairs_evidence(response: str) -> RepairsEvidence:
    """Project Repairs internally; any issue is conservatively blocking."""
    decoded = decode_repairs_response(response)
    if decoded.shape_valid is not True or decoded.issues is None:
        return RepairsEvidence(False, None, None)
    count = len(decoded.issues)
    return RepairsEvidence(True, count, count)


def _extract_exact_framed_json_object(private_output: bytes) -> str | None:
    """Decode exactly one JSON object from a broker-bounded private payload."""
    try:
        text = private_output.decode("utf-8").strip(" \t\r\n")
        value = _strict_json_loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
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
import re
import shutil
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path('/config')
ROOT_FD = None
INTEGRATION = ROOT / 'custom_components' / 'tuya_ble'
HELPER = INTEGRATION / '.phase_a_tools'
STAGE = ROOT / '.ha_tuya_ble_r30_stage'
BACKUP = ROOT / '.ha_tuya_ble_r36_backup'
BACKUP_CONSUMED = ROOT / '.ha_tuya_ble_r36_backup.consumed'
BACKUP_METADATA_NAME = 'metadata.json'
RESTORE_CONSUMED = ROOT / '.ha_tuya_ble_r30_restore.consumed'
EVIDENCE = Path('/var/lib/phase-a-status-probe')
SERVICES = {
    'phase_a_status_probe',
    'phase_a_status_probe_preflight',
    'phase_a_status_probe_receipt',
    'phase_a_status_probe_audit',
}
COUNTERS = {
    'connect_attempts', 'gatt_sessions_claimed', 'authenticated_sessions',
    'packets_sent_total', 'device_status_requests', 'device_info_requests',
    'pair_requests', 'datapoint_write_operations',
    'datapoint_protocol_packets', 'other_packets', 'reconnect_schedules',
    'disconnects',
}

def reject_duplicate_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate_json_member')
        value[key] = item
    return value

def decode_json(value):
    return json.loads(value, object_pairs_hook=reject_duplicate_pairs)

def receive():
    count = int(sys.stdin.readline())
    if count < 1 or count > 4096:
        raise ValueError('chunks')
    encoded = ''.join(sys.stdin.readline().strip() for _ in range(count))
    if len(encoded) > 6 * 1024 * 1024:
        raise ValueError('size')
    value = decode_json(base64.b64decode(encoded, validate=True))
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
    if not isinstance(value, dict) or 'manifest' not in value:
        raise ValueError('manifest')
    manifest = value['manifest']
    if not isinstance(manifest, dict) or set(manifest) != {
        'state', 'authority_commit', 'authority_tree', 'entries'
    }:
        raise ValueError('manifest')
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
    if not isinstance(manifest['entries'], list) or not manifest['entries']:
        raise ValueError('manifest')
    expected = {}
    for entry in manifest['entries']:
        if not isinstance(entry, dict) or set(entry) != {'path', 'size', 'sha256'}:
            raise ValueError('manifest')
        path = str(safe_path(entry['path'], state))
        size = entry['size']
        digest = entry['sha256']
        if path in expected or type(size) is not int or size < 0:
            raise ValueError('manifest')
        if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
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

def open_root_relative(path):
    try:
        parts = path.relative_to(ROOT).parts
    except ValueError:
        raise ValueError('root')
    if ROOT_FD is None:
        raise ValueError('root')
    descriptor = os.dup(ROOT_FD)
    try:
        for part in parts:
            if part in {'', '.', '..'}:
                raise ValueError('root')
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

def replace_root_relative(source, destination):
    source_parent = open_root_relative(source.parent)
    destination_parent = open_root_relative(destination.parent)
    try:
        os.replace(
            source.name,
            destination.name,
            src_dir_fd=source_parent,
            dst_dir_fd=destination_parent,
        )
    finally:
        os.close(source_parent)
        os.close(destination_parent)

def root_relative_exists(path):
    parent = open_root_relative(path.parent)
    try:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True
    finally:
        os.close(parent)

def assert_root_relative_identity(path, descriptor):
    current = open_root_relative(path)
    try:
        expected = os.fstat(descriptor)
        observed = os.fstat(current)
        if expected.st_dev != observed.st_dev or expected.st_ino != observed.st_ino:
            raise ValueError('directory')
    finally:
        os.close(current)

def inventory_fd(descriptor, prefix, excluded_top=None, relative=()):
    observed = {}
    for name in sorted(os.listdir(descriptor)):
        if not relative and name == excluded_top:
            continue
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        logical_parts = relative + (name,)
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(child)
                if (
                    opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or not stat.S_ISDIR(opened.st_mode)
                ):
                    raise ValueError('directory')
                observed.update(
                    inventory_fd(child, prefix, excluded_top, logical_parts)
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (
                    opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                ):
                    raise ValueError('regular')
                content = bytearray()
                while True:
                    chunk = os.read(child, 65536)
                    if not chunk:
                        break
                    content.extend(chunk)
                closed = os.fstat(child)
                if (
                    closed.st_dev != opened.st_dev
                    or closed.st_ino != opened.st_ino
                    or closed.st_size != len(content)
                ):
                    raise ValueError('regular')
            finally:
                os.close(child)
            logical = prefix + '/' + PurePosixPath(*logical_parts).as_posix()
            observed[logical] = (
                len(content), hashlib.sha256(content).hexdigest()
            )
        else:
            raise ValueError('regular')
    return observed

def inventory_root(root, prefix, excluded_top=None):
    try:
        descriptor = open_root_relative(root)
    except FileNotFoundError:
        return {}
    try:
        return inventory_fd(descriptor, prefix, excluded_top)
    finally:
        os.close(descriptor)

def inventory_deployment_fd(descriptor):
    observed = inventory_fd(descriptor, 'integration', '.phase_a_tools')
    try:
        helper = open_relative_directory(descriptor, ('.phase_a_tools',))
    except FileNotFoundError:
        return observed
    try:
        observed.update(inventory_fd(helper, 'helper'))
    finally:
        os.close(helper)
    return observed

def inventory_targets():
    try:
        descriptor = open_root_relative(INTEGRATION)
    except FileNotFoundError:
        return {}
    try:
        observed = inventory_deployment_fd(descriptor)
        assert_root_relative_identity(INTEGRATION, descriptor)
        return observed
    finally:
        os.close(descriptor)

def inventory_deployment(root):
    try:
        descriptor = open_root_relative(root)
    except FileNotFoundError:
        return {}
    try:
        observed = inventory_deployment_fd(descriptor)
        assert_root_relative_identity(root, descriptor)
        return observed
    finally:
        os.close(descriptor)

def open_relative_directory(descriptor, parts, create=False):
    current = os.dup(descriptor)
    try:
        for part in parts:
            if part in {'', '.', '..'}:
                raise ValueError('path')
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise

def copy_deployment_fd(source_fd, destination_fd, expected):
    for logical in sorted(expected):
        prefix, relative = logical.split('/', 1)
        parts = PurePosixPath(relative).parts
        if prefix == 'helper':
            parts = ('.phase_a_tools',) + parts
        elif prefix != 'integration':
            raise ValueError('path')
        source_parent = open_relative_directory(source_fd, parts[:-1])
        destination_parent = open_relative_directory(
            destination_fd, parts[:-1], create=True
        )
        try:
            source_file = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_parent
            )
            destination_file = None
            try:
                destination_file = os.open(
                    parts[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=destination_parent,
                )
                source_metadata = os.fstat(source_file)
                if (
                    not stat.S_ISREG(source_metadata.st_mode)
                    or source_metadata.st_nlink != 1
                ):
                    raise ValueError('regular')
                digest = hashlib.sha256()
                size = 0
                while True:
                    chunk = os.read(source_file, 65536)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                    offset = 0
                    while offset < len(chunk):
                        written = os.write(destination_file, chunk[offset:])
                        if written <= 0:
                            raise OSError(errno.EIO, 'short_write')
                        offset += written
                os.fchmod(destination_file, 0o600)
                os.fsync(destination_file)
                after = os.fstat(source_file)
                if (
                    after.st_dev != source_metadata.st_dev
                    or after.st_ino != source_metadata.st_ino
                    or after.st_size != size
                    or (size, digest.hexdigest()) != expected[logical]
                ):
                    raise ValueError('manifest')
            finally:
                os.close(source_file)
                if destination_file is not None:
                    os.close(destination_file)
        finally:
            os.close(source_parent)
            os.close(destination_parent)

def copy_deployment(source, destination, expected):
    source_fd = open_root_relative(source)
    destination_fd = open_root_relative(destination)
    try:
        copy_deployment_fd(source_fd, destination_fd, expected)
    finally:
        os.close(source_fd)
        os.close(destination_fd)

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

def inventory_identity(observed):
    canonical = ''.join(
        path + '\0' + str(size) + '\0' + digest + '\n'
        for path, (size, digest) in sorted(observed.items())
    ).encode()
    return {
        'file_count': len(observed),
        'manifest_identity': hashlib.sha256(canonical).hexdigest(),
    }

def sync_root():
    if ROOT_FD is None:
        raise ValueError('root')
    os.fsync(ROOT_FD)

def sync_directory(path):
    descriptor = open_root_relative(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def write_private_json(path, value):
    pending = path.with_name(path.name + '.pending')
    payload = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(payload) > 4096:
        raise ValueError('private_state')
    parent = open_root_relative(path.parent)
    try:
        try:
            os.unlink(pending.name, dir_fd=parent)
        except FileNotFoundError:
            pass
        descriptor = os.open(
            pending.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(pending.name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        sync_root()
    finally:
        os.close(parent)

def read_private_json_fd(parent, name, keys):
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent
        )
    except OSError:
        raise ValueError('private_state')
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o777 != 0o600
            or metadata.st_size < 2
            or metadata.st_size > 4096
        ):
            raise ValueError('private_state')
        raw = bytearray()
        while len(raw) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(raw))
            if not chunk:
                raise ValueError('private_state')
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != len(raw)
        ):
            raise ValueError('private_state')
    finally:
        os.close(descriptor)
    value = decode_json(bytes(raw))
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('private_state')
    return value

def read_private_json(path, keys):
    parent = open_root_relative(path.parent)
    try:
        return read_private_json_fd(parent, path.name, keys)
    finally:
        os.close(parent)

def validate_backup_context(value):
    base_keys = {
        'lifecycle_generation', 'source_generation', 'source_state', 'manifest'
    }
    identity_keys = {'backup_generation', 'manifest_identity', 'backup_digest'}
    if not isinstance(value, dict) or frozenset(value) not in {
        frozenset(base_keys), frozenset(base_keys | identity_keys)
    }:
        raise ValueError('backup_context')
    if (
        value['source_state'] != 'PR41_BASELINE'
        or not isinstance(value['lifecycle_generation'], str)
        or re.fullmatch('[0-9a-f]{32}', value['lifecycle_generation']) is None
        or not isinstance(value['source_generation'], str)
        or re.fullmatch('[0-9a-f]{32}', value['source_generation']) is None
        or any(
            not isinstance(value.get(name), str)
            or re.fullmatch(pattern, value[name]) is None
            for name, pattern in (
                ('backup_generation', '[0-9a-f]{32}'),
                ('manifest_identity', '[0-9a-f]{64}'),
                ('backup_digest', '[0-9a-f]{64}'),
            )
            if name in value
        )
    ):
        raise ValueError('backup_context')
    state, expected = expected_manifest(value)
    if state != 'restore':
        raise ValueError('backup_context')
    return expected

def backup_digest(value):
    canonical = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(canonical).hexdigest()

def read_backup_identity_fd(context, package_fd):
    value = read_private_json_fd(
        package_fd,
        BACKUP_METADATA_NAME,
        {
            'schema_version', 'lifecycle_generation', 'source_generation',
            'source_state', 'pr41_commit', 'pr41_tree', 'backup_generation',
            'file_count', 'manifest_identity', 'backup_digest'
        },
    )
    identity_fields = {key: item for key, item in value.items() if key != 'backup_digest'}
    if (
        value['schema_version'] != 1
        or value['source_state'] != 'PR41_BASELINE'
        or value['pr41_commit'] != '4f73a9b008dcb89134bc41001c486f06d6056867'
        or value['pr41_tree'] != '463ed8553da01eae591de611e76e45392ad9e7bf'
        or not isinstance(value['lifecycle_generation'], str)
        or re.fullmatch('[0-9a-f]{32}', value['lifecycle_generation']) is None
        or not isinstance(value['source_generation'], str)
        or re.fullmatch('[0-9a-f]{32}', value['source_generation']) is None
        or not isinstance(value['backup_generation'], str)
        or re.fullmatch('[0-9a-f]{32}', value['backup_generation']) is None
        or not isinstance(value['file_count'], int)
        or isinstance(value['file_count'], bool)
        or value['file_count'] < 1
        or not isinstance(value['manifest_identity'], str)
        or re.fullmatch('[0-9a-f]{64}', value['manifest_identity']) is None
        or value['backup_digest'] != backup_digest(identity_fields)
    ):
        raise ValueError('backup_identity')
    if context is not None and (
        value['lifecycle_generation'] != context.get('lifecycle_generation')
        or value['source_generation'] != context.get('source_generation')
        or context.get('source_state') != 'PR41_BASELINE'
        or any(
            value[name] != context.get(name)
            for name in ('backup_generation', 'manifest_identity', 'backup_digest')
            if name in context
        )
    ):
        raise ValueError('backup_identity')
    return value

def read_backup_identity(context=None, package=BACKUP):
    package_fd = open_root_relative(package)
    try:
        return read_backup_identity_fd(context, package_fd)
    finally:
        os.close(package_fd)

def write_fallback_phase(phase, identity):
    if phase not in {'intent_recorded', 'possibly_applied', 'reconciled'}:
        raise ValueError('fallback_phase')
    write_private_json(
        BACKUP_CONSUMED,
        {
            'phase': phase,
            'file_count': identity['file_count'],
            'manifest_identity': identity['manifest_identity'],
        },
    )

def read_fallback_phase(package_identity=None):
    value = read_private_json(
        BACKUP_CONSUMED, {'phase', 'file_count', 'manifest_identity'}
    )
    if value['phase'] not in {'intent_recorded', 'possibly_applied', 'reconciled'}:
        raise ValueError('fallback_phase')
    identity = {
        'file_count': value['file_count'],
        'manifest_identity': value['manifest_identity'],
    }
    package = (
        read_backup_identity()
        if package_identity is None
        else package_identity
    )
    if (
        identity['file_count'] != package['file_count']
        or identity['manifest_identity'] != package['manifest_identity']
    ):
        raise ValueError('backup_identity')
    return value['phase'], identity

def sync_tree(root):
    descriptor = open_root_relative(root)
    try:
        sync_directory_fd(descriptor)
    finally:
        os.close(descriptor)

def sync_directory_fd(descriptor):
    for name in sorted(os.listdir(descriptor)):
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(child)
                if (
                    opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or not stat.S_ISDIR(opened.st_mode)
                ):
                    raise ValueError('directory')
                sync_directory_fd(child)
            finally:
                os.close(child)
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (
                    opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or opened.st_nlink != 1
                ):
                    raise ValueError('regular')
                os.fsync(child)
            finally:
                os.close(child)
        else:
            raise ValueError('regular')
    os.fsync(descriptor)

def publish_noreplace(source, destination, source_fd):
    if source.parent != ROOT or destination.parent != ROOT:
        raise ValueError('atomic_noreplace')
    function = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    if function is None:
        raise OSError(errno.ENOSYS, 'atomic_noreplace')
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if ROOT_FD is None:
        raise ValueError('root')
    descriptor = os.dup(ROOT_FD)
    destination_fd = None
    try:
        source_identity = os.fstat(source_fd)
        source_entry = os.stat(
            source.name, dir_fd=descriptor, follow_symlinks=False
        )
        if (
            source_entry.st_dev != source_identity.st_dev
            or source_entry.st_ino != source_identity.st_ino
            or not stat.S_ISDIR(source_identity.st_mode)
        ):
            raise ValueError('directory')
        if function(
            descriptor,
            os.fsencode(source.name),
            descriptor,
            os.fsencode(destination.name),
            1,
        ) != 0:
            code = ctypes.get_errno()
            raise OSError(code, 'atomic_noreplace')
        destination_fd = os.open(
            destination.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        destination_identity = os.fstat(destination_fd)
        if (
            destination_identity.st_dev != source_identity.st_dev
            or destination_identity.st_ino != source_identity.st_ino
        ):
            raise ValueError('directory')
        return destination_fd
    except BaseException:
        if destination_fd is not None:
            os.close(destination_fd)
        raise
    finally:
        os.close(descriptor)

def backup(value):
    expected = validate_backup_context(value)
    if root_relative_exists(BACKUP) or root_relative_exists(BACKUP_CONSUMED):
        raise ValueError('backup_exists')
    before = inventory_targets()
    if before != expected:
        raise ValueError('baseline_source')
    pending = BACKUP.with_name(BACKUP.name + '.pending-' + os.urandom(16).hex())
    pending.mkdir(mode=0o700)
    pending_fd = open_root_relative(pending)
    live_fd = staged_fd = package_fd = source_fd = None
    try:
        os.mkdir('integration', mode=0o700, dir_fd=pending_fd)
        live_fd = open_root_relative(INTEGRATION)
        staged_fd = open_relative_directory(pending_fd, ('integration',))
        copy_deployment_fd(live_fd, staged_fd, expected)
        after = inventory_deployment_fd(staged_fd)
        if before != after or after != expected:
            raise ValueError('backup_manifest')
        identity = inventory_identity(after)
        metadata = {
            'schema_version': 1,
            'lifecycle_generation': value['lifecycle_generation'],
            'source_generation': value['source_generation'],
            'source_state': 'PR41_BASELINE',
            'pr41_commit': '4f73a9b008dcb89134bc41001c486f06d6056867',
            'pr41_tree': '463ed8553da01eae591de611e76e45392ad9e7bf',
            'backup_generation': os.urandom(16).hex(),
            **identity,
        }
        metadata['backup_digest'] = backup_digest(metadata)
        payload = json.dumps(metadata, sort_keys=True, separators=(',', ':')).encode('ascii')
        descriptor = os.open(
            BACKUP_METADATA_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=pending_fd,
        )
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError(errno.EIO, 'short_write')
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        sync_directory_fd(pending_fd)
        if read_backup_identity_fd(value, pending_fd) != metadata:
            raise ValueError('backup_identity')
        package_fd = publish_noreplace(pending, BACKUP, pending_fd)
        sync_root()
        pending = None
        published_identity = read_backup_identity_fd(value, package_fd)
        source_fd = open_relative_directory(package_fd, ('integration',))
        published = inventory_deployment_fd(source_fd)
        assert_root_relative_identity(BACKUP, package_fd)
        if published_identity != metadata or published != expected:
            raise ValueError('backup_publication')
        return {
            'success': True,
            'file_count': len(after),
            'manifest_match': True,
            'regular_files_only': True,
            'lifecycle_generation': metadata['lifecycle_generation'],
            'source_generation': metadata['source_generation'],
            'backup_generation': metadata['backup_generation'],
            'manifest_identity': metadata['manifest_identity'],
            'backup_digest': metadata['backup_digest'],
        }
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if package_fd is not None:
            os.close(package_fd)
        if staged_fd is not None:
            os.close(staged_fd)
        if live_fd is not None:
            os.close(live_fd)
        os.close(pending_fd)
        if pending is not None:
            remove(pending)

def reconcile_backup_creation(value):
    expected = validate_backup_context(value)
    package_fd = open_root_relative(BACKUP)
    source_fd = None
    try:
        identity = read_backup_identity_fd(value, package_fd)
        source_fd = open_relative_directory(package_fd, ('integration',))
        packaged = inventory_deployment_fd(source_fd)
        observed_identity = inventory_identity(packaged)
        if (
            packaged != expected
            or inventory_targets() != expected
            or observed_identity['file_count'] != identity['file_count']
            or observed_identity['manifest_identity'] != identity['manifest_identity']
        ):
            raise ValueError('backup_reconciliation')
        assert_root_relative_identity(BACKUP, package_fd)
    finally:
        if source_fd is not None:
            os.close(source_fd)
        os.close(package_fd)
    return {
        'success': True,
        'file_count': identity['file_count'],
        'manifest_match': True,
        'regular_files_only': True,
        'lifecycle_generation': identity['lifecycle_generation'],
        'source_generation': identity['source_generation'],
        'backup_generation': identity['backup_generation'],
        'manifest_identity': identity['manifest_identity'],
        'backup_digest': identity['backup_digest'],
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
        if not isinstance(item, dict) or set(item) != {'path', 'content'}:
            raise ValueError('files')
        logical = str(safe_path(item['path'], state))
        if logical in seen:
            raise ValueError('duplicate')
        seen.add(logical)
        content = base64.b64decode(item['content'], validate=True)
        if (len(content), hashlib.sha256(content).hexdigest()) != expected[logical]:
            raise ValueError('manifest')
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
            os.fsync(descriptor)
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
    replace_root_relative(pending, STAGE)
    sync_root()
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
    left_parent = open_root_relative(left.parent)
    right_parent = open_root_relative(right.parent)
    try:
        if function(
            left_parent,
            os.fsencode(left.name),
            right_parent,
            os.fsencode(right.name),
            2,
        ) != 0:
            code = ctypes.get_errno()
            raise OSError(code, 'atomic_exchange')
    finally:
        os.close(left_parent)
        os.close(right_parent)

def publish_directory_bound(source, destination):
    function = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    if function is None:
        raise OSError(errno.ENOSYS, 'atomic_publish')
    function.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
        ctypes.c_char_p, ctypes.c_uint
    ]
    function.restype = ctypes.c_int
    source_parent = open_root_relative(source.parent)
    destination_parent = open_root_relative(destination.parent)
    source_fd = destination_fd = None
    try:
        source_fd = os.open(
            source.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=source_parent,
        )
        source_identity = os.fstat(source_fd)
        try:
            destination_metadata = os.stat(
                destination.name,
                dir_fd=destination_parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            destination_metadata = None
        if destination_metadata is not None and not stat.S_ISDIR(
            destination_metadata.st_mode
        ):
            raise ValueError('directory')
        flag = 2 if destination_metadata is not None else 1
        if function(
            source_parent,
            os.fsencode(source.name),
            destination_parent,
            os.fsencode(destination.name),
            flag,
        ) != 0:
            code = ctypes.get_errno()
            raise OSError(code, 'atomic_publish')
        os.fsync(source_parent)
        os.fsync(destination_parent)
        sync_root()
        destination_fd = os.open(
            destination.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=destination_parent,
        )
        installed_identity = os.fstat(destination_fd)
        if (
            installed_identity.st_dev != source_identity.st_dev
            or installed_identity.st_ino != source_identity.st_ino
        ):
            raise ValueError('directory')
        return destination_fd
    except BaseException:
        if destination_fd is not None:
            os.close(destination_fd)
        raise
    finally:
        if source_fd is not None:
            os.close(source_fd)
        os.close(source_parent)
        os.close(destination_parent)

def mark_restore_consumed():
    descriptor = os.open(
        RESTORE_CONSUMED,
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
        replace_root_relative(STAGE / 'helper', staged / '.phase_a_tools')
    if inventory_deployment(staged) != expected:
        raise ValueError('assembled')
    if restoring:
        mark_restore_consumed()
    exchanged = INTEGRATION.exists()
    mutated = False
    try:
        if exchanged:
            exchange(staged, INTEGRATION)
        else:
            replace_root_relative(staged, INTEGRATION)
        mutated = True
        installed = inventory_targets()
        if installed != expected:
            raise ValueError('installed')
    except Exception:
        if mutated and exchanged:
            exchange(staged, INTEGRATION)
        elif mutated:
            replace_root_relative(INTEGRATION, staged)
        raise
    remove(STAGE)
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
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError('response_size')
        return response.getcode(), decode_json(body)

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
    if operation not in {'preflight', 'audit'}:
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
    if not invalid:
        label = 'PREFLIGHT' if operation == 'preflight' else label
        if label is None:
            raise ValueError('evidence_label')
        command += ['--evidence-label', label]
    completed = runner.run(
        command, capture_output=True, check=False, timeout=190
    )
    if completed.stderr or completed.returncode not in {0, 65, 66, 67, 78}:
        raise ValueError('helper_exit')
    output = decode_json(completed.stdout)
    expected_output = (
        {'outcome'}
        if completed.returncode == 65
        else {'outcome', 'nonce', 'evidence_written'}
        if completed.returncode == 0
        else {'outcome', 'nonce'}
    )
    if (
        not isinstance(output, dict)
        or set(output) != expected_output
        or not isinstance(output.get('outcome'), str)
        or completed.returncode == 0 and output.get('evidence_written') is not True
        or completed.returncode != 65 and output.get('nonce') != value.get('nonce')
    ):
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
    if not invalid and completed.returncode == 0:
        evidence = EVIDENCE / (operation + '-' + label + '.json')
        response = decode_json(evidence.read_bytes())
        if operation == 'audit':
            if not isinstance(response, dict) or set(response.get('counters', {})) != COUNTERS:
                raise ValueError('audit')
            result['audit'] = response
        else:
            if not isinstance(response, dict) or set(response) != {
                'result', 'protocol_version', 'nonce'
            }:
                raise ValueError('preflight')
            result['preflight'] = response
    return result

def restore_backup(value):
    expected_manifest_value = validate_backup_context(value)
    if root_relative_exists(BACKUP_CONSUMED) or root_relative_exists(
        RESTORE_CONSUMED
    ):
        raise ValueError('backup_consumed')
    package_fd = open_root_relative(BACKUP)
    source_fd = pending_fd = installed_fd = None
    try:
        identity = read_backup_identity_fd(value, package_fd)
        source_fd = open_relative_directory(package_fd, ('integration',))
        expected = inventory_deployment_fd(source_fd)
        observed_identity = inventory_identity(expected)
        if (
            expected != expected_manifest_value
            or observed_identity['file_count'] != identity['file_count']
            or observed_identity['manifest_identity'] != identity['manifest_identity']
        ):
            raise ValueError('backup')
        assert_root_relative_identity(BACKUP, package_fd)
        write_fallback_phase('intent_recorded', identity)
        pending = ROOT / ('.ha_tuya_ble_r36_restore-' + os.urandom(16).hex())
        try:
            pending.mkdir(mode=0o700)
            pending_fd = open_root_relative(pending)
            copy_deployment_fd(source_fd, pending_fd, expected)
            if inventory_deployment_fd(pending_fd) != expected:
                raise ValueError('backup_restore')
            sync_directory_fd(pending_fd)
            assert_root_relative_identity(BACKUP, package_fd)
            os.close(pending_fd)
            pending_fd = None
            write_fallback_phase('possibly_applied', identity)
            installed_fd = publish_directory_bound(pending, INTEGRATION)
            installed = inventory_deployment_fd(installed_fd)
            if installed != expected:
                raise ValueError('backup_restore')
            assert_root_relative_identity(INTEGRATION, installed_fd)
            assert_root_relative_identity(BACKUP, package_fd)
            write_fallback_phase('reconciled', identity)
            try:
                assert_root_relative_identity(INTEGRATION, installed_fd)
                assert_root_relative_identity(BACKUP, package_fd)
            except BaseException:
                write_fallback_phase('possibly_applied', identity)
                raise
        finally:
            remove(pending)
    finally:
        if installed_fd is not None:
            os.close(installed_fd)
        if pending_fd is not None:
            os.close(pending_fd)
        if source_fd is not None:
            os.close(source_fd)
        os.close(package_fd)
    return {
        'installation_success': True,
        'expected_file_count': len(expected),
        'installed_file_count': len(installed),
        'manifest_match': True,
    }

def reconcile_backup(value):
    expected = validate_backup_context(value)
    package_fd = open_root_relative(BACKUP)
    source_fd = None
    try:
        package_identity = read_backup_identity_fd(value, package_fd)
        _phase, identity = read_fallback_phase(package_identity)
        source_fd = open_relative_directory(package_fd, ('integration',))
        packaged = inventory_deployment_fd(source_fd)
        observed_identity = inventory_identity(packaged)
        if (
            packaged != expected
            or observed_identity['file_count'] != package_identity['file_count']
            or observed_identity['manifest_identity'] != package_identity['manifest_identity']
            or identity['file_count'] != package_identity['file_count']
            or identity['manifest_identity'] != package_identity['manifest_identity']
        ):
            raise ValueError('backup_reconciliation')
        assert_root_relative_identity(BACKUP, package_fd)
    finally:
        if source_fd is not None:
            os.close(source_fd)
        os.close(package_fd)
    live = inventory_targets()
    live_identity = inventory_identity(live)['manifest_identity']
    live_matches = live == expected
    if live_matches:
        result_phase = 'reconciled'
    elif live_identity == '4b7d4222c57377a29961d35a7427ebc1b6dd032a82a9274a63a0f0269e13a20e':
        result_phase = 'reconciled_candidate'
    else:
        result_phase = 'reconciled_unknown'
    return {
        'phase': result_phase,
        'restoration_applied': live_matches,
        'manifest_match': live_matches,
        'file_count': len(live),
    }

ROOT_FD = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
root_metadata = os.fstat(ROOT_FD)
if not stat.S_ISDIR(root_metadata.st_mode):
    raise ValueError('root')
value = receive()
operation = sys.argv[1]
try:
    if operation == 'backup':
        result = backup(value)
    elif operation == 'reconcile_backup_creation':
        result = reconcile_backup_creation(value)
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
        result = restore_backup(value)
    elif operation == 'reconcile_backup':
        result = reconcile_backup(value)
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
        self._controller_binding: _ControllerBinding | None = None
        self.__wire_issuer = object()

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

    def _register_lifecycle_controller(
        self,
        controller: object,
        lifecycle_generation: object,
        session_generation: object,
    ) -> object:
        """Register one exact controller identity for the active broker session."""
        if (
            self._state is not BrokerState.SESSION_ACTIVE
            or self._session_generation is not session_generation
            or self._controller_binding is not None
            or controller.__class__ is not FullPreflightLifecycleController
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_CONTROLLER_BINDING_INVALID"
            ) from None
        issuer = _CapabilityIssuer(object(), [], [])
        self._controller_binding = _ControllerBinding(
            controller,
            issuer,
            lifecycle_generation,
            session_generation,
        )
        return issuer

    def _require_capability(
        self,
        capability: object,
        expected_actions: frozenset[LifecycleAction],
        *,
        consume: bool = False,
    ) -> _LifecycleCapability:
        """Validate every binding dimension and optionally consume the capability."""
        binding = self._controller_binding
        if (
            type(capability) is not _LifecycleCapability
            or binding is None
            or self._state is not BrokerState.SESSION_ACTIVE
            or self._session_generation is not binding.session_generation
            or capability.controller is not binding.controller
            or capability.issuer is not binding.issuer.identity
            or capability.lifecycle_generation is not binding.lifecycle_generation
            or capability.session_generation is not binding.session_generation
            or capability.source_generation is None
            or capability.issuance_identity is None
            or capability.action not in expected_actions
            or not any(capability is issued for issued in binding.issuer.issued)
            or any(capability is consumed for consumed in binding.issuer.consumed)
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_CAPABILITY_INVALID"
            ) from None
        if consume:
            binding.issuer.consumed.append(capability)
        return capability

    def __write_wire(self, packet: _PrivateWirePacket) -> None:
        if (
            type(packet) is not _PrivateWirePacket
            or packet.issuer is not self.__wire_issuer
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_WRITE_SCOPE_INVALID"
            ) from None
        if self._master_fd is None:
            self._fail(BrokerFailure.PROTOCOL)
        encoded = packet.payload
        if not encoded or not isinstance(encoded, bytes):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_WRITE_SCOPE_INVALID"
            ) from None
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
        self.__write_wire(
            _PrivateWirePacket(
                (self._frame_printf(payload) + "\n").encode("ascii"),
                self.__wire_issuer,
            )
        )
        self._read_until(frame)

    def _verify_interactive_login_bash(self) -> None:
        """Prove post-``exec`` Bash, interactive mode, and login-shell mode together."""
        payload, frame = self._new_frame("LOGIN")
        command = (
            'if [ -n "${BASH_VERSION-}" ] && '
            "case $- in *i*) true ;; *) false ;; esac && "
            f"shopt -q login_shell; then {self._frame_printf(payload)}; fi\n"
        )
        self.__write_wire(
            _PrivateWirePacket(command.encode("ascii"), self.__wire_issuer)
        )
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
        self.__write_wire(_PrivateWirePacket(b"exec bash -li\n", self.__wire_issuer))
        self._verify_interactive_login_bash()
        self._state = BrokerState.LOGIN_SHELL_READY
        self._session_generation = object()
        self._state = BrokerState.SESSION_ACTIVE
        print(HA_INTERACTIVE_SESSION_READY)
        return self._state

    def _collect_resolution_info(
        self,
        gate: RepairsGate,
        *,
        _capability: object = None,
    ) -> RepairsEvidence:
        """Collect only fixed ``ha resolution info --raw-json`` aggregate evidence."""
        actions = {
            RepairsGate.INITIAL: LifecycleAction.INITIAL_REPAIRS,
            RepairsGate.POST_ACTIVATION: LifecycleAction.POST_ACTIVATION_REPAIRS,
            RepairsGate.POST_ROLLBACK: LifecycleAction.POST_RESTORE_REPAIRS,
        }
        if not isinstance(gate, RepairsGate):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_OPERATION_INVALID"
            ) from None
        capability = self._require_capability(
            _capability, frozenset({actions[gate]}), consume=True
        )
        if self._state is not BrokerState.SESSION_ACTIVE:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_NOT_ACTIVE") from None
        start_payload, start_frame = self._new_frame("RESULT_START")
        end_payload, end_frame = self._new_frame("RESULT_END")
        command = (
            f"{self._frame_printf(start_payload)}; ha resolution info --raw-json; "
            f"{self._frame_printf(end_payload)}\n"
        )
        self.__write_wire(
            _PrivateWirePacket(command.encode("ascii"), self.__wire_issuer)
        )
        self._read_until(start_frame)
        private_output = self._read_until(end_frame)
        response = _extract_exact_framed_json_object(private_output)
        evidence = _fixed_repairs_evidence(response if response is not None else "")
        return _bind_evidence_origin(evidence, capability)

    def _ensure_echo_disabled(self) -> None:
        if self._echo_disabled:
            return
        payload, frame = self._new_frame("ECHO_OFF")
        self.__write_wire(
            _PrivateWirePacket(
                f"stty -echo && {self._frame_printf(payload)}\n".encode("ascii"),
                self.__wire_issuer,
            )
        )
        self._read_until(frame)
        self._echo_disabled = True

    def __execute_bounded_operation(
        self,
        operation: BoundedOperation,
        value: dict[str, object],
        *,
        detail: str = "fixed",
        _capability: object = None,
    ) -> bytes:
        """Run one enum operation with bounded chunks and exact private frames."""
        if not isinstance(operation, BoundedOperation):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_OPERATION_INVALID"
            ) from None
        self._require_capability(
            _capability, _BOUNDED_OPERATION_ACTIONS[operation], consume=True
        )
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
        program_bytes = _REMOTE_CONTROL_PROGRAM.encode("utf-8")
        program_digest = hashlib.sha256(program_bytes).hexdigest()
        encoded_program = base64.b64encode(program_bytes).decode("ascii")
        program_chunks = tuple(
            encoded_program[index : index + _TRANSFER_CHUNK_SIZE]
            for index in range(0, len(encoded_program), _TRANSFER_CHUNK_SIZE)
        )
        if not program_chunks or len(program_chunks) > 256:
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_OPERATION_INVALID"
            ) from None
        bootstrap = (
            "import base64,hashlib,os,sys;"
            "count=int(sys.stdin.readline());"
            "source=''.join(sys.stdin.readline().strip() for _ in range(count));"
            "raw=base64.b64decode(source,validate=True);"
            "expected=os.environ.pop('HA_R30_PROGRAM_SHA256');"
            "assert hashlib.sha256(raw).hexdigest()==expected;"
            "exec(compile(raw,'<ha-r30-control>','exec'))"
        )
        command = (
            f"{self._frame_printf(start_payload)}; "
            f"HA_R30_OPERATION={operation.value} HA_R30_DETAIL={detail} "
            f"HA_R30_PROGRAM_SHA256={program_digest} "
            f"python3 -c {shlex.quote(bootstrap)} {operation.value}; "
            f"{self._frame_printf(end_payload)}\n"
        )
        self.__write_wire(
            _PrivateWirePacket(command.encode("ascii"), self.__wire_issuer)
        )
        self._read_until(start_frame)
        self.__write_wire(
            _PrivateWirePacket(
                (str(len(program_chunks)) + "\n").encode("ascii"),
                self.__wire_issuer,
            )
        )
        for chunk in program_chunks:
            self.__write_wire(
                _PrivateWirePacket((chunk + "\n").encode("ascii"), self.__wire_issuer)
            )
        self.__write_wire(
            _PrivateWirePacket(
                (str(len(chunks)) + "\n").encode("ascii"), self.__wire_issuer
            )
        )
        for chunk in chunks:
            self.__write_wire(
                _PrivateWirePacket((chunk + "\n").encode("ascii"), self.__wire_issuer)
            )
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

    def _create_private_backup(
        self, manifest: SourceManifest, *, _capability: object = None
    ) -> BackupResult:
        capability = self._require_capability(
            _capability, frozenset({LifecycleAction.BACKUP})
        )
        output = self.__execute_bounded_operation(
            BoundedOperation.BACKUP,
            _backup_context_payload(manifest, capability),
            _capability=_capability,
        )
        result = _parse_backup_result(output)
        return _bind_evidence_origin(result, capability)

    def _reconcile_private_backup_creation(
        self, manifest: SourceManifest, *, _capability: object = None
    ) -> BackupResult:
        capability = self._require_capability(
            _capability, frozenset({LifecycleAction.BACKUP_RECONCILE})
        )
        output = self.__execute_bounded_operation(
            BoundedOperation.RECONCILE_BACKUP_CREATION,
            _backup_context_payload(manifest, capability),
            _capability=_capability,
        )
        return _bind_evidence_origin(_parse_backup_result(output), capability)

    def _transfer_source_bundle(
        self, bundle: SourceBundle, *, _capability: object = None
    ) -> TransferResult:
        action = (
            LifecycleAction.CANDIDATE_TRANSFER
            if isinstance(bundle, SourceBundle)
            and bundle.state is SourceState.CANDIDATE
            else LifecycleAction.RESTORE_TRANSFER
        )
        capability = self._require_capability(_capability, frozenset({action}))
        validate_source_bundle(bundle)
        output = self.__execute_bounded_operation(
            BoundedOperation.TRANSFER,
            _bundle_payload(bundle),
            detail=bundle.state.value,
            _capability=_capability,
        )
        result = self._simple_result(
            output,
            TransferResult,
            ("success", "file_count", "manifest_match", "regular_files_only"),
        )
        return _bind_evidence_origin(result, capability)

    def _install_staged_source(
        self, manifest: SourceManifest, *, _capability: object = None
    ) -> InstallResult:
        capability = self._require_capability(
            _capability, frozenset({LifecycleAction.CANDIDATE_INSTALL})
        )
        if (
            not isinstance(manifest, SourceManifest)
            or manifest.state is not SourceState.CANDIDATE
        ):
            raise SourceBundleError("CANDIDATE_MANIFEST_REQUIRED") from None
        output = self.__execute_bounded_operation(
            BoundedOperation.INSTALL,
            {"manifest": _manifest_payload(manifest)},
            detail=manifest.state.value,
            _capability=_capability,
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
        return _bind_evidence_origin(result, capability)

    def _verify_source_inventory(
        self, manifest: SourceManifest, *, _capability: object = None
    ) -> SourceInventoryResult:
        action = (
            LifecycleAction.CANDIDATE_INVENTORY
            if isinstance(manifest, SourceManifest)
            and manifest.state is SourceState.CANDIDATE
            else LifecycleAction.RESTORE_INVENTORY
        )
        capability = self._require_capability(_capability, frozenset({action}))
        if not isinstance(manifest, SourceManifest):
            raise SourceBundleError("SOURCE_MANIFEST_INVALID") from None
        output = self.__execute_bounded_operation(
            BoundedOperation.SOURCE_INVENTORY,
            {"manifest": _manifest_payload(manifest)},
            detail=manifest.state.value,
            _capability=_capability,
        )
        result = _parse_source_inventory_result(_exact_payload(output))
        return _bind_evidence_origin(result, capability)

    def _check_core(
        self, attempt_ordinal: int, *, _capability: object = None
    ) -> CoreCheckResult:
        action_by_state = {
            SourceState.CANDIDATE: {
                1: LifecycleAction.CANDIDATE_CORE_CHECK_1,
                2: LifecycleAction.CANDIDATE_CORE_CHECK_2,
            },
            SourceState.RESTORE: {
                1: LifecycleAction.RESTORE_CORE_CHECK_1,
                2: LifecycleAction.RESTORE_CORE_CHECK_2,
            },
        }
        action = action_by_state.get(self._active_source_state, {}).get(attempt_ordinal)
        capability = self._require_capability(
            _capability, frozenset({action}) if action is not None else frozenset()
        )
        if attempt_ordinal not in {1, 2}:
            raise SessionBrokerError("CORE_CHECK_ATTEMPT_INVALID") from None
        output = self.__execute_bounded_operation(
            BoundedOperation.CORE_CHECK, {}, _capability=_capability
        )
        result = _parse_core_check_result(
            _exact_core_check_payload(output), attempt_ordinal=attempt_ordinal
        )
        return _bind_evidence_origin(result, capability)

    def _restart_core(self, *, _capability: object = None) -> RestartResult:
        state = self._active_source_state
        action = {
            SourceState.CANDIDATE: LifecycleAction.ACTIVATION_RESTART,
            SourceState.RESTORE: LifecycleAction.REMOVAL_RESTART,
        }.get(state)
        capability = self._require_capability(
            _capability, frozenset({action}) if action is not None else frozenset()
        )
        if state is None:
            raise SessionBrokerError("CORE_RESTART_SOURCE_STATE_REQUIRED") from None
        if state in self._restarted_states:
            raise SessionBrokerError("CORE_RESTART_ALREADY_SUBMITTED") from None
        self._restarted_states.add(state)
        output = self.__execute_bounded_operation(
            BoundedOperation.RESTART_CORE, {}, _capability=_capability
        )
        result = self._simple_result(output, RestartResult, ("submitted", "accepted"))
        return _bind_evidence_origin(result, capability)

    def _wait_for_core_readiness(
        self, *, _capability: object = None
    ) -> CoreReadinessResult:
        action = {
            SourceState.CANDIDATE: LifecycleAction.CANDIDATE_READINESS,
            SourceState.RESTORE: LifecycleAction.RESTORE_READINESS,
        }.get(self._active_source_state)
        capability = self._require_capability(
            _capability, frozenset({action}) if action is not None else frozenset()
        )
        if self._active_source_state is None:
            raise SessionBrokerError("CORE_READINESS_SOURCE_STATE_REQUIRED") from None
        output = self.__execute_bounded_operation(
            BoundedOperation.CORE_READINESS,
            {"source_state": self._active_source_state.value},
            _capability=_capability,
        )
        result = self._simple_result(
            output,
            CoreReadinessResult,
            ("core_reachable", "core_running", "integration_loaded", "timed_out"),
        )
        return _bind_evidence_origin(result, capability)

    def _inventory_temporary_services(
        self, expectation: ServiceExpectation, *, _capability: object = None
    ) -> ServiceInventoryResult:
        action = {
            ServiceExpectation.PRESENT: LifecycleAction.SERVICES_PRESENT,
            ServiceExpectation.ABSENT: LifecycleAction.SERVICES_ABSENT,
        }.get(expectation)
        capability = self._require_capability(
            _capability, frozenset({action}) if action is not None else frozenset()
        )
        if not isinstance(expectation, ServiceExpectation):
            raise SessionBrokerError("SERVICE_EXPECTATION_INVALID") from None
        output = self.__execute_bounded_operation(
            BoundedOperation.SERVICE_INVENTORY,
            {"expectation": expectation.value},
            detail=expectation.value,
            _capability=_capability,
        )
        result = _parse_service_inventory_result(_exact_payload(output))
        return _bind_evidence_origin(result, capability)

    def _invoke_phase_a(
        self,
        operation: PhaseAOperation,
        *,
        nonce: str | None = None,
        evidence_label: AuditLabel | None = None,
        _capability: object = None,
    ) -> PhaseAResult:
        if (
            not isinstance(operation, PhaseAOperation)
            or operation is PhaseAOperation.RECEIPT
        ):
            raise SessionBrokerError("PHASE_A_HELPER_OPERATION_INVALID") from None
        if operation is PhaseAOperation.AUDIT:
            action = {
                AuditLabel.A0: LifecycleAction.A0,
                AuditLabel.AP0: LifecycleAction.AP0,
                AuditLabel.A1: LifecycleAction.A1,
                AuditLabel.A2: LifecycleAction.A2,
            }.get(evidence_label)
            actions = frozenset({action}) if action is not None else frozenset()
        elif operation is PhaseAOperation.PREFLIGHT:
            actions = frozenset({LifecycleAction.PREFLIGHT})
        else:
            actions = frozenset()
        capability = self._require_capability(_capability, actions)
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
        submitted_nonce = nonce or secrets.token_hex(16)
        value: dict[str, object] = {
            "helper_operation": operation.value,
            "nonce": submitted_nonce,
        }
        if evidence_label is not None:
            value["evidence_label"] = evidence_label.value
        output = self.__execute_bounded_operation(
            BoundedOperation.PHASE_A_HELPER,
            value,
            detail=operation.value,
            _capability=_capability,
        )
        result = _parse_phase_a_result(
            operation, output, expected_nonce=submitted_nonce
        )
        return _bind_evidence_origin(result, capability)

    def _run_invalid_nonce_preflight(
        self, *, _capability: object = None
    ) -> PhaseAResult:
        capability = self._require_capability(
            _capability, frozenset({LifecycleAction.P0})
        )
        output = self.__execute_bounded_operation(
            BoundedOperation.PHASE_A_HELPER,
            {
                "helper_operation": PhaseAOperation.PREFLIGHT.value,
                "invalid_nonce": True,
            },
            detail="invalid_nonce",
            _capability=_capability,
        )
        result = _parse_phase_a_result(PhaseAOperation.PREFLIGHT, output)
        if (
            result.exit_code != 65
            or result.outcome != "not_submitted"
            or result.nonce is not None
            or result.preflight is not None
            or result.receipt is not None
            or result.audit is not None
        ):
            self._fail(BrokerFailure.PROTOCOL)
        return _bind_evidence_origin(result, capability)

    def _install_staged_restore(
        self, manifest: SourceManifest, *, _capability: object = None
    ) -> InstallResult:
        """Activate one already-staged exact PR #41 source bundle."""
        capability = self._require_capability(
            _capability, frozenset({LifecycleAction.RESTORE_INSTALL})
        )
        if (
            not isinstance(manifest, SourceManifest)
            or manifest.state is not SourceState.RESTORE
        ):
            raise SourceBundleError("RESTORE_MANIFEST_REQUIRED") from None
        output = self.__execute_bounded_operation(
            BoundedOperation.RESTORE,
            {"manifest": _manifest_payload(manifest)},
            detail=manifest.state.value,
            _capability=_capability,
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
        return _bind_evidence_origin(result, capability)

    def _restore_source(
        self,
        bundle: SourceBundle,
        *,
        _transfer_capability: object = None,
        _install_capability: object = None,
    ) -> InstallResult:
        if (
            not isinstance(bundle, SourceBundle)
            or bundle.state is not SourceState.RESTORE
        ):
            raise SourceBundleError("RESTORE_MANIFEST_REQUIRED") from None
        self._require_capability(
            _transfer_capability, frozenset({LifecycleAction.RESTORE_TRANSFER})
        )
        self._require_capability(
            _install_capability, frozenset({LifecycleAction.RESTORE_INSTALL})
        )
        validate_source_bundle(bundle)
        transfer = self._transfer_source_bundle(
            bundle, _capability=_transfer_capability
        )
        if not transfer.success or not transfer.manifest_match:
            self._fail(BrokerFailure.PROTOCOL)
        return self._install_staged_restore(
            bundle.manifest, _capability=_install_capability
        )

    def _restore_private_backup(
        self, manifest: SourceManifest, *, _capability: object = None
    ) -> InstallResult:
        """Use the fixed verified private backup only as a restoration fallback."""
        capability = self._require_capability(
            _capability, frozenset({LifecycleAction.BACKUP_FALLBACK})
        )
        if (
            self._active_source_state is SourceState.RESTORE
            or self._backup_restore_attempted
        ):
            raise SourceBundleError("PRIVATE_BACKUP_ALREADY_CONSUMED") from None
        self._backup_restore_attempted = True
        output = self.__execute_bounded_operation(
            BoundedOperation.RESTORE_BACKUP,
            _backup_context_payload(manifest, capability),
            _capability=_capability,
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
        return _bind_evidence_origin(result, capability)

    def _reconcile_private_backup(
        self, manifest: SourceManifest, *, _capability: object = None
    ) -> FallbackReconciliationResult:
        """Reconcile a durable fallback marker without replaying its permit."""
        capability = self._require_capability(
            _capability, frozenset({LifecycleAction.BACKUP_FALLBACK_RECONCILE})
        )
        output = self.__execute_bounded_operation(
            BoundedOperation.RECONCILE_BACKUP,
            _backup_context_payload(manifest, capability),
            _capability=_capability,
        )
        value = _exact_payload(output)
        if set(value) != {
            "phase",
            "restoration_applied",
            "manifest_match",
            "file_count",
        }:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        result = FallbackReconciliationResult(
            phase=value.get("phase"),
            restoration_applied=value.get("restoration_applied"),
            manifest_match=value.get("manifest_match"),
            file_count=value.get("file_count"),
        )
        return _bind_evidence_origin(result, capability)

    def close(self) -> None:
        """Close the child process group privately and suppress every close message."""
        try:
            if self._master_fd is not None and not self._is_reaped():
                try:
                    self.__write_wire(_PrivateWirePacket(b"exit\n", self.__wire_issuer))
                except (OSError, SessionBrokerError):
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
            self._controller_binding = None
            self.__wire_issuer = object()


class FullPreflightLifecycleController:
    """The sole public live-capable, ordered full-preflight control surface."""

    _RECOVERY_HIDDEN_ENTRYPOINTS = frozenset(
        {
            "admit_initial_repairs",
            "create_backup",
            "stage_candidate",
            "install_candidate",
            "verify_candidate_inventory",
            "check_candidate_core",
            "restart_for_candidate",
            "await_candidate_readiness",
            "verify_research_services_present",
            "admit_post_activation_repairs",
            "collect_a0",
            "run_p0",
            "collect_ap0",
            "run_non_probe_preflight",
            "collect_a1",
            "validate_research_final",
            "collect_a2",
        }
    )

    def __getattribute__(self, name: str) -> Any:
        if name in object.__getattribute__(self, "_RECOVERY_HIDDEN_ENTRYPOINTS"):
            journal = object.__getattribute__(self, "__dict__").get("_journal")
            if journal is not None and journal.recovery_mode:
                raise AttributeError("RECOVERY_ONLY_OPERATION_UNAVAILABLE")
        return object.__getattribute__(self, name)

    def __init__(
        self,
        broker: Any,
    ) -> None:
        if (
            getattr(broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(broker, "_session_generation", None) is None
            or not callable(getattr(broker, "_register_lifecycle_controller", None))
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        self._broker = broker
        self._state = LifecycleState.BASELINE
        self._session_generation = broker._session_generation
        self._session_generation_id = secrets.token_hex(16)
        self._seen_session_generations = [self._session_generation]
        self._journal: _DurableLifecycleJournal | None = None
        durable_required = not _DISABLE_DURABLE_LIFECYCLE_FOR_TESTS and (
            type(broker) is PrivateInteractiveSessionBroker
            or getattr(broker, "_durable_lifecycle_test", False) is True
        )
        if durable_required:
            self._journal = _DurableLifecycleJournal()
            self._lifecycle_generation = self._journal.lifecycle_generation
            self._current_source_generation = self._journal.source_generation
            self._state = self._journal.state
        else:
            self._lifecycle_generation = object()
            self._current_source_generation = object()
        self._candidate_source_generation = (
            self._journal._record["pr45_source"]["generation"]
            if self._journal is not None
            else object()
        )
        self._restore_source_generation = (
            self._journal._record["pr41_restore"]["generation"]
            if self._journal is not None
            else object()
        )
        self.__dispatch_token = object()
        try:
            self._capability_issuer = broker._register_lifecycle_controller(
                self,
                self._lifecycle_generation,
                self._session_generation,
            )
        except (SessionBrokerError, TypeError, ValueError):
            if self._journal is not None:
                self._journal.close()
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        if type(self._capability_issuer) is not _CapabilityIssuer:
            if self._journal is not None:
                self._journal.close()
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        if (
            self._journal is not None
            and type(broker) is PrivateInteractiveSessionBroker
        ):
            reconstructed_stage = self._journal.state
            if reconstructed_stage in _RESTORE_ACTIVE_SOURCE_STAGES:
                broker._active_source_state = SourceState.RESTORE
            if reconstructed_stage in _RESTORE_RESTARTED_STAGES:
                broker._restarted_states.add(SourceState.RESTORE)
        self._permits = {
            action: _InvocationPermit(
                action, self._lifecycle_generation, self._session_generation
            )
            for action in LifecycleAction
        }
        if self._journal is not None:
            for action in self._journal.consumed_actions:
                self._permits[action].consumed = True
            if self._journal.fallback_reconciliation_resumable:
                self._permits[LifecycleAction.BACKUP_FALLBACK_RECONCILE].consumed = (
                    False
                )
        self._evidence_generations: dict[LifecycleAction, int] = {}
        self._evidence_origins: dict[int, tuple[_EvidenceOrigin, int]] = {}
        self._audit_instance_labels: dict[str, str] = {}
        self._normal_chain_aborted = (
            self._journal.recovery_mode if self._journal is not None else False
        )
        self._research_succeeded = (
            self._journal.research_succeeded if self._journal is not None else False
        )
        self._candidate_bundle: SourceBundle | None = None
        self._candidate_manifest: SourceManifest | None = None
        self._restore_bundle: SourceBundle | None = None
        self._restore_manifest: SourceManifest | None = None
        self._candidate_activation_generation: object | None = None
        self._snapshots: dict[AuditLabel, AuditSnapshot] = {}
        self._snapshot_generations: dict[AuditLabel, object] = {}
        self._snapshot_origins: dict[AuditLabel, tuple[_EvidenceOrigin, int]] = {}
        self._audit_comparisons: dict[
            tuple[AuditLabel, AuditLabel], AuditComparison
        ] = {}
        self._preflight_result: PhaseAResult | None = None
        self._preflight_nonce: str | None = None
        self._restore_inventory: SourceInventoryResult | None = None
        self._restore_core_check: CoreCheckResult | None = None
        self._removal_restart: RestartResult | None = None
        self._restart_dispatched: set[SourceState] = set()
        self._restore_readiness: CoreReadinessResult | None = None
        self._restore_services: ServiceInventoryResult | None = None
        self._restore_repairs: RepairsEvidence | None = None

    @property
    def state(self) -> LifecycleState:
        return self._journal.state if self._journal is not None else self._state

    def _assert_session_binding(self) -> None:
        if (
            getattr(self._broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(self._broker, "_session_generation", None)
            is not self._session_generation
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_CHANGED") from None

    def _require_state(self, *states: LifecycleState) -> None:
        current = self.state
        if self._journal is not None and self._journal.recovery_mode:
            recovery_states = {
                LifecycleState.RECOVERY_REQUIRED,
                LifecycleState.ROLLBACK_REQUIRED,
                LifecycleState.RESTORE_STAGED,
                LifecycleState.PR41_RESTORED,
                LifecycleState.RESTORE_INVENTORY_VERIFIED,
                LifecycleState.RESTORE_CORE_CHECKED,
                LifecycleState.REMOVAL_RESTART_CONSUMED,
                LifecycleState.PR41_READY,
                LifecycleState.RESEARCH_SERVICES_ABSENT,
                LifecycleState.POST_RESTORE_REPAIRS_PASS,
            }
            if current not in recovery_states:
                raise LifecycleControllerError("LIFECYCLE_RECOVERY_ONLY") from None
        if current not in states:
            raise LifecycleControllerError("LIFECYCLE_TRANSITION_INVALID") from None

    def _source_generation_for(self, action: LifecycleAction) -> object:
        if action in _CANDIDATE_SOURCE_ACTIONS:
            return self._candidate_source_generation
        if action in _PR41_BOUND_ACTIONS:
            return self._restore_source_generation
        return self._current_source_generation

    def _operation_nonce(self, action: LifecycleAction) -> str | None:
        if action is LifecycleAction.PREFLIGHT:
            return self._preflight_nonce
        return None

    def _advance(
        self,
        state: LifecycleState,
        action: LifecycleAction,
        *,
        source_generation: object | None = None,
        terminal: bool = False,
    ) -> None:
        if (
            self.state not in _LIFECYCLE_ACTION_PREDECESSORS[action]
            or state not in _LIFECYCLE_ACTION_SUCCESSORS[action]
        ):
            raise LifecycleControllerError("LIFECYCLE_TRANSITION_INVALID") from None
        generation = (
            self._source_generation_for(action)
            if source_generation is None
            else source_generation
        )
        self._current_source_generation = generation
        if self._journal is not None:
            self._journal.transition(
                state,
                action=action,
                source_generation=str(generation),
                evidence_generation=self._evidence_generations.get(action),
                recovery=self._normal_chain_aborted,
                terminal=terminal,
            )
        self._state = state
        if state is LifecycleState.A2_COLLECTED and not self._normal_chain_aborted:
            self._research_succeeded = True

    def _enter_recovery(self) -> None:
        self._normal_chain_aborted = True
        if self._journal is not None:
            self._journal.transition(
                LifecycleState.ROLLBACK_REQUIRED,
                action=None,
                source_generation=str(self._current_source_generation),
                evidence_generation=None,
                recovery=True,
            )
        self._state = LifecycleState.ROLLBACK_REQUIRED

    def close(self) -> None:
        """Release the owner lock; an active journal remains reconstructable."""
        if self._journal is not None:
            self._journal.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

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

        try:
            new_issuer = broker._register_lifecycle_controller(
                self,
                self._lifecycle_generation,
                new_session_generation,
            )
        except (SessionBrokerError, TypeError, ValueError):
            raise LifecycleControllerError(
                "LIFECYCLE_ROLLBACK_BINDING_INVALID"
            ) from None
        if type(new_issuer) is not _CapabilityIssuer:
            raise LifecycleControllerError(
                "LIFECYCLE_ROLLBACK_BINDING_INVALID"
            ) from None

        for permit in permits_to_rebind:
            permit.session_generation = new_session_generation
        self._broker = broker
        self._session_generation = new_session_generation
        self._capability_issuer = new_issuer
        self._seen_session_generations.append(new_session_generation)

    def _dispatch(
        self,
        action: LifecycleAction,
        callback: Callable[[_LifecycleCapability], Any],
        *,
        broker_evidence: bool = True,
        _dispatch_token: object = None,
    ) -> Any:
        if _dispatch_token is not self.__dispatch_token:
            raise LifecycleControllerError("LIFECYCLE_DISPATCH_SCOPE_INVALID") from None
        self._assert_session_binding()
        allowed_predecessors = _LIFECYCLE_ACTION_PREDECESSORS.get(action)
        if allowed_predecessors is None or self.state not in allowed_predecessors:
            raise LifecycleControllerError("LIFECYCLE_TRANSITION_INVALID") from None
        permit = self._permits[action]
        if permit.consumed:
            raise LifecycleControllerError("LIFECYCLE_PERMIT_CONSUMED") from None
        source_generation = self._source_generation_for(action)
        continuing_reconciliation = (
            action is LifecycleAction.BACKUP_FALLBACK_RECONCILE
            and self._journal is not None
            and getattr(self._journal, "fallback_reconciliation_resumable", False)
        )
        if self._journal is not None and not continuing_reconciliation:
            self._journal.record_intent(
                action,
                source_generation=str(source_generation),
                nonce=self._operation_nonce(action),
            )
        permit.consume(
            self._lifecycle_generation,
            self._session_generation,
            action,
        )
        capability = _LifecycleCapability(
            self,
            self._capability_issuer.identity,
            self._lifecycle_generation,
            source_generation,
            self._session_generation,
            action,
            secrets.token_hex(16),
            (
                getattr(self._journal, "baseline_backup_identity", None)
                if self._journal is not None
                and action
                in {
                    LifecycleAction.BACKUP_FALLBACK,
                    LifecycleAction.BACKUP_FALLBACK_RECONCILE,
                }
                else None
            ),
        )
        self._capability_issuer.issued.append(capability)
        if self._journal is not None:
            self._journal.record_dispatch_started(action)
        try:
            result = callback(capability)
        except BaseException:
            if self._journal is not None:
                self._journal.record_ambiguous(action)
                if action is LifecycleAction.BACKUP_FALLBACK_RECONCILE and getattr(
                    self._journal, "fallback_reconciliation_resumable", False
                ):
                    permit.consumed = False
            raise
        if self._journal is not None:
            if not broker_evidence and result is not None:
                _bind_evidence_origin(result, capability)
            origin = (
                None if result is None else _claim_evidence_origin(result, capability)
            )
            if (broker_evidence and origin is None) or (
                not broker_evidence and result is not None and origin is None
            ):
                self._journal.record_ambiguous(action)
                raise SessionBrokerError(
                    "PRIVATE_INTERACTIVE_SESSION_EVIDENCE_ORIGIN_INVALID"
                ) from None
            evidence_generation = self._journal.record_result(
                action,
                lifecycle_generation=str(self._lifecycle_generation),
                source_generation=str(source_generation),
                session_generation=self._session_generation_id,
                issuance_identity=str(capability.issuance_identity),
                audit_instance=(
                    None
                    if origin is None or origin.audit_instance is None
                    else self._audit_instance_labels.setdefault(
                        origin.audit_instance, secrets.token_hex(16)
                    )
                ),
                nonce=None if origin is None else origin.nonce,
                evidence=result,
            )
            self._evidence_generations[action] = evidence_generation
            if origin is not None:
                self._evidence_origins[id(result)] = (
                    origin,
                    evidence_generation,
                )
        return result

    def __dispatch_action(
        self,
        action: LifecycleAction,
        callback: Callable[[_LifecycleCapability], Any],
        *,
        broker_evidence: bool = True,
    ) -> Any:
        return self._dispatch(
            action,
            callback,
            broker_evidence=broker_evidence,
            _dispatch_token=self.__dispatch_token,
        )

    def _rollback(self) -> None:
        restoration_states = {
            LifecycleState.RESTORE_STAGED,
            LifecycleState.PR41_RESTORED,
            LifecycleState.RESTORE_INVENTORY_VERIFIED,
            LifecycleState.RESTORE_CORE_CHECKED,
            LifecycleState.REMOVAL_RESTART_CONSUMED,
            LifecycleState.PR41_READY,
            LifecycleState.RESEARCH_SERVICES_ABSENT,
            LifecycleState.POST_RESTORE_REPAIRS_PASS,
        }
        if self.state in restoration_states:
            self._normal_chain_aborted = True
            if self._journal is not None:
                self._journal.transition(
                    LifecycleState.RESTORE_FAILED,
                    action=None,
                    source_generation=str(self._current_source_generation),
                    evidence_generation=None,
                    recovery=True,
                    terminal=True,
                )
                self._journal.close()
            self._state = LifecycleState.RESTORE_FAILED
            raise LifecycleControllerError("LIFECYCLE_RESTORE_FAILED") from None
        self._enter_recovery()
        raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None

    @staticmethod
    def _repairs_pass(evidence: object) -> bool:
        return (
            isinstance(evidence, RepairsEvidence)
            and evidence.shape_valid is True
            and _exact_non_bool_int(evidence.relevant_count)
            and _exact_non_bool_int(evidence.critical_count)
            and evidence.relevant_count == 0
            and evidence.critical_count == 0
        )

    @staticmethod
    def _bundle_result_pass(
        result: object, expected_count: int, result_type: type[Any]
    ) -> bool:
        if not isinstance(result, result_type):
            return False
        if isinstance(result, TransferResult):
            return (
                result.success is True
                and _exact_non_bool_int(result.file_count)
                and result.file_count == expected_count
                and result.manifest_match is True
                and result.regular_files_only is True
            )
        if isinstance(result, InstallResult):
            return (
                result.installation_success is True
                and _exact_non_bool_int(result.expected_file_count)
                and result.expected_file_count == expected_count
                and _exact_non_bool_int(result.installed_file_count)
                and result.installed_file_count == expected_count
                and result.manifest_match is True
            )
        return False

    @staticmethod
    def _inventory_pass(result: object, expected_count: int) -> bool:
        return (
            isinstance(result, SourceInventoryResult)
            and _exact_non_bool_int(result.expected_count)
            and result.expected_count == expected_count
            and _exact_non_bool_int(result.observed_count)
            and result.observed_count == expected_count
            and result.manifest_match is True
            and _exact_non_bool_int(result.unexpected_count)
            and result.unexpected_count == 0
            and _exact_non_bool_int(result.missing_count)
            and result.missing_count == 0
        )

    @staticmethod
    def _readiness_pass(result: object) -> bool:
        return (
            isinstance(result, CoreReadinessResult)
            and result.core_reachable is True
            and result.core_running is True
            and result.integration_loaded is True
            and result.timed_out is False
        )

    @staticmethod
    def _services_present_pass(result: object) -> bool:
        return (
            isinstance(result, ServiceInventoryResult)
            and _exact_non_bool_int(result.expected_present_count)
            and result.expected_present_count == 4
            and _exact_non_bool_int(result.observed_present_count)
            and result.observed_present_count == 4
            and result.all_expected_present is True
            and _exact_non_bool_int(result.expected_absent_count)
            and result.expected_absent_count == 0
            and _exact_non_bool_int(result.observed_absent_count)
            and result.observed_absent_count == 0
            and result.all_expected_absent is True
        )

    @staticmethod
    def _services_absent_pass(result: object) -> bool:
        return (
            isinstance(result, ServiceInventoryResult)
            and _exact_non_bool_int(result.expected_present_count)
            and result.expected_present_count == 0
            and _exact_non_bool_int(result.observed_present_count)
            and result.observed_present_count == 0
            and result.all_expected_present is True
            and _exact_non_bool_int(result.expected_absent_count)
            and result.expected_absent_count == 4
            and _exact_non_bool_int(result.observed_absent_count)
            and result.observed_absent_count == 4
            and result.all_expected_absent is True
        )

    def admit_initial_repairs(self) -> RepairsEvidence:
        self._require_state(LifecycleState.BASELINE)
        try:
            evidence = self.__dispatch_action(
                LifecycleAction.INITIAL_REPAIRS,
                lambda capability: self._broker._collect_resolution_info(
                    RepairsGate.INITIAL,
                    _capability=capability,
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            raise LifecycleControllerError("INITIAL_REPAIRS_ADMISSION_FAILED") from None
        if not self._repairs_pass(evidence):
            raise LifecycleControllerError("INITIAL_REPAIRS_ADMISSION_FAILED") from None
        self._advance(
            LifecycleState.INITIAL_REPAIRS_PASS, LifecycleAction.INITIAL_REPAIRS
        )
        return evidence

    def create_backup(self, manifest: SourceManifest) -> BackupResult:
        self._require_state(LifecycleState.INITIAL_REPAIRS_PASS)
        if (
            not isinstance(manifest, SourceManifest)
            or manifest.state is not SourceState.RESTORE
        ):
            raise LifecycleControllerError("BACKUP_VERIFICATION_FAILED") from None
        try:
            validate_source_manifest(manifest)
        except SourceBundleError:
            raise LifecycleControllerError("BACKUP_VERIFICATION_FAILED") from None

        def create(capability: _LifecycleCapability) -> BackupResult:
            result = self._broker._create_private_backup(
                manifest, _capability=capability
            )
            if not (
                isinstance(result, BackupResult)
                and result.success is True
                and _exact_non_bool_int(result.file_count, minimum=1)
                and result.manifest_match is True
                and result.regular_files_only is True
                and (
                    self._journal is None
                    or result.lifecycle_generation == str(self._lifecycle_generation)
                    and result.source_generation == str(self._restore_source_generation)
                )
                and result.manifest_identity
                == _source_manifest_digest(manifest.entries)
                and re.fullmatch(r"[0-9a-f]{32}", result.backup_generation) is not None
                and re.fullmatch(r"[0-9a-f]{64}", result.backup_digest) is not None
            ):
                raise SessionBrokerError(
                    "PRIVATE_INTERACTIVE_SESSION_PROTOCOL"
                ) from None
            return result

        try:
            result = self.__dispatch_action(LifecycleAction.BACKUP, create)
        except (SessionBrokerError, TypeError, ValueError):
            raise LifecycleControllerError("BACKUP_VERIFICATION_FAILED") from None
        if self._journal is None:
            self._advance(LifecycleState.BACKUP_VERIFIED, LifecycleAction.BACKUP)
        else:
            self._state = LifecycleState.BACKUP_VERIFIED
        self._restore_manifest = manifest
        return result

    def reconcile_backup_creation(self, manifest: SourceManifest) -> BackupResult:
        """Adopt one exact no-clobber package after its result was lost."""
        self._require_state(LifecycleState.RECOVERY_REQUIRED)
        if (
            self._journal is None
            or not isinstance(manifest, SourceManifest)
            or manifest.state is not SourceState.RESTORE
            or self._journal._record["baseline_backup_identity"] is not None
            or LifecycleAction.BACKUP not in self._journal.consumed_actions
            or self._journal.action_transition_committed(LifecycleAction.BACKUP)
        ):
            raise LifecycleControllerError("BACKUP_RECONCILIATION_FAILED") from None
        try:
            validate_source_manifest(manifest)
        except SourceBundleError:
            raise LifecycleControllerError("BACKUP_RECONCILIATION_FAILED") from None

        def reconcile(capability: _LifecycleCapability) -> BackupResult:
            result = self._broker._reconcile_private_backup_creation(
                manifest, _capability=capability
            )
            if not (
                isinstance(result, BackupResult)
                and result.success is True
                and result.manifest_match is True
                and result.regular_files_only is True
                and _exact_non_bool_int(result.file_count, minimum=1)
                and result.lifecycle_generation == str(self._lifecycle_generation)
                and result.source_generation == str(self._restore_source_generation)
                and result.manifest_identity
                == _source_manifest_digest(manifest.entries)
                and re.fullmatch(r"[0-9a-f]{32}", result.backup_generation) is not None
                and re.fullmatch(r"[0-9a-f]{64}", result.backup_digest) is not None
            ):
                raise SessionBrokerError(
                    "PRIVATE_INTERACTIVE_SESSION_PROTOCOL"
                ) from None
            return result

        try:
            result = self.__dispatch_action(
                LifecycleAction.BACKUP_RECONCILE,
                reconcile,
            )
        except (SessionBrokerError, TypeError, ValueError):
            raise LifecycleControllerError("BACKUP_RECONCILIATION_FAILED") from None
        self._state = LifecycleState.BACKUP_VERIFIED
        self._restore_manifest = manifest
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
            result = self.__dispatch_action(
                LifecycleAction.CANDIDATE_TRANSFER,
                lambda capability: self._broker._transfer_source_bundle(
                    bundle, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError("CANDIDATE_TRANSFER_FAILED") from None
        if not self._bundle_result_pass(result, len(bundle.files), TransferResult):
            raise LifecycleControllerError("CANDIDATE_TRANSFER_FAILED") from None
        self._candidate_bundle = bundle
        self._candidate_manifest = bundle.manifest
        self._advance(
            LifecycleState.CANDIDATE_STAGED, LifecycleAction.CANDIDATE_TRANSFER
        )
        return result

    def install_candidate(self, manifest: SourceManifest) -> InstallResult:
        self._require_state(LifecycleState.CANDIDATE_STAGED)
        if (
            manifest != self._candidate_manifest
            or manifest.state is not SourceState.CANDIDATE
        ):
            raise LifecycleControllerError("CANDIDATE_MANIFEST_INVALID") from None
        try:
            result = self.__dispatch_action(
                LifecycleAction.CANDIDATE_INSTALL,
                lambda capability: self._broker._install_staged_source(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._rollback()
        if not self._bundle_result_pass(result, len(manifest.entries), InstallResult):
            self._rollback()
        self._candidate_activation_generation = object()
        self._advance(
            LifecycleState.CANDIDATE_INSTALLED,
            LifecycleAction.CANDIDATE_INSTALL,
            source_generation=self._candidate_source_generation,
        )
        return result

    def verify_candidate_inventory(
        self, manifest: SourceManifest
    ) -> SourceInventoryResult:
        self._require_state(LifecycleState.CANDIDATE_INSTALLED)
        if manifest != self._candidate_manifest:
            raise LifecycleControllerError("CANDIDATE_MANIFEST_INVALID") from None
        try:
            result = self.__dispatch_action(
                LifecycleAction.CANDIDATE_INVENTORY,
                lambda capability: self._broker._verify_source_inventory(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._rollback()
        if not self._inventory_pass(result, len(manifest.entries)):
            self._rollback()
        self._advance(
            LifecycleState.CANDIDATE_INVENTORY_VERIFIED,
            LifecycleAction.CANDIDATE_INVENTORY,
        )
        return result

    def _check_core_for(
        self,
        first_action: LifecycleAction,
    ) -> CoreCheckResult:
        try:
            result = self.__dispatch_action(
                first_action,
                lambda capability: self._broker._check_core(1, _capability=capability),
            )
        except SessionBrokerError:
            self._rollback()
        except (TypeError, ValueError):
            self._rollback()
        if (
            not isinstance(result, CoreCheckResult)
            or not _exact_non_bool_int(result.attempt_ordinal, minimum=1, maximum=2)
            or result.attempt_ordinal != 1
            or not _exact_non_bool_int(result.http_status, minimum=200, maximum=299)
            or result.result != "ok"
            or result.check_passed is not True
            or result.error_class is not None
        ):
            self._rollback()
        return result

    def check_candidate_core(self) -> CoreCheckResult:
        self._require_state(LifecycleState.CANDIDATE_INVENTORY_VERIFIED)
        result = self._check_core_for(
            LifecycleAction.CANDIDATE_CORE_CHECK_1,
        )
        self._advance(
            LifecycleState.CANDIDATE_CORE_CHECKED,
            LifecycleAction.CANDIDATE_CORE_CHECK_1,
        )
        return result

    def _restart(
        self, source_state: SourceState, action: LifecycleAction
    ) -> RestartResult:
        def dispatch_restart(capability: _LifecycleCapability) -> RestartResult:
            self._restart_dispatched.add(source_state)
            return self._broker._restart_core(_capability=capability)

        try:
            result = self.__dispatch_action(action, dispatch_restart)
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not (
            isinstance(result, RestartResult)
            and result.submitted is True
            and result.accepted is True
        ):
            self._rollback()
        return result

    def restart_for_candidate(self) -> RestartResult:
        self._require_state(LifecycleState.CANDIDATE_CORE_CHECKED)
        result = self._restart(
            SourceState.CANDIDATE, LifecycleAction.ACTIVATION_RESTART
        )
        self._advance(
            LifecycleState.ACTIVATION_RESTART_CONSUMED,
            LifecycleAction.ACTIVATION_RESTART,
        )
        return result

    def await_candidate_readiness(self) -> CoreReadinessResult:
        self._require_state(LifecycleState.ACTIVATION_RESTART_CONSUMED)
        try:
            result = self.__dispatch_action(
                LifecycleAction.CANDIDATE_READINESS,
                lambda capability: self._broker._wait_for_core_readiness(
                    _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._readiness_pass(result):
            self._rollback()
        self._advance(
            LifecycleState.CANDIDATE_READY, LifecycleAction.CANDIDATE_READINESS
        )
        return result

    def verify_research_services_present(self) -> ServiceInventoryResult:
        self._require_state(LifecycleState.CANDIDATE_READY)
        try:
            result = self.__dispatch_action(
                LifecycleAction.SERVICES_PRESENT,
                lambda capability: self._broker._inventory_temporary_services(
                    ServiceExpectation.PRESENT, _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._services_present_pass(result):
            self._rollback()
        self._advance(
            LifecycleState.RESEARCH_SERVICES_PRESENT, LifecycleAction.SERVICES_PRESENT
        )
        return result

    def admit_post_activation_repairs(self) -> RepairsEvidence:
        self._require_state(LifecycleState.RESEARCH_SERVICES_PRESENT)
        try:
            evidence = self.__dispatch_action(
                LifecycleAction.POST_ACTIVATION_REPAIRS,
                lambda capability: self._broker._collect_resolution_info(
                    RepairsGate.POST_ACTIVATION,
                    _capability=capability,
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._repairs_pass(evidence):
            self._rollback()
        self._advance(
            LifecycleState.POST_ACTIVATION_REPAIRS_PASS,
            LifecycleAction.POST_ACTIVATION_REPAIRS,
        )
        return evidence

    def _collect_audit(
        self,
        audit_label: AuditLabel,
        action: LifecycleAction,
    ) -> AuditSnapshot:
        nonce = secrets.token_hex(16)
        try:
            result = self.__dispatch_action(
                action,
                lambda capability: self._broker._invoke_phase_a(
                    PhaseAOperation.AUDIT,
                    nonce=nonce,
                    evidence_label=audit_label,
                    _capability=capability,
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
        if self._journal is not None:
            origin = self._evidence_origins.get(id(result))
            if origin is None:
                self._rollback()
            self._snapshot_origins[audit_label] = origin
        if self._candidate_activation_generation is not None:
            self._snapshot_generations[audit_label] = (
                self._candidate_activation_generation
            )
        return snapshot

    def _audit_origin_chain_valid(self, labels: tuple[AuditLabel, ...]) -> bool:
        if self._journal is None:
            return True
        expected_actions = {
            AuditLabel.A0: LifecycleAction.A0,
            AuditLabel.AP0: LifecycleAction.AP0,
            AuditLabel.A1: LifecycleAction.A1,
            AuditLabel.A2: LifecycleAction.A2,
        }
        if set(self._snapshot_origins) != set(labels):
            return False
        origins = [self._snapshot_origins[label] for label in labels]
        audit_instances = {origin.audit_instance for origin, _ in origins}
        generations = [generation for _, generation in origins]
        return (
            None not in audit_instances
            and len(audit_instances) == 1
            and generations == sorted(generations)
            and len(generations) == len(set(generations))
            and all(
                origin.lifecycle_generation is self._lifecycle_generation
                and origin.source_generation is self._candidate_source_generation
                and origin.session_generation is self._session_generation
                and origin.action is expected_actions[label]
                for label, (origin, _generation) in zip(labels, origins)
            )
        )

    def collect_a0(self) -> AuditSnapshot:
        self._require_state(LifecycleState.POST_ACTIVATION_REPAIRS_PASS)
        snapshot = self._collect_audit(AuditLabel.A0, LifecycleAction.A0)
        self._advance(LifecycleState.A0_COLLECTED, LifecycleAction.A0)
        return snapshot

    def run_p0(self) -> PhaseAResult:
        self._require_state(LifecycleState.A0_COLLECTED)
        try:
            result = self.__dispatch_action(
                LifecycleAction.P0,
                lambda capability: self._broker._run_invalid_nonce_preflight(
                    _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if (
            not isinstance(result, PhaseAResult)
            or result.operation is not PhaseAOperation.PREFLIGHT
            or result.exit_code != 65
            or result.outcome != "not_submitted"
            or result.nonce is not None
            or result.preflight is not None
            or result.receipt is not None
            or result.audit is not None
        ):
            self._rollback()
        self._advance(LifecycleState.P0_COMPLETED, LifecycleAction.P0)
        return result

    def collect_ap0(self) -> AuditSnapshot:
        self._require_state(LifecycleState.P0_COMPLETED)
        snapshot = self._collect_audit(AuditLabel.AP0, LifecycleAction.AP0)
        comparison = compare_audit_snapshots(self._snapshots[AuditLabel.A0], snapshot)
        if not comparison.zero_io_unchanged:
            self._rollback()
        self._audit_comparisons[(AuditLabel.A0, AuditLabel.AP0)] = comparison
        self._advance(LifecycleState.AP0_COLLECTED, LifecycleAction.AP0)
        return snapshot

    def run_non_probe_preflight(self) -> PhaseAResult:
        self._require_state(LifecycleState.AP0_COLLECTED)
        nonce = secrets.token_hex(16)
        self._preflight_nonce = nonce
        try:
            result = self.__dispatch_action(
                LifecycleAction.PREFLIGHT,
                lambda capability: self._broker._invoke_phase_a(
                    PhaseAOperation.PREFLIGHT,
                    nonce=nonce,
                    _capability=capability,
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if (
            not isinstance(result, PhaseAResult)
            or result.operation is not PhaseAOperation.PREFLIGHT
            or result.nonce != nonce
            or result.exit_code != 0
            or result.outcome != "preflight_ok"
            or result.preflight != PreflightResponse("preflight_ok", 1, nonce)
            or result.receipt is not None
            or result.audit is not None
        ):
            self._rollback()
        self._preflight_result = result
        self._advance(
            LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED, LifecycleAction.PREFLIGHT
        )
        return result

    def collect_a1(self) -> AuditSnapshot:
        self._require_state(LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED)
        snapshot = self._collect_audit(AuditLabel.A1, LifecycleAction.A1)
        comparison = compare_audit_snapshots(self._snapshots[AuditLabel.AP0], snapshot)
        if not comparison.zero_io_unchanged:
            self._rollback()
        self._audit_comparisons[(AuditLabel.AP0, AuditLabel.A1)] = comparison
        self._advance(LifecycleState.A1_COLLECTED, LifecycleAction.A1)
        return snapshot

    def validate_research_final(self) -> None:
        self._require_state(LifecycleState.A1_COLLECTED)

        def validate(_capability: _LifecycleCapability) -> None:
            generation = self._candidate_activation_generation
            required_labels = {AuditLabel.A0, AuditLabel.AP0, AuditLabel.A1}
            if (
                generation is None
                or set(self._snapshots) != required_labels
                or any(
                    self._snapshot_generations.get(label) is not generation
                    for label in required_labels
                )
                or not self._audit_origin_chain_valid(
                    (AuditLabel.A0, AuditLabel.AP0, AuditLabel.A1)
                )
                or self._preflight_result is None
                or not self._audit_comparisons[
                    (AuditLabel.A0, AuditLabel.AP0)
                ].zero_io_unchanged
                or not self._audit_comparisons[
                    (AuditLabel.AP0, AuditLabel.A1)
                ].zero_io_unchanged
            ):
                self._rollback()

        self.__dispatch_action(
            LifecycleAction.RESEARCH_FINAL, validate, broker_evidence=False
        )
        self._advance(
            LifecycleState.RESEARCH_FINAL_VALIDATED, LifecycleAction.RESEARCH_FINAL
        )

    def collect_a2(self) -> AuditSnapshot:
        self._require_state(LifecycleState.RESEARCH_FINAL_VALIDATED)
        snapshot = self._collect_audit(AuditLabel.A2, LifecycleAction.A2)
        if not self._audit_origin_chain_valid(
            (AuditLabel.A0, AuditLabel.AP0, AuditLabel.A1, AuditLabel.A2)
        ):
            self._rollback()
        adjacent = compare_audit_snapshots(self._snapshots[AuditLabel.A1], snapshot)
        cumulative = compare_audit_snapshots(self._snapshots[AuditLabel.A0], snapshot)
        if not adjacent.zero_io_unchanged or not cumulative.zero_io_unchanged:
            self._rollback()
        self._audit_comparisons[(AuditLabel.A1, AuditLabel.A2)] = adjacent
        self._audit_comparisons[(AuditLabel.A0, AuditLabel.A2)] = cumulative
        self._advance(LifecycleState.A2_COLLECTED, LifecycleAction.A2)
        return snapshot

    def _bind_restore_manifest(self, manifest: SourceManifest) -> None:
        if self._restore_manifest is None:
            if self._journal is None or not self._journal.recovery_mode:
                raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
            try:
                validate_source_manifest(manifest)
            except SourceBundleError:
                raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
            if manifest.state is not SourceState.RESTORE:
                raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
            self._restore_manifest = manifest
        if manifest != self._restore_manifest:
            raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None

    def stage_restore(self, bundle: SourceBundle) -> TransferResult:
        self._require_state(
            LifecycleState.A2_COLLECTED,
            LifecycleState.ROLLBACK_REQUIRED,
            LifecycleState.RECOVERY_REQUIRED,
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
            result = self.__dispatch_action(
                LifecycleAction.RESTORE_TRANSFER,
                lambda capability: self._broker._transfer_source_bundle(
                    bundle, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._enter_recovery()
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        if not self._bundle_result_pass(result, len(bundle.files), TransferResult):
            self._enter_recovery()
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        self._restore_bundle = bundle
        self._restore_manifest = bundle.manifest
        self._advance(LifecycleState.RESTORE_STAGED, LifecycleAction.RESTORE_TRANSFER)
        return result

    def restore_pr41(self, manifest: SourceManifest) -> InstallResult:
        self._require_state(LifecycleState.RESTORE_STAGED)
        self._bind_restore_manifest(manifest)
        if manifest.state is not SourceState.RESTORE:
            raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
        try:
            result = self.__dispatch_action(
                LifecycleAction.RESTORE_INSTALL,
                lambda capability: self._broker._install_staged_restore(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._rollback()
        if not self._bundle_result_pass(result, len(manifest.entries), InstallResult):
            self._rollback()
        self._advance(
            LifecycleState.PR41_RESTORED,
            LifecycleAction.RESTORE_INSTALL,
            source_generation=self._restore_source_generation,
        )
        return result

    def verify_restore_inventory(
        self, manifest: SourceManifest
    ) -> SourceInventoryResult:
        self._require_state(LifecycleState.PR41_RESTORED)
        self._bind_restore_manifest(manifest)
        try:
            result = self.__dispatch_action(
                LifecycleAction.RESTORE_INVENTORY,
                lambda capability: self._broker._verify_source_inventory(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._rollback()
        if not self._inventory_pass(result, len(manifest.entries)):
            self._rollback()
        self._restore_inventory = result
        self._advance(
            LifecycleState.RESTORE_INVENTORY_VERIFIED,
            LifecycleAction.RESTORE_INVENTORY,
        )
        return result

    def check_restore_core(self) -> CoreCheckResult:
        self._require_state(LifecycleState.RESTORE_INVENTORY_VERIFIED)
        result = self._check_core_for(
            LifecycleAction.RESTORE_CORE_CHECK_1,
        )
        self._restore_core_check = result
        self._advance(
            LifecycleState.RESTORE_CORE_CHECKED,
            LifecycleAction.RESTORE_CORE_CHECK_1,
        )
        return result

    def restart_for_restore(self) -> RestartResult:
        self._require_state(LifecycleState.RESTORE_CORE_CHECKED)
        result = self._restart(SourceState.RESTORE, LifecycleAction.REMOVAL_RESTART)
        self._removal_restart = result
        self._advance(
            LifecycleState.REMOVAL_RESTART_CONSUMED,
            LifecycleAction.REMOVAL_RESTART,
        )
        return result

    def await_restore_readiness(self) -> CoreReadinessResult:
        self._require_state(LifecycleState.REMOVAL_RESTART_CONSUMED)
        try:
            result = self.__dispatch_action(
                LifecycleAction.RESTORE_READINESS,
                lambda capability: self._broker._wait_for_core_readiness(
                    _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._readiness_pass(result):
            self._rollback()
        self._restore_readiness = result
        self._advance(LifecycleState.PR41_READY, LifecycleAction.RESTORE_READINESS)
        return result

    def verify_research_services_absent(self) -> ServiceInventoryResult:
        self._require_state(LifecycleState.PR41_READY)
        try:
            result = self.__dispatch_action(
                LifecycleAction.SERVICES_ABSENT,
                lambda capability: self._broker._inventory_temporary_services(
                    ServiceExpectation.ABSENT, _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._services_absent_pass(result):
            self._rollback()
        self._restore_services = result
        self._advance(
            LifecycleState.RESEARCH_SERVICES_ABSENT, LifecycleAction.SERVICES_ABSENT
        )
        return result

    def admit_post_restore_repairs(self) -> RepairsEvidence:
        self._require_state(LifecycleState.RESEARCH_SERVICES_ABSENT)
        try:
            evidence = self.__dispatch_action(
                LifecycleAction.POST_RESTORE_REPAIRS,
                lambda capability: self._broker._collect_resolution_info(
                    RepairsGate.POST_ROLLBACK,
                    _capability=capability,
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not self._repairs_pass(evidence):
            self._rollback()
        self._restore_repairs = evidence
        self._advance(
            LifecycleState.POST_RESTORE_REPAIRS_PASS,
            LifecycleAction.POST_RESTORE_REPAIRS,
        )
        return evidence

    def _durable_action_committed(self, action: LifecycleAction) -> bool:
        return self._journal is not None and self._journal.action_transition_committed(
            action
        )

    def _final_restore_proof(self) -> FinalRestoreProof:
        inventory = self._restore_inventory
        core = self._restore_core_check
        restart = self._removal_restart
        readiness = self._restore_readiness
        services = self._restore_services
        repairs = self._restore_repairs
        restart_permit = self._permits[LifecycleAction.REMOVAL_RESTART]
        inventory_committed = self._durable_action_committed(
            LifecycleAction.RESTORE_INVENTORY
        )
        core_committed = self._durable_action_committed(
            LifecycleAction.RESTORE_CORE_CHECK_1
        ) or self._durable_action_committed(LifecycleAction.RESTORE_CORE_CHECK_2)
        restart_committed = self._durable_action_committed(
            LifecycleAction.REMOVAL_RESTART
        )
        readiness_committed = self._durable_action_committed(
            LifecycleAction.RESTORE_READINESS
        )
        services_committed = self._durable_action_committed(
            LifecycleAction.SERVICES_ABSENT
        )
        repairs_committed = self._durable_action_committed(
            LifecycleAction.POST_RESTORE_REPAIRS
        )
        return FinalRestoreProof(
            source_manifest_match=(
                inventory_committed
                or (
                    inventory is not None
                    and self._restore_manifest is not None
                    and self._inventory_pass(
                        inventory, len(self._restore_manifest.entries)
                    )
                )
            ),
            research_files_absent=(
                inventory_committed
                or (
                    inventory is not None
                    and inventory.unexpected_count == 0
                    and inventory.missing_count == 0
                )
            ),
            core_check_passed=(
                core_committed or (core is not None and core.check_passed)
            ),
            restart_consumed=restart_permit.consumed,
            restart_dispatched=(
                restart_committed or SourceState.RESTORE in self._restart_dispatched
            ),
            restart_submitted=(
                restart_committed or restart is not None and restart.submitted is True
            ),
            restart_accepted=(
                restart_committed or restart is not None and restart.accepted is True
            ),
            core_reachable=(
                readiness_committed
                or readiness is not None
                and readiness.core_reachable is True
            ),
            core_running=(
                readiness_committed
                or readiness is not None
                and readiness.core_running is True
            ),
            integration_loaded=(
                readiness_committed
                or readiness is not None
                and readiness.integration_loaded is True
            ),
            core_not_timed_out=(
                readiness_committed
                or readiness is not None
                and readiness.timed_out is False
            ),
            research_services_absent=(
                services_committed or self._services_absent_pass(services)
            ),
            repairs_shape_valid=(
                repairs_committed or repairs is not None and repairs.shape_valid is True
            ),
            repairs_relevant_zero=(
                repairs_committed
                or repairs is not None
                and _exact_non_bool_int(repairs.relevant_count)
                and repairs.relevant_count == 0
            ),
            repairs_critical_zero=(
                repairs_committed
                or repairs is not None
                and _exact_non_bool_int(repairs.critical_count)
                and repairs.critical_count == 0
            ),
        )

    def _normal_history_complete(self) -> bool:
        if self._journal is None:
            return self._research_succeeded and not self._normal_chain_aborted
        observed = tuple(
            LifecycleState(transition["stage"])
            for transition in self._journal.transitions
        )
        position = 0
        for state in observed:
            if (
                position < len(_NORMAL_LIFECYCLE_HISTORY)
                and state is _NORMAL_LIFECYCLE_HISTORY[position]
            ):
                position += 1
        return (
            position == len(_NORMAL_LIFECYCLE_HISTORY)
            and self._journal.research_succeeded
            and not self._journal.recovery_mode
        )

    def complete(self) -> FinalRestoreProof:
        self._require_state(LifecycleState.POST_RESTORE_REPAIRS_PASS)
        proof = self.__dispatch_action(
            LifecycleAction.FINAL_ACCEPTANCE,
            lambda _capability: self._final_restore_proof(),
            broker_evidence=False,
        )
        if not isinstance(proof, FinalRestoreProof) or proof.complete is not True:
            self._rollback()
        terminal = (
            LifecycleState.COMPLETE_NORMAL
            if self._normal_history_complete()
            else LifecycleState.RESTORED_AFTER_ABORT
        )
        self._advance(
            terminal,
            LifecycleAction.FINAL_ACCEPTANCE,
            source_generation=self._restore_source_generation,
            terminal=True,
        )
        if self._journal is not None:
            self._journal.close()
        return proof

    def restore_private_backup_fallback(
        self, manifest: SourceManifest
    ) -> InstallResult:
        """Consume the fixed fallback once without treating it as PR #41 proof."""
        self._require_state(LifecycleState.ROLLBACK_REQUIRED)
        if (
            not isinstance(manifest, SourceManifest)
            or manifest.state is not SourceState.RESTORE
        ):
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        self._restore_manifest = manifest
        try:
            result = self.__dispatch_action(
                LifecycleAction.BACKUP_FALLBACK,
                lambda capability: self._broker._restore_private_backup(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        if not isinstance(result, InstallResult):
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        return result

    def reconcile_private_backup_fallback(
        self, manifest: SourceManifest
    ) -> FallbackReconciliationResult:
        """Use the separate durable permit to resolve an interrupted fallback."""
        self._require_state(
            LifecycleState.ROLLBACK_REQUIRED, LifecycleState.RECOVERY_REQUIRED
        )
        if (
            not isinstance(manifest, SourceManifest)
            or manifest.state is not SourceState.RESTORE
        ):
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        self._restore_manifest = manifest

        def reconcile(capability: _LifecycleCapability) -> FallbackReconciliationResult:
            result = self._broker._reconcile_private_backup(
                manifest, _capability=capability
            )
            valid_shape = (
                isinstance(result, FallbackReconciliationResult)
                and _exact_non_bool_int(result.file_count)
                and (
                    result.phase == "reconciled"
                    and result.restoration_applied is True
                    and result.manifest_match is True
                    and result.file_count >= 1
                    or result.phase == "reconciled_candidate"
                    and result.restoration_applied is False
                    and result.manifest_match is False
                    and result.file_count >= 1
                    or result.phase == "reconciled_unknown"
                    and result.restoration_applied is False
                    and result.manifest_match is False
                )
            )
            if not valid_shape:
                raise SessionBrokerError(
                    "PRIVATE_INTERACTIVE_SESSION_PROTOCOL"
                ) from None
            return result

        try:
            result = self.__dispatch_action(
                LifecycleAction.BACKUP_FALLBACK_RECONCILE,
                reconcile,
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError("LIFECYCLE_ROLLBACK_REQUIRED") from None
        self._normal_chain_aborted = True
        self._state = {
            "reconciled": LifecycleState.PR41_RESTORED,
            "reconciled_candidate": self.state,
            "reconciled_unknown": LifecycleState.MANUAL_RECOVERY_REQUIRED,
        }[result.phase]
        if result.phase == "reconciled_unknown" and self._journal is not None:
            self._journal.close()
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
