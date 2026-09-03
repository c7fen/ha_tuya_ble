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
from typing import Any, Never, Self, TextIO

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
_LIFECYCLE_JOURNAL_SCHEMA = 2
_MAX_LIFECYCLE_JOURNAL_BYTES = 128 * 1024
_LIFECYCLE_STATE_ROOT: Path | None = None
_LIFECYCLE_ANCHOR_NAME = "anchor.json"
_LIFECYCLE_JOURNAL_NAME = "journal.json"
_LIFECYCLE_LOCK_NAME = "journal.lock"
_FEATURE_VALIDATION_JOURNAL_NAME = "feature-validation.json"
_DISABLE_DURABLE_LIFECYCLE_FOR_TESTS = False
PR45_CANDIDATE_COMMIT = "835f602cc6a73bf224b5d134b3e0c96021696138"
PR45_CANDIDATE_TREE = "2e25fc0971fe0dd6ab698b796454f7970be9b257"
PR41_RESTORE_COMMIT = "4f73a9b008dcb89134bc41001c486f06d6056867"
PR41_RESTORE_TREE = "463ed8553da01eae591de611e76e45392ad9e7bf"
R64_RUNTIME_COMMIT = "7cfcf9598941de253a24b7c30b06170a98b4ba86"
R64_RUNTIME_TREE = "f289523beedb1abe38b28221b1880fa4dec2a7b9"
_AUTHORITY_MANIFEST_DIGESTS = {
    "candidate": "c1599dcd1cdc1201cd320c316059159a1948d5f58d4bdaa4c64ea3c4a0390075",
    "restore": "2d1dd79288b90f0d12c5c35449e6ed5d02c53433335dedd68377c81809731ac2",
    "r64_runtime": "4eaed95e3a0dea264e11fffde6a42facdedf775552a3ea85026e85ecffd4b1d7",
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


class DispatchFailureStage(StrEnum):
    """Bounded stage reached before a typed operation result was durable."""

    CONTROL_PROGRAM = "CONTROL_PROGRAM"
    PAYLOAD = "PAYLOAD"
    RESPONSE_WAIT = "RESPONSE_WAIT"
    RESPONSE_PARSE = "RESPONSE_PARSE"
    RESULT_VALIDATION = "RESULT_VALIDATION"
    CALLBACK = "CALLBACK"
    UNKNOWN = "UNKNOWN"


class DispatchFailureClass(StrEnum):
    """Sanitized generic cause retained for an ambiguous dispatch."""

    TIMEOUT = "timeout"
    CHILD_EXIT = "child_exit"
    FRAMING = "framing"
    REMOTE_OPERATION = "remote_operation"
    SCHEMA = "schema"
    CALLBACK = "callback"
    IO = "io"
    UNKNOWN = "unknown"


class RemoteFailureScope(StrEnum):
    """Fixed remote boundary that rejected or failed an operation."""

    BOOTSTRAP = "BOOTSTRAP"
    ROOT = "ROOT"
    REQUEST = "REQUEST"
    SOURCE_INVENTORY = "SOURCE_INVENTORY"
    BACKUP = "BACKUP"
    TRANSFER = "TRANSFER"
    INSTALL = "INSTALL"
    RESTORE = "RESTORE"
    CORE = "CORE"
    PHASE_A = "PHASE_A"
    OTHER = "OTHER"


class RemoteFailureReason(StrEnum):
    """Fixed remote rejection or failure reason with no private detail."""

    ROOT = "ROOT"
    ROOT_UNRESOLVED = "ROOT_UNRESOLVED"
    ROOT_AMBIGUOUS = "ROOT_AMBIGUOUS"
    ROOT_INVALID = "ROOT_INVALID"
    PAYLOAD = "PAYLOAD"
    AUTHORITY = "AUTHORITY"
    MANIFEST = "MANIFEST"
    PATH = "PATH"
    DIRECTORY = "DIRECTORY"
    REGULAR_FILE = "REGULAR_FILE"
    FILESYSTEM = "FILESYSTEM"
    PRIVATE_STATE = "PRIVATE_STATE"
    RESEARCH_PAYLOAD = "RESEARCH_PAYLOAD"
    RESEARCH_TARGET = "RESEARCH_TARGET"
    RESEARCH_HELPER = "RESEARCH_HELPER"
    RESEARCH_EVIDENCE = "RESEARCH_EVIDENCE"
    RESEARCH_PROBE = "RESEARCH_PROBE"
    RESEARCH_RECEIPT = "RESEARCH_RECEIPT"
    RESEARCH_AUDIT = "RESEARCH_AUDIT"
    RESEARCH_BUDGET = "RESEARCH_BUDGET"
    VALIDATION = "VALIDATION"
    UNKNOWN = "UNKNOWN"


class RemoteRootProfile(StrEnum):
    """Fixed reviewed Home Assistant configuration-root presentations."""

    DIRECT_CONFIG = "DIRECT_CONFIG"
    HOMEASSISTANT_CONFIG = "HOMEASSISTANT_CONFIG"
    SUPERVISOR_HOMEASSISTANT = "SUPERVISOR_HOMEASSISTANT"


class SourceState(StrEnum):
    """The exact repository authorities accepted by bounded control planes."""

    CANDIDATE = "candidate"
    RESTORE = "restore"
    R64_RUNTIME = "r64_runtime"


class CurrentSourceClassification(StrEnum):
    """Bounded comparison against repository-owned runtime manifests."""

    EXACT_PR41 = "EXACT_PR41"
    EXACT_PR45 = "EXACT_PR45"
    EXACT_R64 = "EXACT_R64"
    OTHER = "OTHER"
    INDETERMINATE = "INDETERMINATE"


class CoreCheckResponseContract(StrEnum):
    """The exact bounded Supervisor Core-check response profile."""

    CURRENT_RESULT_OK = "CURRENT_RESULT_OK"
    ERROR = "ERROR"
    INVALID = "INVALID"


class RestartDispatchOutcome(StrEnum):
    """Bounded result of one non-replayable Supervisor restart dispatch."""

    DEFINITELY_NOT_DISPATCHED = "DEFINITELY_NOT_DISPATCHED"
    RESPONSE_ACCEPTED = "RESPONSE_ACCEPTED"
    RESPONSE_REJECTED = "RESPONSE_REJECTED"
    DISPATCHED_RESPONSE_UNKNOWN = "DISPATCHED_RESPONSE_UNKNOWN"


class RestartFailureReason(StrEnum):
    """Fixed, non-sensitive restart transport diagnostic."""

    CONNECT_FAILED = "CONNECT_FAILED"
    SEND_FAILED = "SEND_FAILED"
    RESPONSE_TIMEOUT = "RESPONSE_TIMEOUT"
    RESPONSE_CLOSED = "RESPONSE_CLOSED"
    HTTP_REJECTED = "HTTP_REJECTED"
    INVALID_RESPONSE = "INVALID_RESPONSE"


# Keep the broker's frame deadline outside the restart-specific response wait.
# The 16-minute reconciliation window covers Supervisor's documented 10-minute
# API-response and 15-minute RUNNING windows without extending other calls.
RESTART_TRANSPORT_RESPONSE_DEADLINE_SECONDS = 45.0
RESTART_OPERATION_RESPONSE_DEADLINE_SECONDS = 50.0
RESTART_RECONCILIATION_DEADLINE_SECONDS = 16.0 * 60.0


class PriorBackupClassification(StrEnum):
    """Ownership classification for retained lifecycle remote backup state."""

    NONE = "NONE"
    OWNED_BY_RETAINED_LIFECYCLE = "OWNED_BY_RETAINED_LIFECYCLE"
    OTHER_OR_INDETERMINATE = "OTHER_OR_INDETERMINATE"


class FeatureBackupClassification(StrEnum):
    """Bounded state of the retained Feature-Validation baseline backup."""

    NONE = "NONE"
    OWNED_BY_CURRENT_FEATURE_LIFECYCLE = "OWNED_BY_CURRENT_FEATURE_LIFECYCLE"
    OTHER_OR_INDETERMINATE = "OTHER_OR_INDETERMINATE"


class FeatureLiveResultDurabilityClassification(StrEnum):
    """Whether a retained feature lifecycle contains a sanitized live result."""

    DURABLY_AVAILABLE = "REMOTE_LIVE_RESULT_DURABLY_AVAILABLE"
    NOT_DURABLY_AVAILABLE = "REMOTE_LIVE_RESULT_NOT_DURABLY_AVAILABLE"


class LifecycleAnchorFormat(StrEnum):
    """Exact durable anchor layouts retained by the Issue-37 lifecycle."""

    V1_DEVICE_BOUND = "V1_DEVICE_BOUND"
    V2_STABLE_ROOT = "V2_STABLE_ROOT"


class LifecycleAnchorClassification(StrEnum):
    """Bounded identity result for one structurally valid lifecycle anchor."""

    EXACT = "EXACT"
    DEVICE_DRIFT_ONLY = "DEVICE_DRIFT_ONLY"
    INVALID = "INVALID"


class RetainedBackupAction(StrEnum):
    """The two exact backup-continuity operations available to an inspector."""

    INSPECT = "inspect"
    RETIRE = "retire"


class FeatureBackupAction(StrEnum):
    """Fixed backup-continuity operations available to the feature controller."""

    INSPECT = "inspect"
    RETIRE = "retire"


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
    INSPECT_RETAINED_BACKUP = "inspect_retained_backup"
    RETIRE_RETAINED_BACKUP = "retire_retained_backup"


class PhaseAOperation(StrEnum):
    """The BLE-free PR #45 helper operations admitted by this broker."""

    PREFLIGHT = "preflight"
    AUDIT = "audit"
    RECEIPT = "receipt"


class ResearchOperation(StrEnum):
    """The fixed operations available to the dedicated Phase-A research session."""

    CHECK_READINESS = "check_readiness"
    RUN_FIXED_INVENTORY = "run_fixed_inventory"


class FeatureValidationAction(StrEnum):
    """One-shot operations in the separate exact-R64 validation lifecycle."""

    INITIAL_SOURCE = "initial_source"
    INITIAL_REPAIRS = "initial_repairs"
    BACKUP = "backup"
    R64_TRANSFER = "r64_transfer"
    R64_INSTALL = "r64_install"
    R64_INVENTORY = "r64_inventory"
    R64_CORE_CHECK = "r64_core_check"
    R64_RESTART = "r64_restart"
    R64_READINESS = "r64_readiness"
    R64_POST_RESTART_INVENTORY = "r64_post_restart_inventory"
    LIVE_VALIDATION = "live_validation"
    RESTORE_TRANSFER = "restore_transfer"
    RESTORE_INSTALL = "restore_install"
    BACKUP_FALLBACK = "backup_fallback"
    BACKUP_FALLBACK_RECONCILE = "backup_fallback_reconcile"
    BACKUP_RETIRE = "backup_retire"
    RESTORE_INVENTORY = "restore_inventory"
    RESTORE_CORE_CHECK = "restore_core_check"
    REMOVAL_RESTART = "removal_restart"
    RESTORE_READINESS = "restore_readiness"
    FEATURE_ABSENCE = "feature_absence"
    POST_RESTORE_REPAIRS = "post_restore_repairs"
    FINAL_ACCEPTANCE = "final_acceptance"


class FeatureValidationState(StrEnum):
    """Durable stages for the exact-R64 validation path only."""

    BASELINE = "BASELINE"
    INITIAL_SOURCE_VERIFIED = "INITIAL_SOURCE_VERIFIED"
    INITIAL_REPAIRS_PASS = "INITIAL_REPAIRS_PASS"
    R64_BACKUP_VERIFIED = "R64_BACKUP_VERIFIED"
    R64_STAGED = "R64_STAGED"
    R64_INSTALLED = "R64_INSTALLED"
    R64_INVENTORY_VERIFIED = "R64_INVENTORY_VERIFIED"
    R64_CORE_CHECKED = "R64_CORE_CHECKED"
    R64_RESTART_CONSUMED = "R64_RESTART_CONSUMED"
    R64_READY = "R64_READY"
    R64_POST_RESTART_INVENTORY_VERIFIED = "R64_POST_RESTART_INVENTORY_VERIFIED"
    LIVE_VALIDATION_CONSUMED = "LIVE_VALIDATION_CONSUMED"
    RESTORE_STAGED = "RESTORE_STAGED"
    PR41_RESTORED = "PR41_RESTORED"
    RESTORE_INVENTORY_VERIFIED = "RESTORE_INVENTORY_VERIFIED"
    RESTORE_CORE_CHECKED = "RESTORE_CORE_CHECKED"
    REMOVAL_RESTART_CONSUMED = "REMOVAL_RESTART_CONSUMED"
    PR41_READY = "PR41_READY"
    FEATURE_ABSENCE_VERIFIED = "FEATURE_ABSENCE_VERIFIED"
    POST_RESTORE_REPAIRS_PASS = "POST_RESTORE_REPAIRS_PASS"
    COMPLETE_NORMAL = "COMPLETE_NORMAL"
    RESTORE_REQUIRED = "RESTORE_REQUIRED"
    RESTORE_FAILED = "RESTORE_FAILED"


class ResearchFailureCategory(StrEnum):
    """Whether a failed run proves that no PROBE could have been submitted."""

    PRE_PROBE_FAILURE = "PRE_PROBE_FAILURE"
    POST_OR_POSSIBLY_SUBMITTED_PROBE_FAILURE = (
        "POST_OR_POSSIBLY_SUBMITTED_PROBE_FAILURE"
    )


class ResearchFailureStage(StrEnum):
    """Small fixed research boundaries useful to a no-replay caller."""

    ADMISSION = "ADMISSION"
    TARGET_RESOLUTION = "TARGET_RESOLUTION"
    HELPER_INVOCATION = "HELPER_INVOCATION"
    PROBE_EVIDENCE = "PROBE_EVIDENCE"
    RECEIPT_RECONCILIATION = "RECEIPT_RECONCILIATION"
    AUDIT = "AUDIT"
    REQUEST_ACCOUNTING = "REQUEST_ACCOUNTING"
    DP_AGGREGATION = "DP_AGGREGATION"
    RESULT_VALIDATION = "RESULT_VALIDATION"
    REMOTE_TRANSPORT = "REMOTE_TRANSPORT"


class ResearchFailureReason(StrEnum):
    """Identifier-free terminal reasons for one fixed research operation."""

    INVALID_SHAPE = "INVALID_SHAPE"
    HTTP_REJECTED = "HTTP_REJECTED"
    NO_ELIGIBLE_TARGET = "NO_ELIGIBLE_TARGET"
    TARGET_METADATA_UNAVAILABLE = "TARGET_METADATA_UNAVAILABLE"
    NONCE_MISMATCH = "NONCE_MISMATCH"
    HELPER_TERMINAL = "HELPER_TERMINAL"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
    AUDIT_INSTANCE_CHANGED = "AUDIT_INSTANCE_CHANGED"
    COUNTER_REGRESSION = "COUNTER_REGRESSION"
    REQUEST_COUNT_MISMATCH = "REQUEST_COUNT_MISMATCH"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    PROTOCOL_WRITE_DETECTED = "PROTOCOL_WRITE_DETECTED"
    AMBIGUOUS_SUBMISSION = "AMBIGUOUS_SUBMISSION"
    UNKNOWN_BOUNDED = "UNKNOWN_BOUNDED"


class PreflightFailureReason(StrEnum):
    """Fixed reportable reasons for one typed non-success PREFLIGHT result."""

    NOT_SUBMITTED = "NOT_SUBMITTED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    NONCE_MISMATCH = "NONCE_MISMATCH"
    EVIDENCE_WRITE_FAILED = "EVIDENCE_WRITE_FAILED"
    HTTP_REJECTED = "HTTP_REJECTED"
    TRANSPORT_AMBIGUOUS = "TRANSPORT_AMBIGUOUS"
    RESULT_INVALID = "RESULT_INVALID"


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
    ABORTED_AT_BASELINE = "ABORTED_AT_BASELINE"
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

_CANDIDATE_RESTARTED_STAGES = frozenset(
    {
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
    }
)

_RECONSTRUCTABLE_CANDIDATE_RESTART_STAGES = frozenset(
    {
        LifecycleState.ACTIVATION_RESTART_CONSUMED,
        LifecycleState.A2_COLLECTED,
    }
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
    BoundedOperation.INSPECT_RETAINED_BACKUP: frozenset(),
    BoundedOperation.RETIRE_RETAINED_BACKUP: frozenset(),
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
    "_inspect_current_source",
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


class _RemoteOperationFailure(SessionBrokerError):
    """One exact bounded remote failure with no free-form detail."""

    def __init__(self, scope: RemoteFailureScope, reason: RemoteFailureReason) -> None:
        super().__init__("PRIVATE_INTERACTIVE_SESSION_REMOTE_OPERATION_FAILED")
        self.scope = scope
        self.reason = reason


class _DispatchFailure(SessionBrokerError):
    """A sanitized bounded dispatch failure with no exception text."""

    def __init__(
        self,
        stage: DispatchFailureStage,
        failure_class: DispatchFailureClass,
        remote_failure_scope: RemoteFailureScope | None = None,
        remote_failure_reason: RemoteFailureReason | None = None,
    ) -> None:
        super().__init__("PRIVATE_INTERACTIVE_SESSION_DISPATCH_FAILED")
        self.stage = stage
        self.failure_class = failure_class
        self.remote_failure_scope = remote_failure_scope
        self.remote_failure_reason = remote_failure_reason


def _bounded_dispatch_failure(
    stage: DispatchFailureStage, error: BaseException
) -> _DispatchFailure:
    """Discard exception text and retain only one fixed diagnostic class."""
    if isinstance(error, _DispatchFailure):
        return error
    remote_failure_scope = None
    remote_failure_reason = None
    if isinstance(error, _RemoteOperationFailure):
        failure_class = DispatchFailureClass.REMOTE_OPERATION
        remote_failure_scope = error.scope
        remote_failure_reason = error.reason
    elif isinstance(error, SessionBrokerError):
        error_code = (
            error.args[0]
            if len(error.args) == 1 and isinstance(error.args[0], str)
            else None
        )
        failure_class = {
            "PRIVATE_INTERACTIVE_SESSION_TIMEOUT": DispatchFailureClass.TIMEOUT,
            "PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED": (
                DispatchFailureClass.CHILD_EXIT
            ),
            "PRIVATE_INTERACTIVE_SESSION_OUTPUT_LIMIT": DispatchFailureClass.FRAMING,
            "PRIVATE_INTERACTIVE_SESSION_PROTOCOL": DispatchFailureClass.FRAMING,
            "PRIVATE_INTERACTIVE_SESSION_REMOTE_OPERATION_FAILED": (
                DispatchFailureClass.REMOTE_OPERATION
            ),
        }.get(error_code)
        if failure_class is None:
            failure_class = DispatchFailureClass.UNKNOWN
    elif isinstance(error, (SourceBundleError, TypeError, ValueError)):
        failure_class = DispatchFailureClass.SCHEMA
    elif isinstance(error, OSError):
        failure_class = DispatchFailureClass.IO
    else:
        failure_class = DispatchFailureClass.UNKNOWN
    return _DispatchFailure(
        stage,
        failure_class,
        remote_failure_scope,
        remote_failure_reason,
    )


class SourceBundleError(ValueError):
    """A fixed source-admission failure without paths or content."""


class LifecycleControllerError(RuntimeError):
    """A fixed lifecycle failure that contains no private operation data."""


class PreflightRejectedError(LifecycleControllerError):
    """Expose one typed helper terminal without private or free-form data."""

    def __init__(
        self,
        reason: PreflightFailureReason,
        http_status: int | None = None,
    ) -> None:
        if (
            not isinstance(reason, PreflightFailureReason)
            or reason is PreflightFailureReason.HTTP_REJECTED
            and (type(http_status) is not int or not 400 <= http_status <= 599)
            or reason is not PreflightFailureReason.HTTP_REJECTED
            and http_status is not None
        ):
            raise TypeError("PREFLIGHT_FAILURE_REASON_INVALID") from None
        super().__init__("LIFECYCLE_ROLLBACK_REQUIRED")
        self.reason = reason
        self.http_status = http_status


class RemotePhaseAResearchError(LifecycleControllerError):
    """Expose only bounded dispatch provenance when no typed result survived."""

    def __init__(
        self,
        dispatch_stage: DispatchFailureStage,
        dispatch_class: DispatchFailureClass,
        remote_scope: RemoteFailureScope | None,
        remote_reason: RemoteFailureReason | None,
    ) -> None:
        if (
            not isinstance(dispatch_stage, DispatchFailureStage)
            or not isinstance(dispatch_class, DispatchFailureClass)
            or (remote_scope is None) != (remote_reason is None)
            or remote_scope is not None
            and (
                not isinstance(remote_scope, RemoteFailureScope)
                or not isinstance(remote_reason, RemoteFailureReason)
                or dispatch_class is not DispatchFailureClass.REMOTE_OPERATION
            )
        ):
            raise TypeError("REMOTE_PHASE_A_RESEARCH_ERROR_INVALID") from None
        super().__init__("REMOTE_PHASE_A_RESEARCH_DISPATCH_FAILED")
        self.dispatch_stage = dispatch_stage
        self.dispatch_class = dispatch_class
        self.remote_scope = remote_scope
        self.remote_reason = remote_reason


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
class _SourceInspectionCapability:
    """One broker-bound read capability outside lifecycle operation permits."""

    controller: object
    issuer: object
    session_generation: object
    issuance_identity: object


@dataclass(frozen=True, slots=True)
class _RetainedBackupCapability:
    """One exact retained-terminal backup inspection or retirement permit."""

    controller: object
    issuer: object
    lifecycle_generation: object
    source_generation: object
    session_generation: object
    issuance_identity: object
    action: RetainedBackupAction
    backup_identity: object = field(repr=False)
    restore_marker_owned: bool = False


@dataclass(frozen=True, slots=True)
class _FeatureBackupContinuityCapability:
    """One controller-owned feature-backup inspection or retirement permit."""

    controller: object = field(repr=False)
    issuer: object = field(repr=False)
    lifecycle_generation: object = field(repr=False)
    source_generation: object = field(repr=False)
    session_generation: object = field(repr=False)
    issuance_identity: object = field(repr=False)
    action: FeatureBackupAction
    backup_identity: object = field(default=None, repr=False)
    restore_marker_owned: bool = False


@dataclass(frozen=True, slots=True)
class _RemotePhaseAInventoryPermit:
    """One controller-issued opening permit outside LifecycleAction."""

    controller: object = field(repr=False)
    issuer: object = field(repr=False)
    lifecycle_generation: object = field(repr=False)
    source_generation: object = field(repr=False)
    session_generation: object = field(repr=False)
    issuance_identity: object = field(repr=False)


@dataclass(frozen=True, slots=True)
class _RemotePhaseAResearchCapability:
    """One session-bound capability for the fixed remote inventory run."""

    controller: object = field(repr=False)
    research_session: object = field(repr=False)
    issuer: object = field(repr=False)
    lifecycle_generation: object = field(repr=False)
    source_generation: object = field(repr=False)
    session_generation: object = field(repr=False)
    operation: ResearchOperation
    issuance_identity: object = field(repr=False)


@dataclass(frozen=True, slots=True)
class _FeatureValidationCapability:
    """One exact feature-lifecycle operation bound to a broker session."""

    controller: object = field(repr=False)
    issuer: object = field(repr=False)
    lifecycle_generation: object = field(repr=False)
    source_generation: object = field(repr=False)
    session_generation: object = field(repr=False)
    action: FeatureValidationAction
    issuance_identity: object = field(repr=False)
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
        return {
            SourceState.CANDIDATE: PR45_CANDIDATE_COMMIT,
            SourceState.RESTORE: PR41_RESTORE_COMMIT,
            SourceState.R64_RUNTIME: R64_RUNTIME_COMMIT,
        }[self.state]

    @property
    def authority_tree(self) -> str:
        return {
            SourceState.CANDIDATE: PR45_CANDIDATE_TREE,
            SourceState.RESTORE: PR41_RESTORE_TREE,
            SourceState.R64_RUNTIME: R64_RUNTIME_TREE,
        }[self.state]


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
    observed_managed_count: int
    manifest_match: bool
    unexpected_count: int
    missing_count: int
    root_profile: RemoteRootProfile | None = None
    content_mismatch_count: int = 0
    runtime_cache_file_count: int = 0
    managed_manifest_identity: str = ""

    @property
    def observed_count(self) -> int:
        """Retain the pre-R57 aggregate name for local callers."""
        return self.observed_managed_count


@dataclass(frozen=True)
class CurrentSourceInventoryResult:
    classification: CurrentSourceClassification
    evidence: SourceInventoryResult | None = None
    failure_stage: DispatchFailureStage | None = None
    failure_class: DispatchFailureClass | None = None
    remote_failure_scope: RemoteFailureScope | None = None
    remote_failure_reason: RemoteFailureReason | None = None

    @property
    def root_profile(self) -> RemoteRootProfile | None:
        """Return the bounded resolved profile for a successful inspection."""
        return self.evidence.root_profile if self.evidence is not None else None


class RefreshStatusFailureClass(StrEnum):
    """Identifier-free outcome classes for the fixed live validation."""

    OWNERSHIP_NOT_PROVEN = "OWNERSHIP_NOT_PROVEN"
    PRECONDITION_NOT_PROVEN = "PRECONDITION_NOT_PROVEN"
    LOGGER_CONTROL_UNAVAILABLE = "LOGGER_CONTROL_UNAVAILABLE"
    LOG_BOUNDARY_NOT_ESTABLISHED = "LOG_BOUNDARY_NOT_ESTABLISHED"
    COLD_STATE_NOT_PROVEN = "COLD_STATE_NOT_PROVEN"
    COLD_SESSION_PROVENANCE_FAILED = "COLD_SESSION_PROVENANCE_FAILED"
    COLD_REQUEST_FAILED = "COLD_REQUEST_FAILED"
    WARM_SESSION_PROVENANCE_FAILED = "WARM_SESSION_PROVENANCE_FAILED"
    WARM_REQUEST_FAILED = "WARM_REQUEST_FAILED"
    RETAINED_CONFIRMATION_NOT_OBSERVED = "RETAINED_CONFIRMATION_NOT_OBSERVED"
    DATAPOINT_WRITE_DETECTED = "DATAPOINT_WRITE_DETECTED"
    HOLD_RELEASE_NOT_OBSERVED = "HOLD_RELEASE_NOT_OBSERVED"
    AUTOMATIC_RECONNECT_OBSERVED = "AUTOMATIC_RECONNECT_OBSERVED"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class RefreshPacketCounts:
    """Sanitized outbound logical-packet counts for one press window."""

    device_info: int
    pair: int
    device_status: int
    datapoint: int
    other: int


class RefreshSessionProvenance(StrEnum):
    """Runtime-owned classification of the exact bound refresh session."""

    NEW_SESSION = "NEW_SESSION"
    REUSED_SESSION = "REUSED_SESSION"


@dataclass(frozen=True, slots=True)
class RefreshPressResult:
    """Sanitized result for one explicitly consumed Refresh Status press."""

    service_success: bool
    counts: RefreshPacketCounts
    session_provenance: RefreshSessionProvenance | None
    last_status_update_advanced: bool
    retained_confirmation_changed_dp_ids: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class RefreshHoldResult:
    """Sanitized passive On-Demand hold/release observation."""

    warm_immediately_after_press: bool
    normal_release_observed: bool
    automatic_reconnect_observed: bool


@dataclass(frozen=True, slots=True)
class RefreshStatusLiveValidationResult:
    """Only public aggregate returned by the fixed remote validation."""

    eligible_s1_count: int
    selected: bool
    refresh_button_present: bool
    policy_on_demand: bool
    ble_control_enabled: bool
    hold_time_valid: bool
    cold: RefreshPressResult
    warm: RefreshPressResult
    same_authenticated_session: bool
    hold: RefreshHoldResult
    ambiguous: bool
    failure_class: RefreshStatusFailureClass | None
    conditional_omission_observed: bool

    @property
    def passed(self) -> bool:
        """Return the exact cold, warm, hold, and non-actuation predicate."""
        return (
            self.selected is True
            and self.refresh_button_present is True
            and self.policy_on_demand is True
            and self.ble_control_enabled is True
            and self.hold_time_valid is True
            and self.cold.service_success is True
            and self.cold.counts.device_info == 1
            and self.cold.counts.pair == 1
            and self.cold.counts.device_status == 1
            and self.cold.counts.datapoint == 0
            and self.cold.session_provenance is RefreshSessionProvenance.NEW_SESSION
            and self.warm.service_success is True
            and self.warm.counts.device_info == 0
            and self.warm.counts.pair == 0
            and self.warm.counts.device_status == 1
            and self.warm.counts.datapoint == 0
            and self.warm.session_provenance is RefreshSessionProvenance.REUSED_SESSION
            and self.same_authenticated_session is True
            and self.hold == RefreshHoldResult(True, True, False)
            and self.ambiguous is False
            and self.failure_class is None
        )


@dataclass(frozen=True, slots=True)
class FeatureAbsenceResult:
    """Post-restore proof that the R64 runtime entity is not active."""

    refresh_button_active: bool


def _source_inventory_exact(result: object, expected_count: int) -> bool:
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


def _feature_restore_inventory_exact(result: object, manifest: SourceManifest) -> bool:
    """Require the complete current-source evidence used for backup retirement."""
    return (
        manifest.state is SourceState.RESTORE
        and _source_inventory_exact(result, len(manifest.entries))
        and isinstance(result, SourceInventoryResult)
        and result.root_profile is RemoteRootProfile.HOMEASSISTANT_CONFIG
        and _exact_non_bool_int(result.content_mismatch_count)
        and result.content_mismatch_count == 0
        and result.managed_manifest_identity
        == _source_manifest_digest(manifest.entries)
    )


@dataclass(frozen=True)
class CoreCheckResult:
    attempt_ordinal: int
    http_status: int | None
    result: str | None
    check_passed: bool
    error_class: str | None
    response_contract: CoreCheckResponseContract = CoreCheckResponseContract.INVALID
    legacy_check_passed_present: bool = False


@dataclass(frozen=True)
class PriorBackupContinuityResult:
    classification: PriorBackupClassification
    retired: bool = False


@dataclass(frozen=True)
class FeatureBackupContinuityResult:
    """Identifier-free state of the retained Feature-Validation backup."""

    classification: FeatureBackupClassification
    retired: bool = False


@dataclass(frozen=True)
class LifecycleAnchorMigrationResult:
    """Sanitized proof of one completed V1-to-V2 anchor migration."""

    migrated: bool
    anchor_format: LifecycleAnchorFormat
    journal_changed: bool
    journal_revision_changed: bool
    terminal_changed: bool
    lifecycle_generation_changed: bool
    backup_identity_changed: bool
    anchor_revision_changed: bool
    reread_valid: bool


@dataclass(frozen=True)
class RestartResult:
    dispatch_outcome: RestartDispatchOutcome
    http_status: int | None
    failure_reason: RestartFailureReason | None

    @property
    def response_accepted(self) -> bool:
        """Return whether a complete successful Supervisor response arrived."""
        return self.dispatch_outcome is RestartDispatchOutcome.RESPONSE_ACCEPTED

    @property
    def dispatched_response_unknown(self) -> bool:
        """Return whether a complete POST was sent without a final response."""
        return (
            self.dispatch_outcome is RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN
        )


class LifecycleJournalFormat(StrEnum):
    """Exact persisted journal layouts retained by the Issue-37 lifecycle."""

    V1_PRE_R59 = "V1_PRE_R59"
    V1_R59_TRANSITIONAL = "V1_R59_TRANSITIONAL"
    V2_CURRENT = "V2_CURRENT"


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
    http_status: int | None = None


@dataclass(frozen=True, slots=True)
class RemotePhaseASlotSummary:
    """One public, identifier-free logical research-slot summary."""

    label: str
    mode: str
    request_count: int
    cold_result: str | None
    retained_result: str | None
    same_session_retained: bool
    normal_release_observed: bool
    automatic_reconnect_observed: bool
    observation_overflow: bool
    receipt_used: bool


@dataclass(frozen=True, slots=True)
class RemotePhaseADPInventory:
    """Value-free aggregate metadata for one datapoint identifier."""

    dp_id: int
    cold_reported_count: int
    cold_eligible_count: int
    retained_reported_count: int
    retained_eligible_count: int
    cold_type_set: tuple[str, ...]
    cold_encoded_length_set: tuple[int, ...]
    retained_type_set: tuple[str, ...]
    retained_encoded_length_set: tuple[int, ...]
    classification: str


@dataclass(frozen=True, slots=True)
class RemotePhaseAInventoryResult:
    """The complete sanitized result of the single fixed remote research run."""

    outcome: str
    eligible_s1_count: int
    selected: bool
    same_private_target: bool
    completed_probe_slots: int
    cold_request_count: int
    retained_request_count: int
    total_device_status_requests: int
    cold_ack_success_count: int
    retained_ack_success_count: int
    failure_count: int
    timeout_count: int
    receipt_lookup_count: int
    ambiguity_count: int
    normal_release_count: int
    same_session_retained_count: int
    automatic_reconnect_count: int
    observation_overflow_count: int
    protocol_datapoint_write_delta: int
    protocol_datapoint_packet_delta: int
    slots: tuple[RemotePhaseASlotSummary, ...]
    dp_inventory: tuple[RemotePhaseADPInventory, ...]
    failure_category: ResearchFailureCategory | None
    failure_stage: ResearchFailureStage | None
    failure_reason: ResearchFailureReason | None
    failed_slot: int | None
    probe_submission_possible: bool


@dataclass(frozen=True, slots=True)
class RemotePhaseAReadinessResult:
    """Sanitized device-free admission for the fixed inventory operation."""

    ready: bool
    eligible_s1_count: int
    selected: bool
    same_target_binding_ready: bool
    audit_ready: bool
    audit_instance_continuity: bool
    protocol_write_delta_zero: bool
    failure_stage: ResearchFailureStage | None
    failure_reason: ResearchFailureReason | None


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
    restart_dispatch_acceptable: bool
    restart_effect_proven: bool
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
                self.restart_dispatch_acceptable,
                self.restart_effect_proven,
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
            "restart_results",
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
    _V1_PRE_R59_TOP_LEVEL_KEYS = _TOP_LEVEL_KEYS - {"restart_results"}
    _V1_ANCHOR_FIELDS = frozenset(
        {
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
    )
    _V2_ANCHOR_FIELDS = _V1_ANCHOR_FIELDS - {"state_root_device"}
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

    def __init__(
        self,
        *,
        _retained_terminal_inspection: bool = False,
        _retained_anchor_continuity: bool = False,
    ) -> None:
        self._directory = _fixed_lifecycle_state_root()
        self._anchor_name = _lifecycle_anchor_path(self._directory).name
        self._parent_fd: int | None = None
        self._root_fd: int | None = None
        self._lock_fd: int | None = None
        self._closed = False
        try:
            self._secure_directory()
            self._acquire_lock()
            try:
                os.stat(
                    _FEATURE_VALIDATION_JOURNAL_NAME,
                    dir_fd=self._root_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise LifecycleControllerError("LIFECYCLE_MODE_CONFLICT") from None
            newly_created = False
            anchor = self._read_anchor()
            record = self._read_record()
            if record is None:
                if _retained_terminal_inspection:
                    raise LifecycleControllerError(
                        "LIFECYCLE_TERMINAL_REQUIRED"
                    ) from None
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
                anchor_classification = self._classify_anchor(anchor, record)
                if _retained_anchor_continuity:
                    if anchor_classification is LifecycleAnchorClassification.INVALID:
                        raise LifecycleControllerError(
                            "LIFECYCLE_ANCHOR_INVALID"
                        ) from None
                    if anchor_classification is not (
                        LifecycleAnchorClassification.DEVICE_DRIFT_ONLY
                    ):
                        raise LifecycleControllerError(
                            "LIFECYCLE_ANCHOR_DEVICE_DRIFT_REQUIRED"
                        ) from None
                    if record["active"] is True:
                        raise LifecycleControllerError(
                            "LIFECYCLE_ANCHOR_DEVICE_DRIFT_ACTIVE_UNSUPPORTED"
                        ) from None
                else:
                    self._validate_anchor(anchor, record)
                if (
                    _retained_terminal_inspection
                    and self._journal_format is LifecycleJournalFormat.V1_PRE_R59
                    and anchor["root_revision"] != record["revision"]
                ):
                    raise LifecycleControllerError(
                        "LIFECYCLE_JOURNAL_REVISION_INVALID"
                    ) from None
                if not _retained_anchor_continuity:
                    self._reconcile_anchor_revision(anchor, record)
            self._anchor = anchor if anchor is not None else self._read_anchor()
            self._anchor_format = self._anchor_format_of(self._anchor)
            self._anchor_classification = (
                LifecycleAnchorClassification.DEVICE_DRIFT_ONLY
                if _retained_anchor_continuity
                else LifecycleAnchorClassification.EXACT
            )
            self._record = record
            if _retained_terminal_inspection and record["active"] is True:
                raise LifecycleControllerError("LIFECYCLE_TERMINAL_REQUIRED") from None
            if (
                not _retained_terminal_inspection
                and self._journal_format is LifecycleJournalFormat.V1_PRE_R59
                and record["active"] is True
            ):
                raise LifecycleControllerError(
                    "LIFECYCLE_LEGACY_ACTIVE_UNSUPPORTED"
                ) from None
            if (
                not _retained_terminal_inspection
                and not newly_created
                and record["active"] is not True
            ):
                raise LifecycleControllerError("LIFECYCLE_TERMINAL_RETAINED") from None
            if not _retained_terminal_inspection and not newly_created:
                consumed = set(record["consumed_operations"])
                if not consumed.intersection(self._RISKY_ACTIONS):
                    raise LifecycleControllerError(
                        "LIFECYCLE_PREPARATION_ABANDONED"
                    ) from None
                record = copy.deepcopy(record)
                incomplete_restore = any(
                    operation["action"]
                    in {action.value for action in _RESTORE_SOURCE_ACTIONS}
                    and operation["phase"] != "transition_committed"
                    for operation in record["operations"]
                )
                stage = LifecycleState(record["stage"])
                candidate_restart = record["restart_results"].get(
                    LifecycleAction.ACTIVATION_RESTART.value
                )
                try:
                    candidate_restart_resumable = (
                        stage in _RECONSTRUCTABLE_CANDIDATE_RESTART_STAGES
                        and _parse_restart_result(candidate_restart).dispatch_outcome
                        in {
                            RestartDispatchOutcome.RESPONSE_ACCEPTED,
                            RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
                        }
                    )
                except SessionBrokerError:
                    candidate_restart_resumable = False
                if not candidate_restart_resumable:
                    record["recovery_mode"] = True
                    record["rollback_mode"] = True
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
                elif stage not in _RECONSTRUCTABLE_RESTORE_STAGES and not (
                    stage in _RECONSTRUCTABLE_CANDIDATE_RESTART_STAGES
                    and candidate_restart_resumable
                ):
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

    @classmethod
    def open_retained_terminal(cls) -> Self:
        return cls(_retained_terminal_inspection=True)

    @classmethod
    def open_retained_anchor_continuity(cls) -> Self:
        return cls(
            _retained_terminal_inspection=True,
            _retained_anchor_continuity=True,
        )

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
        self._journal_format = self._validate_record(record)
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
            "schema_version": 2,
            "state_root_generation": self._token(),
            "state_root_inode": root_metadata.st_ino,
            "original_lifecycle_generation": record["lifecycle_generation"],
            "pr41_commit": PR41_RESTORE_COMMIT,
            "pr41_tree": PR41_RESTORE_TREE,
            "baseline_backup_identity": None,
            "root_revision": 0,
        }

    @classmethod
    def _anchor_format_of(cls, anchor: dict[str, object]) -> LifecycleAnchorFormat:
        if anchor.get("schema_version") == 1 and set(anchor) == cls._V1_ANCHOR_FIELDS:
            return LifecycleAnchorFormat.V1_DEVICE_BOUND
        if anchor.get("schema_version") == 2 and set(anchor) == cls._V2_ANCHOR_FIELDS:
            return LifecycleAnchorFormat.V2_STABLE_ROOT
        raise LifecycleControllerError("LIFECYCLE_ANCHOR_INVALID") from None

    def _classify_anchor(
        self, anchor: dict[str, object], record: dict[str, object]
    ) -> LifecycleAnchorClassification:
        if self._root_fd is None:
            return LifecycleAnchorClassification.INVALID
        root_metadata = os.fstat(self._root_fd)
        token = re.compile(r"[0-9a-f]{32}\Z")
        try:
            anchor_format = self._anchor_format_of(anchor)
        except LifecycleControllerError:
            return LifecycleAnchorClassification.INVALID
        common_valid = (
            isinstance(anchor.get("state_root_generation"), str)
            and token.fullmatch(anchor.get("state_root_generation", "")) is not None
            and _exact_non_bool_int(anchor.get("state_root_inode"), minimum=1)
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
        if not common_valid:
            return LifecycleAnchorClassification.INVALID
        if anchor_format is LifecycleAnchorFormat.V2_STABLE_ROOT:
            return LifecycleAnchorClassification.EXACT
        if not _exact_non_bool_int(anchor.get("state_root_device"), minimum=1):
            return LifecycleAnchorClassification.INVALID
        if anchor.get("state_root_device") == root_metadata.st_dev:
            return LifecycleAnchorClassification.EXACT
        if anchor.get("root_revision") == record.get("revision") and anchor.get(
            "baseline_backup_identity"
        ) == record.get("baseline_backup_identity"):
            return LifecycleAnchorClassification.DEVICE_DRIFT_ONLY
        return LifecycleAnchorClassification.INVALID

    def _validate_anchor(
        self, anchor: dict[str, object], record: dict[str, object]
    ) -> None:
        if self._classify_anchor(anchor, record) is not (
            LifecycleAnchorClassification.EXACT
        ):
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

    def migrate_device_drift_anchor(self) -> LifecycleAnchorMigrationResult:
        """Replace one proven device-drift-only V1 anchor with exact V2."""
        if (
            self._closed
            or self._anchor_classification
            is not LifecycleAnchorClassification.DEVICE_DRIFT_ONLY
            or self._anchor_format is not LifecycleAnchorFormat.V1_DEVICE_BOUND
            or self._record["active"] is not False
        ):
            raise LifecycleControllerError(
                "LIFECYCLE_ANCHOR_MIGRATION_NOT_AUTHORIZED"
            ) from None
        before_anchor = copy.deepcopy(self._anchor)
        before_record = copy.deepcopy(self._record)
        candidate = copy.deepcopy(before_anchor)
        candidate["schema_version"] = 2
        del candidate["state_root_device"]
        try:
            self._write_anchor(candidate, replace_existing=True)
        except LifecycleControllerError:
            try:
                observed = self._read_anchor()
            except LifecycleControllerError:
                raise LifecycleControllerError(
                    "LIFECYCLE_ANCHOR_MIGRATION_INDETERMINATE"
                ) from None
            if observed == before_anchor:
                raise LifecycleControllerError(
                    "LIFECYCLE_ANCHOR_MIGRATION_FAILED_OLD_ANCHOR_INTACT"
                ) from None
            raise LifecycleControllerError(
                "LIFECYCLE_ANCHOR_MIGRATION_INDETERMINATE"
            ) from None
        observed = self._read_anchor()
        if (
            observed != candidate
            or self._classify_anchor(observed, self._record)
            is not LifecycleAnchorClassification.EXACT
            or self._anchor_format_of(observed)
            is not LifecycleAnchorFormat.V2_STABLE_ROOT
        ):
            raise LifecycleControllerError(
                "LIFECYCLE_ANCHOR_MIGRATION_INDETERMINATE"
            ) from None
        self._anchor = observed
        self._anchor_format = LifecycleAnchorFormat.V2_STABLE_ROOT
        self._anchor_classification = LifecycleAnchorClassification.EXACT
        return LifecycleAnchorMigrationResult(
            migrated=True,
            anchor_format=self._anchor_format,
            journal_changed=self._record != before_record,
            journal_revision_changed=(
                self._record["revision"] != before_record["revision"]
            ),
            terminal_changed=self._record["terminal"] != before_record["terminal"],
            lifecycle_generation_changed=(
                self._record["lifecycle_generation"]
                != before_record["lifecycle_generation"]
            ),
            backup_identity_changed=(
                self._record["baseline_backup_identity"]
                != before_record["baseline_backup_identity"]
            ),
            anchor_revision_changed=(
                observed["root_revision"] != before_anchor["root_revision"]
            ),
            reread_valid=True,
        )

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
            "restart_results": {},
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
    def _validate_record(cls, record: dict[str, object]) -> LifecycleJournalFormat:
        if (
            record.get("schema_version") == 1
            and set(record) == cls._V1_PRE_R59_TOP_LEVEL_KEYS
        ):
            journal_format = LifecycleJournalFormat.V1_PRE_R59
        elif record.get("schema_version") == 1 and set(record) == cls._TOP_LEVEL_KEYS:
            journal_format = LifecycleJournalFormat.V1_R59_TRANSITIONAL
        elif record.get("schema_version") == 2 and set(record) == cls._TOP_LEVEL_KEYS:
            journal_format = LifecycleJournalFormat.V2_CURRENT
        else:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
        invalid = False
        token = re.compile(r"[0-9a-f]{32}\Z")
        states = {item.value for item in LifecycleState}
        actions = {item.value for item in LifecycleAction}
        terminal_values = {
            LifecycleState.COMPLETE_NORMAL.value,
            LifecycleState.RESTORED_AFTER_ABORT.value,
            LifecycleState.ABORTED_AT_BASELINE.value,
            LifecycleState.RESTORE_FAILED.value,
            LifecycleState.MANUAL_RECOVERY_REQUIRED.value,
        }
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
        restart_results = record.get("restart_results")
        if journal_format is LifecycleJournalFormat.V1_PRE_R59:
            invalid = invalid or restart_results is not None
        else:
            invalid = invalid or type(restart_results) is not dict
        if type(restart_results) is dict:
            for action, value in restart_results.items():
                invalid = invalid or action not in {
                    LifecycleAction.ACTIVATION_RESTART.value,
                    LifecycleAction.REMOVAL_RESTART.value,
                }
                try:
                    _parse_restart_result(value)
                except SessionBrokerError:
                    invalid = True
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
                            LifecycleState.ABORTED_AT_BASELINE,
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
        restart_actions = {
            LifecycleAction.ACTIVATION_RESTART.value,
            LifecycleAction.REMOVAL_RESTART.value,
        }
        if type(operations) is list:
            seen: set[str] = set()
            for operation in operations:
                operation_keys = set(operation) if type(operation) is dict else set()
                base_operation_keys = {
                    "action",
                    "phase",
                    "source_generation",
                    "nonce",
                }
                invalid = (
                    invalid
                    or type(operation) is not dict
                    or operation_keys
                    not in {
                        frozenset(base_operation_keys),
                        frozenset(
                            base_operation_keys | {"failure_stage", "failure_class"}
                        ),
                        frozenset(
                            base_operation_keys
                            | {
                                "failure_stage",
                                "failure_class",
                                "remote_failure_scope",
                                "remote_failure_reason",
                            }
                        ),
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
                    has_failure = "failure_stage" in operation
                    invalid = invalid or has_failure != ("failure_class" in operation)
                    has_remote_scope = "remote_failure_scope" in operation
                    has_remote_reason = "remote_failure_reason" in operation
                    invalid = invalid or has_remote_scope != has_remote_reason
                    if has_failure:
                        invalid = invalid or operation.get("phase") != "ambiguous"
                        invalid = invalid or operation.get("failure_stage") not in {
                            item.value for item in DispatchFailureStage
                        }
                        invalid = invalid or operation.get("failure_class") not in {
                            item.value for item in DispatchFailureClass
                        }
                    if has_remote_scope:
                        invalid = (
                            invalid
                            or not has_failure
                            or operation.get("failure_class")
                            != DispatchFailureClass.REMOTE_OPERATION.value
                            or operation.get("remote_failure_scope")
                            not in {item.value for item in RemoteFailureScope}
                            or operation.get("remote_failure_reason")
                            not in {item.value for item in RemoteFailureReason}
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
            if journal_format is not LifecycleJournalFormat.V1_PRE_R59:
                expected_restart_results = {
                    operation["action"]
                    for operation in operations
                    if type(operation) is dict
                    and operation.get("action") in restart_actions
                    and operation.get("phase")
                    in {"result_durable", "transition_committed", "reconciled"}
                }
                invalid = invalid or set(restart_results) != expected_restart_results
        helper_actions = {
            LifecycleAction.A0.value,
            LifecycleAction.P0.value,
            LifecycleAction.AP0.value,
            LifecycleAction.PREFLIGHT.value,
            LifecycleAction.A1.value,
            LifecycleAction.A2.value,
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
        return journal_format

    def _write_record(self, record: dict[str, object]) -> None:
        current = getattr(self, "_record", None)
        if current is not None and record.get("revision") != current["revision"] + 1:
            raise LifecycleControllerError(
                "LIFECYCLE_JOURNAL_REVISION_INVALID"
            ) from None
        self._journal_format = self._validate_record(record)
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
    def journal_format(self) -> LifecycleJournalFormat:
        return self._journal_format

    @property
    def anchor_format(self) -> LifecycleAnchorFormat:
        return self._anchor_format

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

    @property
    def source_mutation_may_have_occurred(self) -> bool:
        submission_possible = {
            "dispatch_started",
            "result_durable",
            "transition_committed",
            "ambiguous",
            "reconciled",
        }
        source_mutating_actions = {
            LifecycleAction.CANDIDATE_INSTALL.value,
            LifecycleAction.RESTORE_INSTALL.value,
            LifecycleAction.BACKUP_FALLBACK.value,
            LifecycleAction.BACKUP_FALLBACK_RECONCILE.value,
        }
        return any(
            operation["action"] in source_mutating_actions
            and operation["phase"] in submission_possible
            for operation in self._record["operations"]
        )

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
            if phase != "ambiguous":
                matches[0].pop("failure_stage", None)
                matches[0].pop("failure_class", None)
                matches[0].pop("remote_failure_scope", None)
                matches[0].pop("remote_failure_reason", None)
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

    def record_ambiguous(
        self,
        action: LifecycleAction,
        stage: DispatchFailureStage = DispatchFailureStage.UNKNOWN,
        failure_class: DispatchFailureClass = DispatchFailureClass.UNKNOWN,
        remote_failure_scope: RemoteFailureScope | None = None,
        remote_failure_reason: RemoteFailureReason | None = None,
    ) -> None:
        if (remote_failure_scope is None) != (remote_failure_reason is None) or (
            remote_failure_scope is not None
            and (
                failure_class is not DispatchFailureClass.REMOTE_OPERATION
                or not isinstance(remote_failure_scope, RemoteFailureScope)
                or not isinstance(remote_failure_reason, RemoteFailureReason)
            )
        ):
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None

        def mutate(record: dict[str, object]) -> None:
            matches = [
                operation
                for operation in record["operations"]
                if operation["action"] == action.value
            ]
            if len(matches) != 1:
                raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None
            matches[0]["phase"] = "ambiguous"
            matches[0]["failure_stage"] = stage.value
            matches[0]["failure_class"] = failure_class.value
            if remote_failure_scope is not None and remote_failure_reason is not None:
                matches[0]["remote_failure_scope"] = remote_failure_scope.value
                matches[0]["remote_failure_reason"] = remote_failure_reason.value
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
        transition_state: LifecycleState | None = None,
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
            if action in {
                LifecycleAction.ACTIVATION_RESTART,
                LifecycleAction.REMOVAL_RESTART,
            }:
                if not isinstance(evidence, RestartResult):
                    raise LifecycleControllerError(
                        "LIFECYCLE_RESTART_RESULT_INVALID"
                    ) from None
                record["restart_results"][action.value] = {
                    "dispatch_outcome": evidence.dispatch_outcome.value,
                    "http_status": evidence.http_status,
                    "failure_reason": (
                        None
                        if evidence.failure_reason is None
                        else evidence.failure_reason.value
                    ),
                }
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
            if transition_state is not None:
                if (
                    action is not LifecycleAction.PREFLIGHT
                    or transition_state
                    is not LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED
                    or LifecycleState(record["stage"])
                    not in _LIFECYCLE_ACTION_PREDECESSORS[action]
                    or transition_state not in _LIFECYCLE_ACTION_SUCCESSORS[action]
                ):
                    raise LifecycleControllerError(
                        "LIFECYCLE_TRANSITION_INVALID"
                    ) from None
                matches[0]["phase"] = "transition_committed"
                record["stage"] = transition_state.value
                record["source_generation"] = source_generation
                record["transitions"].append(
                    {
                        "sequence": len(record["transitions"]),
                        "stage": transition_state.value,
                        "action": action.value,
                        "source_generation": source_generation,
                        "evidence_generation": generation,
                    }
                )

        self._commit(mutate)
        return generation

    def restart_result(self, action: LifecycleAction) -> RestartResult | None:
        """Return the durable bounded restart report for a consumed action."""
        if action not in {
            LifecycleAction.ACTIVATION_RESTART,
            LifecycleAction.REMOVAL_RESTART,
        }:
            raise LifecycleControllerError("LIFECYCLE_RESTART_RESULT_INVALID") from None
        if self._journal_format is LifecycleJournalFormat.V1_PRE_R59:
            return None
        value = self._record["restart_results"].get(action.value)
        if value is None:
            return None
        try:
            return _parse_restart_result(value)
        except SessionBrokerError:
            raise LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID") from None

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

    def retire_terminal(self) -> None:
        if (
            self._closed
            or self._record["active"] is not False
            or self._record["terminal"] is None
            or self._root_fd is None
            or self._parent_fd is None
        ):
            raise LifecycleControllerError(
                "LIFECYCLE_TERMINAL_RETIREMENT_INVALID"
            ) from None
        anchor_removed = False
        journal_removed = False
        try:
            os.unlink(self._anchor_name, dir_fd=self._parent_fd)
            anchor_removed = True
            os.fsync(self._parent_fd)
            os.unlink(_LIFECYCLE_JOURNAL_NAME, dir_fd=self._root_fd)
            journal_removed = True
            os.fsync(self._root_fd)
        except OSError:
            if anchor_removed and not journal_removed:
                try:
                    self._write_anchor(self._anchor)
                except LifecycleControllerError:
                    pass
            raise LifecycleControllerError(
                "LIFECYCLE_TERMINAL_RETIREMENT_FAILED"
            ) from None

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


class _DurableFeatureValidationJournal:
    """Small durable ledger for the separate exact-R64 lifecycle."""

    _FIELDS = frozenset(
        {
            "schema_version",
            "revision",
            "lifecycle_generation",
            "active",
            "state",
            "terminal",
            "authorities",
            "consumed_actions",
            "operations",
            "backup_identity",
            "restart_results",
            "source_classification",
        }
    )

    def __init__(self, *, _retained_terminal_inspection: bool = False) -> None:
        self._directory = _fixed_lifecycle_state_root()
        self._root_fd: int | None = None
        self._lock_fd: int | None = None
        self._closed = False
        self._retained_terminal_inspection = _retained_terminal_inspection
        self._retired = False
        self.reconstructed = False
        try:
            self._directory.parent.mkdir(parents=True, exist_ok=True)
            parent_fd = os.open(
                self._directory.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            try:
                try:
                    os.mkdir(self._directory.name, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                self._root_fd = os.open(
                    self._directory.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
            finally:
                os.close(parent_fd)
            details = os.fstat(self._root_fd)
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) != 0o700
            ):
                raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None
            self._lock_fd = os.open(
                _LIFECYCLE_LOCK_NAME,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._root_fd,
            )
            lock_details = os.fstat(self._lock_fd)
            if (
                not stat.S_ISREG(lock_details.st_mode)
                or lock_details.st_uid != os.getuid()
                or stat.S_IMODE(lock_details.st_mode) != 0o600
                or lock_details.st_nlink != 1
            ):
                raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                os.stat(
                    _LIFECYCLE_JOURNAL_NAME, dir_fd=self._root_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                pass
            else:
                raise LifecycleControllerError("LIFECYCLE_MODE_CONFLICT") from None
            record = self._read()
            if record is None:
                if _retained_terminal_inspection:
                    raise LifecycleControllerError(
                        "FEATURE_TERMINAL_REQUIRED"
                    ) from None
                record = {
                    "schema_version": 1,
                    "revision": 0,
                    "lifecycle_generation": secrets.token_hex(16),
                    "active": True,
                    "state": FeatureValidationState.BASELINE.value,
                    "terminal": None,
                    "authorities": {
                        "r64_commit": R64_RUNTIME_COMMIT,
                        "r64_tree": R64_RUNTIME_TREE,
                        "pr41_commit": PR41_RESTORE_COMMIT,
                        "pr41_tree": PR41_RESTORE_TREE,
                    },
                    "consumed_actions": [],
                    "operations": {},
                    "backup_identity": None,
                    "restart_results": {},
                    "source_classification": None,
                }
                self._write(record, replace=False)
            else:
                self.reconstructed = True
                self._validate(record)
                if _retained_terminal_inspection:
                    if record["active"] is True:
                        raise LifecycleControllerError(
                            "FEATURE_TERMINAL_REQUIRED"
                        ) from None
                    if (
                        record["terminal"]
                        != FeatureValidationState.COMPLETE_NORMAL.value
                        or record["state"]
                        != FeatureValidationState.COMPLETE_NORMAL.value
                    ):
                        raise LifecycleControllerError(
                            "FEATURE_TERMINAL_NOT_COMPLETE"
                        ) from None
                elif record["active"] is not True:
                    raise LifecycleControllerError(
                        "FEATURE_TERMINAL_RETAINED"
                    ) from None
            self._record = record
        except BaseException:
            self.close()
            raise

    @classmethod
    def open_retained_terminal(cls) -> Self:
        """Open only a retained successful Feature-Validation terminal."""
        return cls(_retained_terminal_inspection=True)

    @staticmethod
    def _final_restore_complete(record: dict[str, object]) -> bool:
        """Return the canonical durable equivalent of FinalRestoreProof.complete."""
        operations = record.get("operations")
        restart_results = record.get("restart_results")
        required = {
            FeatureValidationAction.RESTORE_INVENTORY.value,
            FeatureValidationAction.RESTORE_CORE_CHECK.value,
            FeatureValidationAction.REMOVAL_RESTART.value,
            FeatureValidationAction.RESTORE_READINESS.value,
            FeatureValidationAction.FEATURE_ABSENCE.value,
            FeatureValidationAction.POST_RESTORE_REPAIRS.value,
            FeatureValidationAction.FINAL_ACCEPTANCE.value,
        }
        return (
            record.get("active") is False
            and record.get("state") == FeatureValidationState.COMPLETE_NORMAL.value
            and record.get("terminal") == FeatureValidationState.COMPLETE_NORMAL.value
            and isinstance(operations, dict)
            and all(
                operations.get(action) == "transition_committed" for action in required
            )
            and isinstance(restart_results, dict)
            and restart_results.get(FeatureValidationAction.REMOVAL_RESTART.value)
            in {
                RestartDispatchOutcome.RESPONSE_ACCEPTED.value,
                RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN.value,
            }
        )

    def _read(self) -> dict[str, object] | None:
        try:
            descriptor = os.open(
                _FEATURE_VALIDATION_JOURNAL_NAME,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=self._root_fd,
            )
        except FileNotFoundError:
            return None
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size > _MAX_LIFECYCLE_JOURNAL_BYTES
            ):
                raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None
            raw = b""
            while len(raw) <= _MAX_LIFECYCLE_JOURNAL_BYTES:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                raw += chunk
        finally:
            os.close(descriptor)
        return _strict_json_object(raw)

    @classmethod
    def _validate(cls, record: dict[str, object]) -> None:
        valid_actions = {action.value for action in FeatureValidationAction}
        valid_phases = {
            "intent_durable",
            "dispatch_started",
            "result_durable",
            "transition_committed",
            "ambiguous",
        }
        backup = record.get("backup_identity")
        backup_valid = backup is None or (
            isinstance(backup, dict)
            and set(backup)
            == {
                "lifecycle_generation",
                "source_generation",
                "backup_generation",
                "manifest_identity",
                "backup_digest",
            }
            and backup.get("lifecycle_generation") == record.get("lifecycle_generation")
            and backup.get("source_generation") == PR41_RESTORE_COMMIT
            and backup.get("manifest_identity")
            == _AUTHORITY_MANIFEST_DIGESTS[SourceState.RESTORE.value]
            and isinstance(backup.get("backup_generation"), str)
            and re.fullmatch(r"[0-9a-f]{32}", backup["backup_generation"]) is not None
            and isinstance(backup.get("backup_digest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", backup["backup_digest"]) is not None
        )
        if (
            set(record) != cls._FIELDS
            or record.get("schema_version") != 1
            or not _exact_non_bool_int(record.get("revision"))
            or not isinstance(record.get("lifecycle_generation"), str)
            or re.fullmatch(r"[0-9a-f]{32}", record["lifecycle_generation"]) is None
            or type(record.get("active")) is not bool
            or record.get("state")
            not in {state.value for state in FeatureValidationState}
            or record.get("terminal")
            not in {
                None,
                FeatureValidationState.COMPLETE_NORMAL.value,
                FeatureValidationState.RESTORE_FAILED.value,
            }
            or record.get("authorities")
            != {
                "r64_commit": R64_RUNTIME_COMMIT,
                "r64_tree": R64_RUNTIME_TREE,
                "pr41_commit": PR41_RESTORE_COMMIT,
                "pr41_tree": PR41_RESTORE_TREE,
            }
            or not isinstance(record.get("consumed_actions"), list)
            or len(record["consumed_actions"]) != len(set(record["consumed_actions"]))
            or any(item not in valid_actions for item in record["consumed_actions"])
            or not isinstance(record.get("operations"), dict)
            or any(
                key not in valid_actions or value not in valid_phases
                for key, value in record["operations"].items()
            )
            or set(record["operations"]) != set(record["consumed_actions"])
            or not isinstance(record.get("restart_results"), dict)
            or any(
                key
                not in {
                    FeatureValidationAction.R64_RESTART.value,
                    FeatureValidationAction.REMOVAL_RESTART.value,
                }
                or value
                not in {
                    RestartDispatchOutcome.RESPONSE_ACCEPTED.value,
                    RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN.value,
                }
                for key, value in record["restart_results"].items()
            )
            or not backup_valid
            or record.get("source_classification")
            not in {
                None,
                CurrentSourceClassification.EXACT_PR41.value,
                CurrentSourceClassification.EXACT_R64.value,
            }
            or record.get("active") is True
            and record.get("terminal") is not None
            or record.get("active") is False
            and (
                record.get("terminal") is None
                or record.get("terminal") != record.get("state")
            )
        ):
            raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None

    def _write(self, record: dict[str, object], *, replace: bool = True) -> None:
        self._validate(record)
        name = f".{_FEATURE_VALIDATION_JOURNAL_NAME}.{secrets.token_hex(8)}"
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._root_fd,
        )
        try:
            raw = json.dumps(record, separators=(",", ":"), sort_keys=True).encode(
                "ascii"
            )
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise OSError(errno.EIO, "short_write")
                offset += written
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            if not replace:
                try:
                    os.stat(
                        _FEATURE_VALIDATION_JOURNAL_NAME,
                        dir_fd=self._root_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    raise LifecycleControllerError("FEATURE_JOURNAL_EXISTS") from None
            os.replace(
                name,
                _FEATURE_VALIDATION_JOURNAL_NAME,
                src_dir_fd=self._root_fd,
                dst_dir_fd=self._root_fd,
            )
            os.fsync(self._root_fd)
        finally:
            try:
                os.unlink(name, dir_fd=self._root_fd)
            except FileNotFoundError:
                pass

    @property
    def state(self) -> FeatureValidationState:
        return FeatureValidationState(self._record["state"])

    @property
    def terminal_state(self) -> FeatureValidationState | None:
        value = self._record["terminal"]
        return None if value is None else FeatureValidationState(value)

    @property
    def active(self) -> bool:
        return self._record["active"]

    @property
    def schema_version(self) -> int:
        return self._record["schema_version"]

    @property
    def final_restore_complete(self) -> bool:
        return self._final_restore_complete(self._record)

    @property
    def lifecycle_generation(self) -> str:
        return self._record["lifecycle_generation"]

    @property
    def consumed_actions(self) -> frozenset[FeatureValidationAction]:
        return frozenset(
            FeatureValidationAction(item) for item in self._record["consumed_actions"]
        )

    def committed(self, action: FeatureValidationAction) -> bool:
        return self._record["operations"].get(action.value) == "transition_committed"

    def operation_phase(self, action: FeatureValidationAction) -> str | None:
        return self._record["operations"].get(action.value)

    @property
    def backup_identity(self) -> dict[str, object] | None:
        value = self._record["backup_identity"]
        return None if value is None else copy.deepcopy(value)

    def _mutate(self, callback: Callable[[dict[str, object]], None]) -> None:
        record = copy.deepcopy(self._record)
        callback(record)
        record["revision"] += 1
        self._write(record)
        self._record = record

    def begin(self, action: FeatureValidationAction) -> None:
        if action in self.consumed_actions:
            raise LifecycleControllerError("FEATURE_ACTION_ALREADY_CONSUMED") from None

        def mutate(record: dict[str, object]) -> None:
            record["consumed_actions"].append(action.value)
            record["operations"][action.value] = "intent_durable"

        self._mutate(mutate)

    def mark(self, action: FeatureValidationAction, phase: str) -> None:
        if phase not in {"dispatch_started", "result_durable", "transition_committed"}:
            raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None

        def mutate(record: dict[str, object]) -> None:
            if record["operations"].get(action.value) not in {
                "intent_durable",
                "dispatch_started",
                "result_durable",
            }:
                raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None
            record["operations"][action.value] = phase

        self._mutate(mutate)

    def transition(
        self, state: FeatureValidationState, action: FeatureValidationAction
    ) -> None:
        def mutate(record: dict[str, object]) -> None:
            if record["operations"].get(action.value) != "result_durable":
                raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None
            record["operations"][action.value] = "transition_committed"
            record["state"] = state.value

        self._mutate(mutate)

    def record_restart(
        self, action: FeatureValidationAction, result: RestartResult
    ) -> None:
        if action not in {
            FeatureValidationAction.R64_RESTART,
            FeatureValidationAction.REMOVAL_RESTART,
        } or result.dispatch_outcome not in {
            RestartDispatchOutcome.RESPONSE_ACCEPTED,
            RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
        }:
            raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None

        def mutate(record: dict[str, object]) -> None:
            record["restart_results"][action.value] = result.dispatch_outcome.value

        self._mutate(mutate)

    def restart_outcome(
        self, action: FeatureValidationAction
    ) -> RestartDispatchOutcome | None:
        value = self._record["restart_results"].get(action.value)
        return None if value is None else RestartDispatchOutcome(value)

    def require_restore(self, action: FeatureValidationAction) -> None:
        """Durably consume an uncertain operation and permit only restoration."""

        def mutate(record: dict[str, object]) -> None:
            if record["operations"].get(action.value) not in {
                "intent_durable",
                "dispatch_started",
                "result_durable",
            }:
                raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None
            record["operations"][action.value] = "ambiguous"
            record["state"] = FeatureValidationState.RESTORE_REQUIRED.value

        self._mutate(mutate)

    def mark_ambiguous_state_neutral(self, action: FeatureValidationAction) -> None:
        """Retain the lifecycle state while tombstoning an uncertain mutation."""
        if action is not FeatureValidationAction.BACKUP_RETIRE:
            raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None

        def mutate(record: dict[str, object]) -> None:
            if record["operations"].get(action.value) not in {
                "intent_durable",
                "dispatch_started",
                "result_durable",
            }:
                raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None
            record["operations"][action.value] = "ambiguous"

        self._mutate(mutate)

    def commit_state_neutral(self, action: FeatureValidationAction) -> None:
        """Commit one result without changing the restore-side lifecycle state."""
        if action is not FeatureValidationAction.BACKUP_RETIRE:
            raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None

        def mutate(record: dict[str, object]) -> None:
            if record["operations"].get(action.value) != "result_durable":
                raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None
            record["operations"][action.value] = "transition_committed"

        self._mutate(mutate)

    def reconcile_state_neutral_ambiguity(
        self, action: FeatureValidationAction
    ) -> None:
        """Resolve an uncertain mutation from later non-mutating evidence."""
        if action is not FeatureValidationAction.BACKUP_RETIRE:
            raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None

        def mutate(record: dict[str, object]) -> None:
            if record["operations"].get(action.value) != "ambiguous":
                raise LifecycleControllerError("FEATURE_JOURNAL_INVALID") from None
            record["operations"][action.value] = "transition_committed"

        self._mutate(mutate)

    def reconstruction_requires_restore(self) -> None:
        """Persist the restore-only posture before a reconstructed mutation."""

        def mutate(record: dict[str, object]) -> None:
            record["state"] = FeatureValidationState.RESTORE_REQUIRED.value

        self._mutate(mutate)

    @property
    def source_classification(self) -> CurrentSourceClassification | None:
        value = self._record["source_classification"]
        return None if value is None else CurrentSourceClassification(value)

    def record_source_reconciliation(
        self, classification: CurrentSourceClassification
    ) -> None:
        if classification not in {
            CurrentSourceClassification.EXACT_PR41,
            CurrentSourceClassification.EXACT_R64,
        }:
            raise LifecycleControllerError("FEATURE_SOURCE_RECONCILIATION_FAILED")

        def mutate(record: dict[str, object]) -> None:
            record["source_classification"] = classification.value
            record["state"] = (
                FeatureValidationState.PR41_RESTORED.value
                if classification is CurrentSourceClassification.EXACT_PR41
                else FeatureValidationState.RESTORE_REQUIRED.value
            )

        self._mutate(mutate)

    def bind_backup(self, result: BackupResult) -> None:
        def mutate(record: dict[str, object]) -> None:
            if record["backup_identity"] is not None:
                raise LifecycleControllerError("FEATURE_BACKUP_ALREADY_BOUND") from None
            record["backup_identity"] = {
                "lifecycle_generation": result.lifecycle_generation,
                "source_generation": result.source_generation,
                "backup_generation": result.backup_generation,
                "manifest_identity": result.manifest_identity,
                "backup_digest": result.backup_digest,
            }

        self._mutate(mutate)

    def reconcile_backup_creation(self, result: BackupResult) -> None:
        """Bind an exact existing package without moving the current source state."""

        def mutate(record: dict[str, object]) -> None:
            if (
                record["backup_identity"] is not None
                or record["operations"].get(FeatureValidationAction.BACKUP.value)
                != "ambiguous"
            ):
                raise LifecycleControllerError(
                    "FEATURE_BACKUP_RECONCILIATION_FAILED"
                ) from None
            record["backup_identity"] = {
                "lifecycle_generation": result.lifecycle_generation,
                "source_generation": result.source_generation,
                "backup_generation": result.backup_generation,
                "manifest_identity": result.manifest_identity,
                "backup_digest": result.backup_digest,
            }
            record["operations"][
                FeatureValidationAction.BACKUP.value
            ] = "transition_committed"

        self._mutate(mutate)

    def terminal(self, state: FeatureValidationState) -> None:
        def mutate(record: dict[str, object]) -> None:
            record["state"] = state.value
            record["terminal"] = state.value
            record["active"] = False

        self._mutate(mutate)

    def retire_terminal(self) -> None:
        """Remove only this successfully completed retained feature journal."""
        if (
            not self._retained_terminal_inspection
            or self._retired
            or not self.final_restore_complete
        ):
            raise LifecycleControllerError(
                "FEATURE_TERMINAL_RETIREMENT_NOT_AUTHORIZED"
            ) from None
        try:
            os.unlink(_FEATURE_VALIDATION_JOURNAL_NAME, dir_fd=self._root_fd)
            os.fsync(self._root_fd)
        except OSError:
            raise LifecycleControllerError(
                "FEATURE_TERMINAL_RETIREMENT_FAILED"
            ) from None
        self._retired = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for descriptor_name in ("_lock_fd", "_root_fd"):
            descriptor = getattr(self, descriptor_name)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, descriptor_name, None)


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


def _retained_backup_context_payload(
    manifest: SourceManifest, capability: _RetainedBackupCapability
) -> dict[str, object]:
    if manifest.state is not SourceState.RESTORE:
        raise SourceBundleError("RESTORE_MANIFEST_REQUIRED") from None
    validate_source_manifest(manifest)
    identity = capability.backup_identity
    if not (
        type(identity) is dict
        and identity.get("lifecycle_generation") == str(capability.lifecycle_generation)
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
    return {
        "lifecycle_generation": str(capability.lifecycle_generation),
        "source_generation": str(capability.source_generation),
        "source_state": "PR41_BASELINE",
        "manifest": _manifest_payload(manifest),
        "backup_generation": identity["backup_generation"],
        "manifest_identity": identity["manifest_identity"],
        "backup_digest": identity["backup_digest"],
        "restore_marker_owned": capability.restore_marker_owned,
    }


def _feature_backup_context_payload(
    manifest: SourceManifest, capability: _FeatureBackupContinuityCapability
) -> dict[str, object]:
    """Build an authority-owned context without accepting caller identity."""
    if manifest.state is not SourceState.RESTORE:
        raise SourceBundleError("RESTORE_MANIFEST_REQUIRED") from None
    validate_source_manifest(manifest)
    payload = {
        "lifecycle_generation": str(capability.lifecycle_generation),
        "source_generation": str(capability.source_generation),
        "source_state": "PR41_BASELINE",
        "manifest": _manifest_payload(manifest),
        "restore_marker_owned": capability.restore_marker_owned,
    }
    identity = capability.backup_identity
    if identity is None:
        return payload
    if not (
        type(identity) is dict
        and identity.get("lifecycle_generation") == str(capability.lifecycle_generation)
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
    if (
        isinstance(payload, dict)
        and "error_class" in payload
        and payload["error_class"] == "OPERATION_FAILED"
    ):
        if set(payload) != {"error_class", "error_scope", "error_reason"}:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        try:
            scope = RemoteFailureScope(payload["error_scope"])
            reason = RemoteFailureReason(payload["error_reason"])
        except (TypeError, ValueError):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        raise _RemoteOperationFailure(scope, reason) from None
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


def _exact_restart_payload(private_output: bytes) -> dict[str, Any]:
    """Decode only the bounded restart dispatch report."""
    payload = _exact_payload(private_output)
    if set(payload) != {"dispatch_outcome", "http_status", "failure_reason"}:
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
            "observed_managed_count",
            "manifest_match",
            "unexpected_count",
            "missing_count",
            "content_mismatch_count",
            "runtime_cache_file_count",
            "managed_manifest_identity",
            "root_profile",
        }:
            raise ValueError
        expected_count = _count(payload["expected_count"])
        observed_managed_count = _count(payload["observed_managed_count"])
        manifest_match = _bool(payload["manifest_match"])
        unexpected_count = _count(payload["unexpected_count"])
        missing_count = _count(payload["missing_count"])
        content_mismatch_count = _count(payload["content_mismatch_count"])
        runtime_cache_file_count = _count(payload["runtime_cache_file_count"])
        managed_manifest_identity = payload["managed_manifest_identity"]
        if (
            not isinstance(managed_manifest_identity, str)
            or re.fullmatch(r"[0-9a-f]{64}", managed_manifest_identity) is None
        ):
            raise ValueError
        if manifest_match != (
            expected_count == observed_managed_count
            and unexpected_count == 0
            and missing_count == 0
            and content_mismatch_count == 0
        ):
            raise ValueError
        return SourceInventoryResult(
            expected_count,
            observed_managed_count,
            manifest_match,
            unexpected_count,
            missing_count,
            RemoteRootProfile(payload["root_profile"]),
            content_mismatch_count,
            runtime_cache_file_count,
            managed_manifest_identity,
        )
    except (KeyError, TypeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None


def _parse_core_check_result(value: object, *, attempt_ordinal: int) -> CoreCheckResult:
    if attempt_ordinal not in {1, 2}:
        raise SessionBrokerError("CORE_CHECK_ATTEMPT_INVALID") from None
    legacy_field_present = isinstance(value, dict) and "check_passed" in value
    invalid = CoreCheckResult(
        attempt_ordinal,
        None,
        None,
        False,
        "INVALID_RESPONSE",
        CoreCheckResponseContract.INVALID,
        legacy_field_present,
    )
    if not isinstance(value, dict) or not set(value).issubset(
        {"http_status", "result", "check_passed", "error_class"}
    ):
        return invalid
    status = value.get("http_status")
    result = value.get("result")
    error_class = value.get("error_class")
    if (
        type(status) is not int
        or not isinstance(result, str)
        or legacy_field_present
        or "error_class" in value
        and (
            not isinstance(error_class, str)
            or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", error_class) is None
        )
    ):
        return invalid
    exact_pass = (
        set(value) == {"http_status", "result"}
        and 200 <= status < 300
        and result == "ok"
        and error_class is None
    )
    contract = (
        CoreCheckResponseContract.CURRENT_RESULT_OK
        if exact_pass
        else CoreCheckResponseContract.ERROR
    )
    return CoreCheckResult(
        attempt_ordinal,
        status,
        result,
        exact_pass,
        None if exact_pass else error_class or "CHECK_FAILED",
        contract,
        False,
    )


def _parse_restart_result(value: object) -> RestartResult:
    """Validate the complete, private-data-free restart dispatch contract."""
    try:
        if not isinstance(value, dict) or set(value) != {
            "dispatch_outcome",
            "http_status",
            "failure_reason",
        }:
            raise ValueError
        outcome = RestartDispatchOutcome(value["dispatch_outcome"])
        status = value["http_status"]
        reason = value["failure_reason"]
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError
        if reason is not None:
            reason = RestartFailureReason(reason)
        result = RestartResult(outcome, status, reason)
    except (KeyError, TypeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    if result.response_accepted:
        valid = 200 <= (result.http_status or 0) < 300 and result.failure_reason is None
    elif outcome is RestartDispatchOutcome.RESPONSE_REJECTED:
        valid = result.http_status is not None and result.failure_reason in {
            RestartFailureReason.HTTP_REJECTED,
            RestartFailureReason.INVALID_RESPONSE,
        }
    elif outcome is RestartDispatchOutcome.DEFINITELY_NOT_DISPATCHED:
        valid = result.http_status is None and result.failure_reason in {
            RestartFailureReason.CONNECT_FAILED,
            RestartFailureReason.SEND_FAILED,
        }
    else:
        valid = result.http_status is None and result.failure_reason in {
            RestartFailureReason.RESPONSE_TIMEOUT,
            RestartFailureReason.RESPONSE_CLOSED,
        }
    if not valid:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return result


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
    http_status = value.get("http_status")
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
    elif operation is PhaseAOperation.PREFLIGHT and exit_code == 66:
        if (
            set(value) != {"exit_code", "outcome", "nonce", "http_status"}
            or outcome != "http_rejected"
            or nonce is None
            or type(http_status) is not int
            or not 400 <= http_status <= 599
        ):
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

    if expected_nonce is not None and exit_code != 65 and nonce != expected_nonce:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return PhaseAResult(
        operation=operation,
        exit_code=exit_code,
        outcome=outcome,
        nonce=nonce,
        preflight=preflight,
        receipt=receipt,
        audit=audit,
        http_status=http_status,
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


def _parse_remote_phase_a_inventory_result(
    private_output: bytes,
) -> RemotePhaseAInventoryResult:
    """Parse only the fixed identifier-free research aggregate."""
    payload = _exact_payload(private_output)
    scalar_keys = {
        "outcome",
        "eligible_s1_count",
        "selected",
        "same_private_target",
        "completed_probe_slots",
        "cold_request_count",
        "retained_request_count",
        "total_device_status_requests",
        "cold_ack_success_count",
        "retained_ack_success_count",
        "failure_count",
        "timeout_count",
        "receipt_lookup_count",
        "ambiguity_count",
        "normal_release_count",
        "same_session_retained_count",
        "automatic_reconnect_count",
        "observation_overflow_count",
        "protocol_datapoint_write_delta",
        "protocol_datapoint_packet_delta",
        "slots",
        "dp_inventory",
        "failure_category",
        "failure_stage",
        "failure_reason",
        "failed_slot",
        "probe_submission_possible",
    }
    if not isinstance(payload, dict) or set(payload) != scalar_keys:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    outcomes = {
        "complete",
        "sample_incomplete",
        "probe_ambiguous",
        "protocol_write_gate_failed",
        "target_resolution_unsupported",
        "research_failed",
    }
    if payload["outcome"] not in outcomes:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    bool_keys = {"selected", "same_private_target", "probe_submission_possible"}
    failure_keys = {
        "failure_category",
        "failure_stage",
        "failure_reason",
        "failed_slot",
    }
    count_keys = (
        scalar_keys
        - bool_keys
        - failure_keys
        - {
            "outcome",
            "slots",
            "dp_inventory",
        }
    )
    try:
        counts = {key: _count(payload[key]) for key in count_keys}
        booleans = {key: _bool(payload[key]) for key in bool_keys}
        failure_category = (
            None
            if payload["failure_category"] is None
            else ResearchFailureCategory(payload["failure_category"])
        )
        failure_stage = (
            None
            if payload["failure_stage"] is None
            else ResearchFailureStage(payload["failure_stage"])
        )
        failure_reason = (
            None
            if payload["failure_reason"] is None
            else ResearchFailureReason(payload["failure_reason"])
        )
        failed_slot = (
            None if payload["failed_slot"] is None else _count(payload["failed_slot"])
        )
    except (TypeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    if (
        counts["completed_probe_slots"] > 10
        or counts["cold_request_count"] > 10
        or counts["retained_request_count"] > 5
        or counts["total_device_status_requests"] > 15
        or counts["total_device_status_requests"]
        != counts["cold_request_count"] + counts["retained_request_count"]
        or counts["receipt_lookup_count"] > 30
        or not isinstance(payload["slots"], list)
        or len(payload["slots"]) > 10
        or not isinstance(payload["dp_inventory"], list)
        or len(payload["dp_inventory"]) > 256
        or counts["cold_ack_success_count"] > counts["cold_request_count"]
        or counts["retained_ack_success_count"] > counts["retained_request_count"]
        or counts["receipt_lookup_count"] > counts["ambiguity_count"] * 3
        or counts["normal_release_count"] > len(payload["slots"])
        or counts["same_session_retained_count"] > counts["retained_request_count"]
        or counts["automatic_reconnect_count"] > len(payload["slots"])
        or counts["observation_overflow_count"] > len(payload["slots"])
        or failed_slot is not None
        and failed_slot > 10
        or payload["outcome"] == "research_failed"
        and (
            failure_category is None
            or failure_stage is None
            or failure_reason is None
            or failed_slot is None
        )
        or payload["outcome"] != "research_failed"
        and any(
            item is not None
            for item in (
                failure_category,
                failure_stage,
                failure_reason,
                failed_slot,
            )
        )
        or failure_category is ResearchFailureCategory.PRE_PROBE_FAILURE
        and (
            booleans["probe_submission_possible"]
            or counts["total_device_status_requests"] != 0
            or counts["completed_probe_slots"] != 0
        )
        or failure_category
        is ResearchFailureCategory.POST_OR_POSSIBLY_SUBMITTED_PROBE_FAILURE
        and not booleans["probe_submission_possible"]
    ):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    slot_keys = {
        "label",
        "mode",
        "request_count",
        "cold_result",
        "retained_result",
        "same_session_retained",
        "normal_release_observed",
        "automatic_reconnect_observed",
        "observation_overflow",
        "receipt_used",
    }
    slots: list[RemotePhaseASlotSummary] = []
    request_results = {
        "ack_success",
        "update_failed",
        "ack_failed",
        "ack_missing",
        "session_not_retained",
    }
    for index, value in enumerate(payload["slots"], 1):
        expected_label = f"R{index:02d}"
        expected_mode = "cold_then_retained" if index <= 5 else "cold"
        if (
            not isinstance(value, dict)
            or set(value) != slot_keys
            or value["label"] != expected_label
            or value["mode"] != expected_mode
            or value["cold_result"] is not None
            and value["cold_result"] not in request_results
            or value["retained_result"] is not None
            and value["retained_result"] not in request_results
        ):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        try:
            slots.append(
                RemotePhaseASlotSummary(
                    value["label"],
                    value["mode"],
                    _count(value["request_count"]),
                    value["cold_result"],
                    value["retained_result"],
                    *(
                        _bool(value[key])
                        for key in (
                            "same_session_retained",
                            "normal_release_observed",
                            "automatic_reconnect_observed",
                            "observation_overflow",
                            "receipt_used",
                        )
                    ),
                )
            )
        except (TypeError, ValueError):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        if slots[-1].request_count > (2 if index <= 5 else 1):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        if (
            (slots[-1].request_count >= 1) != (slots[-1].cold_result is not None)
            or (slots[-1].request_count >= 2) != (slots[-1].retained_result is not None)
            or index > 5
            and slots[-1].same_session_retained
        ):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    dp_keys = {
        "dp_id",
        "cold_reported_count",
        "cold_eligible_count",
        "retained_reported_count",
        "retained_eligible_count",
        "cold_type_set",
        "cold_encoded_length_set",
        "retained_type_set",
        "retained_encoded_length_set",
        "classification",
    }
    dp_rows: list[RemotePhaseADPInventory] = []
    seen_ids: set[int] = set()
    classifications = {
        "ALWAYS_REPORTED",
        "CONDITIONALLY_REPORTED",
        "NOT_REPORTED",
        "AMBIGUOUS",
    }
    for value in payload["dp_inventory"]:
        if not isinstance(value, dict) or set(value) != dp_keys:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        try:
            dp_id = _count(value["dp_id"])
            cold_reported = _count(value["cold_reported_count"])
            cold_eligible = _count(value["cold_eligible_count"])
            retained_reported = _count(value["retained_reported_count"])
            retained_eligible = _count(value["retained_eligible_count"])
        except (TypeError, ValueError):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        if (
            dp_id in seen_ids
            or dp_id > 255
            or cold_reported > cold_eligible
            or cold_eligible > 10
            or retained_reported > retained_eligible
            or retained_eligible > 5
            or value["classification"] not in classifications
            or not isinstance(value["cold_type_set"], list)
            or not all(
                item
                in {
                    "DT_RAW",
                    "DT_BOOL",
                    "DT_VALUE",
                    "DT_STRING",
                    "DT_ENUM",
                    "DT_BITMAP",
                }
                for item in value["cold_type_set"]
            )
            or len(set(value["cold_type_set"])) != len(value["cold_type_set"])
            or not isinstance(value["retained_type_set"], list)
            or not all(
                item
                in {
                    "DT_RAW",
                    "DT_BOOL",
                    "DT_VALUE",
                    "DT_STRING",
                    "DT_ENUM",
                    "DT_BITMAP",
                }
                for item in value["retained_type_set"]
            )
            or len(set(value["retained_type_set"])) != len(value["retained_type_set"])
            or not isinstance(value["cold_encoded_length_set"], list)
            or any(
                type(item) is not int or item < 0
                for item in value["cold_encoded_length_set"]
            )
            or len(set(value["cold_encoded_length_set"]))
            != len(value["cold_encoded_length_set"])
            or not isinstance(value["retained_encoded_length_set"], list)
            or any(
                type(item) is not int or item < 0
                for item in value["retained_encoded_length_set"]
            )
            or len(set(value["retained_encoded_length_set"]))
            != len(value["retained_encoded_length_set"])
        ):
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
        seen_ids.add(dp_id)
        dp_rows.append(
            RemotePhaseADPInventory(
                dp_id,
                cold_reported,
                cold_eligible,
                retained_reported,
                retained_eligible,
                tuple(value["cold_type_set"]),
                tuple(value["cold_encoded_length_set"]),
                tuple(value["retained_type_set"]),
                tuple(value["retained_encoded_length_set"]),
                value["classification"],
            )
        )
    if tuple(row.dp_id for row in dp_rows) != tuple(sorted(seen_ids)):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    minimum_dp_ids = {8, 21, 33, 34, 36, 40, 47}
    complete = payload["outcome"] == "complete"
    if (
        booleans["selected"]
        and payload["outcome"] != "research_failed"
        and not minimum_dp_ids.issubset(seen_ids)
        or sum(slot.request_count for slot in slots)
        > counts["total_device_status_requests"]
        or complete
        and (
            not booleans["selected"]
            or not booleans["same_private_target"]
            or counts["eligible_s1_count"] < 1
            or len(slots) != 10
            or counts["completed_probe_slots"] != 10
            or counts["cold_request_count"] != 10
            or counts["retained_request_count"] != 5
            or counts["total_device_status_requests"] != 15
            or counts["ambiguity_count"] != 0
            or counts["protocol_datapoint_write_delta"] != 0
            or counts["protocol_datapoint_packet_delta"] != 0
            or any(
                slot.request_count != (2 if index <= 5 else 1)
                for index, slot in enumerate(slots, 1)
            )
            or any(row.cold_eligible_count != 10 for row in dp_rows)
            or any(row.retained_eligible_count != 5 for row in dp_rows)
        )
        or payload["outcome"] == "target_resolution_unsupported"
        and (
            booleans["selected"]
            or booleans["same_private_target"]
            or counts["eligible_s1_count"] != 0
            or slots
            or dp_rows
            or any(counts.values())
        )
        or payload["outcome"] == "protocol_write_gate_failed"
        and counts["protocol_datapoint_write_delta"] == 0
        and counts["protocol_datapoint_packet_delta"] == 0
        or payload["outcome"] == "probe_ambiguous"
        and counts["ambiguity_count"] == 0
        or payload["outcome"]
        not in {"target_resolution_unsupported", "research_failed"}
        and (
            not booleans["selected"]
            or not booleans["same_private_target"]
            or counts["eligible_s1_count"] < 1
        )
        or any(
            (
                row.classification
                != (
                    "ALWAYS_REPORTED"
                    if row.cold_reported_count + row.retained_reported_count == 15
                    else (
                        "NOT_REPORTED"
                        if row.cold_reported_count + row.retained_reported_count == 0
                        else "CONDITIONALLY_REPORTED"
                    )
                )
                if complete
                else row.classification != "AMBIGUOUS"
            )
            for row in dp_rows
        )
    ):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return RemotePhaseAInventoryResult(
        payload["outcome"],
        counts["eligible_s1_count"],
        booleans["selected"],
        booleans["same_private_target"],
        counts["completed_probe_slots"],
        counts["cold_request_count"],
        counts["retained_request_count"],
        counts["total_device_status_requests"],
        counts["cold_ack_success_count"],
        counts["retained_ack_success_count"],
        counts["failure_count"],
        counts["timeout_count"],
        counts["receipt_lookup_count"],
        counts["ambiguity_count"],
        counts["normal_release_count"],
        counts["same_session_retained_count"],
        counts["automatic_reconnect_count"],
        counts["observation_overflow_count"],
        counts["protocol_datapoint_write_delta"],
        counts["protocol_datapoint_packet_delta"],
        tuple(slots),
        tuple(dp_rows),
        failure_category,
        failure_stage,
        failure_reason,
        failed_slot,
        booleans["probe_submission_possible"],
    )


def _parse_remote_phase_a_readiness_result(
    private_output: bytes,
) -> RemotePhaseAReadinessResult:
    """Parse only the exact device-free readiness aggregate."""
    payload = _exact_payload(private_output)
    keys = {
        "ready",
        "eligible_s1_count",
        "selected",
        "same_target_binding_ready",
        "audit_ready",
        "audit_instance_continuity",
        "protocol_write_delta_zero",
        "failure_stage",
        "failure_reason",
    }
    if not isinstance(payload, dict) or set(payload) != keys:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    try:
        ready = _bool(payload["ready"])
        eligible_count = _count(payload["eligible_s1_count"])
        booleans = {
            key: _bool(payload[key])
            for key in (
                "selected",
                "same_target_binding_ready",
                "audit_ready",
                "audit_instance_continuity",
                "protocol_write_delta_zero",
            )
        }
        failure_stage = (
            None
            if payload["failure_stage"] is None
            else ResearchFailureStage(payload["failure_stage"])
        )
        failure_reason = (
            None
            if payload["failure_reason"] is None
            else ResearchFailureReason(payload["failure_reason"])
        )
    except (TypeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    if (
        eligible_count > 128
        or ready
        and (
            eligible_count < 1
            or not all(booleans.values())
            or failure_stage is not None
            or failure_reason is not None
        )
        or not ready
        and (failure_stage is None or failure_reason is None)
    ):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return RemotePhaseAReadinessResult(
        ready,
        eligible_count,
        booleans["selected"],
        booleans["same_target_binding_ready"],
        booleans["audit_ready"],
        booleans["audit_instance_continuity"],
        booleans["protocol_write_delta_zero"],
        failure_stage,
        failure_reason,
    )


def _parse_refresh_status_live_validation_result(
    private_output: bytes,
) -> RefreshStatusLiveValidationResult:
    """Parse the fixed aggregate without retaining remote identifiers or logs."""
    value = _exact_payload(private_output)
    if set(value) != {
        "eligible_s1_count",
        "selected",
        "refresh_button_present",
        "policy_on_demand",
        "ble_control_enabled",
        "hold_time_valid",
        "cold",
        "warm",
        "same_authenticated_session",
        "hold",
        "ambiguous",
        "failure_class",
        "conditional_omission_observed",
    }:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None

    def parse_counts(payload: object) -> RefreshPacketCounts:
        names = ("device_info", "pair", "device_status", "datapoint", "other")
        if not isinstance(payload, dict) or set(payload) != set(names):
            raise ValueError
        result = RefreshPacketCounts(*(_count(payload[name]) for name in names))
        if any(item > 8 for item in asdict(result).values()):
            raise ValueError
        return result

    def parse_press(payload: object) -> RefreshPressResult:
        if not isinstance(payload, dict) or set(payload) != {
            "service_success",
            "counts",
            "session_provenance",
            "last_status_update_advanced",
            "retained_confirmation_changed_dp_ids",
        }:
            raise ValueError
        ids = payload["retained_confirmation_changed_dp_ids"]
        if (
            not isinstance(ids, list)
            or any(type(item) is not int or item not in {8, 33, 34, 36} for item in ids)
            or ids != sorted(set(ids))
        ):
            raise ValueError
        return RefreshPressResult(
            _bool(payload["service_success"]),
            parse_counts(payload["counts"]),
            (
                None
                if payload["session_provenance"] is None
                else RefreshSessionProvenance(payload["session_provenance"])
            ),
            _bool(payload["last_status_update_advanced"]),
            tuple(ids),
        )

    try:
        cold = parse_press(value["cold"])
        warm = parse_press(value["warm"])
        hold_value = value["hold"]
        if not isinstance(hold_value, dict) or set(hold_value) != {
            "warm_immediately_after_press",
            "normal_release_observed",
            "automatic_reconnect_observed",
        }:
            raise ValueError
        failure = value["failure_class"]
        result = RefreshStatusLiveValidationResult(
            _count(value["eligible_s1_count"]),
            _bool(value["selected"]),
            _bool(value["refresh_button_present"]),
            _bool(value["policy_on_demand"]),
            _bool(value["ble_control_enabled"]),
            _bool(value["hold_time_valid"]),
            cold,
            warm,
            _bool(value["same_authenticated_session"]),
            RefreshHoldResult(
                _bool(hold_value["warm_immediately_after_press"]),
                _bool(hold_value["normal_release_observed"]),
                _bool(hold_value["automatic_reconnect_observed"]),
            ),
            _bool(value["ambiguous"]),
            None if failure is None else RefreshStatusFailureClass(failure),
            _bool(value["conditional_omission_observed"]),
        )
    except (KeyError, TypeError, ValueError):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    if (
        result.eligible_s1_count > 64
        or result.cold.counts.device_status > 1
        or result.warm.counts.device_status > 1
        or result.cold.counts.device_status + result.warm.counts.device_status > 2
    ):
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return result


def _parse_feature_absence_result(private_output: bytes) -> FeatureAbsenceResult:
    value = _exact_payload(private_output)
    if set(value) != {"refresh_button_active"}:
        raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL") from None
    return FeatureAbsenceResult(_bool(value["refresh_button_active"]))


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
import http.client
import socket
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path('/config')
ROOT_CANDIDATES = (
    ('DIRECT_CONFIG', ROOT),
    ('HOMEASSISTANT_CONFIG', Path('/homeassistant')),
    ('SUPERVISOR_HOMEASSISTANT', Path('/mnt/data/supervisor/homeassistant')),
)
ROOT_PROFILE = None
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

# Supervisor keeps the restart request open while Docker restarts Core and it
# observes Core return to RUNNING.  R59 bounds only the response wait here;
# after that the controller reconciles from the runtime evidence below.
RESTART_RESPONSE_TIMEOUT_SECONDS = 45
# Supervisor permits up to 10 minutes before its API appears and then up to 15
# minutes for RUNNING.  Keep reconciliation compatible with that contract.
RESTART_READINESS_TIMEOUT_SECONDS = 16 * 60

REMOTE_SCOPES = {
    'BOOTSTRAP', 'ROOT', 'REQUEST', 'SOURCE_INVENTORY', 'BACKUP', 'TRANSFER',
    'INSTALL', 'RESTORE', 'CORE', 'PHASE_A', 'OTHER',
}
REMOTE_REASONS = {
    'ROOT', 'ROOT_UNRESOLVED', 'ROOT_AMBIGUOUS', 'ROOT_INVALID', 'PAYLOAD',
    'AUTHORITY', 'MANIFEST', 'PATH', 'DIRECTORY', 'REGULAR_FILE', 'FILESYSTEM',
    'PRIVATE_STATE', 'RESEARCH_PAYLOAD', 'RESEARCH_TARGET', 'RESEARCH_HELPER',
    'RESEARCH_EVIDENCE', 'RESEARCH_PROBE', 'RESEARCH_RECEIPT',
    'RESEARCH_AUDIT', 'RESEARCH_BUDGET', 'VALIDATION', 'UNKNOWN',
}
REMOTE_REASON_BY_TOKEN = {
    'root': 'ROOT',
    'root_unresolved': 'ROOT_UNRESOLVED',
    'root_ambiguous': 'ROOT_AMBIGUOUS',
    'root_invalid': 'ROOT_INVALID',
    'authority': 'AUTHORITY',
    'manifest': 'MANIFEST',
    'fingerprint': 'MANIFEST',
    'helper': 'MANIFEST',
    'path': 'PATH',
    'directory': 'DIRECTORY',
    'regular': 'REGULAR_FILE',
    'private_state': 'PRIVATE_STATE',
    'backup_identity': 'PRIVATE_STATE',
    'fallback_phase': 'PRIVATE_STATE',
    'research_payload': 'RESEARCH_PAYLOAD',
    'research_operation': 'RESEARCH_PAYLOAD',
    'research_target': 'RESEARCH_TARGET',
    'research_helper_exit': 'RESEARCH_HELPER',
    'research_helper_output': 'RESEARCH_HELPER',
    'research_helper_nonce': 'RESEARCH_HELPER',
    'research_evidence': 'RESEARCH_EVIDENCE',
    'research_probe': 'RESEARCH_PROBE',
    'research_receipt': 'RESEARCH_RECEIPT',
    'research_audit': 'RESEARCH_AUDIT',
    'research_budget': 'RESEARCH_BUDGET',
}

def remote_error(scope, reason):
    if scope not in REMOTE_SCOPES:
        scope = 'OTHER'
    if reason not in REMOTE_REASONS:
        reason = 'UNKNOWN'
    return {
        'error_class': 'OPERATION_FAILED',
        'error_scope': scope,
        'error_reason': reason,
    }

def operation_scope(operation):
    return {
        'backup': 'BACKUP',
        'reconcile_backup_creation': 'BACKUP',
        'transfer': 'TRANSFER',
        'install': 'INSTALL',
        'source_inventory': 'SOURCE_INVENTORY',
        'core_check': 'CORE',
        'restart_core': 'CORE',
        'core_readiness': 'CORE',
        'service_inventory': 'CORE',
        'phase_a_helper': 'PHASE_A',
        'remote_phase_a_inventory': 'PHASE_A',
        'remote_phase_a_readiness': 'PHASE_A',
        'restore': 'RESTORE',
        'restore_backup': 'RESTORE',
        'reconcile_backup': 'RESTORE',
    }.get(operation, 'OTHER')

def operation_reason(error):
    if isinstance(error, OSError):
        return 'FILESYSTEM'
    if (
        isinstance(error, ValueError)
        and len(error.args) == 1
        and isinstance(error.args[0], str)
    ):
        return REMOTE_REASON_BY_TOKEN.get(error.args[0], 'VALIDATION')
    return 'UNKNOWN'

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

def bind_root(profile, path, descriptor):
    global ROOT, ROOT_PROFILE, ROOT_FD, INTEGRATION, HELPER, STAGE
    global BACKUP, BACKUP_CONSUMED, RESTORE_CONSUMED
    ROOT = path
    ROOT_PROFILE = profile
    ROOT_FD = descriptor
    INTEGRATION = ROOT / 'custom_components' / 'tuya_ble'
    HELPER = INTEGRATION / '.phase_a_tools'
    STAGE = ROOT / '.ha_tuya_ble_r30_stage'
    BACKUP = ROOT / '.ha_tuya_ble_r36_backup'
    BACKUP_CONSUMED = ROOT / '.ha_tuya_ble_r36_backup.consumed'
    RESTORE_CONSUMED = ROOT / '.ha_tuya_ble_r30_restore.consumed'

def inspect_root_candidate(path):
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return 'absent', None
    except OSError:
        return 'invalid', None
    if not stat.S_ISDIR(metadata.st_mode):
        return 'invalid', None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return 'invalid', None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            return 'invalid', None
        try:
            structure = os.stat(
                'custom_components', dir_fd=descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            return 'unsupported', None
        except OSError:
            return 'invalid', None
        if not stat.S_ISDIR(structure.st_mode):
            return 'invalid', None
        try:
            structure_fd = os.open(
                'custom_components',
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
        except OSError:
            return 'invalid', None
        try:
            opened_structure = os.fstat(structure_fd)
            if (
                not stat.S_ISDIR(opened_structure.st_mode)
                or opened_structure.st_dev != structure.st_dev
                or opened_structure.st_ino != structure.st_ino
            ):
                return 'invalid', None
        finally:
            os.close(structure_fd)
        result = descriptor
        descriptor = None
        return 'valid', result
    finally:
        if descriptor is not None:
            os.close(descriptor)

def resolve_root():
    valid = []
    invalid = False
    for profile, path in ROOT_CANDIDATES:
        status, descriptor = inspect_root_candidate(path)
        if status == 'valid':
            valid.append((profile, path, descriptor))
        elif status == 'invalid':
            invalid = True
    if len(valid) != 1:
        for _profile, _path, descriptor in valid:
            os.close(descriptor)
        if len(valid) > 1:
            raise ValueError('root_ambiguous')
        if invalid:
            raise ValueError('root_invalid')
        raise ValueError('root_unresolved')
    profile, path, descriptor = valid[0]
    bind_root(profile, path, descriptor)
    return profile

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
            '835f602cc6a73bf224b5d134b3e0c96021696138',
            '2e25fc0971fe0dd6ab698b796454f7970be9b257',
        ),
        'restore': (
            '4f73a9b008dcb89134bc41001c486f06d6056867',
            '463ed8553da01eae591de611e76e45392ad9e7bf',
        ),
        'r64_runtime': (
            '7cfcf9598941de253a24b7c30b06170a98b4ba86',
            'f289523beedb1abe38b28221b1880fa4dec2a7b9',
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
        'candidate': 'c1599dcd1cdc1201cd320c316059159a1948d5f58d4bdaa4c64ea3c4a0390075',
        'restore': '2d1dd79288b90f0d12c5c35449e6ed5d02c53433335dedd68377c81809731ac2',
        'r64_runtime': '4eaed95e3a0dea264e11fffde6a42facdedf775552a3ea85026e85ecffd4b1d7',
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

def count_runtime_cache_files_fd(descriptor):
    count = 0
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
                count += count_runtime_cache_files_fd(child)
            finally:
                os.close(child)
        elif stat.S_ISREG(metadata.st_mode):
            count += 1
    return count

def inventory_fd(
    descriptor, prefix, excluded_top=None, relative=(),
    runtime_cache_counter=None, managed_directories=None
):
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
                if name == '__pycache__':
                    if runtime_cache_counter is not None:
                        runtime_cache_counter[0] += count_runtime_cache_files_fd(child)
                else:
                    if managed_directories is not None:
                        managed_directories.add(
                            prefix + '/' + PurePosixPath(*logical_parts).as_posix()
                        )
                    observed.update(
                        inventory_fd(
                            child, prefix, excluded_top, logical_parts,
                            runtime_cache_counter, managed_directories
                        )
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

def inventory_deployment_fd(
    descriptor, runtime_cache_counter=None, managed_directories=None
):
    observed = inventory_fd(
        descriptor, 'integration', '.phase_a_tools', (),
        runtime_cache_counter, managed_directories
    )
    try:
        helper = open_relative_directory(descriptor, ('.phase_a_tools',))
    except FileNotFoundError:
        return observed
    try:
        if managed_directories is not None:
            managed_directories.add('helper')
        observed.update(
            inventory_fd(
                helper, 'helper', None, (),
                runtime_cache_counter, managed_directories
            )
        )
    finally:
        os.close(helper)
    return observed

def inventory_targets(runtime_cache_counter=None, managed_directories=None):
    try:
        descriptor = open_root_relative(INTEGRATION)
    except FileNotFoundError:
        return {}
    try:
        observed = inventory_deployment_fd(
            descriptor, runtime_cache_counter, managed_directories
        )
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

def copy_deployment_fd(
    source_fd, destination_fd, expected, retained_files=None, destination_prefix=()
):
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
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
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
                after = os.fstat(source_file)
                if (
                    after.st_dev != source_metadata.st_dev
                    or after.st_ino != source_metadata.st_ino
                    or after.st_size != size
                    or (size, digest.hexdigest()) != expected[logical]
                ):
                    raise ValueError('manifest')
                os.fchmod(destination_file, 0o600)
                if retained_files is None:
                    sync_written_file(
                        destination_file, expected[logical][0], expected[logical][1]
                    )
                else:
                    retained_files.append((
                        destination_prefix + parts,
                        destination_file,
                        destination_parent,
                        expected[logical][0],
                        expected[logical][1],
                    ))
                    destination_file = None
                    destination_parent = None
            finally:
                os.close(source_file)
                if destination_file is not None:
                    os.close(destination_file)
        finally:
            os.close(source_parent)
            if destination_parent is not None:
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

def expected_directories(expected):
    directories = set()
    for logical in expected:
        parts = PurePosixPath(logical).parts
        if parts[0] == 'helper':
            directories.add('helper')
        for length in range(2, len(parts)):
            directories.add(PurePosixPath(*parts[:length]).as_posix())
    return directories

def inventory_result(
    expected, observed, runtime_cache_file_count=0, observed_directories=()
):
    unexpected_files = set(observed) - set(expected)
    unexpected_directories = set(observed_directories) - expected_directories(expected)
    common = set(expected) & set(observed)
    content_mismatch_count = sum(
        expected[path] != observed[path] for path in common
    )
    identity = inventory_identity(observed)
    return {
        'expected_count': len(expected),
        'observed_managed_count': len(observed),
        'manifest_match': (
            expected == observed and not unexpected_directories
        ),
        'unexpected_count': len(unexpected_files) + len(unexpected_directories),
        'missing_count': len(set(expected) - set(observed)),
        'content_mismatch_count': content_mismatch_count,
        'runtime_cache_file_count': runtime_cache_file_count,
        'managed_manifest_identity': identity['manifest_identity'],
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
        or (
            re.fullmatch('[0-9a-f]{32}', value['source_generation']) is None
            and value['source_generation']
            != '4f73a9b008dcb89134bc41001c486f06d6056867'
        )
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
        or (
            re.fullmatch('[0-9a-f]{32}', value['source_generation']) is None
            and value['source_generation']
            != '4f73a9b008dcb89134bc41001c486f06d6056867'
        )
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

def inode_record(metadata, kind):
    return (
        kind, metadata.st_dev, metadata.st_ino, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )

def inode_identity(metadata, kind):
    return kind, metadata.st_dev, metadata.st_ino

def inode_state(metadata):
    return metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns

def sync_written_file(descriptor, expected_size, expected_digest):
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or opened.st_size != expected_size
    ):
        raise ValueError('regular')
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    validated = os.fstat(descriptor)
    if (
        inode_record(opened, 'regular') != inode_record(validated, 'regular')
        or size != expected_size
        or digest.hexdigest() != expected_digest
    ):
        raise ValueError('regular')
    before = os.fstat(descriptor)
    os.fsync(descriptor)
    after = os.fstat(descriptor)
    if (
        not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
        or inode_identity(before, 'regular') != inode_identity(after, 'regular')
        or inode_state(before) != inode_state(after)
    ):
        raise ValueError('regular')
    return inode_record(after, 'regular')

def sync_backup_directory(descriptor, is_package_root):
    if not isinstance(is_package_root, bool):
        raise ValueError('directory')
    os.fsync(descriptor)

def open_backup_directories(package_fd):
    directories = {(): os.dup(package_fd)}
    regular_files = set()
    try:
        pending = [()]
        while pending:
            relative = pending.pop()
            descriptor = directories[relative]
            for name in sorted(os.listdir(descriptor)):
                metadata = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False
                )
                logical = relative + (name,)
                if stat.S_ISDIR(metadata.st_mode):
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    opened = os.fstat(child)
                    if (
                        opened.st_dev != metadata.st_dev
                        or opened.st_ino != metadata.st_ino
                        or not stat.S_ISDIR(opened.st_mode)
                    ):
                        os.close(child)
                        raise ValueError('directory')
                    directories[logical] = child
                    pending.append(logical)
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    regular_files.add(logical)
                else:
                    raise ValueError('regular')
        return directories, regular_files
    except BaseException:
        for descriptor in directories.values():
            os.close(descriptor)
        raise

def sync_backup_package_fd(package_fd, integration_fd, retained_files):
    directories, regular_files = open_backup_directories(package_fd)
    try:
        package_identity = os.fstat(package_fd)
        opened_package_identity = os.fstat(directories[()])
        integration_identity = os.fstat(integration_fd)
        opened_integration_identity = os.fstat(directories[('integration',)])
        if (
            package_identity.st_dev != opened_package_identity.st_dev
            or package_identity.st_ino != opened_package_identity.st_ino
            or not stat.S_ISDIR(package_identity.st_mode)
            or integration_identity.st_dev != opened_integration_identity.st_dev
            or integration_identity.st_ino != opened_integration_identity.st_ino
            or not stat.S_ISDIR(integration_identity.st_mode)
        ):
            raise ValueError('directory')
        retained = {}
        for logical, descriptor, parent, size, digest in retained_files:
            if logical in retained:
                raise ValueError('regular')
            retained[logical] = (descriptor, parent, size, digest)
        if set(retained) != regular_files:
            raise ValueError('regular')
        observed = {}
        for logical in sorted(retained):
            descriptor, parent, size, digest = retained[logical]
            expected_parent = os.fstat(directories[logical[:-1]])
            retained_parent = os.fstat(parent)
            if (
                expected_parent.st_dev != retained_parent.st_dev
                or expected_parent.st_ino != retained_parent.st_ino
                or not stat.S_ISDIR(retained_parent.st_mode)
            ):
                raise ValueError('directory')
            synced = sync_written_file(descriptor, size, digest)
            entry = os.stat(
                logical[-1], dir_fd=parent, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(entry.st_mode)
                or entry.st_nlink != 1
                or inode_record(entry, 'regular') != synced
            ):
                raise ValueError('regular')
            observed['/'.join(logical)] = synced
        root_record = None
        for logical in sorted(directories, key=len, reverse=True):
            descriptor = directories[logical]
            before = os.fstat(descriptor)
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError('directory')
            sync_backup_directory(descriptor, not logical)
            after = os.fstat(descriptor)
            if (
                inode_identity(before, 'directory')
                != inode_identity(after, 'directory')
                or inode_state(before) != inode_state(after)
            ):
                raise ValueError('directory')
            record = inode_record(after, 'directory')
            if logical:
                entry = os.stat(
                    logical[-1],
                    dir_fd=directories[logical[:-1]],
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(entry.st_mode)
                    or inode_record(entry, 'directory') != record
                ):
                    raise ValueError('directory')
                observed['/'.join(logical)] = record
            else:
                root_record = record
        if root_record is None:
            raise ValueError('directory')
        return observed, root_record
    finally:
        for descriptor in directories.values():
            os.close(descriptor)

def assert_root_relative_record(path, descriptor, expected):
    current = open_root_relative(path)
    try:
        if (
            inode_record(os.fstat(descriptor), 'directory') != expected
            or inode_record(os.fstat(current), 'directory') != expected
        ):
            raise ValueError('directory')
    finally:
        os.close(current)

def sync_directory_fd(descriptor, relative=()):
    observed = {}
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
                observed.update(sync_directory_fd(child, relative + (name,)))
                closed = os.fstat(child)
                if (
                    closed.st_dev != opened.st_dev
                    or closed.st_ino != opened.st_ino
                ):
                    raise ValueError('directory')
                observed['/'.join(relative + (name,))] = inode_record(
                    closed, 'directory'
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
                    or opened.st_nlink != 1
                ):
                    raise ValueError('regular')
                os.fsync(child)
                closed = os.fstat(child)
                if (
                    closed.st_dev != opened.st_dev
                    or closed.st_ino != opened.st_ino
                ):
                    raise ValueError('regular')
                observed['/'.join(relative + (name,))] = inode_record(
                    closed, 'regular'
                )
            finally:
                os.close(child)
        else:
            raise ValueError('regular')
    os.fsync(descriptor)
    return observed

def directory_inode_snapshot(descriptor, relative=()):
    observed = {}
    for name in sorted(os.listdir(descriptor)):
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        logical = '/'.join(relative + (name,))
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
                    directory_inode_snapshot(child, relative + (name,))
                )
                closed = os.fstat(child)
                if (
                    closed.st_dev != opened.st_dev
                    or closed.st_ino != opened.st_ino
                ):
                    raise ValueError('directory')
                observed[logical] = inode_record(closed, 'directory')
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
                observed[logical] = inode_record(opened, 'regular')
            finally:
                os.close(child)
        else:
            raise ValueError('regular')
    return observed

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
    pending_fd = live_fd = staged_fd = package_fd = source_fd = None
    retained_files = []
    try:
        pending_fd = open_root_relative(pending)
        os.mkdir('integration', mode=0o700, dir_fd=pending_fd)
        live_fd = open_root_relative(INTEGRATION)
        staged_fd = open_relative_directory(pending_fd, ('integration',))
        copy_deployment_fd(
            live_fd, staged_fd, expected, retained_files, ('integration',)
        )
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
        descriptor = parent = None
        try:
            descriptor = os.open(
                BACKUP_METADATA_NAME,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=pending_fd,
            )
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError(errno.EIO, 'short_write')
                offset += written
            parent = os.dup(pending_fd)
            retained_files.append((
                (BACKUP_METADATA_NAME,), descriptor, parent, len(payload),
                hashlib.sha256(payload).hexdigest(),
            ))
            descriptor = parent = None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if parent is not None:
                os.close(parent)
        synced_inodes, synced_root = sync_backup_package_fd(
            pending_fd, staged_fd, retained_files
        )
        if (
            read_backup_identity_fd(value, pending_fd) != metadata
            or directory_inode_snapshot(pending_fd) != synced_inodes
        ):
            raise ValueError('backup_identity')
        assert_root_relative_record(pending, pending_fd, synced_root)
        package_fd = publish_noreplace(pending, BACKUP, pending_fd)
        sync_root()
        pending = None
        published_identity = read_backup_identity_fd(value, package_fd)
        source_fd = open_relative_directory(package_fd, ('integration',))
        published = inventory_deployment_fd(source_fd)
        assert_root_relative_identity(BACKUP, package_fd)
        if (
            published_identity != metadata
            or published != expected
            or directory_inode_snapshot(package_fd) != synced_inodes
        ):
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
        descriptors = [source_fd, package_fd]
        for _logical, descriptor, parent, _size, _digest in retained_files:
            descriptors.extend((descriptor, parent))
        descriptors.extend((staged_fd, live_fd, pending_fd))
        close_error = None
        for descriptor in descriptors:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    if close_error is None:
                        close_error = error
        try:
            if pending is not None:
                remove(pending)
        finally:
            if close_error is not None:
                raise close_error

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

def retained_backup_continuity(value):
    if not isinstance(value, dict) or type(value.get('restore_marker_owned')) is not bool:
        raise ValueError('backup_context')
    context = dict(value)
    restore_marker_owned = context.pop('restore_marker_owned')
    expected = validate_backup_context(context)
    package_present = root_relative_exists(BACKUP)
    backup_consumed_present = root_relative_exists(BACKUP_CONSUMED)
    restore_consumed_present = root_relative_exists(RESTORE_CONSUMED)
    stale_stage_present = root_relative_exists(STAGE) or any(
        name.startswith(BACKUP.name + '.pending-')
        or name.startswith(STAGE.name + '.pending')
        or name.startswith('.ha_tuya_ble_r36_restore-')
        for name in os.listdir(ROOT_FD)
    )
    restore_marker_valid = not restore_consumed_present
    if restore_consumed_present and restore_marker_owned:
        marker_parent = marker_fd = None
        try:
            marker_parent = open_root_relative(RESTORE_CONSUMED.parent)
            marker_fd = os.open(
                RESTORE_CONSUMED.name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=marker_parent,
            )
            marker = os.fstat(marker_fd)
            restore_marker_valid = (
                stat.S_ISREG(marker.st_mode)
                and marker.st_uid == os.getuid()
                and marker.st_nlink == 1
                and marker.st_mode & 0o777 == 0o600
                and marker.st_size == 0
            )
        except OSError:
            restore_marker_valid = False
        finally:
            if marker_fd is not None:
                os.close(marker_fd)
            if marker_parent is not None:
                os.close(marker_parent)
    other_present = (
        backup_consumed_present
        or stale_stage_present
        or restore_consumed_present and not restore_marker_owned
        or not restore_marker_valid
    )
    if not package_present and restore_consumed_present:
        if not other_present and restore_marker_owned and restore_marker_valid:
            return {
                'classification': 'OWNED_BY_RETAINED_LIFECYCLE',
                'retired': False,
            }
        return {'classification': 'OTHER_OR_INDETERMINATE', 'retired': False}
    if not package_present and not other_present:
        return {'classification': 'NONE', 'retired': False}
    if not package_present or other_present:
        return {'classification': 'OTHER_OR_INDETERMINATE', 'retired': False}
    package_fd = source_fd = None
    try:
        package_fd = open_root_relative(BACKUP)
        identity = read_backup_identity_fd(value, package_fd)
        source_fd = open_relative_directory(package_fd, ('integration',))
        packaged = inventory_deployment_fd(source_fd)
        observed_identity = inventory_identity(packaged)
        if (
            packaged != expected
            or observed_identity['file_count'] != identity['file_count']
            or observed_identity['manifest_identity'] != identity['manifest_identity']
        ):
            raise ValueError('backup_identity')
        assert_root_relative_identity(BACKUP, package_fd)
    except Exception:
        return {'classification': 'OTHER_OR_INDETERMINATE', 'retired': False}
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if package_fd is not None:
            os.close(package_fd)
    return {'classification': 'OWNED_BY_RETAINED_LIFECYCLE', 'retired': False}

def retire_retained_backup(value):
    result = retained_backup_continuity(value)
    if result['classification'] != 'OWNED_BY_RETAINED_LIFECYCLE':
        return result
    remove(BACKUP)
    if value['restore_marker_owned'] and root_relative_exists(RESTORE_CONSUMED):
        remove(RESTORE_CONSUMED)
    sync_root()
    if any(
        root_relative_exists(path)
        for path in (BACKUP, BACKUP_CONSUMED, RESTORE_CONSUMED, STAGE)
    ):
        raise ValueError('private_state')
    return {'classification': 'NONE', 'retired': True}

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
    if state == 'candidate':
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
        if (
            not isinstance(body, dict)
            or set(body) != {'result', 'data'}
            or body.get('result') != 'ok'
            or body.get('data') != {}
        ):
            return {
                'http_status': status,
                'result': body.get('result') if isinstance(body, dict) else 'error',
                **(
                    {'check_passed': body['check_passed']}
                    if isinstance(body, dict) and 'check_passed' in body
                    else {}
                ),
                'error_class': 'INVALID_RESPONSE',
            }
        return {
            'http_status': status,
            'result': 'ok',
        }
    except urllib.error.HTTPError as error:
        try:
            body_bytes = error.read(1024 * 1024 + 1)
            if len(body_bytes) > 1024 * 1024:
                raise ValueError('response_size')
            body = decode_json(body_bytes)
            result = body.get('result') if isinstance(body, dict) else None
        except Exception:
            result = None
        return {
            'http_status': error.code,
            'result': result if isinstance(result, str) else 'error',
            'error_class': 'CHECK_REJECTED',
        }
    except Exception:
        return {
            'http_status': 0,
            'result': 'error',
            'error_class': 'REQUEST_FAILED',
        }

def restart_core():
    connection = http.client.HTTPConnection(
        'supervisor', timeout=RESTART_RESPONSE_TIMEOUT_SECONDS
    )
    try:
        connection.connect()
    except (OSError, http.client.HTTPException):
        return {
            'dispatch_outcome': 'DEFINITELY_NOT_DISPATCHED',
            'http_status': None,
            'failure_reason': 'CONNECT_FAILED',
        }
    try:
        connection.putrequest('POST', '/core/restart', skip_host=True)
        connection.putheader('Host', 'supervisor')
        for name, value in headers().items():
            connection.putheader(name, value)
        connection.putheader('Content-Length', '0')
        connection.endheaders()
    except (OSError, http.client.HTTPException):
        connection.close()
        return {
            'dispatch_outcome': 'DEFINITELY_NOT_DISPATCHED',
            'http_status': None,
            'failure_reason': 'SEND_FAILED',
        }
    try:
        response = connection.getresponse()
        status = response.status
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError('response_size')
        decoded = decode_json(body)
    except socket.timeout:
        return {
            'dispatch_outcome': 'DISPATCHED_RESPONSE_UNKNOWN',
            'http_status': None,
            'failure_reason': 'RESPONSE_TIMEOUT',
        }
    except (OSError, http.client.HTTPException):
        return {
            'dispatch_outcome': 'DISPATCHED_RESPONSE_UNKNOWN',
            'http_status': None,
            'failure_reason': 'RESPONSE_CLOSED',
        }
    except (TypeError, ValueError, json.JSONDecodeError):
        return {
            'dispatch_outcome': 'RESPONSE_REJECTED',
            'http_status': status if 'status' in locals() else None,
            'failure_reason': 'INVALID_RESPONSE',
        }
    finally:
        connection.close()
    if not 200 <= status < 300:
        return {
            'dispatch_outcome': 'RESPONSE_REJECTED',
            'http_status': status,
            'failure_reason': 'HTTP_REJECTED',
        }
    if not (
        isinstance(decoded, dict)
        and set(decoded) == {'result', 'data'}
        and decoded.get('result') == 'ok'
        and decoded.get('data') == {}
    ):
        return {
            'dispatch_outcome': 'RESPONSE_REJECTED',
            'http_status': status,
            'failure_reason': 'INVALID_RESPONSE',
        }
    return {
        'dispatch_outcome': 'RESPONSE_ACCEPTED',
        'http_status': status,
        'failure_reason': None,
    }

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
    deadline = time.monotonic() + RESTART_READINESS_TIMEOUT_SECONDS
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
        else {'outcome', 'nonce', 'http_status'}
        if completed.returncode == 66
        else {'outcome', 'nonce'}
    )
    if (
        not isinstance(output, dict)
        or set(output) != expected_output
        or not isinstance(output.get('outcome'), str)
        or completed.returncode == 0 and output.get('evidence_written') is not True
        or completed.returncode == 66
        and (
            output.get('outcome') != 'http_rejected'
            or type(output.get('http_status')) is not int
            or not 400 <= output['http_status'] <= 599
        )
        or completed.returncode != 65 and output.get('nonce') != value.get('nonce')
    ):
        raise ValueError('helper_output')
    result = {
        'exit_code': completed.returncode,
        'outcome': output['outcome'],
    }
    if 'nonce' in output:
        result['nonce'] = output['nonce']
    if 'http_status' in output:
        result['http_status'] = output['http_status']
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

def research_evidence_path(operation, label):
    if operation not in {'probe', 'receipt', 'audit'}:
        raise ValueError('research_operation')
    if not isinstance(label, str) or not re.fullmatch(r'R63S_[A-Z0-9_]{1,24}', label):
        raise ValueError('research_label')
    return EVIDENCE / (operation + '-' + label + '.json')

def read_research_evidence(operation, label):
    path = research_evidence_path(operation, label)
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or metadata.st_size > 512 * 1024
        ):
            raise ValueError('research_evidence')
        return decode_json(path.read_bytes())
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

def invoke_research_helper(operation, label, nonce, mode=None, target=None):
    if operation not in {'probe', 'receipt', 'audit'}:
        raise ValueError('research_operation')
    if not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{32}', nonce):
        raise ValueError('research_nonce')
    path = research_evidence_path(operation, label)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    command = [
        sys.executable,
        '-S',
        str(HELPER / 'phase_a_status_probe_helper.py'),
        operation,
        '--nonce',
        nonce,
        '--evidence-label',
        label,
    ]
    environment = os.environ.copy()
    if operation == 'probe':
        if mode not in {'cold', 'cold_then_retained'} or not isinstance(target, str):
            raise ValueError('research_probe')
        command += ['--mode', mode]
        environment['PHASE_A_STATUS_PROBE_CONFIG_ENTRY_ID'] = target
    elif mode is not None or target is not None:
        raise ValueError('research_helper_arguments')
    runner = __import__('sub' + 'process')
    try:
        completed = runner.run(
            command,
            capture_output=True,
            check=False,
            timeout=190,
            env=environment,
        )
    except runner.TimeoutExpired:
        return 78, 'transport_ambiguous', None, None
    if completed.stderr or completed.returncode not in {0, 65, 66, 67, 78}:
        raise ValueError('research_helper_exit')
    output = decode_json(completed.stdout)
    if not isinstance(output, dict) or not isinstance(output.get('outcome'), str):
        raise ValueError('research_helper_output')
    evidence = None
    http_status = None
    if completed.returncode in {0, 66} and output.get('evidence_written') is True:
        if set(output) != {'outcome', 'nonce', 'evidence_written'}:
            raise ValueError('research_helper_output')
        evidence = read_research_evidence(operation, label)
    elif completed.returncode == 66 and output.get('outcome') == 'http_rejected':
        if (
            set(output) != {'outcome', 'nonce', 'http_status'}
            or type(output.get('http_status')) is not int
            or not 400 <= output['http_status'] <= 599
        ):
            raise ValueError('research_helper_output')
        http_status = output['http_status']
    elif completed.returncode in {67, 78}:
        if set(output) != {'outcome', 'nonce'}:
            raise ValueError('research_helper_output')
    elif completed.returncode == 65:
        if output != {'outcome': 'not_submitted'}:
            raise ValueError('research_helper_output')
    else:
        raise ValueError('research_helper_output')
    if completed.returncode != 65 and output.get('nonce') != nonce:
        raise ValueError('research_helper_nonce')
    return completed.returncode, output['outcome'], evidence, http_status

def loaded_tuya_entries():
    status, entries = request_json(
        'http://supervisor/core/api/config/config_entries/entry?domain=tuya_ble'
    )
    if not 200 <= status < 300 or not isinstance(entries, list) or len(entries) > 128:
        raise ValueError('research_target')
    result = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('research_target')
        entry_id = entry.get('entry_id')
        if (
            entry.get('domain') != 'tuya_ble'
            or not isinstance(entry_id, str)
            or not re.fullmatch(
                r'(?:[0-9a-f]{32}|[0-9A-HJKMNP-TV-Z]{26})', entry_id
            )
            or entry_id in seen
        ):
            raise ValueError('research_target')
        seen.add(entry_id)
        if entry.get('state') != 'loaded':
            continue
        result.append(entry_id)
    return tuple(sorted(result))

def resolve_research_target():
    loaded = loaded_tuya_entries()
    eligible = []
    for entry_id in loaded:
        status, diagnostics = request_json(
            'http://supervisor/core/api/diagnostics/config_entry/' + entry_id
        )
        if not 200 <= status < 300 or not isinstance(diagnostics, dict):
            raise ValueError('research_target')
        data = diagnostics.get('data')
        if not isinstance(data, dict):
            raise ValueError('research_target')
        entry = data.get('entry')
        options = data.get('options')
        if not isinstance(entry, dict) or not isinstance(options, dict):
            raise ValueError('research_target')
        if entry.get('entry_id') != entry_id:
            raise ValueError('research_target')
        if options.get('category') == 'jtmspro' and options.get('product_id') == 'xqeob8h6':
            eligible.append(entry_id)
    eligible = tuple(sorted(eligible))
    if not eligible:
        return 0, None
    selected = eligible[0]
    if selected not in loaded_tuya_entries():
        raise ValueError('research_target')
    return len(eligible), selected

def validate_research_audit(value, expected_nonce=None):
    required = {
        'result', 'protocol_version', 'audit_instance_token', 'event_ordinal',
        'history_overflow', 'runtime_ms', 'counters', 'events',
    }
    if expected_nonce is not None:
        required.add('nonce')
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError('research_audit')
    if (
        value['result'] != 'audit_snapshot'
        or value['protocol_version'] != 1
        or not isinstance(value['audit_instance_token'], str)
        or not re.fullmatch(r'[0-9a-f]{16,32}', value['audit_instance_token'])
        or type(value['event_ordinal']) is not int
        or value['event_ordinal'] < 0
        or type(value['history_overflow']) is not bool
        or value['history_overflow']
        or type(value['runtime_ms']) is not int
        or value['runtime_ms'] < 0
        or not isinstance(value['counters'], dict)
        or set(value['counters']) != COUNTERS
        or any(type(item) is not int or item < 0 for item in value['counters'].values())
        or not isinstance(value['events'], list)
        or len(value['events']) > 128
        or expected_nonce is not None and value.get('nonce') != expected_nonce
    ):
        raise ValueError('research_audit')
    return value

def validate_research_probe(value, mode, nonce):
    keys = {
        'mode', 'result', 'cold_request_attempted', 'retained_request_attempted',
        'request_count', 'same_session_retained', 'normal_release_observed',
        'automatic_reconnect_observed', 'observation_overflow', 'duration_ms',
        'requests', 'events', 'invocation_nonce',
    }
    results = {
        'completed', 'invalid_or_incomplete', 'invalid_input',
        'precondition_failed', 'probe_already_active', 'duplicate_nonce',
        'nonce_capacity_reached', 'observation_overflow',
        'known_service_error', 'service_error',
    }
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or value['mode'] != mode
        or value['result'] not in results
        or value['invocation_nonce'] != nonce
        or type(value['request_count']) is not int
        or not 0 <= value['request_count'] <= (2 if mode == 'cold_then_retained' else 1)
        or type(value['duration_ms']) is not int
        or value['duration_ms'] < 0
        or any(
            type(value[key]) is not bool
            for key in (
                'cold_request_attempted', 'retained_request_attempted',
                'same_session_retained', 'normal_release_observed',
                'automatic_reconnect_observed', 'observation_overflow',
            )
        )
        or not isinstance(value['requests'], list)
        or len(value['requests']) != value['request_count']
        or not isinstance(value['events'], list)
        or len(value['events']) > 64
    ):
        raise ValueError('research_probe')
    request_results = {'ack_success', 'update_failed', 'ack_failed', 'ack_missing', 'session_not_retained'}
    expected_trials = list(range(1, len(value['requests']) + 1))
    for ordinal, request in enumerate(value['requests'], 1):
        if (
            not isinstance(request, dict)
            or set(request) != {'trial', 'result', 'duration_ms'}
            or request.get('trial') != ordinal
            or request.get('result') not in request_results
            or type(request.get('duration_ms')) is not int
            or request['duration_ms'] < 0
        ):
            raise ValueError('research_probe')
    del expected_trials
    event_keys = {
        'trial', 'observation_ordinal', 'origin', 'kind', 'event_ordinal',
        'batch_ordinal', 'dp_ids', 'dp_types', 'encoded_value_lengths',
        'exact_session', 'ack_result', 'ack_phase', 'monotonic_ms',
    }
    event_kinds = {
        'REQUEST_CREATED', 'REQUEST_HANDED_TO_TRANSPORT', 'ACK_SUCCESS',
        'ACK_FAILURE', 'ACK_TIMEOUT', 'DP_BATCH', 'OBSERVATION_SUPERSEDED',
        'OBSERVATION_ENDED', 'SESSION_INVALIDATED',
    }
    dp_types = {'DT_RAW', 'DT_BOOL', 'DT_VALUE', 'DT_STRING', 'DT_ENUM', 'DT_BITMAP'}
    for event in value['events']:
        if (
            not isinstance(event, dict)
            or set(event) != event_keys
            or event.get('origin') not in {'explicit', 'automatic'}
            or event.get('kind') not in event_kinds
            or type(event.get('trial')) is not int
            or event['trial'] not in {1, 2}
            or type(event.get('observation_ordinal')) is not int
            or event['observation_ordinal'] < 0
            or type(event.get('event_ordinal')) is not int
            or event['event_ordinal'] < 0
            or event.get('batch_ordinal') is not None
            and (
                type(event['batch_ordinal']) is not int
                or event['batch_ordinal'] < 0
            )
            or type(event.get('monotonic_ms')) is not int
            or event['monotonic_ms'] < 0
            or type(event.get('exact_session')) is not bool
            or event.get('ack_result') not in {None, 'success', 'failure', 'timeout'}
            or event.get('ack_phase') not in {None, 'before_ack', 'after_ack'}
            or not isinstance(event.get('dp_ids'), list)
            or not isinstance(event.get('dp_types'), list)
            or not isinstance(event.get('encoded_value_lengths'), list)
            or not len(event['dp_ids']) == len(event['dp_types']) == len(event['encoded_value_lengths'])
            or any(type(item) is not int or item < 0 or item > 255 for item in event['dp_ids'])
            or any(item not in dp_types for item in event['dp_types'])
            or any(type(item) is not int or item < 0 for item in event['encoded_value_lengths'])
        ):
            raise ValueError('research_probe')
    if mode == 'cold' and (
        value['retained_request_attempted'] or value['same_session_retained']
        or len(value['requests']) > 1
    ):
        raise ValueError('research_probe')
    if value['result'] == 'completed':
        expected = 2 if mode == 'cold_then_retained' else 1
        if (
            value['request_count'] != expected
            or any(item['result'] != 'ack_success' for item in value['requests'])
            or not value['normal_release_observed']
            or value['automatic_reconnect_observed']
            or value['observation_overflow']
            or mode == 'cold_then_retained' and not value['same_session_retained']
        ):
            raise ValueError('research_probe')
    return value

def validate_research_receipt(value, nonce):
    keys = {
        'nonce', 'known', 'service_entered', 'request_handed_to_transport',
        'terminal_class', 'response_available',
    }
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or value.get('nonce') != nonce
        or any(type(value.get(key)) is not bool for key in (
            'known', 'service_entered', 'request_handed_to_transport',
            'response_available',
        ))
        or value.get('terminal_class') is not None
        and not isinstance(value.get('terminal_class'), str)
    ):
        raise ValueError('research_receipt')
    return value

def research_audit_after_slot(index, previous):
    nonce = os.urandom(16).hex()
    label = 'R63S_A' + str(index).zfill(2)
    code, outcome, evidence, _status = invoke_research_helper('audit', label, nonce)
    if code != 0 or outcome != 'audit_snapshot' or evidence is None:
        raise ValueError('research_audit')
    current = validate_research_audit(evidence, nonce)
    if (
        current['audit_instance_token'] != previous['audit_instance_token']
        or current['event_ordinal'] < previous['event_ordinal']
        or any(current['counters'][key] < previous['counters'][key] for key in COUNTERS)
    ):
        raise ValueError('research_audit')
    delta = {
        key: current['counters'][key] - previous['counters'][key]
        for key in COUNTERS
    }
    return current, delta

def research_failure_inventory_result(
    stage, reason, failed_slot, submission_possible,
    eligible_count=0, selected=False, counters=None, slots=None,
):
    if counters is None:
        counters = {
            'completed': 0, 'cold': 0, 'retained': 0, 'cold_ack': 0,
            'retained_ack': 0, 'failure': 0, 'timeout': 0, 'receipt': 0,
            'ambiguity': 0, 'release': 0, 'same_session': 0,
            'reconnect': 0, 'overflow': 0, 'writes': 0, 'packets': 0,
        }
    if slots is None:
        slots = []
    return {
        'outcome': 'research_failed', 'eligible_s1_count': eligible_count,
        'selected': selected, 'same_private_target': False,
        'completed_probe_slots': counters['completed'],
        'cold_request_count': counters['cold'],
        'retained_request_count': counters['retained'],
        'total_device_status_requests': counters['cold'] + counters['retained'],
        'cold_ack_success_count': counters['cold_ack'],
        'retained_ack_success_count': counters['retained_ack'],
        'failure_count': counters['failure'] + 1,
        'timeout_count': counters['timeout'],
        'receipt_lookup_count': counters['receipt'],
        'ambiguity_count': counters['ambiguity'],
        'normal_release_count': counters['release'],
        'same_session_retained_count': counters['same_session'],
        'automatic_reconnect_count': counters['reconnect'],
        'observation_overflow_count': counters['overflow'],
        'protocol_datapoint_write_delta': counters['writes'],
        'protocol_datapoint_packet_delta': counters['packets'],
        'slots': slots, 'dp_inventory': [],
        'failure_category': (
            'POST_OR_POSSIBLY_SUBMITTED_PROBE_FAILURE'
            if submission_possible else 'PRE_PROBE_FAILURE'
        ),
        'failure_stage': stage, 'failure_reason': reason,
        'failed_slot': failed_slot,
        'probe_submission_possible': submission_possible,
    }

def research_readiness_result(
    ready, eligible_count, selected, target_ready, audit_ready,
    instance_continuity, zero_delta, stage=None, reason=None,
):
    return {
        'ready': ready, 'eligible_s1_count': eligible_count,
        'selected': selected,
        'same_target_binding_ready': target_ready,
        'audit_ready': audit_ready,
        'audit_instance_continuity': instance_continuity,
        'protocol_write_delta_zero': zero_delta,
        'failure_stage': stage, 'failure_reason': reason,
    }

def remote_phase_a_readiness(value):
    if not isinstance(value, dict) or set(value) != {'baseline'}:
        return research_readiness_result(
            False, 0, False, False, False, False, False,
            'ADMISSION', 'INVALID_SHAPE',
        )
    try:
        baseline = validate_research_audit(value['baseline'])
    except Exception:
        return research_readiness_result(
            False, 0, False, False, False, False, False,
            'ADMISSION', 'INVALID_SHAPE',
        )
    try:
        eligible_count, selected = resolve_research_target()
    except Exception:
        return research_readiness_result(
            False, 0, False, False, False, False, False,
            'TARGET_RESOLUTION', 'TARGET_METADATA_UNAVAILABLE',
        )
    if selected is None:
        return research_readiness_result(
            False, eligible_count, False, False, False, False, False,
            'TARGET_RESOLUTION', 'NO_ELIGIBLE_TARGET',
        )
    nonce = os.urandom(16).hex()
    try:
        code, outcome, evidence, _status = invoke_research_helper(
            'audit', 'R63S_READY', nonce
        )
    except Exception:
        return research_readiness_result(
            False, eligible_count, True, True, False, False, False,
            'AUDIT', 'HELPER_TERMINAL',
        )
    if code != 0 or outcome != 'audit_snapshot' or evidence is None:
        return research_readiness_result(
            False, eligible_count, True, True, False, False, False,
            'AUDIT', 'HELPER_TERMINAL',
        )
    try:
        current = validate_research_audit(evidence, nonce)
    except Exception:
        return research_readiness_result(
            False, eligible_count, True, True, False, False, False,
            'AUDIT', 'INVALID_SHAPE',
        )
    if current['audit_instance_token'] != baseline['audit_instance_token']:
        return research_readiness_result(
            False, eligible_count, True, True, True, False, False,
            'AUDIT', 'AUDIT_INSTANCE_CHANGED',
        )
    if (
        current['event_ordinal'] < baseline['event_ordinal']
        or any(current['counters'][key] < baseline['counters'][key] for key in COUNTERS)
    ):
        return research_readiness_result(
            False, eligible_count, True, True, True, True, False,
            'AUDIT', 'COUNTER_REGRESSION',
        )
    zero_keys = {
        'device_status_requests', 'device_info_requests', 'pair_requests',
        'datapoint_write_operations', 'datapoint_protocol_packets',
    }
    zero_delta = all(
        current['counters'][key] == baseline['counters'][key]
        for key in zero_keys
    )
    if not zero_delta:
        return research_readiness_result(
            False, eligible_count, True, True, True, True, False,
            'AUDIT', 'PROTOCOL_WRITE_DETECTED',
        )
    return research_readiness_result(
        True, eligible_count, True, True, True, True, True,
    )

def remote_phase_a_inventory(value):
    if not isinstance(value, dict) or set(value) != {'baseline'}:
        return research_failure_inventory_result(
            'ADMISSION', 'INVALID_SHAPE', 0, False
        )
    try:
        baseline = validate_research_audit(value['baseline'])
    except Exception:
        return research_failure_inventory_result(
            'ADMISSION', 'INVALID_SHAPE', 0, False
        )
    try:
        eligible_count, selected = resolve_research_target()
    except Exception:
        return research_failure_inventory_result(
            'TARGET_RESOLUTION', 'TARGET_METADATA_UNAVAILABLE', 0, False
        )
    if selected is None:
        return {
            'outcome': 'target_resolution_unsupported', 'eligible_s1_count': 0,
            'selected': False, 'same_private_target': False,
            'completed_probe_slots': 0, 'cold_request_count': 0,
            'retained_request_count': 0, 'total_device_status_requests': 0,
            'cold_ack_success_count': 0, 'retained_ack_success_count': 0,
            'failure_count': 0, 'timeout_count': 0, 'receipt_lookup_count': 0,
            'ambiguity_count': 0, 'normal_release_count': 0,
            'same_session_retained_count': 0, 'automatic_reconnect_count': 0,
            'observation_overflow_count': 0,
            'protocol_datapoint_write_delta': 0,
            'protocol_datapoint_packet_delta': 0, 'slots': [],
            'dp_inventory': [],
            'failure_category': None, 'failure_stage': None,
            'failure_reason': None, 'failed_slot': None,
            'probe_submission_possible': False,
        }
    plan = (
        ('R01', 'cold_then_retained'), ('R02', 'cold_then_retained'),
        ('R03', 'cold_then_retained'), ('R04', 'cold_then_retained'),
        ('R05', 'cold_then_retained'), ('R06', 'cold'), ('R07', 'cold'),
        ('R08', 'cold'), ('R09', 'cold'), ('R10', 'cold'),
    )
    used_nonces = set()
    previous = baseline
    slots = []
    cold_samples = []
    retained_samples = []
    cold_dp_types_seen = {}
    cold_dp_lengths_seen = {}
    retained_dp_types_seen = {}
    retained_dp_lengths_seen = {}
    counters = {
        'completed': 0, 'cold': 0, 'retained': 0, 'cold_ack': 0,
        'retained_ack': 0, 'failure': 0, 'timeout': 0, 'receipt': 0,
        'ambiguity': 0, 'release': 0, 'same_session': 0, 'reconnect': 0,
        'overflow': 0, 'writes': 0, 'packets': 0,
    }
    outcome = 'complete'
    helper_target_checks = 0
    private_target = selected
    for index, (slot, mode) in enumerate(plan, 1):
        if counters['cold'] >= 10 or counters['retained'] >= 5 and mode == 'cold_then_retained':
            return research_failure_inventory_result(
                'REQUEST_ACCOUNTING', 'BUDGET_EXCEEDED', index,
                bool(slots), eligible_count, True, counters, slots,
            )
        nonce = os.urandom(16).hex()
        if nonce in used_nonces:
            return research_failure_inventory_result(
                'ADMISSION', 'NONCE_MISMATCH', index,
                bool(slots), eligible_count, True, counters, slots,
            )
        used_nonces.add(nonce)
        try:
            code, helper_outcome, evidence, _status = invoke_research_helper(
                'probe', 'R63S_' + slot, nonce, mode, private_target
            )
        except Exception:
            return research_failure_inventory_result(
                'HELPER_INVOCATION', 'HELPER_TERMINAL', index,
                True, eligible_count, True, counters, slots,
            )
        helper_target_checks += 1
        receipt_used = False
        receipt_handed = False
        probe = None
        stop_after = False
        if evidence is not None:
            try:
                probe = validate_research_probe(evidence, mode, nonce)
            except Exception:
                return research_failure_inventory_result(
                    'PROBE_EVIDENCE', 'INVALID_SHAPE', index,
                    True, eligible_count, True, counters, slots,
                )
        elif code == 78 and helper_outcome == 'transport_ambiguous':
            receipt_used = True
            counters['ambiguity'] += 1
            outcome = 'probe_ambiguous'
            for receipt_index in range(1, 4):
                receipt_nonce = nonce
                try:
                    receipt_code, _receipt_outcome, receipt_evidence, _receipt_status = invoke_research_helper(
                        'receipt', 'R63S_Q' + str(index).zfill(2) + '_' + str(receipt_index), receipt_nonce
                    )
                except Exception:
                    return research_failure_inventory_result(
                        'RECEIPT_RECONCILIATION', 'HELPER_TERMINAL', index,
                        True, eligible_count, True, counters, slots,
                    )
                counters['receipt'] += 1
                if receipt_evidence is not None:
                    try:
                        receipt = validate_research_receipt(receipt_evidence, nonce)
                    except Exception:
                        return research_failure_inventory_result(
                            'RECEIPT_RECONCILIATION', 'INVALID_SHAPE', index,
                            True, eligible_count, True, counters, slots,
                        )
                    receipt_handed = (
                        receipt_handed or receipt['request_handed_to_transport']
                    )
                    if receipt['known'] and (
                        receipt['response_available']
                        or receipt['terminal_class'] not in {None, 'entered'}
                    ):
                        break
                elif receipt_code not in {66, 78}:
                    break
            stop_after = True
        else:
            counters['failure'] += 1
            outcome = 'sample_incomplete'
            stop_after = True
        try:
            current, delta = research_audit_after_slot(index, previous)
        except Exception:
            if probe is not None:
                request_count = probe['request_count']
                cold_result = (
                    probe['requests'][0]['result'] if request_count >= 1 else None
                )
                retained_result = (
                    probe['requests'][1]['result'] if request_count >= 2 else None
                )
                counters['cold'] += int(request_count >= 1)
                counters['retained'] += int(request_count >= 2)
                counters['cold_ack'] += int(cold_result == 'ack_success')
                counters['retained_ack'] += int(retained_result == 'ack_success')
                slots.append({
                    'label': slot, 'mode': mode, 'request_count': request_count,
                    'cold_result': cold_result,
                    'retained_result': retained_result,
                    'same_session_retained': probe['same_session_retained'],
                    'normal_release_observed': probe['normal_release_observed'],
                    'automatic_reconnect_observed': probe['automatic_reconnect_observed'],
                    'observation_overflow': probe['observation_overflow'],
                    'receipt_used': receipt_used,
                })
            return research_failure_inventory_result(
                'AUDIT', 'INVALID_SHAPE', index,
                True, eligible_count, True, counters, slots,
            )
        previous = current
        counters['writes'] += delta['datapoint_write_operations']
        counters['packets'] += delta['datapoint_protocol_packets']
        if counters['writes'] or counters['packets']:
            outcome = 'protocol_write_gate_failed'
            stop_after = True
        cold_result = retained_result = None
        request_count = 0
        same_session = release = reconnect = overflow = False
        if probe is not None:
            request_count = probe['request_count']
            cold_result = probe['requests'][0]['result'] if request_count >= 1 else None
            retained_result = probe['requests'][1]['result'] if request_count >= 2 else None
            same_session = probe['same_session_retained']
            release = probe['normal_release_observed']
            reconnect = probe['automatic_reconnect_observed']
            overflow = probe['observation_overflow']
            if delta['device_status_requests'] != request_count:
                return research_failure_inventory_result(
                    'REQUEST_ACCOUNTING', 'REQUEST_COUNT_MISMATCH', index,
                    True, eligible_count, True, counters, slots,
                )
            counters['cold'] += int(request_count >= 1)
            counters['retained'] += int(request_count >= 2)
            counters['cold_ack'] += int(cold_result == 'ack_success')
            counters['retained_ack'] += int(retained_result == 'ack_success')
            counters['release'] += int(release)
            counters['same_session'] += int(same_session)
            counters['reconnect'] += int(reconnect)
            counters['overflow'] += int(overflow)
            if probe['result'] == 'completed':
                counters['completed'] += 1
                request_sets = {1: set(), 2: set()}
                for event in probe['events']:
                    if event['kind'] != 'DP_BATCH' or not event['exact_session']:
                        continue
                    trial = event['trial']
                    for dp_id, dp_type, length in zip(
                        event['dp_ids'], event['dp_types'], event['encoded_value_lengths']
                    ):
                        request_sets[trial].add(dp_id)
                        type_map = (
                            cold_dp_types_seen
                            if trial == 1
                            else retained_dp_types_seen
                        )
                        length_map = (
                            cold_dp_lengths_seen
                            if trial == 1
                            else retained_dp_lengths_seen
                        )
                        type_map.setdefault(dp_id, set()).add(dp_type)
                        length_map.setdefault(dp_id, set()).add(length)
                cold_samples.append(request_sets[1])
                if mode == 'cold_then_retained':
                    retained_samples.append(request_sets[2])
            else:
                outcome = 'sample_incomplete'
                counters['failure'] += 1
                if probe['result'] == 'precondition_failed':
                    stop_after = True
            timed_out_trials = {
                event['trial']
                for event in probe['events']
                if event['kind'] == 'ACK_TIMEOUT'
            }
            counters['timeout'] += len(timed_out_trials)
        else:
            possible_requests = delta['device_status_requests']
            if receipt_handed and possible_requests == 0:
                possible_requests = 1
            per_slot_limit = 2 if mode == 'cold_then_retained' else 1
            if possible_requests > per_slot_limit:
                return research_failure_inventory_result(
                    'REQUEST_ACCOUNTING', 'BUDGET_EXCEEDED', index,
                    True, eligible_count, True, counters, slots,
                )
            counters['cold'] += int(possible_requests >= 1)
            counters['retained'] += int(possible_requests >= 2)
        if (
            counters['cold'] > 10
            or counters['retained'] > 5
            or counters['cold'] + counters['retained'] > 15
        ):
            return research_failure_inventory_result(
                'REQUEST_ACCOUNTING', 'BUDGET_EXCEEDED', index,
                True, eligible_count, True, counters, slots,
            )
        slots.append({
            'label': slot, 'mode': mode, 'request_count': request_count,
            'cold_result': cold_result, 'retained_result': retained_result,
            'same_session_retained': same_session,
            'normal_release_observed': release,
            'automatic_reconnect_observed': reconnect,
            'observation_overflow': overflow, 'receipt_used': receipt_used,
        })
        if stop_after:
            break
    complete = (
        len(slots) == 10 and counters['completed'] == 10
        and counters['cold'] == 10 and counters['retained'] == 5
        and counters['writes'] == 0 and counters['packets'] == 0
        and counters['ambiguity'] == 0 and len(cold_samples) == 10
        and len(retained_samples) == 5 and helper_target_checks == 10
    )
    if outcome == 'complete' and not complete:
        outcome = 'sample_incomplete'
    all_ids = {8, 21, 33, 34, 36, 40, 47}
    all_ids.update(cold_dp_types_seen)
    all_ids.update(retained_dp_types_seen)
    rows = []
    for dp_id in sorted(all_ids):
        cold_reported = sum(dp_id in sample for sample in cold_samples)
        retained_reported = sum(dp_id in sample for sample in retained_samples)
        if not complete:
            classification = 'AMBIGUOUS'
        else:
            reported = cold_reported + retained_reported
            if reported == 15:
                classification = 'ALWAYS_REPORTED'
            elif reported == 0:
                classification = 'NOT_REPORTED'
            else:
                classification = 'CONDITIONALLY_REPORTED'
        rows.append({
            'dp_id': dp_id, 'cold_reported_count': cold_reported,
            'cold_eligible_count': len(cold_samples),
            'retained_reported_count': retained_reported,
            'retained_eligible_count': len(retained_samples),
            'cold_type_set': sorted(cold_dp_types_seen.get(dp_id, set())),
            'cold_encoded_length_set': sorted(cold_dp_lengths_seen.get(dp_id, set())),
            'retained_type_set': sorted(retained_dp_types_seen.get(dp_id, set())),
            'retained_encoded_length_set': sorted(retained_dp_lengths_seen.get(dp_id, set())),
            'classification': classification,
        })
    return {
        'outcome': outcome, 'eligible_s1_count': eligible_count,
        'selected': True, 'same_private_target': helper_target_checks == len(slots),
        'completed_probe_slots': counters['completed'],
        'cold_request_count': counters['cold'],
        'retained_request_count': counters['retained'],
        'total_device_status_requests': counters['cold'] + counters['retained'],
        'cold_ack_success_count': counters['cold_ack'],
        'retained_ack_success_count': counters['retained_ack'],
        'failure_count': counters['failure'], 'timeout_count': counters['timeout'],
        'receipt_lookup_count': counters['receipt'],
        'ambiguity_count': counters['ambiguity'],
        'normal_release_count': counters['release'],
        'same_session_retained_count': counters['same_session'],
        'automatic_reconnect_count': counters['reconnect'],
        'observation_overflow_count': counters['overflow'],
        'protocol_datapoint_write_delta': counters['writes'],
        'protocol_datapoint_packet_delta': counters['packets'],
        'slots': slots, 'dp_inventory': rows,
        'failure_category': None, 'failure_stage': None,
        'failure_reason': None, 'failed_slot': None,
        'probe_submission_possible': False,
    }

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
    elif live_identity == 'c1599dcd1cdc1201cd320c316059159a1948d5f58d4bdaa4c64ea3c4a0390075':
        result_phase = 'reconciled_candidate'
    else:
        result_phase = 'reconciled_unknown'
    return {
        'phase': result_phase,
        'restoration_applied': live_matches,
        'manifest_match': live_matches,
        'file_count': len(live),
    }

operation = sys.argv[1]
try:
    resolve_root()
except ValueError as error:
    result = remote_error('ROOT', operation_reason(error))
except Exception:
    result = remote_error('ROOT', 'ROOT_INVALID')
else:
    try:
        value = receive()
    except Exception:
        result = remote_error('REQUEST', 'PAYLOAD')
    else:
        try:
            if operation == 'backup':
                result = backup(value)
            elif operation == 'reconcile_backup_creation':
                result = reconcile_backup_creation(value)
            elif operation == 'inspect_retained_backup':
                result = retained_backup_continuity(value)
            elif operation == 'retire_retained_backup':
                result = retire_retained_backup(value)
            elif operation == 'transfer':
                result = transfer(value)
            elif operation == 'install':
                result = activate(value)
            elif operation == 'source_inventory':
                _, expected = expected_manifest(value)
                runtime_cache_counter = [0]
                managed_directories = set()
                observed = inventory_targets(
                    runtime_cache_counter, managed_directories
                )
                result = inventory_result(
                    expected, observed, runtime_cache_counter[0], managed_directories
                )
                result['root_profile'] = ROOT_PROFILE
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
            elif operation == 'remote_phase_a_inventory':
                result = remote_phase_a_inventory(value)
            elif operation == 'remote_phase_a_readiness':
                result = remote_phase_a_readiness(value)
            elif operation == 'restore':
                result = activate(value, restoring=True)
            elif operation == 'restore_backup':
                result = restore_backup(value)
            elif operation == 'reconcile_backup':
                result = reconcile_backup(value)
            else:
                raise ValueError('operation')
        except Exception as error:
            result = remote_error(operation_scope(operation), operation_reason(error))
print(json.dumps(result, separators=(',', ':'), sort_keys=True), flush=True)
"""


_REMOTE_REFRESH_STATUS_PROGRAM = r"""
import base64
import json
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

LOGGER = 'custom_components.tuya_ble.tuya_ble.tuya_ble'
BOUNDARY_LOGGER = 'ha_tuya_ble.r65_validation_boundary'
EMPTY_COUNTS = {'device_info': 0, 'pair': 0, 'device_status': 0, 'datapoint': 0, 'other': 0}
EMPTY_PRESS = {
    'service_success': False,
    'counts': dict(EMPTY_COUNTS),
    'session_provenance': None,
    'last_status_update_advanced': False,
    'retained_confirmation_changed_dp_ids': [],
}

def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)

def headers():
    token = os.environ.get('SUPERVISOR_TOKEN')
    if not token:
        raise ValueError('context')
    return {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}

def http_json(path, method='GET', data=None, limit=1024 * 1024):
    body = None if data is None else json.dumps(data, separators=(',', ':')).encode()
    request = urllib.request.Request(
        'http://supervisor/core/api' + path,
        data=body,
        headers=headers(),
        method=method,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(limit + 1)
        if len(raw) > limit or response.getcode() // 100 != 2:
            raise ValueError('response')
    return strict_json(raw.decode())

class WebSocket:
    def __init__(self):
        self.sock = socket.create_connection(('supervisor', 80), timeout=15)
        key = base64.b64encode(os.urandom(16)).decode()
        token = os.environ.get('SUPERVISOR_TOKEN')
        request = (
            'GET /core/websocket HTTP/1.1\r\nHost: supervisor\r\nUpgrade: websocket\r\n'
            'Connection: Upgrade\r\nSec-WebSocket-Key: ' + key + '\r\n'
            'Sec-WebSocket-Version: 13\r\nAuthorization: Bearer ' + token + '\r\n\r\n'
        )
        self.sock.sendall(request.encode('ascii'))
        response = b''
        while b'\r\n\r\n' not in response and len(response) <= 16384:
            response += self.sock.recv(4096)
        if not response.startswith(b'HTTP/1.1 101'):
            raise ValueError('websocket')
        self.next_id = 1
        first = self.recv()
        if first.get('type') == 'auth_required':
            self.send({'type': 'auth', 'access_token': token})
            first = self.recv()
        if first.get('type') != 'auth_ok':
            raise ValueError('websocket_auth')

    def _read(self, size):
        value = b''
        while len(value) < size:
            part = self.sock.recv(size - len(value))
            if not part:
                raise ValueError('websocket_closed')
            value += part
        return value

    def send(self, value):
        data = json.dumps(value, separators=(',', ':')).encode()
        mask = os.urandom(4)
        length = len(data)
        head = bytearray([0x81])
        if length < 126:
            head.append(0x80 | length)
        elif length < 65536:
            head.append(0x80 | 126); head.extend(struct.pack('>H', length))
        else:
            head.append(0x80 | 127); head.extend(struct.pack('>Q', length))
        masked = bytes(item ^ mask[index % 4] for index, item in enumerate(data))
        self.sock.sendall(bytes(head) + mask + masked)

    def recv(self):
        while True:
            first, second = self._read(2)
            opcode = first & 0x0f
            length = second & 0x7f
            if length == 126:
                length = struct.unpack('>H', self._read(2))[0]
            elif length == 127:
                length = struct.unpack('>Q', self._read(8))[0]
            if length > 2 * 1024 * 1024 or second & 0x80:
                raise ValueError('websocket_frame')
            data = self._read(length)
            if opcode == 9:
                self._send_control(10, data); continue
            if opcode != 1:
                raise ValueError('websocket_frame')
            value = strict_json(data.decode())
            if not isinstance(value, dict):
                raise ValueError('websocket_shape')
            return value

    def _send_control(self, opcode, data):
        mask = os.urandom(4)
        self.sock.sendall(bytes([0x80 | opcode, 0x80 | len(data)]) + mask + bytes(
            item ^ mask[index % 4] for index, item in enumerate(data)
        ))

    def command(self, kind, **fields):
        identifier = self.next_id; self.next_id += 1
        self.send({'id': identifier, 'type': kind, **fields})
        while True:
            value = self.recv()
            if value.get('id') != identifier:
                continue
            if value.get('type') != 'result' or value.get('success') is not True:
                raise ValueError('websocket_command')
            return value.get('result')

    def close(self):
        try: self._send_control(8, b'')
        except Exception: pass
        try: self.sock.close()
        except Exception: pass

class LogStream:
    def __init__(self):
        request = urllib.request.Request(
            'http://supervisor/core/logs/follow?lines=1&no_colors',
            headers={**headers(), 'Accept': 'text/plain'},
        )
        self.response = urllib.request.urlopen(request, timeout=30)
        self.lines = queue.Queue(maxsize=512)
        self.overflow = False
        self.closed = False
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        try:
            while not self.closed:
                line = self.response.readline(4097)
                if not line:
                    break
                if len(line) > 4096:
                    self.overflow = True; break
                try: self.lines.put_nowait(line.decode('utf-8', 'replace'))
                except queue.Full: self.overflow = True; break
        except Exception:
            if not self.closed: self.overflow = True

    def take_available(self):
        result = []
        while True:
            try: result.append(self.lines.get_nowait())
            except queue.Empty: break
        if self.overflow:
            raise ValueError('log_overflow')
        return result

    def until_marker(self, marker):
        deadline = time.monotonic() + 10
        result = []
        while time.monotonic() < deadline:
            if self.overflow:
                raise ValueError('log_overflow')
            try:
                line = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                break
            if marker_line(line, marker):
                return result
            result.append(line)
        raise ValueError('log_marker')

    def close(self):
        self.closed = True
        try: self.response.close()
        except Exception: pass
        self.thread.join(timeout=1)

def marker_line(raw, marker):
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw.rstrip('\r\n'))
    match = re.fullmatch(
        r'.*\[ha_tuya_ble\.r65_validation_boundary\] '
        r'(R65_WINDOW_(?:START|END)_[0-9a-f]{64})',
        raw,
    )
    return match is not None and match.group(1) == marker

def emit_validation_log_marker(ws, marker):
    ws.command(
        'call_service', domain='system_log', service='write',
        service_data={'message': marker, 'level': 'critical',
                      'logger': BOUNDARY_LOGGER},
        return_response=False,
    )

class LogBoundaryNotEstablished(Exception):
    pass

class LogWindow:
    def __init__(self, stream, ws):
        token = os.urandom(32).hex()
        self.stream = stream
        self.ws = ws
        self.start_marker = 'R65_WINDOW_START_' + token
        self.end_marker = 'R65_WINDOW_END_' + token
        self.established = False
        self.finish_attempted = False
        self.closed = False
        self.lines = []

    def start(self):
        emit_validation_log_marker(self.ws, self.start_marker)
        try:
            self.stream.until_marker(self.start_marker)
        except Exception:
            raise LogBoundaryNotEstablished() from None
        self.established = True

    def wait_for_refresh_terminal(self):
        if not self.established or self.finish_attempted:
            raise ValueError('log_window')
        deadline = time.monotonic() + 30
        refresh_identity = None
        while time.monotonic() < deadline:
            if self.stream.overflow:
                raise ValueError('log_overflow')
            try:
                line = self.stream.lines.get(
                    timeout=max(0.01, deadline - time.monotonic())
                )
            except queue.Empty:
                break
            self.lines.append(line)
            raw = re.sub(r'\x1b\[[0-9;]*m', '', line.rstrip('\r\n'))
            match = LOG_RE.fullmatch(raw)
            if not match:
                continue
            identity, message = match.groups()
            if message == 'S1_REFRESH_ACCEPTED':
                if refresh_identity is not None:
                    raise ValueError('refresh_lifecycle')
                refresh_identity = identity
            elif (
                refresh_identity == identity
                and REFRESH_TERMINAL_RE.fullmatch(message)
            ):
                return
        raise ValueError('refresh_terminal')

    def finish(self):
        if not self.established or self.finish_attempted:
            raise ValueError('log_window')
        self.finish_attempted = True
        emit_validation_log_marker(self.ws, self.end_marker)
        lines = self.lines + self.stream.until_marker(self.end_marker)
        self.closed = True
        return lines

def entries_by_key(entities, device_id, domain, key):
    return [entry for entry in entities if (
        isinstance(entry, dict)
        and entry.get('di') == device_id
        and entry.get('pl') == 'tuya_ble'
        and entry.get('tk') == key
        and isinstance(entry.get('ei'), str)
        and entry['ei'].startswith(domain + '.')
    )]

def state(entity_id):
    value = http_json('/states/' + entity_id)
    if not isinstance(value, dict) or value.get('entity_id') != entity_id:
        raise ValueError('state')
    return value

def stamp(value):
    attributes = value.get('attributes')
    if not isinstance(attributes, dict):
        return None
    return attributes.get('last_confirmed_at', value.get('state'))

LOG_RE = re.compile(
    r'^.*\[custom_components\.tuya_ble\.tuya_ble\.tuya_ble\] '
    r'(tuya-ble-session-[ghjkmnpqrstuvwxyz]{16}): (.*)$'
)
SEND_RE = re.compile(r'^Sending packet: #[0-9]+ ([A-Z0-9_]+)(?: in response to #[0-9]+)?$')
REFRESH_BOUND_RE = re.compile(
    r'^S1_REFRESH_SESSION_BOUND_(NEW|REUSED) session_ordinal=([1-9][0-9]*)$'
)
REFRESH_TERMINAL_RE = re.compile(
    r'^S1_REFRESH_(COMPLETED|FAILED) session_ordinal=([1-9][0-9]*|none)$'
)

def parse_lines(lines, required_identity=None):
    records = []
    for raw in lines:
        raw = re.sub(r'\x1b\[[0-9;]*m', '', raw.rstrip('\r\n'))
        match = LOG_RE.fullmatch(raw)
        if match: records.append((match.group(1), match.group(2)))
    if required_identity is None:
        raise ValueError('identity')
    counts = dict(EMPTY_COUNTS)
    events = []
    for identity, message in records:
        if identity != required_identity: continue
        sent = SEND_RE.fullmatch(message)
        if sent:
            code = sent.group(1)
            name = {
                'FUN_SENDER_DEVICE_INFO': 'device_info',
                'FUN_SENDER_PAIR': 'pair',
                'FUN_SENDER_DEVICE_STATUS': 'device_status',
                'FUN_SENDER_DPS': 'datapoint',
                'FUN_SENDER_DPS_V4': 'datapoint',
            }.get(code, 'other')
            counts[name] += 1
        for prefix, event in (
            ('Connecting;', 'connecting'), ('Connected;', 'connected'),
            ('Successfully connected', 'authenticated'), ('Disconnecting', 'disconnecting'),
            ('Disconnected from device;', 'disconnected'), ('Scheduling reconnect;', 'reconnect'),
            ('Reconnect,', 'reconnect'),
        ):
            if message.startswith(prefix): events.append(event)
    return required_identity, counts, events

def parse_refresh_lifecycle(lines, required_identity=None):
    records = []
    for raw in lines:
        raw = re.sub(r'\x1b\[[0-9;]*m', '', raw.rstrip('\r\n'))
        match = LOG_RE.fullmatch(raw)
        if match:
            records.append((match.group(1), match.group(2)))
    accepted = [
        (index, identity)
        for index, (identity, message) in enumerate(records)
        if message == 'S1_REFRESH_ACCEPTED'
    ]
    if len(accepted) != 1:
        raise ValueError('refresh_lifecycle')
    start, identity = accepted[0]
    if required_identity is not None and identity != required_identity:
        raise ValueError('refresh_lifecycle')
    counts = dict(EMPTY_COUNTS)
    events = []
    bound = None
    terminal = None
    terminal_index = None
    for index, (record_identity, message) in enumerate(
        records[start + 1:], start + 1
    ):
        if record_identity != identity:
            continue
        if message == 'S1_REFRESH_ACCEPTED':
            raise ValueError('refresh_lifecycle')
        bound_match = REFRESH_BOUND_RE.fullmatch(message)
        if bound_match:
            if bound is not None:
                raise ValueError('refresh_lifecycle')
            bound = (bound_match.group(1) + '_SESSION', int(bound_match.group(2)))
            continue
        terminal_match = REFRESH_TERMINAL_RE.fullmatch(message)
        if terminal_match:
            if bound is None or terminal_match.group(2) == 'none':
                raise ValueError('refresh_lifecycle')
            if int(terminal_match.group(2)) != bound[1]:
                raise ValueError('refresh_lifecycle')
            terminal = terminal_match.group(1) == 'COMPLETED'
            terminal_index = index
            break
        sent = SEND_RE.fullmatch(message)
        if sent:
            code = sent.group(1)
            name = {
                'FUN_SENDER_DEVICE_INFO': 'device_info',
                'FUN_SENDER_PAIR': 'pair',
                'FUN_SENDER_DEVICE_STATUS': 'device_status',
                'FUN_SENDER_DPS': 'datapoint',
                'FUN_SENDER_DPS_V4': 'datapoint',
            }.get(code, 'other')
            counts[name] += 1
        for prefix, event in (
            ('Connecting;', 'connecting'), ('Connected;', 'connected'),
            ('Successfully connected', 'authenticated'),
            ('Disconnecting', 'disconnecting'),
            ('Disconnected from device;', 'disconnected'),
            ('Scheduling reconnect;', 'reconnect'), ('Reconnect,', 'reconnect'),
        ):
            if message.startswith(prefix): events.append(event)
    if terminal is None or terminal_index is None:
        raise ValueError('refresh_lifecycle')
    if any(
        record_identity == identity
        and (
            message == 'S1_REFRESH_ACCEPTED'
            or REFRESH_BOUND_RE.fullmatch(message)
            or REFRESH_TERMINAL_RE.fullmatch(message)
        )
        for record_identity, message in records[terminal_index + 1:]
    ):
        raise ValueError('refresh_lifecycle')
    return identity, counts, events, bound[0], bound[1], terminal

def press(ws, entity_id):
    ws.command('call_service', domain='button', service='press',
               target={'entity_id': entity_id}, return_response=False)

def empty_result():
    return {
        'eligible_s1_count': 0, 'selected': False,
        'refresh_button_present': False, 'policy_on_demand': False,
        'ble_control_enabled': False, 'hold_time_valid': False,
        'cold': dict(EMPTY_PRESS), 'warm': dict(EMPTY_PRESS),
        'same_authenticated_session': False,
        'hold': {'warm_immediately_after_press': False,
                 'normal_release_observed': False,
                 'automatic_reconnect_observed': False},
        'ambiguous': False, 'failure_class': None,
        'conditional_omission_observed': False,
    }

def run_validation():
    result = empty_result(); ws = stream = window = None; prior_level = None
    try:
        ws = WebSocket()
        display = ws.command('config/entity_registry/list_for_display')
        devices = ws.command('config/device_registry/list')
        if not isinstance(display, dict) or not isinstance(display.get('entities'), list) or not isinstance(devices, list):
            raise ValueError('registry')
        entities = display['entities']; device_map = {item.get('id'): item for item in devices if isinstance(item, dict)}
        config_entries = http_json('/config/config_entries/entry?domain=tuya_ble')
        if not isinstance(config_entries, list): raise ValueError('entries')
        entry_map = {item.get('entry_id'): item for item in config_entries if isinstance(item, dict) and item.get('state') == 'loaded'}
        eligible = []
        for entry_id in sorted(entry_map):
            diagnostic = http_json('/diagnostics/config_entry/' + entry_id)
            data = diagnostic.get('data') if isinstance(diagnostic, dict) else None
            options = data.get('options') if isinstance(data, dict) else None
            if isinstance(options, dict) and options.get('category') == 'jtmspro' and options.get('product_id') == 'xqeob8h6':
                eligible.append((entry_id, options))
        result['eligible_s1_count'] = len(eligible)
        if not eligible:
            result['failure_class'] = 'OWNERSHIP_NOT_PROVEN'; return result
        entry_id, options = eligible[0]
        owned_devices = [item.get('id') for item in devices if (
            isinstance(item, dict) and isinstance(item.get('id'), str)
            and isinstance(item.get('config_entries'), list)
            and entry_id in item['config_entries']
        )]
        if len(owned_devices) != 1:
            result['failure_class'] = 'OWNERSHIP_NOT_PROVEN'; return result
        device_id = owned_devices[0]
        owned = entries_by_key(entities, device_id, 'button', 'refresh_status')
        if len(owned) != 1:
            result['failure_class'] = 'OWNERSHIP_NOT_PROVEN'; return result
        button_id = owned[0]['ei']
        if state(button_id).get('state') == 'unavailable':
            result['failure_class'] = 'OWNERSHIP_NOT_PROVEN'; return result
        result['selected'] = True; result['refresh_button_present'] = True
        result['policy_on_demand'] = options.get('connection_mode') == 'on_demand'
        result['ble_control_enabled'] = options.get('ble_control_enabled') is True
        hold = options.get('on_demand_connection_hold_time', 15)
        result['hold_time_valid'] = type(hold) is int and 15 <= hold <= 105
        if not (result['policy_on_demand'] and result['ble_control_enabled'] and result['hold_time_valid']):
            result['failure_class'] = 'PRECONDITION_NOT_PROVEN'; return result
        last_entities = entries_by_key(entities, device_id, 'sensor', 'last_status_update')
        connection_entities = entries_by_key(
            entities, device_id, 'binary_sensor', 'bluetooth_connection'
        )
        if len(last_entities) != 1 or len(connection_entities) != 1:
            result['failure_class'] = 'PRECONDITION_NOT_PROVEN'; return result
        last_id = last_entities[0]['ei']; connection_id = connection_entities[0]['ei']
        dp_entities = {}
        for dp, domain, key in ((8, 'sensor', 'battery'), (33, 'switch', 'automatic_lock'), (34, 'select', 'unlock_switch'), (36, 'number', 'auto_lock_time')):
            matches = entries_by_key(entities, device_id, domain, key)
            if len(matches) == 1: dp_entities[dp] = matches[0]['ei']
        info = ws.command('logger/log_info')
        levels = [item.get('level') for item in info if isinstance(item, dict) and item.get('domain') == 'tuya_ble'] if isinstance(info, list) else []
        if len(levels) != 1 or levels[0] not in {0, 10, 20, 30, 40, 50}:
            result['failure_class'] = 'LOGGER_CONTROL_UNAVAILABLE'; return result
        prior_level = {0: 'notset', 10: 'debug', 20: 'info', 30: 'warning', 40: 'error', 50: 'critical'}[levels[0]]
        ws.command('logger/integration_log_level', integration='tuya_ble', level='debug', persistence='none')
        stream = LogStream()
        window = LogWindow(stream, ws); window.start()
        if state(connection_id).get('state') != 'off':
            window.finish(); window = None
            result['failure_class'] = 'COLD_STATE_NOT_PROVEN'; return result
        before_last = state(last_id).get('state')
        before_dp = {dp: stamp(state(entity)) for dp, entity in dp_entities.items()}
        press(ws, button_id)
        window.wait_for_refresh_terminal()
        cold_lines = window.finish(); window = None
        identity, cold_counts, _cold_events, cold_provenance, cold_session, cold_completed = parse_refresh_lifecycle(cold_lines)
        after_cold = state(last_id).get('state')
        changed_cold = sorted(dp for dp, entity in dp_entities.items() if stamp(state(entity)) != before_dp[dp])
        result['cold'] = {'service_success': cold_completed, 'counts': cold_counts,
                          'session_provenance': cold_provenance,
                          'last_status_update_advanced': after_cold != before_last,
                          'retained_confirmation_changed_dp_ids': changed_cold}
        result['conditional_omission_observed'] = bool(dp_entities) and len(changed_cold) < len(dp_entities)
        if cold_counts['datapoint']:
            result['failure_class'] = 'DATAPOINT_WRITE_DETECTED'; return result
        if cold_provenance != 'NEW_SESSION':
            result['failure_class'] = 'COLD_SESSION_PROVENANCE_FAILED'; return result
        if not (cold_completed and state(connection_id).get('state') == 'on' and cold_counts['device_info'] == 1 and cold_counts['pair'] == 1 and cold_counts['device_status'] == 1):
            result['failure_class'] = 'COLD_REQUEST_FAILED'; return result
        before_warm = after_cold; before_dp = {dp: stamp(state(entity)) for dp, entity in dp_entities.items()}
        window = LogWindow(stream, ws); window.start()
        if state(connection_id).get('state') != 'on':
            window.finish(); window = None
            result['failure_class'] = 'WARM_REQUEST_FAILED'; return result
        press(ws, button_id)
        window.wait_for_refresh_terminal()
        warm_lines = window.finish(); window = None
        _, warm_counts, _warm_events, warm_provenance, warm_session, warm_completed = parse_refresh_lifecycle(warm_lines, identity)
        after_warm = state(last_id).get('state')
        changed_warm = sorted(dp for dp, entity in dp_entities.items() if stamp(state(entity)) != before_dp[dp])
        result['warm'] = {'service_success': warm_completed, 'counts': warm_counts,
                          'session_provenance': warm_provenance,
                          'last_status_update_advanced': after_warm != before_warm,
                          'retained_confirmation_changed_dp_ids': changed_warm}
        if warm_counts['datapoint']:
            result['failure_class'] = 'DATAPOINT_WRITE_DETECTED'; return result
        result['same_authenticated_session'] = warm_session == cold_session
        if warm_provenance != 'REUSED_SESSION' or not result['same_authenticated_session']:
            result['failure_class'] = 'WARM_SESSION_PROVENANCE_FAILED'; return result
        if not (warm_completed and state(connection_id).get('state') == 'on' and warm_counts['device_info'] == 0 and warm_counts['pair'] == 0 and warm_counts['device_status'] == 1):
            result['failure_class'] = 'WARM_REQUEST_FAILED'; return result
        result['hold']['warm_immediately_after_press'] = True
        window = LogWindow(stream, ws); window.start()
        time.sleep(hold + 5); hold_lines = window.finish(); window = None
        _, _, release_events = parse_lines(hold_lines, identity)
        result['hold']['normal_release_observed'] = state(connection_id).get('state') == 'off' and 'disconnecting' in release_events and 'disconnected' in release_events
        if not result['hold']['normal_release_observed']:
            result['failure_class'] = 'HOLD_RELEASE_NOT_OBSERVED'; return result
        window = LogWindow(stream, ws); window.start()
        time.sleep(5); post_lines = window.finish(); window = None
        _, _, post_events = parse_lines(post_lines, identity)
        result['hold']['automatic_reconnect_observed'] = state(connection_id).get('state') != 'off' or any(event in post_events for event in ('connecting', 'connected', 'authenticated', 'reconnect'))
        if result['hold']['automatic_reconnect_observed']:
            result['failure_class'] = 'AUTOMATIC_RECONNECT_OBSERVED'; return result
        return result
    except LogBoundaryNotEstablished:
        result['failure_class'] = 'LOG_BOUNDARY_NOT_ESTABLISHED'; return result
    except Exception:
        result['ambiguous'] = True; result['failure_class'] = 'AMBIGUOUS'; return result
    finally:
        if window is not None and window.established and not window.finish_attempted:
            try:
                window.finish()
            except Exception:
                result['ambiguous'] = True
                result['failure_class'] = 'AMBIGUOUS'
        if stream is not None: stream.close()
        if ws is not None:
            if prior_level is not None:
                try:
                    ws.command('logger/integration_log_level', integration='tuya_ble', level=prior_level, persistence='none')
                except Exception:
                    result['ambiguous'] = True
                    result['failure_class'] = 'AMBIGUOUS'
            ws.close()

def feature_absence():
    ws = WebSocket()
    try:
        display = ws.command('config/entity_registry/list_for_display')
        entities = display.get('entities') if isinstance(display, dict) else None
        if not isinstance(entities, list): raise ValueError('registry')
        active = False
        for entry in entities:
            if isinstance(entry, dict) and entry.get('pl') == 'tuya_ble' and entry.get('tk') == 'refresh_status' and isinstance(entry.get('ei'), str) and entry['ei'].startswith('button.'):
                try:
                    active = active or state(entry['ei']).get('state') != 'unavailable'
                except urllib.error.HTTPError as error:
                    if error.code != 404: raise
        return {'refresh_button_active': active}
    finally:
        ws.close()

operation = sys.argv[1]
try:
    result = run_validation() if operation == 'refresh_status_live_validation' else feature_absence() if operation == 'feature_absence' else None
    if result is None: raise ValueError('operation')
except Exception:
    result = {'error_class': 'OPERATION_FAILED', 'error_scope': 'OTHER', 'error_reason': 'VALIDATION'}
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
        self.__inspection_token = object()

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
            or controller.__class__
            not in {
                FullPreflightLifecycleController,
                RefreshStatusLiveValidationController,
                RetainedAnchorContinuityInspector,
                RetainedFeatureValidationTerminalInspector,
                RetainedTerminalLifecycleInspector,
            }
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

    def _release_retained_anchor_continuity_inspector(
        self,
        controller: object,
        issuer: object,
        session_generation: object,
    ) -> None:
        """Release only a completed restricted continuity-inspector binding."""
        binding = self._controller_binding
        if (
            controller.__class__ is not RetainedAnchorContinuityInspector
            or binding is None
            or binding.controller is not controller
            or binding.issuer is not issuer
            or binding.session_generation is not session_generation
            or self._session_generation is not session_generation
            or any(
                not any(capability is consumed for consumed in binding.issuer.consumed)
                for capability in binding.issuer.issued
            )
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_CONTROLLER_RELEASE_INVALID"
            ) from None
        self._controller_binding = None

    def _release_retained_feature_validation_terminal_inspector(
        self,
        controller: object,
        issuer: object,
        session_generation: object,
    ) -> None:
        """Release only the exact completed feature-terminal inspector."""
        binding = self._controller_binding
        if (
            controller.__class__ is not RetainedFeatureValidationTerminalInspector
            or binding is None
            or binding.controller is not controller
            or binding.issuer is not issuer
            or binding.session_generation is not session_generation
            or self._session_generation is not session_generation
            or any(
                not any(capability is consumed for consumed in binding.issuer.consumed)
                for capability in binding.issuer.issued
            )
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_CONTROLLER_RELEASE_INVALID"
            ) from None
        self._controller_binding = None

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

    def _require_source_inspection_capability(
        self, capability: object, *, consume: bool = False
    ) -> _SourceInspectionCapability:
        binding = self._controller_binding
        if (
            type(capability) is not _SourceInspectionCapability
            or binding is None
            or self._state is not BrokerState.SESSION_ACTIVE
            or self._session_generation is not binding.session_generation
            or capability.controller is not binding.controller
            or capability.issuer is not binding.issuer.identity
            or capability.session_generation is not binding.session_generation
            or capability.issuance_identity is None
            or not any(capability is issued for issued in binding.issuer.issued)
            or any(capability is consumed for consumed in binding.issuer.consumed)
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_INSPECTION_CAPABILITY_INVALID"
            ) from None
        if consume:
            binding.issuer.consumed.append(capability)
        return capability

    def _require_research_capability(
        self, capability: object, *, consume: bool = False
    ) -> _RemotePhaseAResearchCapability:
        """Validate the one fixed research-run capability outside LifecycleAction."""
        binding = self._controller_binding
        if (
            type(capability) is not _RemotePhaseAResearchCapability
            or binding is None
            or self._state is not BrokerState.SESSION_ACTIVE
            or self._session_generation is not binding.session_generation
            or capability.controller is not binding.controller
            or capability.issuer is not binding.issuer.identity
            or capability.lifecycle_generation is not binding.lifecycle_generation
            or capability.source_generation is None
            or capability.session_generation is not binding.session_generation
            or capability.operation
            not in {
                ResearchOperation.CHECK_READINESS,
                ResearchOperation.RUN_FIXED_INVENTORY,
            }
            or capability.issuance_identity is None
            or not any(capability is issued for issued in binding.issuer.issued)
            or any(capability is consumed for consumed in binding.issuer.consumed)
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_RESEARCH_CAPABILITY_INVALID"
            ) from None
        if consume:
            binding.issuer.consumed.append(capability)
        return capability

    def _require_feature_capability(
        self,
        capability: object,
        actions: frozenset[FeatureValidationAction],
        *,
        consume: bool = False,
    ) -> _FeatureValidationCapability:
        """Validate one fixed feature action without widening LifecycleAction."""
        binding = self._controller_binding
        if (
            type(capability) is not _FeatureValidationCapability
            or binding is None
            or self._state is not BrokerState.SESSION_ACTIVE
            or self._session_generation is not binding.session_generation
            or capability.controller is not binding.controller
            or capability.issuer is not binding.issuer.identity
            or capability.lifecycle_generation is not binding.lifecycle_generation
            or capability.session_generation is not binding.session_generation
            or capability.source_generation is None
            or capability.action not in actions
            or capability.issuance_identity is None
            or not any(capability is issued for issued in binding.issuer.issued)
            or any(capability is consumed for consumed in binding.issuer.consumed)
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_FEATURE_CAPABILITY_INVALID"
            ) from None
        if consume:
            binding.issuer.consumed.append(capability)
        return capability

    def _require_retained_backup_capability(
        self,
        capability: object,
        action: RetainedBackupAction,
        *,
        consume: bool = False,
    ) -> _RetainedBackupCapability:
        binding = self._controller_binding
        if (
            type(capability) is not _RetainedBackupCapability
            or binding is None
            or self._state is not BrokerState.SESSION_ACTIVE
            or self._session_generation is not binding.session_generation
            or capability.controller is not binding.controller
            or capability.issuer is not binding.issuer.identity
            or capability.lifecycle_generation is not binding.lifecycle_generation
            or capability.source_generation is None
            or capability.session_generation is not binding.session_generation
            or capability.issuance_identity is None
            or capability.action is not action
            or type(capability.backup_identity) is not dict
            or not any(capability is issued for issued in binding.issuer.issued)
            or any(capability is consumed for consumed in binding.issuer.consumed)
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_BACKUP_CAPABILITY_INVALID"
            ) from None
        if consume:
            binding.issuer.consumed.append(capability)
        return capability

    def _require_feature_backup_continuity_capability(
        self,
        capability: object,
        action: FeatureBackupAction,
        *,
        consume: bool = False,
    ) -> _FeatureBackupContinuityCapability:
        """Validate one controller-owned feature-backup continuity permit."""
        binding = self._controller_binding
        if (
            type(capability) is not _FeatureBackupContinuityCapability
            or binding is None
            or self._state is not BrokerState.SESSION_ACTIVE
            or self._session_generation is not binding.session_generation
            or capability.controller is not binding.controller
            or capability.issuer is not binding.issuer.identity
            or capability.lifecycle_generation is not binding.lifecycle_generation
            or capability.source_generation is None
            or capability.session_generation is not binding.session_generation
            or capability.issuance_identity is None
            or capability.action is not action
            or action is FeatureBackupAction.RETIRE
            and type(capability.backup_identity) is not dict
            or action is FeatureBackupAction.INSPECT
            and capability.backup_identity is not None
            and type(capability.backup_identity) is not dict
            or not any(capability is issued for issued in binding.issuer.issued)
            or any(capability is consumed for consumed in binding.issuer.consumed)
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_BACKUP_CAPABILITY_INVALID"
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
        _inspection_token: object = None,
    ) -> bytes:
        """Run one enum operation with bounded chunks and exact private frames."""
        if not isinstance(operation, BoundedOperation):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_OPERATION_INVALID"
            ) from None
        neutral_inspection = (
            operation
            in {
                BoundedOperation.SOURCE_INVENTORY,
                BoundedOperation.INSPECT_RETAINED_BACKUP,
                BoundedOperation.RETIRE_RETAINED_BACKUP,
            }
            and _inspection_token is not None
            and _inspection_token
            is getattr(
                self,
                "_PrivateInteractiveSessionBroker__inspection_token",
                None,
            )
            and _capability is None
        )
        if not neutral_inspection:
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
        bootstrap_body = (
            "try:\n"
            " count=int(sys.stdin.readline())\n"
            " source=''.join(sys.stdin.readline().strip() for _ in range(count))\n"
            " raw=base64.b64decode(source,validate=True)\n"
            " expected=os.environ.pop('HA_R30_PROGRAM_SHA256')\n"
            " assert hashlib.sha256(raw).hexdigest()==expected\n"
            " exec(compile(raw,'<ha-r30-control>','exec'))\n"
            "except Exception:\n"
            ' print(\'{"error_class":"OPERATION_FAILED","error_scope":"BOOTSTRAP",'
            '"error_reason":"UNKNOWN"}\',flush=True)\n'
        )
        bootstrap = "import base64,hashlib,os,sys;exec(" + repr(bootstrap_body) + ")"
        command = (
            f"{self._frame_printf(start_payload)}; "
            f"HA_R30_OPERATION={operation.value} HA_R30_DETAIL={detail} "
            f"HA_R30_PROGRAM_SHA256={program_digest} "
            f"python3 -c {shlex.quote(bootstrap)} {operation.value}; "
            f"{self._frame_printf(end_payload)}\n"
        )
        try:
            self._ensure_echo_disabled()
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
                    _PrivateWirePacket(
                        (chunk + "\n").encode("ascii"), self.__wire_issuer
                    )
                )
        except SessionBrokerError as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.CONTROL_PROGRAM, error
            ) from None
        try:
            self.__write_wire(
                _PrivateWirePacket(
                    (str(len(chunks)) + "\n").encode("ascii"), self.__wire_issuer
                )
            )
            for chunk in chunks:
                self.__write_wire(
                    _PrivateWirePacket(
                        (chunk + "\n").encode("ascii"), self.__wire_issuer
                    )
                )
        except SessionBrokerError as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.PAYLOAD, error
            ) from None
        deadlines = {
            BoundedOperation.TRANSFER: 90.0,
            BoundedOperation.INSTALL: 90.0,
            BoundedOperation.RESTORE: 90.0,
            BoundedOperation.CORE_CHECK: 40.0,
            BoundedOperation.RESTART_CORE: RESTART_OPERATION_RESPONSE_DEADLINE_SECONDS,
            BoundedOperation.CORE_READINESS: RESTART_RECONCILIATION_DEADLINE_SECONDS,
            BoundedOperation.PHASE_A_HELPER: 200.0,
        }
        try:
            return self._read_until(
                end_frame,
                timeout_seconds=max(
                    self._timeout_seconds, deadlines.get(operation, 40.0)
                ),
            )
        except SessionBrokerError as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_WAIT, error
            ) from None

    def __execute_remote_phase_a_inventory(
        self,
        baseline: dict[str, object],
        *,
        _capability: object,
    ) -> bytes:
        """Run the one fixed research program without an operation/target input."""
        capability = self._require_research_capability(_capability, consume=True)
        if self._state is not BrokerState.SESSION_ACTIVE or not isinstance(
            baseline, dict
        ):
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_RESEARCH_INVALID"
            ) from None
        encoded_payload = base64.b64encode(
            json.dumps(
                {"baseline": baseline}, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
        ).decode("ascii")
        chunks = tuple(
            encoded_payload[index : index + _TRANSFER_CHUNK_SIZE]
            for index in range(0, len(encoded_payload), _TRANSFER_CHUNK_SIZE)
        )
        if not chunks or len(chunks) > 8:
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_RESEARCH_INVALID"
            ) from None
        start_payload, start_frame = self._new_frame("RESEARCH_START")
        end_payload, end_frame = self._new_frame("RESEARCH_END")
        program_bytes = _REMOTE_CONTROL_PROGRAM.encode("utf-8")
        program_digest = hashlib.sha256(program_bytes).hexdigest()
        encoded_program = base64.b64encode(program_bytes).decode("ascii")
        program_chunks = tuple(
            encoded_program[index : index + _TRANSFER_CHUNK_SIZE]
            for index in range(0, len(encoded_program), _TRANSFER_CHUNK_SIZE)
        )
        if not program_chunks or len(program_chunks) > 256:
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_RESEARCH_INVALID"
            ) from None
        bootstrap_body = (
            "try:\n"
            " count=int(sys.stdin.readline())\n"
            " source=''.join(sys.stdin.readline().strip() for _ in range(count))\n"
            " raw=base64.b64decode(source,validate=True)\n"
            " expected=os.environ.pop('HA_R63S_PROGRAM_SHA256')\n"
            " assert hashlib.sha256(raw).hexdigest()==expected\n"
            " exec(compile(raw,'<ha-r63s-research>','exec'))\n"
            "except Exception:\n"
            ' print(\'{"error_class":"OPERATION_FAILED","error_scope":"BOOTSTRAP",'
            '"error_reason":"UNKNOWN"}\',flush=True)\n'
        )
        bootstrap = "import base64,hashlib,os,sys;exec(" + repr(bootstrap_body) + ")"
        remote_operation = (
            "remote_phase_a_readiness"
            if capability.operation is ResearchOperation.CHECK_READINESS
            else "remote_phase_a_inventory"
        )
        command = (
            f"{self._frame_printf(start_payload)}; "
            f"HA_R30_OPERATION={remote_operation} HA_R30_DETAIL=fixed "
            f"HA_R63S_PROGRAM_SHA256={program_digest} "
            f"python3 -c {shlex.quote(bootstrap)} {remote_operation}; "
            f"{self._frame_printf(end_payload)}\n"
        )
        try:
            self._ensure_echo_disabled()
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
                    _PrivateWirePacket(
                        (chunk + "\n").encode("ascii"), self.__wire_issuer
                    )
                )
            self.__write_wire(
                _PrivateWirePacket(
                    (str(len(chunks)) + "\n").encode("ascii"), self.__wire_issuer
                )
            )
            for chunk in chunks:
                self.__write_wire(
                    _PrivateWirePacket(
                        (chunk + "\n").encode("ascii"), self.__wire_issuer
                    )
                )
            return self._read_until(end_frame, timeout_seconds=2400.0)
        except SessionBrokerError as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_WAIT, error
            ) from None

    def __execute_refresh_feature_operation(
        self,
        operation: str,
        *,
        _capability: object,
    ) -> bytes:
        """Run one parameter-free exact-R64 validation operation."""
        actions = {
            "refresh_status_live_validation": FeatureValidationAction.LIVE_VALIDATION,
            "feature_absence": FeatureValidationAction.FEATURE_ABSENCE,
        }
        action = actions.get(operation)
        if action is None:
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_FEATURE_INVALID"
            ) from None
        self._require_feature_capability(_capability, frozenset({action}), consume=True)
        if self._state is not BrokerState.SESSION_ACTIVE:
            raise SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_NOT_ACTIVE") from None
        start_payload, start_frame = self._new_frame("FEATURE_START")
        end_payload, end_frame = self._new_frame("FEATURE_END")
        program_bytes = _REMOTE_REFRESH_STATUS_PROGRAM.encode("utf-8")
        program_digest = hashlib.sha256(program_bytes).hexdigest()
        encoded_program = base64.b64encode(program_bytes).decode("ascii")
        chunks = tuple(
            encoded_program[index : index + _TRANSFER_CHUNK_SIZE]
            for index in range(0, len(encoded_program), _TRANSFER_CHUNK_SIZE)
        )
        if not chunks or len(chunks) > 256:
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_FEATURE_INVALID"
            ) from None
        bootstrap_body = (
            "try:\n"
            " count=int(sys.stdin.readline())\n"
            " source=''.join(sys.stdin.readline().strip() for _ in range(count))\n"
            " raw=base64.b64decode(source,validate=True)\n"
            " expected=os.environ.pop('HA_R65_PROGRAM_SHA256')\n"
            " assert hashlib.sha256(raw).hexdigest()==expected\n"
            " exec(compile(raw,'<ha-r65-feature>','exec'))\n"
            "except Exception:\n"
            ' print(\'{"error_class":"OPERATION_FAILED","error_scope":"BOOTSTRAP",'
            '"error_reason":"UNKNOWN"}\',flush=True)\n'
        )
        bootstrap = "import base64,hashlib,os,sys;exec(" + repr(bootstrap_body) + ")"
        command = (
            f"{self._frame_printf(start_payload)}; "
            f"HA_R65_PROGRAM_SHA256={program_digest} "
            f"python3 -c {shlex.quote(bootstrap)} {operation}; "
            f"{self._frame_printf(end_payload)}\n"
        )
        try:
            self._ensure_echo_disabled()
            self.__write_wire(
                _PrivateWirePacket(command.encode("ascii"), self.__wire_issuer)
            )
            self._read_until(start_frame)
            self.__write_wire(
                _PrivateWirePacket(
                    (str(len(chunks)) + "\n").encode("ascii"), self.__wire_issuer
                )
            )
            for chunk in chunks:
                self.__write_wire(
                    _PrivateWirePacket(
                        (chunk + "\n").encode("ascii"), self.__wire_issuer
                    )
                )
            return self._read_until(
                end_frame,
                timeout_seconds=(
                    360.0 if action is FeatureValidationAction.LIVE_VALIDATION else 40.0
                ),
            )
        except SessionBrokerError as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_WAIT, error
            ) from None

    def _run_s1_refresh_status_live_validation(
        self, *, _capability: object = None
    ) -> RefreshStatusLiveValidationResult:
        output = self.__execute_refresh_feature_operation(
            "refresh_status_live_validation", _capability=_capability
        )
        try:
            return _parse_refresh_status_live_validation_result(output)
        except (SessionBrokerError, TypeError, ValueError) as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_PARSE, error
            ) from None

    def _verify_refresh_feature_absent(
        self, *, _capability: object = None
    ) -> FeatureAbsenceResult:
        output = self.__execute_refresh_feature_operation(
            "feature_absence", _capability=_capability
        )
        try:
            return _parse_feature_absence_result(output)
        except (SessionBrokerError, TypeError, ValueError) as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_PARSE, error
            ) from None

    def _invoke_remote_phase_a_research(
        self,
        baseline: AuditSnapshot,
        *,
        _capability: object = None,
    ) -> RemotePhaseAInventoryResult | RemotePhaseAReadinessResult:
        """Invoke the fixed research program through its dedicated capability."""
        if not isinstance(baseline, AuditSnapshot) or baseline.nonce is None:
            raise SessionBrokerError(
                "PRIVATE_INTERACTIVE_SESSION_RESEARCH_BASELINE_INVALID"
            ) from None
        baseline_payload: dict[str, object] = {
            "result": "audit_snapshot",
            "protocol_version": baseline.protocol_version,
            "audit_instance_token": baseline.audit_instance_token,
            "event_ordinal": baseline.event_ordinal,
            "history_overflow": baseline.history_overflow,
            "runtime_ms": baseline.runtime_ms,
            "counters": dict(baseline.counters),
            "events": [asdict(event) for event in baseline.events],
        }
        try:
            output = self.__execute_remote_phase_a_inventory(
                baseline_payload, _capability=_capability
            )
            if _capability.operation is ResearchOperation.CHECK_READINESS:
                return _parse_remote_phase_a_readiness_result(output)
            return _parse_remote_phase_a_inventory_result(output)
        except (SessionBrokerError, TypeError, ValueError) as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_PARSE, error
            ) from None

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
        try:
            result = _parse_backup_result(output)
        except (SessionBrokerError, TypeError, ValueError) as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_PARSE, error
            ) from None
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
            and bundle.state in {SourceState.CANDIDATE, SourceState.R64_RUNTIME}
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
        try:
            result = self._simple_result(
                output,
                TransferResult,
                ("success", "file_count", "manifest_match", "regular_files_only"),
            )
        except (SessionBrokerError, TypeError, ValueError) as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_PARSE, error
            ) from None
        return _bind_evidence_origin(result, capability)

    def _install_staged_source(
        self, manifest: SourceManifest, *, _capability: object = None
    ) -> InstallResult:
        capability = self._require_capability(
            _capability, frozenset({LifecycleAction.CANDIDATE_INSTALL})
        )
        if not isinstance(manifest, SourceManifest) or manifest.state not in {
            SourceState.CANDIDATE,
            SourceState.R64_RUNTIME,
        }:
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
            self._active_source_state = manifest.state
        return _bind_evidence_origin(result, capability)

    def _verify_source_inventory(
        self, manifest: SourceManifest, *, _capability: object = None
    ) -> SourceInventoryResult:
        action = (
            LifecycleAction.CANDIDATE_INVENTORY
            if isinstance(manifest, SourceManifest)
            and manifest.state in {SourceState.CANDIDATE, SourceState.R64_RUNTIME}
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

    def _inspect_current_source(
        self,
        candidate_manifest: SourceManifest,
        restore_manifest: SourceManifest,
        *,
        _capability: object = None,
    ) -> CurrentSourceInventoryResult:
        self._require_source_inspection_capability(_capability, consume=True)
        if (
            not isinstance(candidate_manifest, SourceManifest)
            or candidate_manifest.state
            not in {SourceState.CANDIDATE, SourceState.R64_RUNTIME}
            or not isinstance(restore_manifest, SourceManifest)
            or restore_manifest.state is not SourceState.RESTORE
        ):
            raise SourceBundleError("SOURCE_MANIFEST_INVALID") from None

        def inspect(manifest: SourceManifest) -> SourceInventoryResult:
            output = self.__execute_bounded_operation(
                BoundedOperation.SOURCE_INVENTORY,
                {"manifest": _manifest_payload(manifest)},
                detail=manifest.state.value,
                _inspection_token=self.__inspection_token,
            )
            try:
                return _parse_source_inventory_result(_exact_payload(output))
            except (SessionBrokerError, TypeError, ValueError) as error:
                raise _bounded_dispatch_failure(
                    DispatchFailureStage.RESPONSE_PARSE, error
                ) from None

        try:
            restore_result = inspect(restore_manifest)
            if _source_inventory_exact(restore_result, len(restore_manifest.entries)):
                return CurrentSourceInventoryResult(
                    CurrentSourceClassification.EXACT_PR41, restore_result
                )
            candidate_result = inspect(candidate_manifest)
            if _source_inventory_exact(
                candidate_result, len(candidate_manifest.entries)
            ):
                return CurrentSourceInventoryResult(
                    (
                        CurrentSourceClassification.EXACT_PR45
                        if candidate_manifest.state is SourceState.CANDIDATE
                        else CurrentSourceClassification.EXACT_R64
                    ),
                    candidate_result,
                )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError) as error:
            failure = _bounded_dispatch_failure(DispatchFailureStage.UNKNOWN, error)
            return CurrentSourceInventoryResult(
                CurrentSourceClassification.INDETERMINATE,
                failure_stage=failure.stage,
                failure_class=failure.failure_class,
                remote_failure_scope=failure.remote_failure_scope,
                remote_failure_reason=failure.remote_failure_reason,
            )
        return CurrentSourceInventoryResult(
            CurrentSourceClassification.OTHER, candidate_result
        )

    def _retained_backup_operation(
        self,
        manifest: SourceManifest,
        action: RetainedBackupAction,
        *,
        _capability: object = None,
    ) -> PriorBackupContinuityResult:
        capability = self._require_retained_backup_capability(
            _capability, action, consume=True
        )
        operation = {
            RetainedBackupAction.INSPECT: BoundedOperation.INSPECT_RETAINED_BACKUP,
            RetainedBackupAction.RETIRE: BoundedOperation.RETIRE_RETAINED_BACKUP,
        }[action]
        output = self.__execute_bounded_operation(
            operation,
            _retained_backup_context_payload(manifest, capability),
            detail=manifest.state.value,
            _inspection_token=self.__inspection_token,
        )
        try:
            payload = _exact_payload(output)
            if not isinstance(payload, dict) or set(payload) != {
                "classification",
                "retired",
            }:
                raise ValueError
            result = PriorBackupContinuityResult(
                PriorBackupClassification(payload["classification"]),
                _bool(payload["retired"]),
            )
            if (
                action is RetainedBackupAction.INSPECT
                and result.retired is not False
                or action is RetainedBackupAction.RETIRE
                and (
                    result.classification is not PriorBackupClassification.NONE
                    or result.retired is not True
                )
            ):
                raise ValueError
            return result
        except (KeyError, TypeError, ValueError) as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_PARSE, error
            ) from None

    def _feature_backup_continuity_operation(
        self,
        manifest: SourceManifest,
        action: FeatureBackupAction,
        *,
        _capability: object = None,
    ) -> FeatureBackupContinuityResult:
        """Inspect or retire only the current feature lifecycle's PR41 backup."""
        capability = self._require_feature_backup_continuity_capability(
            _capability, action, consume=True
        )
        operation = {
            FeatureBackupAction.INSPECT: BoundedOperation.INSPECT_RETAINED_BACKUP,
            FeatureBackupAction.RETIRE: BoundedOperation.RETIRE_RETAINED_BACKUP,
        }[action]
        output = self.__execute_bounded_operation(
            operation,
            _feature_backup_context_payload(manifest, capability),
            detail=manifest.state.value,
            _inspection_token=self.__inspection_token,
        )
        try:
            payload = _exact_payload(output)
            if not isinstance(payload, dict) or set(payload) != {
                "classification",
                "retired",
            }:
                raise ValueError
            classification = {
                PriorBackupClassification.NONE.value: FeatureBackupClassification.NONE,
                PriorBackupClassification.OWNED_BY_RETAINED_LIFECYCLE.value: (
                    FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
                ),
                PriorBackupClassification.OTHER_OR_INDETERMINATE.value: (
                    FeatureBackupClassification.OTHER_OR_INDETERMINATE
                ),
            }[payload["classification"]]
            result = FeatureBackupContinuityResult(
                classification, _bool(payload["retired"])
            )
            if (
                action is FeatureBackupAction.INSPECT
                and result.retired is not False
                or action is FeatureBackupAction.RETIRE
                and (
                    result.classification is not FeatureBackupClassification.NONE
                    or result.retired is not True
                )
            ):
                raise ValueError
            return result
        except (KeyError, TypeError, ValueError) as error:
            raise _bounded_dispatch_failure(
                DispatchFailureStage.RESPONSE_PARSE, error
            ) from None

    def _check_core(
        self, attempt_ordinal: int, *, _capability: object = None
    ) -> CoreCheckResult:
        action_by_state = {
            SourceState.CANDIDATE: {
                1: LifecycleAction.CANDIDATE_CORE_CHECK_1,
                2: LifecycleAction.CANDIDATE_CORE_CHECK_2,
            },
            SourceState.R64_RUNTIME: {
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
            SourceState.R64_RUNTIME: LifecycleAction.ACTIVATION_RESTART,
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
        result = _parse_restart_result(_exact_restart_payload(output))
        return _bind_evidence_origin(result, capability)

    def _wait_for_core_readiness(
        self, *, _capability: object = None
    ) -> CoreReadinessResult:
        action = {
            SourceState.CANDIDATE: LifecycleAction.CANDIDATE_READINESS,
            SourceState.R64_RUNTIME: LifecycleAction.CANDIDATE_READINESS,
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


def _inspect_current_source(
    owner: Any,
    candidate_manifest: SourceManifest,
    restore_manifest: SourceManifest,
) -> CurrentSourceInventoryResult:
    owner._assert_session_binding()
    try:
        validate_source_manifest(candidate_manifest)
        validate_source_manifest(restore_manifest)
    except (SourceBundleError, TypeError, ValueError):
        raise LifecycleControllerError("SOURCE_INSPECTION_FAILED") from None
    if (
        candidate_manifest.state is not SourceState.CANDIDATE
        or restore_manifest.state is not SourceState.RESTORE
    ):
        raise LifecycleControllerError("SOURCE_INSPECTION_FAILED") from None
    capability = _SourceInspectionCapability(
        owner,
        owner._capability_issuer.identity,
        owner._session_generation,
        secrets.token_hex(16),
    )
    owner._capability_issuer.issued.append(capability)
    try:
        result = owner._broker._inspect_current_source(
            candidate_manifest,
            restore_manifest,
            _capability=capability,
        )
    except (SessionBrokerError, SourceBundleError, TypeError, ValueError) as error:
        failure = _bounded_dispatch_failure(DispatchFailureStage.UNKNOWN, error)
        return CurrentSourceInventoryResult(
            CurrentSourceClassification.INDETERMINATE,
            failure_stage=failure.stage,
            failure_class=failure.failure_class,
            remote_failure_scope=failure.remote_failure_scope,
            remote_failure_reason=failure.remote_failure_reason,
        )
    if not isinstance(result, CurrentSourceInventoryResult):
        return CurrentSourceInventoryResult(
            CurrentSourceClassification.INDETERMINATE,
            failure_stage=DispatchFailureStage.RESULT_VALIDATION,
            failure_class=DispatchFailureClass.SCHEMA,
        )
    return result


@dataclass(frozen=True, slots=True)
class RetainedTerminalMetadata:
    """Reportable identity of one retained terminal lifecycle."""

    state: LifecycleState
    revision: int
    lifecycle_generation: str


@dataclass(frozen=True, slots=True)
class RetainedFeatureValidationTerminalMetadata:
    """Public-safe facts about one retained successful feature lifecycle."""

    state: FeatureValidationState
    terminal: FeatureValidationState
    active: bool
    schema_version: int
    final_restore_complete: bool
    live_result_durability: FeatureLiveResultDurabilityClassification


@dataclass(frozen=True, slots=True)
class RetainedAnchorContinuityMetadata:
    """Sanitized identity of one retained device-drift continuity case."""

    state: LifecycleState
    revision: int
    journal_format: LifecycleJournalFormat
    anchor_format: LifecycleAnchorFormat
    classification: LifecycleAnchorClassification


class RetainedAnchorContinuityInspector:
    """Restricted one-shot migration handle for a retained drifted V1 anchor."""

    def __init__(self, broker: Any) -> None:
        if (
            getattr(broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(broker, "_session_generation", None) is None
            or not callable(getattr(broker, "_register_lifecycle_controller", None))
            or not callable(
                getattr(
                    broker,
                    "_release_retained_anchor_continuity_inspector",
                    None,
                )
            )
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        self._broker = broker
        self._session_generation = broker._session_generation
        self._source_inspection_attempted = False
        self._source_proven = False
        self._migration_attempted = False
        self._closed = False
        self._journal = _DurableLifecycleJournal.open_retained_anchor_continuity()
        try:
            self._capability_issuer = broker._register_lifecycle_controller(
                self,
                self._journal.lifecycle_generation,
                self._session_generation,
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._journal.close()
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        if type(self._capability_issuer) is not _CapabilityIssuer:
            self._journal.close()
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None

    @property
    def metadata(self) -> RetainedAnchorContinuityMetadata:
        return RetainedAnchorContinuityMetadata(
            state=self._journal.state,
            revision=self._journal._record["revision"],
            journal_format=self._journal.journal_format,
            anchor_format=self._journal.anchor_format,
            classification=self._journal._anchor_classification,
        )

    def _assert_session_binding(self) -> None:
        if (
            self._closed
            or getattr(self._broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(self._broker, "_session_generation", None)
            is not self._session_generation
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_CHANGED") from None

    def inspect_current_source(
        self,
        candidate_manifest: SourceManifest,
        restore_manifest: SourceManifest,
    ) -> CurrentSourceInventoryResult:
        if self._source_inspection_attempted:
            raise LifecycleControllerError(
                "SOURCE_INSPECTION_ALREADY_ATTEMPTED"
            ) from None
        self._source_inspection_attempted = True
        result = _inspect_current_source(self, candidate_manifest, restore_manifest)
        evidence = result.evidence
        self._source_proven = (
            result.classification is CurrentSourceClassification.EXACT_PR41
            and result.root_profile is RemoteRootProfile.HOMEASSISTANT_CONFIG
            and _source_inventory_exact(evidence, len(restore_manifest.entries))
            and evidence is not None
            and evidence.content_mismatch_count == 0
            and evidence.managed_manifest_identity
            == _source_manifest_digest(restore_manifest.entries)
        )
        return result

    def migrate_anchor(self) -> LifecycleAnchorMigrationResult:
        self._assert_session_binding()
        if self._migration_attempted or not self._source_proven:
            raise LifecycleControllerError(
                "LIFECYCLE_ANCHOR_MIGRATION_NOT_AUTHORIZED"
            ) from None
        self._migration_attempted = True
        return self._journal.migrate_device_drift_anchor()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        release_error: SessionBrokerError | None = None
        try:
            self._broker._release_retained_anchor_continuity_inspector(
                self,
                self._capability_issuer,
                self._session_generation,
            )
        except SessionBrokerError as error:
            release_error = error
        finally:
            self._journal.close()
        if release_error is not None:
            raise LifecycleControllerError("LIFECYCLE_SESSION_RELEASE_FAILED") from None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class RetainedTerminalLifecycleInspector:
    """Inspection-only handle for one retained terminal lifecycle."""

    def __init__(self, broker: Any) -> None:
        if (
            getattr(broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(broker, "_session_generation", None) is None
            or not callable(getattr(broker, "_register_lifecycle_controller", None))
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        self._broker = broker
        self._session_generation = broker._session_generation
        self._source_classification: CurrentSourceClassification | None = None
        self._prior_backup_classification: PriorBackupClassification | None = None
        self._backup_retirement_attempted = False
        self._retired = False
        self._journal = _DurableLifecycleJournal.open_retained_terminal()
        try:
            self._capability_issuer = broker._register_lifecycle_controller(
                self,
                self._journal.lifecycle_generation,
                self._session_generation,
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._journal.close()
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        if type(self._capability_issuer) is not _CapabilityIssuer:
            self._journal.close()
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None

    @property
    def metadata(self) -> RetainedTerminalMetadata:
        return RetainedTerminalMetadata(
            self._journal.state,
            self._journal._record["revision"],
            self._journal.lifecycle_generation,
        )

    @property
    def journal_format(self) -> LifecycleJournalFormat:
        """Return the recognized retained format without changing durable state."""
        return self._journal.journal_format

    @property
    def anchor_format(self) -> LifecycleAnchorFormat:
        """Return the exact retained anchor format without durable mutation."""
        return self._journal.anchor_format

    def _assert_session_binding(self) -> None:
        if (
            getattr(self._broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(self._broker, "_session_generation", None)
            is not self._session_generation
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_CHANGED") from None

    def inspect_current_source(
        self,
        candidate_manifest: SourceManifest,
        restore_manifest: SourceManifest,
    ) -> CurrentSourceInventoryResult:
        if self._retired:
            raise LifecycleControllerError("LIFECYCLE_TERMINAL_RETIRED") from None
        result = _inspect_current_source(self, candidate_manifest, restore_manifest)
        self._source_classification = result.classification
        return result

    def _retained_backup_capability(
        self, action: RetainedBackupAction
    ) -> _RetainedBackupCapability:
        self._assert_session_binding()
        identity = self._journal.baseline_backup_identity
        if (
            self._retired
            or self._source_classification is not CurrentSourceClassification.EXACT_PR41
            or type(identity) is not dict
        ):
            raise LifecycleControllerError(
                "PRIOR_BACKUP_CONTINUITY_NOT_AUTHORIZED"
            ) from None
        capability = _RetainedBackupCapability(
            self,
            self._capability_issuer.identity,
            self._journal.lifecycle_generation,
            identity["source_generation"],
            self._session_generation,
            secrets.token_hex(16),
            action,
            identity,
            self._journal.action_transition_committed(LifecycleAction.RESTORE_INSTALL),
        )
        self._capability_issuer.issued.append(capability)
        return capability

    def inspect_prior_backup(
        self, restore_manifest: SourceManifest
    ) -> PriorBackupContinuityResult:
        if self._prior_backup_classification is not None:
            raise LifecycleControllerError("PRIOR_BACKUP_ALREADY_INSPECTED") from None
        capability = self._retained_backup_capability(RetainedBackupAction.INSPECT)
        try:
            result = self._broker._retained_backup_operation(
                restore_manifest,
                RetainedBackupAction.INSPECT,
                _capability=capability,
            )
            if (
                not isinstance(result, PriorBackupContinuityResult)
                or result.retired is not False
            ):
                raise TypeError
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            result = PriorBackupContinuityResult(
                PriorBackupClassification.OTHER_OR_INDETERMINATE
            )
        self._prior_backup_classification = result.classification
        return result

    def retire_owned_prior_backup(
        self, restore_manifest: SourceManifest
    ) -> PriorBackupContinuityResult:
        if (
            self._backup_retirement_attempted
            or self._prior_backup_classification
            is not PriorBackupClassification.OWNED_BY_RETAINED_LIFECYCLE
        ):
            raise LifecycleControllerError(
                "PRIOR_BACKUP_RETIREMENT_NOT_AUTHORIZED"
            ) from None
        self._backup_retirement_attempted = True
        capability = self._retained_backup_capability(RetainedBackupAction.RETIRE)
        try:
            result = self._broker._retained_backup_operation(
                restore_manifest,
                RetainedBackupAction.RETIRE,
                _capability=capability,
            )
            if (
                not isinstance(result, PriorBackupContinuityResult)
                or result.classification is not PriorBackupClassification.NONE
                or result.retired is not True
            ):
                raise TypeError
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._prior_backup_classification = (
                PriorBackupClassification.OTHER_OR_INDETERMINATE
            )
            raise LifecycleControllerError("PRIOR_BACKUP_RETIREMENT_FAILED") from None
        self._prior_backup_classification = result.classification
        return result

    def retire_terminal(self) -> None:
        self._assert_session_binding()
        if (
            self._retired
            or self._source_classification is not CurrentSourceClassification.EXACT_PR41
            or self._prior_backup_classification is not PriorBackupClassification.NONE
        ):
            raise LifecycleControllerError(
                "LIFECYCLE_TERMINAL_RETIREMENT_NOT_AUTHORIZED"
            ) from None
        self._journal.retire_terminal()
        self._retired = True

    def close(self) -> None:
        self._journal.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


_REMOTE_PHASE_A_SESSION_CONSTRUCTOR = object()


class RemotePhaseAInventorySession:
    """One parameter-free, fixed-plan remote Phase-A research session."""

    def __init__(
        self,
        controller: object,
        broker: object,
        permit: object,
        baseline: object,
        *,
        _constructor: object = None,
    ) -> None:
        if (
            _constructor is not _REMOTE_PHASE_A_SESSION_CONSTRUCTOR
            or controller.__class__ is not FullPreflightLifecycleController
            or type(permit) is not _RemotePhaseAInventoryPermit
            or not isinstance(baseline, AuditSnapshot)
        ):
            raise LifecycleControllerError("RESEARCH_SESSION_INVALID") from None
        self._controller = controller
        self._broker = broker
        self._permit = permit
        self._baseline = baseline
        self._readiness_attempted = False
        self._readiness_passed = False
        self._ran = False
        self._closed = False

    def __repr__(self) -> str:
        return (
            "RemotePhaseAInventorySession("
            f"ran={self._ran!r}, closed={self._closed!r})"
        )

    @staticmethod
    def _dispatch_error(error: BaseException) -> RemotePhaseAResearchError:
        failure = _bounded_dispatch_failure(
            DispatchFailureStage.UNKNOWN,
            error,
        )
        return RemotePhaseAResearchError(
            failure.stage,
            failure.failure_class,
            failure.remote_failure_scope,
            failure.remote_failure_reason,
        )

    def _assert_active(self) -> tuple[FullPreflightLifecycleController, object]:
        controller = self._controller
        permit = self._permit
        if (
            self._closed
            or controller.state is not LifecycleState.A2_COLLECTED
            or not getattr(controller, "_research_session_active", False)
            or permit.controller is not controller
            or permit.lifecycle_generation is not controller._lifecycle_generation
            or permit.source_generation is not controller._candidate_source_generation
            or permit.session_generation is not controller._session_generation
        ):
            raise LifecycleControllerError("RESEARCH_SESSION_INVALID") from None
        return controller, permit

    def check_readiness(self) -> RemotePhaseAReadinessResult:
        """Run the one device-free target and audit admission exactly once."""
        if self._readiness_attempted or self._ran:
            raise LifecycleControllerError("RESEARCH_READINESS_CONSUMED") from None
        controller, permit = self._assert_active()
        self._readiness_attempted = True
        capability = _RemotePhaseAResearchCapability(
            controller,
            self,
            permit.issuer,
            permit.lifecycle_generation,
            permit.source_generation,
            permit.session_generation,
            ResearchOperation.CHECK_READINESS,
            object(),
        )
        controller._capability_issuer.issued.append(capability)
        try:
            result = self._broker._invoke_remote_phase_a_research(
                self._baseline, _capability=capability
            )
        except (SessionBrokerError, TypeError, ValueError) as error:
            raise self._dispatch_error(error) from None
        if not isinstance(result, RemotePhaseAReadinessResult):
            raise RemotePhaseAResearchError(
                DispatchFailureStage.RESULT_VALIDATION,
                DispatchFailureClass.SCHEMA,
                None,
                None,
            ) from None
        self._readiness_passed = result.ready
        return result

    def run_remote_phase_a_inventory(self) -> RemotePhaseAInventoryResult:
        """Execute the immutable R01-R10 plan exactly once."""
        if self._closed or self._ran:
            raise LifecycleControllerError("RESEARCH_SESSION_CONSUMED") from None
        if not self._readiness_passed:
            raise LifecycleControllerError("RESEARCH_READINESS_REQUIRED") from None
        controller, permit = self._assert_active()
        self._ran = True
        capability = _RemotePhaseAResearchCapability(
            controller,
            self,
            permit.issuer,
            permit.lifecycle_generation,
            permit.source_generation,
            permit.session_generation,
            ResearchOperation.RUN_FIXED_INVENTORY,
            object(),
        )
        controller._capability_issuer.issued.append(capability)
        try:
            result = self._broker._invoke_remote_phase_a_research(
                self._baseline, _capability=capability
            )
        except (SessionBrokerError, TypeError, ValueError) as error:
            raise self._dispatch_error(error) from None
        if not isinstance(result, RemotePhaseAInventoryResult):
            raise RemotePhaseAResearchError(
                DispatchFailureStage.RESULT_VALIDATION,
                DispatchFailureClass.SCHEMA,
                None,
                None,
            ) from None
        return result

    def close(self) -> None:
        """Permanently close the permit and return restore authority to controller."""
        if self._closed:
            return
        self._closed = True
        self._controller._close_remote_phase_a_inventory_session(self)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


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
            if reconstructed_stage in _CANDIDATE_RESTARTED_STAGES:
                broker._active_source_state = SourceState.CANDIDATE
                broker._restarted_states.add(SourceState.CANDIDATE)
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
        self._activation_restart: RestartResult | None = (
            None
            if self._journal is None
            else self._journal.restart_result(LifecycleAction.ACTIVATION_RESTART)
        )
        self._removal_restart: RestartResult | None = None
        self._restart_dispatched: set[SourceState] = set()
        self._pre_source_recovery_inspected = False
        self._restore_readiness: CoreReadinessResult | None = None
        self._restore_services: ServiceInventoryResult | None = None
        self._restore_repairs: RepairsEvidence | None = None
        self._research_session_issued = False
        self._research_session_active = False
        self._research_session: RemotePhaseAInventorySession | None = None

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
        success_state: LifecycleState | None = None,
        success_predicate: Callable[[Any], bool] | None = None,
        _dispatch_token: object = None,
    ) -> Any:
        if _dispatch_token is not self.__dispatch_token:
            raise LifecycleControllerError("LIFECYCLE_DISPATCH_SCOPE_INVALID") from None
        self._assert_session_binding()
        allowed_predecessors = _LIFECYCLE_ACTION_PREDECESSORS.get(action)
        if allowed_predecessors is None or self.state not in allowed_predecessors:
            raise LifecycleControllerError("LIFECYCLE_TRANSITION_INVALID") from None
        if (
            (success_state is None) != (success_predicate is None)
            or success_state is not None
            and (
                action is not LifecycleAction.PREFLIGHT
                or success_state not in _LIFECYCLE_ACTION_SUCCESSORS[action]
            )
        ):
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
        except BaseException as error:
            if self._journal is not None:
                if isinstance(error, _DispatchFailure):
                    failure_stage = error.stage
                    failure_class = error.failure_class
                    remote_failure_scope = error.remote_failure_scope
                    remote_failure_reason = error.remote_failure_reason
                else:
                    failure_stage = DispatchFailureStage.CALLBACK
                    failure_class = DispatchFailureClass.CALLBACK
                    remote_failure_scope = None
                    remote_failure_reason = None
                self._journal.record_ambiguous(
                    action,
                    failure_stage,
                    failure_class,
                    remote_failure_scope,
                    remote_failure_reason,
                )
                if action is LifecycleAction.BACKUP_FALLBACK_RECONCILE and getattr(
                    self._journal, "fallback_reconciliation_resumable", False
                ):
                    permit.consumed = False
            raise
        atomic_success = (
            success_predicate is not None
            and success_state is not None
            and success_predicate(result)
        )
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
                transition_state=success_state if atomic_success else None,
            )
            self._evidence_generations[action] = evidence_generation
            if origin is not None:
                self._evidence_origins[id(result)] = (
                    origin,
                    evidence_generation,
                )
        if atomic_success:
            self._current_source_generation = source_generation
            self._state = success_state
        return result

    def __dispatch_action(
        self,
        action: LifecycleAction,
        callback: Callable[[_LifecycleCapability], Any],
        *,
        broker_evidence: bool = True,
        success_state: LifecycleState | None = None,
        success_predicate: Callable[[Any], bool] | None = None,
    ) -> Any:
        return self._dispatch(
            action,
            callback,
            broker_evidence=broker_evidence,
            success_state=success_state,
            success_predicate=success_predicate,
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
        return _source_inventory_exact(result, expected_count)

    def inspect_current_source(
        self,
        candidate_manifest: SourceManifest,
        restore_manifest: SourceManifest,
    ) -> CurrentSourceInventoryResult:
        return _inspect_current_source(self, candidate_manifest, restore_manifest)

    def resolve_pre_source_abort(
        self,
        candidate_manifest: SourceManifest,
        restore_manifest: SourceManifest,
    ) -> CurrentSourceInventoryResult:
        self._require_state(
            LifecycleState.ROLLBACK_REQUIRED, LifecycleState.RECOVERY_REQUIRED
        )
        if self._journal is None or self._journal.source_mutation_may_have_occurred:
            raise LifecycleControllerError(
                "PRE_SOURCE_RECOVERY_DECISION_INVALID"
            ) from None
        result = self.inspect_current_source(candidate_manifest, restore_manifest)
        if result.classification is CurrentSourceClassification.EXACT_PR41:
            self._journal.transition(
                LifecycleState.ABORTED_AT_BASELINE,
                action=None,
                source_generation=self._journal._record["pr41_restore"]["generation"],
                evidence_generation=None,
                recovery=True,
                terminal=True,
            )
            self._state = LifecycleState.ABORTED_AT_BASELINE
            self._journal.close()
        else:
            self._pre_source_recovery_inspected = True
        return result

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
                raise _DispatchFailure(
                    DispatchFailureStage.RESULT_VALIDATION,
                    DispatchFailureClass.SCHEMA,
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
            and result.dispatch_outcome
            in {
                RestartDispatchOutcome.RESPONSE_ACCEPTED,
                RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
            }
        ):
            self._rollback()
        return result

    def restart_for_candidate(self) -> RestartResult:
        self._require_state(LifecycleState.CANDIDATE_CORE_CHECKED)
        result = self._restart(
            SourceState.CANDIDATE, LifecycleAction.ACTIVATION_RESTART
        )
        self._activation_restart = result
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
            or result.http_status is not None
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
            or result.http_status is not None
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

        def valid_preflight(result: object) -> bool:
            return (
                isinstance(result, PhaseAResult)
                and result.operation is PhaseAOperation.PREFLIGHT
                and result.nonce == nonce
                and result.exit_code == 0
                and result.outcome == "preflight_ok"
                and result.preflight == PreflightResponse("preflight_ok", 1, nonce)
                and result.receipt is None
                and result.audit is None
                and result.http_status is None
            )

        try:
            result = self.__dispatch_action(
                LifecycleAction.PREFLIGHT,
                lambda capability: self._broker._invoke_phase_a(
                    PhaseAOperation.PREFLIGHT,
                    nonce=nonce,
                    _capability=capability,
                ),
                success_state=LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED,
                success_predicate=valid_preflight,
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._rollback()
        if not valid_preflight(result):
            reason = PreflightFailureReason.RESULT_INVALID
            http_status = None
            if (
                isinstance(result, PhaseAResult)
                and result.operation is PhaseAOperation.PREFLIGHT
                and result.preflight is None
                and result.receipt is None
                and result.audit is None
            ):
                if (
                    result.exit_code == 65
                    and result.outcome == "not_submitted"
                    and result.nonce is None
                    and result.http_status is None
                ):
                    reason = PreflightFailureReason.NOT_SUBMITTED
                elif (
                    result.exit_code == 66
                    and result.outcome == "http_rejected"
                    and result.nonce == nonce
                    and type(result.http_status) is int
                    and 400 <= result.http_status <= 599
                ):
                    reason = PreflightFailureReason.HTTP_REJECTED
                    http_status = result.http_status
                elif result.nonce == nonce and result.http_status is None:
                    reason = {
                        (67, "schema_invalid"): PreflightFailureReason.SCHEMA_INVALID,
                        (67, "nonce_mismatch"): PreflightFailureReason.NONCE_MISMATCH,
                        (
                            67,
                            "evidence_write_failed",
                        ): PreflightFailureReason.EVIDENCE_WRITE_FAILED,
                        (
                            78,
                            "transport_ambiguous",
                        ): PreflightFailureReason.TRANSPORT_AMBIGUOUS,
                    }.get(
                        (result.exit_code, result.outcome),
                        PreflightFailureReason.RESULT_INVALID,
                    )
            self._enter_recovery()
            raise PreflightRejectedError(reason, http_status) from None
        self._preflight_result = result
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

    def open_remote_phase_a_inventory_session(
        self,
    ) -> RemotePhaseAInventorySession:
        """Issue exactly one dedicated research permit after durable A2."""
        self._require_state(LifecycleState.A2_COLLECTED)
        self._assert_session_binding()
        baseline = self._snapshots.get(AuditLabel.A2)
        candidate_manifest = self._candidate_manifest
        if (
            self._research_session_issued
            or self._research_session_active
            or not isinstance(baseline, AuditSnapshot)
            or not isinstance(candidate_manifest, SourceManifest)
            or candidate_manifest.state is not SourceState.CANDIDATE
            or _source_manifest_digest(candidate_manifest.entries)
            != _AUTHORITY_MANIFEST_DIGESTS[SourceState.CANDIDATE.value]
            or not self._audit_origin_chain_valid(
                (AuditLabel.A0, AuditLabel.AP0, AuditLabel.A1, AuditLabel.A2)
            )
            or baseline.history_overflow
        ):
            raise LifecycleControllerError("RESEARCH_SESSION_INVALID") from None
        permit = _RemotePhaseAInventoryPermit(
            self,
            self._capability_issuer.identity,
            self._lifecycle_generation,
            self._candidate_source_generation,
            self._session_generation,
            object(),
        )
        self._capability_issuer.issued.append(permit)
        self._capability_issuer.consumed.append(permit)
        session = RemotePhaseAInventorySession(
            self,
            self._broker,
            permit,
            baseline,
            _constructor=_REMOTE_PHASE_A_SESSION_CONSTRUCTOR,
        )
        self._research_session_issued = True
        self._research_session_active = True
        self._research_session = session
        return session

    def _close_remote_phase_a_inventory_session(
        self, session: RemotePhaseAInventorySession
    ) -> None:
        if (
            not self._research_session_active
            or self._research_session is not session
            or session._controller is not self
        ):
            raise LifecycleControllerError("RESEARCH_SESSION_INVALID") from None
        self._research_session_active = False
        self._research_session = None

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
        if self._research_session_active:
            raise LifecycleControllerError("RESEARCH_SESSION_ACTIVE") from None
        if (
            self._journal is not None
            and self._journal.recovery_mode
            and not self._journal.source_mutation_may_have_occurred
            and not self._pre_source_recovery_inspected
        ):
            raise LifecycleControllerError("PRE_SOURCE_INVENTORY_REQUIRED") from None
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
        restart = self._removal_restart or (
            None
            if self._journal is None
            else self._journal.restart_result(LifecycleAction.REMOVAL_RESTART)
        )
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
        readiness_committed = self._durable_action_committed(
            LifecycleAction.RESTORE_READINESS
        )
        services_committed = self._durable_action_committed(
            LifecycleAction.SERVICES_ABSENT
        )
        repairs_committed = self._durable_action_committed(
            LifecycleAction.POST_RESTORE_REPAIRS
        )
        source_manifest_match = inventory_committed or (
            inventory is not None
            and self._restore_manifest is not None
            and self._inventory_pass(inventory, len(self._restore_manifest.entries))
        )
        research_files_absent = inventory_committed or (
            inventory is not None
            and inventory.unexpected_count == 0
            and inventory.missing_count == 0
        )
        core_reachable = readiness_committed or (
            readiness is not None and readiness.core_reachable is True
        )
        core_running = readiness_committed or (
            readiness is not None and readiness.core_running is True
        )
        integration_loaded = readiness_committed or (
            readiness is not None and readiness.integration_loaded is True
        )
        core_not_timed_out = readiness_committed or (
            readiness is not None and readiness.timed_out is False
        )
        research_services_absent = services_committed or self._services_absent_pass(
            services
        )
        restart_dispatch_acceptable = isinstance(
            restart, RestartResult
        ) and restart.dispatch_outcome in {
            RestartDispatchOutcome.RESPONSE_ACCEPTED,
            RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
        }
        restart_effect_proven = (
            restart_dispatch_acceptable
            and isinstance(restart, RestartResult)
            and (
                restart.response_accepted
                or (
                    restart.dispatched_response_unknown
                    and source_manifest_match
                    and research_files_absent
                    and core_reachable
                    and core_running
                    and integration_loaded
                    and core_not_timed_out
                    and research_services_absent
                )
            )
        )
        return FinalRestoreProof(
            source_manifest_match=source_manifest_match,
            research_files_absent=research_files_absent,
            core_check_passed=(
                core_committed or (core is not None and core.check_passed)
            ),
            restart_consumed=restart_permit.consumed,
            restart_dispatch_acceptable=restart_dispatch_acceptable,
            restart_effect_proven=restart_effect_proven,
            core_reachable=core_reachable,
            core_running=core_running,
            integration_loaded=integration_loaded,
            core_not_timed_out=core_not_timed_out,
            research_services_absent=research_services_absent,
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


_FEATURE_RESTORE_SIDE_STATES = frozenset(
    {
        FeatureValidationState.PR41_RESTORED,
        FeatureValidationState.RESTORE_INVENTORY_VERIFIED,
        FeatureValidationState.RESTORE_CORE_CHECKED,
        FeatureValidationState.REMOVAL_RESTART_CONSUMED,
        FeatureValidationState.PR41_READY,
        FeatureValidationState.FEATURE_ABSENCE_VERIFIED,
        FeatureValidationState.POST_RESTORE_REPAIRS_PASS,
    }
)


_FEATURE_ACTION_PREDECESSORS: dict[
    FeatureValidationAction, frozenset[FeatureValidationState]
] = {
    FeatureValidationAction.INITIAL_SOURCE: frozenset(
        {FeatureValidationState.BASELINE}
    ),
    FeatureValidationAction.INITIAL_REPAIRS: frozenset(
        {FeatureValidationState.INITIAL_SOURCE_VERIFIED}
    ),
    FeatureValidationAction.BACKUP: frozenset(
        {FeatureValidationState.INITIAL_REPAIRS_PASS}
    ),
    FeatureValidationAction.R64_TRANSFER: frozenset(
        {FeatureValidationState.R64_BACKUP_VERIFIED}
    ),
    FeatureValidationAction.R64_INSTALL: frozenset({FeatureValidationState.R64_STAGED}),
    FeatureValidationAction.R64_INVENTORY: frozenset(
        {FeatureValidationState.R64_INSTALLED}
    ),
    FeatureValidationAction.R64_CORE_CHECK: frozenset(
        {FeatureValidationState.R64_INVENTORY_VERIFIED}
    ),
    FeatureValidationAction.R64_RESTART: frozenset(
        {FeatureValidationState.R64_CORE_CHECKED}
    ),
    FeatureValidationAction.R64_READINESS: frozenset(
        {FeatureValidationState.R64_RESTART_CONSUMED}
    ),
    FeatureValidationAction.R64_POST_RESTART_INVENTORY: frozenset(
        {FeatureValidationState.R64_READY}
    ),
    FeatureValidationAction.LIVE_VALIDATION: frozenset(
        {FeatureValidationState.R64_POST_RESTART_INVENTORY_VERIFIED}
    ),
    FeatureValidationAction.RESTORE_TRANSFER: frozenset(
        {
            FeatureValidationState.R64_BACKUP_VERIFIED,
            FeatureValidationState.R64_STAGED,
            FeatureValidationState.R64_INSTALLED,
            FeatureValidationState.R64_INVENTORY_VERIFIED,
            FeatureValidationState.R64_CORE_CHECKED,
            FeatureValidationState.R64_RESTART_CONSUMED,
            FeatureValidationState.R64_READY,
            FeatureValidationState.R64_POST_RESTART_INVENTORY_VERIFIED,
            FeatureValidationState.LIVE_VALIDATION_CONSUMED,
            FeatureValidationState.RESTORE_REQUIRED,
        }
    ),
    FeatureValidationAction.RESTORE_INSTALL: frozenset(
        {FeatureValidationState.RESTORE_STAGED}
    ),
    FeatureValidationAction.BACKUP_FALLBACK: frozenset(
        {FeatureValidationState.RESTORE_REQUIRED}
    ),
    FeatureValidationAction.BACKUP_FALLBACK_RECONCILE: frozenset(
        {FeatureValidationState.RESTORE_REQUIRED}
    ),
    FeatureValidationAction.BACKUP_RETIRE: _FEATURE_RESTORE_SIDE_STATES,
    FeatureValidationAction.RESTORE_INVENTORY: frozenset(
        {FeatureValidationState.PR41_RESTORED}
    ),
    FeatureValidationAction.RESTORE_CORE_CHECK: frozenset(
        {FeatureValidationState.RESTORE_INVENTORY_VERIFIED}
    ),
    FeatureValidationAction.REMOVAL_RESTART: frozenset(
        {FeatureValidationState.RESTORE_CORE_CHECKED}
    ),
    FeatureValidationAction.RESTORE_READINESS: frozenset(
        {FeatureValidationState.REMOVAL_RESTART_CONSUMED}
    ),
    FeatureValidationAction.FEATURE_ABSENCE: frozenset(
        {FeatureValidationState.PR41_READY}
    ),
    FeatureValidationAction.POST_RESTORE_REPAIRS: frozenset(
        {FeatureValidationState.FEATURE_ABSENCE_VERIFIED}
    ),
    FeatureValidationAction.FINAL_ACCEPTANCE: frozenset(
        {FeatureValidationState.POST_RESTORE_REPAIRS_PASS}
    ),
}

_FEATURE_TO_LIFECYCLE_ACTION = {
    FeatureValidationAction.INITIAL_REPAIRS: LifecycleAction.INITIAL_REPAIRS,
    FeatureValidationAction.BACKUP: LifecycleAction.BACKUP,
    FeatureValidationAction.R64_TRANSFER: LifecycleAction.CANDIDATE_TRANSFER,
    FeatureValidationAction.R64_INSTALL: LifecycleAction.CANDIDATE_INSTALL,
    FeatureValidationAction.R64_INVENTORY: LifecycleAction.CANDIDATE_INVENTORY,
    FeatureValidationAction.R64_CORE_CHECK: LifecycleAction.CANDIDATE_CORE_CHECK_1,
    FeatureValidationAction.R64_RESTART: LifecycleAction.ACTIVATION_RESTART,
    FeatureValidationAction.R64_READINESS: LifecycleAction.CANDIDATE_READINESS,
    FeatureValidationAction.R64_POST_RESTART_INVENTORY: (
        LifecycleAction.CANDIDATE_INVENTORY
    ),
    FeatureValidationAction.RESTORE_TRANSFER: LifecycleAction.RESTORE_TRANSFER,
    FeatureValidationAction.RESTORE_INSTALL: LifecycleAction.RESTORE_INSTALL,
    FeatureValidationAction.BACKUP_FALLBACK: LifecycleAction.BACKUP_FALLBACK,
    FeatureValidationAction.BACKUP_FALLBACK_RECONCILE: (
        LifecycleAction.BACKUP_FALLBACK_RECONCILE
    ),
    FeatureValidationAction.RESTORE_INVENTORY: LifecycleAction.RESTORE_INVENTORY,
    FeatureValidationAction.RESTORE_CORE_CHECK: LifecycleAction.RESTORE_CORE_CHECK_1,
    FeatureValidationAction.REMOVAL_RESTART: LifecycleAction.REMOVAL_RESTART,
    FeatureValidationAction.RESTORE_READINESS: LifecycleAction.RESTORE_READINESS,
    FeatureValidationAction.POST_RESTORE_REPAIRS: (
        LifecycleAction.POST_RESTORE_REPAIRS
    ),
}


class RetainedFeatureValidationTerminalInspector:
    """State-neutral handle for one retained successful feature lifecycle."""

    def __init__(self, broker: Any) -> None:
        if (
            getattr(broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(broker, "_session_generation", None) is None
            or not callable(getattr(broker, "_register_lifecycle_controller", None))
            or not callable(
                getattr(
                    broker,
                    "_release_retained_feature_validation_terminal_inspector",
                    None,
                )
            )
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        self._broker = broker
        self._session_generation = broker._session_generation
        self._source_inspection_attempted = False
        self._exact_pr41_source_proven = False
        self._feature_backup_classification: FeatureBackupClassification | None = None
        self._retired = False
        self._closed = False
        self._journal = _DurableFeatureValidationJournal.open_retained_terminal()
        try:
            self._capability_issuer = broker._register_lifecycle_controller(
                self,
                self._journal.lifecycle_generation,
                self._session_generation,
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._journal.close()
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        if type(self._capability_issuer) is not _CapabilityIssuer:
            self._journal.close()
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None

    @property
    def metadata(self) -> RetainedFeatureValidationTerminalMetadata:
        return RetainedFeatureValidationTerminalMetadata(
            state=self._journal.state,
            terminal=self._journal.terminal_state,
            active=self._journal.active,
            schema_version=self._journal.schema_version,
            final_restore_complete=self._journal.final_restore_complete,
            live_result_durability=(
                FeatureLiveResultDurabilityClassification.NOT_DURABLY_AVAILABLE
            ),
        )

    def _assert_session_binding(self) -> None:
        if (
            self._closed
            or getattr(self._broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(self._broker, "_session_generation", None)
            is not self._session_generation
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_CHANGED") from None

    @staticmethod
    def _exact_inventory(
        result: CurrentSourceInventoryResult,
        manifest: SourceManifest,
    ) -> bool:
        evidence = result.evidence
        return (
            evidence is not None
            and _source_inventory_exact(evidence, len(manifest.entries))
            and evidence.root_profile is RemoteRootProfile.HOMEASSISTANT_CONFIG
            and _exact_non_bool_int(evidence.content_mismatch_count)
            and evidence.content_mismatch_count == 0
            and evidence.managed_manifest_identity
            == _source_manifest_digest(manifest.entries)
        )

    def inspect_current_source(
        self,
        r64_manifest: SourceManifest,
        restore_manifest: SourceManifest,
    ) -> CurrentSourceInventoryResult:
        """Classify current source without progressing the retained lifecycle."""
        self._assert_session_binding()
        if self._source_inspection_attempted:
            raise LifecycleControllerError(
                "FEATURE_SOURCE_INSPECTION_ALREADY_ATTEMPTED"
            ) from None
        self._source_inspection_attempted = True
        self._exact_pr41_source_proven = False
        self._feature_backup_classification = None
        try:
            validate_source_manifest(r64_manifest)
            validate_source_manifest(restore_manifest)
        except (SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError("FEATURE_SOURCE_INSPECTION_FAILED") from None
        if (
            r64_manifest.state is not SourceState.R64_RUNTIME
            or restore_manifest.state is not SourceState.RESTORE
        ):
            raise LifecycleControllerError("FEATURE_SOURCE_INSPECTION_FAILED") from None
        capability = _SourceInspectionCapability(
            self,
            self._capability_issuer.identity,
            self._session_generation,
            secrets.token_hex(16),
        )
        self._capability_issuer.issued.append(capability)
        try:
            result = self._broker._inspect_current_source(
                r64_manifest,
                restore_manifest,
                _capability=capability,
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError) as error:
            failure = _bounded_dispatch_failure(DispatchFailureStage.UNKNOWN, error)
            return CurrentSourceInventoryResult(
                CurrentSourceClassification.INDETERMINATE,
                failure_stage=failure.stage,
                failure_class=failure.failure_class,
                remote_failure_scope=failure.remote_failure_scope,
                remote_failure_reason=failure.remote_failure_reason,
            )
        if not isinstance(result, CurrentSourceInventoryResult):
            return CurrentSourceInventoryResult(
                CurrentSourceClassification.INDETERMINATE,
                failure_stage=DispatchFailureStage.RESULT_VALIDATION,
                failure_class=DispatchFailureClass.SCHEMA,
            )
        expected_manifest = {
            CurrentSourceClassification.EXACT_PR41: restore_manifest,
            CurrentSourceClassification.EXACT_R64: r64_manifest,
        }.get(result.classification)
        if expected_manifest is not None and not self._exact_inventory(
            result, expected_manifest
        ):
            return CurrentSourceInventoryResult(
                CurrentSourceClassification.INDETERMINATE,
                failure_stage=DispatchFailureStage.RESULT_VALIDATION,
                failure_class=DispatchFailureClass.SCHEMA,
            )
        self._exact_pr41_source_proven = (
            result.classification is CurrentSourceClassification.EXACT_PR41
        )
        return result

    def inspect_feature_backup(
        self, restore_manifest: SourceManifest
    ) -> FeatureBackupContinuityResult:
        """Classify this lifecycle's remote backup without mutating it."""
        self._assert_session_binding()
        if (
            not self._exact_pr41_source_proven
            or self._feature_backup_classification is not None
        ):
            raise LifecycleControllerError(
                "FEATURE_BACKUP_CONTINUITY_NOT_AUTHORIZED"
            ) from None
        try:
            validate_source_manifest(restore_manifest)
        except (SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError(
                "FEATURE_BACKUP_CONTINUITY_NOT_AUTHORIZED"
            ) from None
        if restore_manifest.state is not SourceState.RESTORE:
            raise LifecycleControllerError(
                "FEATURE_BACKUP_CONTINUITY_NOT_AUTHORIZED"
            ) from None
        capability = _FeatureBackupContinuityCapability(
            self,
            self._capability_issuer.identity,
            self._journal.lifecycle_generation,
            PR41_RESTORE_COMMIT,
            self._session_generation,
            secrets.token_hex(16),
            FeatureBackupAction.INSPECT,
            self._journal.backup_identity,
            self._journal.committed(FeatureValidationAction.RESTORE_INSTALL),
        )
        self._capability_issuer.issued.append(capability)
        try:
            result = self._broker._feature_backup_continuity_operation(
                restore_manifest,
                FeatureBackupAction.INSPECT,
                _capability=capability,
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            result = FeatureBackupContinuityResult(
                FeatureBackupClassification.OTHER_OR_INDETERMINATE
            )
        if not isinstance(result, FeatureBackupContinuityResult) or result.retired:
            result = FeatureBackupContinuityResult(
                FeatureBackupClassification.OTHER_OR_INDETERMINATE
            )
        self._feature_backup_classification = result.classification
        return result

    def retire_terminal(self) -> None:
        """Retire exactly this proven clean completed feature terminal."""
        self._assert_session_binding()
        if (
            self._retired
            or not self._exact_pr41_source_proven
            or self._feature_backup_classification
            is not FeatureBackupClassification.NONE
            or not self._journal.final_restore_complete
        ):
            raise LifecycleControllerError(
                "FEATURE_TERMINAL_RETIREMENT_NOT_AUTHORIZED"
            ) from None
        self._journal.retire_terminal()
        self._retired = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        release_error: SessionBrokerError | None = None
        try:
            self._broker._release_retained_feature_validation_terminal_inspector(
                self,
                self._capability_issuer,
                self._session_generation,
            )
        except SessionBrokerError as error:
            release_error = error
        finally:
            self._journal.close()
        if release_error is not None:
            raise LifecycleControllerError("LIFECYCLE_SESSION_RELEASE_FAILED") from None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class RefreshStatusLiveValidationController:
    """One durable, parameter-free exact-R64 validation and PR41 restoration."""

    _FORWARD_ACTIONS = frozenset(
        {
            FeatureValidationAction.INITIAL_SOURCE,
            FeatureValidationAction.INITIAL_REPAIRS,
            FeatureValidationAction.BACKUP,
            FeatureValidationAction.R64_TRANSFER,
            FeatureValidationAction.R64_INSTALL,
            FeatureValidationAction.R64_INVENTORY,
            FeatureValidationAction.R64_CORE_CHECK,
            FeatureValidationAction.R64_RESTART,
            FeatureValidationAction.R64_READINESS,
            FeatureValidationAction.R64_POST_RESTART_INVENTORY,
            FeatureValidationAction.LIVE_VALIDATION,
        }
    )

    def __init__(self, broker: Any) -> None:
        if (
            getattr(broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(broker, "_session_generation", None) is None
            or not callable(getattr(broker, "_register_lifecycle_controller", None))
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_REQUIRED") from None
        self._broker = broker
        self._session_generation = broker._session_generation
        durable_required = not _DISABLE_DURABLE_LIFECYCLE_FOR_TESTS and (
            type(broker) is PrivateInteractiveSessionBroker
            or getattr(broker, "_durable_lifecycle_test", False) is True
        )
        self._journal = _DurableFeatureValidationJournal() if durable_required else None
        if self._journal is not None and self._journal.reconstructed:
            for action in (
                FeatureValidationAction.R64_TRANSFER,
                FeatureValidationAction.R64_INSTALL,
                FeatureValidationAction.RESTORE_TRANSFER,
                FeatureValidationAction.RESTORE_INSTALL,
                FeatureValidationAction.BACKUP_FALLBACK,
            ):
                if self._journal.operation_phase(action) in {
                    "intent_durable",
                    "dispatch_started",
                    "result_durable",
                }:
                    self._journal.require_restore(action)
                    break
            if self._journal.operation_phase(FeatureValidationAction.BACKUP_RETIRE) in {
                "intent_durable",
                "dispatch_started",
                "result_durable",
            }:
                self._journal.mark_ambiguous_state_neutral(
                    FeatureValidationAction.BACKUP_RETIRE
                )
            for action, predecessor, successor in (
                (
                    FeatureValidationAction.R64_RESTART,
                    FeatureValidationState.R64_CORE_CHECKED,
                    FeatureValidationState.R64_RESTART_CONSUMED,
                ),
                (
                    FeatureValidationAction.REMOVAL_RESTART,
                    FeatureValidationState.RESTORE_CORE_CHECKED,
                    FeatureValidationState.REMOVAL_RESTART_CONSUMED,
                ),
            ):
                if (
                    self._journal.state is predecessor
                    and self._journal.operation_phase(action) == "result_durable"
                    and self._journal.restart_outcome(action) is not None
                ):
                    self._journal.transition(successor, action)
            if self._journal.state in {
                FeatureValidationState.R64_BACKUP_VERIFIED,
                FeatureValidationState.R64_STAGED,
                FeatureValidationState.R64_INSTALLED,
                FeatureValidationState.R64_INVENTORY_VERIFIED,
                FeatureValidationState.R64_CORE_CHECKED,
                FeatureValidationState.R64_RESTART_CONSUMED,
                FeatureValidationState.R64_READY,
                FeatureValidationState.R64_POST_RESTART_INVENTORY_VERIFIED,
                FeatureValidationState.LIVE_VALIDATION_CONSUMED,
            }:
                self._journal.reconstruction_requires_restore()
        self._state = (
            self._journal.state
            if self._journal is not None
            else FeatureValidationState.BASELINE
        )
        self._lifecycle_generation = (
            self._journal.lifecycle_generation
            if self._journal is not None
            else object()
        )
        self._r64_source_generation = R64_RUNTIME_COMMIT
        self._restore_source_generation = PR41_RESTORE_COMMIT
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
        self._consumed = (
            set(self._journal.consumed_actions) if self._journal is not None else set()
        )
        self._r64_bundle: SourceBundle | None = None
        self._r64_manifest: SourceManifest | None = None
        self._restore_bundle: SourceBundle | None = None
        self._restore_manifest: SourceManifest | None = None
        self._restore_inventory: SourceInventoryResult | None = None
        self._restore_core_check: CoreCheckResult | None = None
        self._removal_restart: RestartResult | None = None
        self._restore_readiness: CoreReadinessResult | None = None
        self._feature_absence: FeatureAbsenceResult | None = None
        self._restore_repairs: RepairsEvidence | None = None
        self._live_result: RefreshStatusLiveValidationResult | None = None
        self._exact_pr41_source_proven = False
        self._feature_backup_classification: FeatureBackupClassification | None = None
        self._feature_backup_identity = (
            self._journal.backup_identity if self._journal is not None else None
        )
        if (
            self._journal is not None
            and type(broker) is PrivateInteractiveSessionBroker
        ):
            self._restore_broker_runtime_state()

    @property
    def state(self) -> FeatureValidationState:
        return self._journal.state if self._journal is not None else self._state

    def _restore_broker_runtime_state(self) -> None:
        if self.state in {
            FeatureValidationState.R64_INSTALLED,
            FeatureValidationState.R64_INVENTORY_VERIFIED,
            FeatureValidationState.R64_CORE_CHECKED,
            FeatureValidationState.R64_RESTART_CONSUMED,
            FeatureValidationState.R64_READY,
            FeatureValidationState.R64_POST_RESTART_INVENTORY_VERIFIED,
            FeatureValidationState.LIVE_VALIDATION_CONSUMED,
            FeatureValidationState.RESTORE_STAGED,
        }:
            self._broker._active_source_state = SourceState.R64_RUNTIME
        elif self.state in {
            FeatureValidationState.PR41_RESTORED,
            FeatureValidationState.RESTORE_INVENTORY_VERIFIED,
            FeatureValidationState.RESTORE_CORE_CHECKED,
            FeatureValidationState.REMOVAL_RESTART_CONSUMED,
            FeatureValidationState.PR41_READY,
            FeatureValidationState.FEATURE_ABSENCE_VERIFIED,
            FeatureValidationState.POST_RESTORE_REPAIRS_PASS,
        }:
            self._broker._active_source_state = SourceState.RESTORE
        elif (
            self.state is FeatureValidationState.RESTORE_REQUIRED
            and self._journal is not None
            and self._journal.source_classification is not None
        ):
            self._broker._active_source_state = {
                CurrentSourceClassification.EXACT_R64: SourceState.R64_RUNTIME,
                CurrentSourceClassification.EXACT_PR41: SourceState.RESTORE,
            }[self._journal.source_classification]
        if FeatureValidationAction.R64_RESTART in self._consumed:
            self._broker._restarted_states.add(SourceState.R64_RUNTIME)
        if FeatureValidationAction.REMOVAL_RESTART in self._consumed:
            self._broker._restarted_states.add(SourceState.RESTORE)

    def _assert_session(self) -> None:
        if (
            getattr(self._broker, "state", None) is not BrokerState.SESSION_ACTIVE
            or getattr(self._broker, "_session_generation", None)
            is not self._session_generation
        ):
            raise LifecycleControllerError("LIFECYCLE_SESSION_CHANGED") from None

    def _require(self, action: FeatureValidationAction) -> None:
        self._assert_session()
        if (
            action in self._consumed
            or self.state not in _FEATURE_ACTION_PREDECESSORS[action]
            or self._journal is not None
            and self._journal.reconstructed
            and action in self._FORWARD_ACTIONS
        ):
            raise LifecycleControllerError("FEATURE_TRANSITION_INVALID") from None

    def _begin(self, action: FeatureValidationAction) -> None:
        self._require(action)
        if self._journal is not None:
            self._journal.begin(action)
        self._consumed.add(action)

    def _mark(self, action: FeatureValidationAction, phase: str) -> None:
        if self._journal is not None:
            self._journal.mark(action, phase)

    def _advance(
        self, state: FeatureValidationState, action: FeatureValidationAction
    ) -> None:
        if self._journal is not None:
            self._journal.transition(state, action)
        self._state = state

    def _source_generation(self, action: FeatureValidationAction) -> object:
        if action in {
            FeatureValidationAction.RESTORE_TRANSFER,
            FeatureValidationAction.RESTORE_INSTALL,
            FeatureValidationAction.RESTORE_INVENTORY,
            FeatureValidationAction.RESTORE_CORE_CHECK,
            FeatureValidationAction.REMOVAL_RESTART,
            FeatureValidationAction.RESTORE_READINESS,
            FeatureValidationAction.FEATURE_ABSENCE,
            FeatureValidationAction.POST_RESTORE_REPAIRS,
            FeatureValidationAction.FINAL_ACCEPTANCE,
            FeatureValidationAction.BACKUP,
            FeatureValidationAction.INITIAL_SOURCE,
            FeatureValidationAction.INITIAL_REPAIRS,
        }:
            return self._restore_source_generation
        return self._r64_source_generation

    def _shared_capability(
        self, action: FeatureValidationAction
    ) -> _LifecycleCapability:
        capability = _LifecycleCapability(
            self,
            self._capability_issuer.identity,
            self._lifecycle_generation,
            self._source_generation(action),
            self._session_generation,
            _FEATURE_TO_LIFECYCLE_ACTION[action],
            secrets.token_hex(16),
        )
        self._capability_issuer.issued.append(capability)
        return capability

    def _dispatch_shared(
        self,
        action: FeatureValidationAction,
        callback: Callable[[_LifecycleCapability], Any],
    ) -> Any:
        self._begin(action)
        capability = self._shared_capability(action)
        self._mark(action, "dispatch_started")
        try:
            result = callback(capability)
        except BaseException:
            self._require_restoration(action)
            raise
        self._mark(action, "result_durable")
        return result

    def _dispatch_feature(
        self,
        action: FeatureValidationAction,
        callback: Callable[[_FeatureValidationCapability], Any],
    ) -> Any:
        self._begin(action)
        capability = _FeatureValidationCapability(
            self,
            self._capability_issuer.identity,
            self._lifecycle_generation,
            self._source_generation(action),
            self._session_generation,
            action,
            secrets.token_hex(16),
        )
        self._capability_issuer.issued.append(capability)
        self._mark(action, "dispatch_started")
        try:
            result = callback(capability)
        except BaseException:
            self._require_restoration(action)
            raise
        self._mark(action, "result_durable")
        return result

    def _require_restoration(self, action: FeatureValidationAction) -> None:
        if self._journal is not None:
            self._journal.require_restore(action)
        self._state = FeatureValidationState.RESTORE_REQUIRED

    @staticmethod
    def _repairs_pass(value: object) -> bool:
        return (
            isinstance(value, RepairsEvidence)
            and value.shape_valid is True
            and value.relevant_count == 0
            and value.critical_count == 0
            and _exact_non_bool_int(value.relevant_count)
            and _exact_non_bool_int(value.critical_count)
        )

    @staticmethod
    def _bundle_pass(value: object, count: int) -> bool:
        if isinstance(value, TransferResult):
            return (
                value.success is True
                and value.file_count == count
                and value.manifest_match is True
                and value.regular_files_only is True
            )
        if isinstance(value, InstallResult):
            return (
                value.installation_success is True
                and value.expected_file_count == count
                and value.installed_file_count == count
                and value.manifest_match is True
            )
        return False

    @staticmethod
    def _core_pass(value: object) -> bool:
        return (
            isinstance(value, CoreCheckResult)
            and value.attempt_ordinal == 1
            and type(value.http_status) is int
            and 200 <= value.http_status <= 299
            and value.result == "ok"
            and value.check_passed is True
            and value.error_class is None
        )

    @staticmethod
    def _readiness_pass(value: object) -> bool:
        return (
            isinstance(value, CoreReadinessResult)
            and value.core_reachable is True
            and value.core_running is True
            and value.integration_loaded is True
            and value.timed_out is False
        )

    def inspect_initial_source(
        self, r64_manifest: SourceManifest, restore_manifest: SourceManifest
    ) -> CurrentSourceInventoryResult:
        self._begin(FeatureValidationAction.INITIAL_SOURCE)
        capability = _SourceInspectionCapability(
            self,
            self._capability_issuer.identity,
            self._session_generation,
            secrets.token_hex(16),
        )
        self._capability_issuer.issued.append(capability)
        self._mark(FeatureValidationAction.INITIAL_SOURCE, "dispatch_started")
        try:
            result = self._broker._inspect_current_source(
                r64_manifest, restore_manifest, _capability=capability
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._require_restoration(FeatureValidationAction.INITIAL_SOURCE)
            raise LifecycleControllerError("INITIAL_SOURCE_NOT_EXACT_PR41") from None
        if result.classification is not CurrentSourceClassification.EXACT_PR41:
            self._require_restoration(FeatureValidationAction.INITIAL_SOURCE)
            raise LifecycleControllerError("INITIAL_SOURCE_NOT_EXACT_PR41") from None
        self._mark(FeatureValidationAction.INITIAL_SOURCE, "result_durable")
        self._r64_manifest = r64_manifest
        self._restore_manifest = restore_manifest
        self._advance(
            FeatureValidationState.INITIAL_SOURCE_VERIFIED,
            FeatureValidationAction.INITIAL_SOURCE,
        )
        return result

    def admit_initial_repairs(self) -> RepairsEvidence:
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.INITIAL_REPAIRS,
                lambda capability: self._broker._collect_resolution_info(
                    RepairsGate.INITIAL, _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            raise LifecycleControllerError("INITIAL_REPAIRS_ADMISSION_FAILED") from None
        if not self._repairs_pass(result):
            self._require_restoration(FeatureValidationAction.INITIAL_REPAIRS)
            raise LifecycleControllerError("INITIAL_REPAIRS_ADMISSION_FAILED") from None
        self._advance(
            FeatureValidationState.INITIAL_REPAIRS_PASS,
            FeatureValidationAction.INITIAL_REPAIRS,
        )
        return result

    def create_backup(self, manifest: SourceManifest) -> BackupResult:
        if (
            manifest != self._restore_manifest
            or manifest.state is not SourceState.RESTORE
        ):
            raise LifecycleControllerError("BACKUP_VERIFICATION_FAILED") from None
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.BACKUP,
                lambda capability: self._broker._create_private_backup(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError("BACKUP_VERIFICATION_FAILED") from None
        if not (
            isinstance(result, BackupResult)
            and result.success is True
            and result.file_count == len(manifest.entries)
            and result.manifest_match is True
            and result.regular_files_only is True
            and result.lifecycle_generation == str(self._lifecycle_generation)
            and result.source_generation == str(self._restore_source_generation)
            and result.manifest_identity == _source_manifest_digest(manifest.entries)
            and re.fullmatch(r"[0-9a-f]{32}", result.backup_generation)
            and re.fullmatch(r"[0-9a-f]{64}", result.backup_digest)
        ):
            self._require_restoration(FeatureValidationAction.BACKUP)
            raise LifecycleControllerError("BACKUP_VERIFICATION_FAILED") from None
        if self._journal is not None:
            self._journal.bind_backup(result)
        self._feature_backup_identity = {
            "lifecycle_generation": result.lifecycle_generation,
            "source_generation": result.source_generation,
            "backup_generation": result.backup_generation,
            "manifest_identity": result.manifest_identity,
            "backup_digest": result.backup_digest,
        }
        self._advance(
            FeatureValidationState.R64_BACKUP_VERIFIED,
            FeatureValidationAction.BACKUP,
        )
        return result

    def stage_r64(self, bundle: SourceBundle) -> TransferResult:
        if bundle.state is not SourceState.R64_RUNTIME:
            raise LifecycleControllerError("R64_BUNDLE_INVALID") from None
        validate_source_bundle(bundle)
        result = self._dispatch_shared(
            FeatureValidationAction.R64_TRANSFER,
            lambda capability: self._broker._transfer_source_bundle(
                bundle, _capability=capability
            ),
        )
        if not self._bundle_pass(result, len(bundle.files)):
            self._require_restoration(FeatureValidationAction.R64_TRANSFER)
            raise LifecycleControllerError("R64_TRANSFER_FAILED") from None
        self._r64_bundle = bundle
        self._r64_manifest = bundle.manifest
        self._advance(
            FeatureValidationState.R64_STAGED, FeatureValidationAction.R64_TRANSFER
        )
        return result

    def install_r64(self, manifest: SourceManifest) -> InstallResult:
        if (
            manifest != self._r64_manifest
            or manifest.state is not SourceState.R64_RUNTIME
        ):
            raise LifecycleControllerError("R64_MANIFEST_INVALID") from None
        result = self._dispatch_shared(
            FeatureValidationAction.R64_INSTALL,
            lambda capability: self._broker._install_staged_source(
                manifest, _capability=capability
            ),
        )
        if not self._bundle_pass(result, len(manifest.entries)):
            self._require_restoration(FeatureValidationAction.R64_INSTALL)
            raise LifecycleControllerError("R64_INSTALL_FAILED") from None
        self._advance(
            FeatureValidationState.R64_INSTALLED, FeatureValidationAction.R64_INSTALL
        )
        return result

    def verify_r64_inventory(self, manifest: SourceManifest) -> SourceInventoryResult:
        if manifest != self._r64_manifest:
            raise LifecycleControllerError("R64_MANIFEST_INVALID") from None
        action = (
            FeatureValidationAction.R64_INVENTORY
            if self.state is FeatureValidationState.R64_INSTALLED
            else FeatureValidationAction.R64_POST_RESTART_INVENTORY
        )
        result = self._dispatch_shared(
            action,
            lambda capability: self._broker._verify_source_inventory(
                manifest, _capability=capability
            ),
        )
        if not _source_inventory_exact(result, len(manifest.entries)):
            self._require_restoration(action)
            raise LifecycleControllerError("R64_INVENTORY_FAILED") from None
        target = (
            FeatureValidationState.R64_INVENTORY_VERIFIED
            if action is FeatureValidationAction.R64_INVENTORY
            else FeatureValidationState.R64_POST_RESTART_INVENTORY_VERIFIED
        )
        self._advance(target, action)
        return result

    def check_r64_core(self) -> CoreCheckResult:
        result = self._dispatch_shared(
            FeatureValidationAction.R64_CORE_CHECK,
            lambda capability: self._broker._check_core(1, _capability=capability),
        )
        if not self._core_pass(result):
            self._require_restoration(FeatureValidationAction.R64_CORE_CHECK)
            raise LifecycleControllerError("R64_CORE_CHECK_FAILED") from None
        self._advance(
            FeatureValidationState.R64_CORE_CHECKED,
            FeatureValidationAction.R64_CORE_CHECK,
        )
        return result

    def restart_for_r64(self) -> RestartResult:
        result = self._dispatch_shared(
            FeatureValidationAction.R64_RESTART,
            lambda capability: self._broker._restart_core(_capability=capability),
        )
        if not isinstance(result, RestartResult) or result.dispatch_outcome not in {
            RestartDispatchOutcome.RESPONSE_ACCEPTED,
            RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
        }:
            self._require_restoration(FeatureValidationAction.R64_RESTART)
            raise LifecycleControllerError("R64_RESTART_FAILED") from None
        if self._journal is not None:
            self._journal.record_restart(FeatureValidationAction.R64_RESTART, result)
        self._advance(
            FeatureValidationState.R64_RESTART_CONSUMED,
            FeatureValidationAction.R64_RESTART,
        )
        return result

    def await_r64_readiness(self) -> CoreReadinessResult:
        result = self._dispatch_shared(
            FeatureValidationAction.R64_READINESS,
            lambda capability: self._broker._wait_for_core_readiness(
                _capability=capability
            ),
        )
        if not self._readiness_pass(result):
            self._require_restoration(FeatureValidationAction.R64_READINESS)
            raise LifecycleControllerError("R64_READINESS_FAILED") from None
        self._advance(
            FeatureValidationState.R64_READY, FeatureValidationAction.R64_READINESS
        )
        return result

    def run_s1_refresh_status_live_validation(
        self,
    ) -> RefreshStatusLiveValidationResult:
        try:
            result = self._dispatch_feature(
                FeatureValidationAction.LIVE_VALIDATION,
                lambda capability: self._broker._run_s1_refresh_status_live_validation(
                    _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            zero = RefreshPacketCounts(0, 0, 0, 0, 0)
            result = RefreshStatusLiveValidationResult(
                0,
                False,
                False,
                False,
                False,
                False,
                RefreshPressResult(False, zero, None, False),
                RefreshPressResult(False, zero, None, False),
                False,
                RefreshHoldResult(False, False, False),
                True,
                RefreshStatusFailureClass.AMBIGUOUS,
                False,
            )
            self._live_result = result
            return result
        if not isinstance(result, RefreshStatusLiveValidationResult):
            self._require_restoration(FeatureValidationAction.LIVE_VALIDATION)
            raise LifecycleControllerError("LIVE_VALIDATION_RESULT_INVALID") from None
        self._live_result = result
        self._advance(
            FeatureValidationState.LIVE_VALIDATION_CONSUMED,
            FeatureValidationAction.LIVE_VALIDATION,
        )
        return result

    def stage_restore(self, bundle: SourceBundle) -> TransferResult:
        if bundle.state is not SourceState.RESTORE:
            raise LifecycleControllerError("RESTORE_BUNDLE_INVALID") from None
        if (
            self._journal is not None
            and self._journal.reconstructed
            and self.state is FeatureValidationState.RESTORE_REQUIRED
            and self._journal.source_classification is None
        ):
            raise LifecycleControllerError(
                "FEATURE_SOURCE_RECONCILIATION_REQUIRED"
            ) from None
        validate_source_bundle(bundle)
        result = self._dispatch_shared(
            FeatureValidationAction.RESTORE_TRANSFER,
            lambda capability: self._broker._transfer_source_bundle(
                bundle, _capability=capability
            ),
        )
        if not self._bundle_pass(result, len(bundle.files)):
            self._require_restoration(FeatureValidationAction.RESTORE_TRANSFER)
            raise LifecycleControllerError(
                "LIFECYCLE_RESTORE_RECONCILIATION_REQUIRED"
            ) from None
        self._restore_bundle = bundle
        self._restore_manifest = bundle.manifest
        self._advance(
            FeatureValidationState.RESTORE_STAGED,
            FeatureValidationAction.RESTORE_TRANSFER,
        )
        return result

    def reconcile_interrupted_source(
        self, r64_manifest: SourceManifest, restore_manifest: SourceManifest
    ) -> CurrentSourceInventoryResult:
        """Classify installed source before resuming or cleaning restoration."""
        if (
            r64_manifest.state is not SourceState.R64_RUNTIME
            or restore_manifest.state is not SourceState.RESTORE
        ):
            raise LifecycleControllerError(
                "FEATURE_SOURCE_RECONCILIATION_FAILED"
            ) from None
        validate_source_manifest(r64_manifest)
        validate_source_manifest(restore_manifest)
        self._assert_session()
        starting_state = self.state
        if starting_state not in {
            FeatureValidationState.RESTORE_REQUIRED,
            *_FEATURE_RESTORE_SIDE_STATES,
        }:
            raise LifecycleControllerError(
                "FEATURE_SOURCE_RECONCILIATION_FAILED"
            ) from None
        self._exact_pr41_source_proven = False
        capability = _SourceInspectionCapability(
            self,
            self._capability_issuer.identity,
            self._session_generation,
            secrets.token_hex(16),
        )
        self._capability_issuer.issued.append(capability)
        try:
            result = self._broker._inspect_current_source(
                r64_manifest, restore_manifest, _capability=capability
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError(
                "FEATURE_SOURCE_RECONCILIATION_FAILED"
            ) from None
        if (
            not isinstance(result, CurrentSourceInventoryResult)
            or result.classification
            not in {
                CurrentSourceClassification.EXACT_PR41,
                CurrentSourceClassification.EXACT_R64,
            }
            or (
                result.classification is CurrentSourceClassification.EXACT_PR41
                and not _feature_restore_inventory_exact(
                    result.evidence, restore_manifest
                )
            )
            or (
                starting_state in _FEATURE_RESTORE_SIDE_STATES
                and result.classification is not CurrentSourceClassification.EXACT_PR41
            )
        ):
            raise LifecycleControllerError(
                "FEATURE_SOURCE_RECONCILIATION_FAILED"
            ) from None
        self._r64_manifest = r64_manifest
        self._restore_manifest = restore_manifest
        target = starting_state
        if starting_state is FeatureValidationState.RESTORE_REQUIRED:
            target = (
                FeatureValidationState.PR41_RESTORED
                if result.classification is CurrentSourceClassification.EXACT_PR41
                else FeatureValidationState.RESTORE_REQUIRED
            )
        if (
            self._journal is not None
            and starting_state is FeatureValidationState.RESTORE_REQUIRED
        ):
            self._journal.record_source_reconciliation(result.classification)
        self._state = target
        self._exact_pr41_source_proven = (
            result.classification is CurrentSourceClassification.EXACT_PR41
        )
        if type(self._broker) is PrivateInteractiveSessionBroker:
            self._broker._active_source_state = (
                SourceState.RESTORE
                if result.classification is CurrentSourceClassification.EXACT_PR41
                else SourceState.R64_RUNTIME
            )
        return result

    def _feature_backup_capability(
        self, action: FeatureBackupAction
    ) -> _FeatureBackupContinuityCapability:
        capability = _FeatureBackupContinuityCapability(
            self,
            self._capability_issuer.identity,
            self._lifecycle_generation,
            self._restore_source_generation,
            self._session_generation,
            secrets.token_hex(16),
            action,
            self._feature_backup_identity,
            (
                self._journal is not None
                and self._journal.committed(FeatureValidationAction.RESTORE_INSTALL)
            ),
        )
        self._capability_issuer.issued.append(capability)
        return capability

    def _bind_feature_restore_manifest(self, manifest: SourceManifest) -> None:
        if not isinstance(manifest, SourceManifest):
            raise LifecycleControllerError("FEATURE_BACKUP_CONTINUITY_FAILED") from None
        try:
            validate_source_manifest(manifest)
        except SourceBundleError:
            raise LifecycleControllerError("FEATURE_BACKUP_CONTINUITY_FAILED") from None
        if (
            manifest.state is not SourceState.RESTORE
            or self.state not in _FEATURE_RESTORE_SIDE_STATES
            or self._restore_manifest is not None
            and manifest != self._restore_manifest
        ):
            raise LifecycleControllerError("FEATURE_BACKUP_CONTINUITY_FAILED") from None
        self._restore_manifest = manifest

    def inspect_feature_backup(
        self, manifest: SourceManifest
    ) -> FeatureBackupContinuityResult:
        """Classify the fixed feature backup without consuming a mutation."""
        self._assert_session()
        self._bind_feature_restore_manifest(manifest)
        capability = self._feature_backup_capability(FeatureBackupAction.INSPECT)
        try:
            result = self._broker._feature_backup_continuity_operation(
                manifest,
                FeatureBackupAction.INSPECT,
                _capability=capability,
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._feature_backup_classification = (
                FeatureBackupClassification.OTHER_OR_INDETERMINATE
            )
            raise LifecycleControllerError("FEATURE_BACKUP_CONTINUITY_FAILED") from None
        if not isinstance(result, FeatureBackupContinuityResult) or result.retired:
            self._feature_backup_classification = (
                FeatureBackupClassification.OTHER_OR_INDETERMINATE
            )
            raise LifecycleControllerError("FEATURE_BACKUP_CONTINUITY_FAILED") from None
        self._feature_backup_classification = result.classification
        if (
            result.classification is FeatureBackupClassification.NONE
            and self._journal is not None
            and self._journal.operation_phase(FeatureValidationAction.BACKUP_RETIRE)
            == "ambiguous"
        ):
            self._journal.reconcile_state_neutral_ambiguity(
                FeatureValidationAction.BACKUP_RETIRE
            )
        return result

    def reconcile_feature_backup_creation(
        self, manifest: SourceManifest
    ) -> FeatureBackupContinuityResult:
        """Adopt an exact existing package without replaying backup creation."""
        self._assert_session()
        self._bind_feature_restore_manifest(manifest)
        if (
            not self._exact_pr41_source_proven
            or self._feature_backup_classification
            is not FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
            or self._journal is None
            or self._feature_backup_identity is not None
            or self._journal.operation_phase(FeatureValidationAction.BACKUP)
            != "ambiguous"
        ):
            raise LifecycleControllerError(
                "FEATURE_BACKUP_RECONCILIATION_FAILED"
            ) from None
        capability = _LifecycleCapability(
            self,
            self._capability_issuer.identity,
            self._lifecycle_generation,
            self._restore_source_generation,
            self._session_generation,
            LifecycleAction.BACKUP_RECONCILE,
            secrets.token_hex(16),
        )
        self._capability_issuer.issued.append(capability)
        try:
            result = self._broker._reconcile_private_backup_creation(
                manifest, _capability=capability
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError(
                "FEATURE_BACKUP_RECONCILIATION_FAILED"
            ) from None
        if not (
            isinstance(result, BackupResult)
            and result.success is True
            and result.file_count == len(manifest.entries)
            and result.manifest_match is True
            and result.regular_files_only is True
            and result.lifecycle_generation == str(self._lifecycle_generation)
            and result.source_generation == str(self._restore_source_generation)
            and result.manifest_identity == _source_manifest_digest(manifest.entries)
            and re.fullmatch(r"[0-9a-f]{32}", result.backup_generation)
            and re.fullmatch(r"[0-9a-f]{64}", result.backup_digest)
        ):
            raise LifecycleControllerError(
                "FEATURE_BACKUP_RECONCILIATION_FAILED"
            ) from None
        self._journal.reconcile_backup_creation(result)
        self._feature_backup_identity = self._journal.backup_identity
        return FeatureBackupContinuityResult(
            FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
        )

    def retire_owned_feature_backup(
        self, manifest: SourceManifest
    ) -> FeatureBackupContinuityResult:
        """Consume at most one exact-owner retirement dispatch."""
        self._assert_session()
        self._bind_feature_restore_manifest(manifest)
        if (
            not self._exact_pr41_source_proven
            or self._feature_backup_classification
            is not FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
            or type(self._feature_backup_identity) is not dict
        ):
            raise LifecycleControllerError(
                "FEATURE_BACKUP_RETIREMENT_NOT_AUTHORIZED"
            ) from None
        action = FeatureValidationAction.BACKUP_RETIRE
        self._begin(action)
        capability = self._feature_backup_capability(FeatureBackupAction.RETIRE)
        self._mark(action, "dispatch_started")
        try:
            result = self._broker._feature_backup_continuity_operation(
                manifest,
                FeatureBackupAction.RETIRE,
                _capability=capability,
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._feature_backup_classification = None
            if self._journal is not None:
                self._journal.mark_ambiguous_state_neutral(action)
            raise LifecycleControllerError(
                "FEATURE_BACKUP_RETIREMENT_AMBIGUOUS"
            ) from None
        self._mark(action, "result_durable")
        if not (
            isinstance(result, FeatureBackupContinuityResult)
            and result.classification is FeatureBackupClassification.NONE
            and result.retired is True
        ):
            self._feature_backup_classification = None
            if self._journal is not None:
                self._journal.mark_ambiguous_state_neutral(action)
            raise LifecycleControllerError(
                "FEATURE_BACKUP_RETIREMENT_AMBIGUOUS"
            ) from None
        if self._journal is not None:
            self._journal.commit_state_neutral(action)
        self._feature_backup_classification = None
        return result

    def restore_private_backup_fallback(
        self, manifest: SourceManifest
    ) -> InstallResult:
        """Use the exact bound PR41 backup after an ambiguous restore mutation."""
        if (
            manifest.state is not SourceState.RESTORE
            or self._journal is None
            or self._journal.source_classification
            is not CurrentSourceClassification.EXACT_R64
        ):
            raise LifecycleControllerError("LIFECYCLE_RESTORE_FAILED") from None
        validate_source_manifest(manifest)
        self._restore_manifest = manifest
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.BACKUP_FALLBACK,
                lambda capability: self._broker._restore_private_backup(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError(
                "LIFECYCLE_RESTORE_RECONCILIATION_REQUIRED"
            ) from None
        if not self._bundle_pass(result, len(manifest.entries)):
            self._require_restoration(FeatureValidationAction.BACKUP_FALLBACK)
            raise LifecycleControllerError(
                "LIFECYCLE_RESTORE_RECONCILIATION_REQUIRED"
            ) from None
        self._advance(
            FeatureValidationState.PR41_RESTORED,
            FeatureValidationAction.BACKUP_FALLBACK,
        )
        return result

    def reconcile_private_backup_fallback(
        self, manifest: SourceManifest
    ) -> FallbackReconciliationResult:
        """Resolve an interrupted fallback without replaying its mutation."""
        if (
            manifest.state is not SourceState.RESTORE
            or self._journal is None
            or FeatureValidationAction.BACKUP_FALLBACK
            not in self._journal.consumed_actions
            or self._journal.operation_phase(FeatureValidationAction.BACKUP_FALLBACK)
            != "ambiguous"
        ):
            raise LifecycleControllerError("LIFECYCLE_RESTORE_FAILED") from None
        validate_source_manifest(manifest)
        self._restore_manifest = manifest
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.BACKUP_FALLBACK_RECONCILE,
                lambda capability: self._broker._reconcile_private_backup(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._restore_failed()
        valid = (
            isinstance(result, FallbackReconciliationResult)
            and result.phase == "reconciled"
            and result.restoration_applied is True
            and result.manifest_match is True
            and result.file_count == len(manifest.entries)
        )
        if not valid:
            self._restore_failed()
        self._advance(
            FeatureValidationState.PR41_RESTORED,
            FeatureValidationAction.BACKUP_FALLBACK_RECONCILE,
        )
        return result

    def _restore_failed(self) -> Never:
        self._state = FeatureValidationState.RESTORE_FAILED
        if self._journal is not None:
            self._journal.terminal(FeatureValidationState.RESTORE_FAILED)
            self._journal.close()
        raise LifecycleControllerError("LIFECYCLE_RESTORE_FAILED") from None

    def restore_pr41(self, manifest: SourceManifest) -> InstallResult:
        if (
            not isinstance(manifest, SourceManifest)
            or manifest.state is not SourceState.RESTORE
        ):
            raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
        try:
            validate_source_manifest(manifest)
        except SourceBundleError:
            raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
        if (
            self._restore_manifest is None
            and self.state is FeatureValidationState.RESTORE_STAGED
        ):
            self._restore_manifest = manifest
        if manifest != self._restore_manifest:
            raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.RESTORE_INSTALL,
                lambda capability: self._broker._install_staged_restore(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            raise LifecycleControllerError(
                "LIFECYCLE_RESTORE_RECONCILIATION_REQUIRED"
            ) from None
        if not self._bundle_pass(result, len(manifest.entries)):
            self._require_restoration(FeatureValidationAction.RESTORE_INSTALL)
            raise LifecycleControllerError(
                "LIFECYCLE_RESTORE_RECONCILIATION_REQUIRED"
            ) from None
        self._advance(
            FeatureValidationState.PR41_RESTORED,
            FeatureValidationAction.RESTORE_INSTALL,
        )
        return result

    def verify_restore_inventory(
        self, manifest: SourceManifest
    ) -> SourceInventoryResult:
        if (
            self._restore_manifest is None
            and self.state is FeatureValidationState.PR41_RESTORED
        ):
            try:
                validate_source_manifest(manifest)
            except SourceBundleError:
                raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
            self._restore_manifest = manifest
        if manifest != self._restore_manifest:
            raise LifecycleControllerError("RESTORE_MANIFEST_INVALID") from None
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.RESTORE_INVENTORY,
                lambda capability: self._broker._verify_source_inventory(
                    manifest, _capability=capability
                ),
            )
        except (SessionBrokerError, SourceBundleError, TypeError, ValueError):
            self._restore_failed()
        if not _source_inventory_exact(result, len(manifest.entries)):
            self._restore_failed()
        self._restore_inventory = result
        self._advance(
            FeatureValidationState.RESTORE_INVENTORY_VERIFIED,
            FeatureValidationAction.RESTORE_INVENTORY,
        )
        return result

    def check_restore_core(self) -> CoreCheckResult:
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.RESTORE_CORE_CHECK,
                lambda capability: self._broker._check_core(1, _capability=capability),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._restore_failed()
        if not self._core_pass(result):
            self._restore_failed()
        self._restore_core_check = result
        self._advance(
            FeatureValidationState.RESTORE_CORE_CHECKED,
            FeatureValidationAction.RESTORE_CORE_CHECK,
        )
        return result

    def restart_for_restore(self) -> RestartResult:
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.REMOVAL_RESTART,
                lambda capability: self._broker._restart_core(_capability=capability),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._restore_failed()
        if not isinstance(result, RestartResult) or result.dispatch_outcome not in {
            RestartDispatchOutcome.RESPONSE_ACCEPTED,
            RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
        }:
            self._restore_failed()
        self._removal_restart = result
        if self._journal is not None:
            self._journal.record_restart(
                FeatureValidationAction.REMOVAL_RESTART, result
            )
        self._advance(
            FeatureValidationState.REMOVAL_RESTART_CONSUMED,
            FeatureValidationAction.REMOVAL_RESTART,
        )
        return result

    def await_restore_readiness(self) -> CoreReadinessResult:
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.RESTORE_READINESS,
                lambda capability: self._broker._wait_for_core_readiness(
                    _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._restore_failed()
        if not self._readiness_pass(result):
            self._restore_failed()
        self._restore_readiness = result
        self._advance(
            FeatureValidationState.PR41_READY,
            FeatureValidationAction.RESTORE_READINESS,
        )
        return result

    def verify_refresh_feature_absent(self) -> FeatureAbsenceResult:
        try:
            result = self._dispatch_feature(
                FeatureValidationAction.FEATURE_ABSENCE,
                lambda capability: self._broker._verify_refresh_feature_absent(
                    _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._restore_failed()
        if not isinstance(result, FeatureAbsenceResult) or result.refresh_button_active:
            self._restore_failed()
        self._feature_absence = result
        self._advance(
            FeatureValidationState.FEATURE_ABSENCE_VERIFIED,
            FeatureValidationAction.FEATURE_ABSENCE,
        )
        return result

    def admit_post_restore_repairs(self) -> RepairsEvidence:
        try:
            result = self._dispatch_shared(
                FeatureValidationAction.POST_RESTORE_REPAIRS,
                lambda capability: self._broker._collect_resolution_info(
                    RepairsGate.POST_ROLLBACK, _capability=capability
                ),
            )
        except (SessionBrokerError, TypeError, ValueError):
            self._restore_failed()
        if not self._repairs_pass(result):
            self._restore_failed()
        self._restore_repairs = result
        self._advance(
            FeatureValidationState.POST_RESTORE_REPAIRS_PASS,
            FeatureValidationAction.POST_RESTORE_REPAIRS,
        )
        return result

    def _final_proof(self) -> FinalRestoreProof:
        def committed(action: FeatureValidationAction) -> bool:
            return self._journal is not None and self._journal.committed(action)

        restart = self._removal_restart
        if restart is None and self._journal is not None:
            outcome = self._journal.restart_outcome(
                FeatureValidationAction.REMOVAL_RESTART
            )
            if outcome is not None:
                restart = RestartResult(outcome, None, None)
        restart_acceptable = isinstance(restart, RestartResult) and (
            restart.dispatch_outcome
            in {
                RestartDispatchOutcome.RESPONSE_ACCEPTED,
                RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
            }
        )
        inventory_exact = committed(FeatureValidationAction.RESTORE_INVENTORY) or (
            self._restore_inventory is not None
            and self._restore_manifest is not None
            and _source_inventory_exact(
                self._restore_inventory, len(self._restore_manifest.entries)
            )
        )
        readiness = self._restore_readiness
        repairs = self._restore_repairs
        return FinalRestoreProof(
            inventory_exact,
            inventory_exact,
            committed(FeatureValidationAction.RESTORE_CORE_CHECK)
            or self._core_pass(self._restore_core_check),
            FeatureValidationAction.REMOVAL_RESTART in self._consumed,
            restart_acceptable,
            restart_acceptable
            and (
                committed(FeatureValidationAction.RESTORE_READINESS)
                or self._readiness_pass(readiness)
            ),
            committed(FeatureValidationAction.RESTORE_READINESS)
            or readiness is not None
            and readiness.core_reachable is True,
            committed(FeatureValidationAction.RESTORE_READINESS)
            or readiness is not None
            and readiness.core_running is True,
            committed(FeatureValidationAction.RESTORE_READINESS)
            or readiness is not None
            and readiness.integration_loaded is True,
            committed(FeatureValidationAction.RESTORE_READINESS)
            or readiness is not None
            and readiness.timed_out is False,
            committed(FeatureValidationAction.FEATURE_ABSENCE)
            or self._feature_absence == FeatureAbsenceResult(False),
            committed(FeatureValidationAction.POST_RESTORE_REPAIRS)
            or repairs is not None
            and repairs.shape_valid is True,
            committed(FeatureValidationAction.POST_RESTORE_REPAIRS)
            or repairs is not None
            and repairs.relevant_count == 0,
            committed(FeatureValidationAction.POST_RESTORE_REPAIRS)
            or repairs is not None
            and repairs.critical_count == 0,
        )

    def complete(self) -> FinalRestoreProof:
        action = FeatureValidationAction.FINAL_ACCEPTANCE
        if (
            not self._exact_pr41_source_proven
            or self._feature_backup_classification
            is not FeatureBackupClassification.NONE
            or self._journal is not None
            and self._journal.operation_phase(FeatureValidationAction.BACKUP_RETIRE)
            not in {None, "transition_committed"}
        ):
            raise LifecycleControllerError(
                "FEATURE_BACKUP_CONTINUITY_REQUIRED"
            ) from None
        self._begin(action)
        proof = self._final_proof()
        self._mark(action, "dispatch_started")
        self._mark(action, "result_durable")
        if not proof.complete:
            self._restore_failed()
        self._advance(FeatureValidationState.COMPLETE_NORMAL, action)
        if self._journal is not None:
            self._journal.terminal(FeatureValidationState.COMPLETE_NORMAL)
            self._journal.close()
        return proof

    def close(self) -> None:
        if self._journal is not None:
            self._journal.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


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
