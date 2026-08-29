"""Sanitized local HTTP helper for the temporary Issue-37 research services.

This module is deliberately repository-owned so the BLE-free preflight and
real probe use the same request, REST-wrapper extraction, response validation,
and evidence-writing path. It contains no binding lookup, token, target, or
device identifier storage.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any

_NONCE_RE = re.compile(r"[0-9a-f]{16,32}\Z")
_MAX_EVENTS = 64


class HelperOperation(str, Enum):
    """The only response-capable temporary research operations."""

    PREFLIGHT = "preflight"
    PROBE = "probe"
    RECEIPT = "receipt"
    AUDIT = "audit"


class HelperExit(IntEnum):
    """Non-overlapping local helper terminal classes."""

    SUCCESS = 0
    DEFINITELY_NOT_SUBMITTED = 65
    SERVICE_REJECTED = 66
    SCHEMA_PRIVACY_FAILURE = 67
    AMBIGUOUS_POST_SUBMISSION = 78


@dataclass(frozen=True)
class HelperResult:
    """A JSON-safe terminal helper result, with no raw HTTP wrapper retained."""

    exit_code: HelperExit
    outcome: str
    response: dict[str, Any] | None = None
    nonce: str | None = None


def generate_nonce() -> str:
    """Generate a 32-character opaque correlation value before HTTP submission."""
    return secrets.token_hex(16)


def _nonce(value: object) -> str:
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise ValueError("nonce")
    return value


def _nonnegative_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("integer")
    return value


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("text")
    return value


def _clean_event(value: object) -> dict[str, Any]:
    """Allow the real optional observer fields that C01's helper rejected."""
    keys = {
        "trial",
        "observation_ordinal",
        "origin",
        "kind",
        "event_ordinal",
        "batch_ordinal",
        "dp_ids",
        "dp_types",
        "encoded_value_lengths",
        "exact_session",
        "ack_result",
        "ack_phase",
        "monotonic_ms",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("event_shape")
    for key in ("trial", "observation_ordinal", "event_ordinal", "monotonic_ms"):
        _nonnegative_int(value[key])
    if value["batch_ordinal"] is not None:
        _nonnegative_int(value["batch_ordinal"])
    if not all(
        isinstance(value[key], str) and len(value[key]) <= 64
        for key in ("origin", "kind")
    ):
        raise ValueError("event_text")
    if not isinstance(value["exact_session"], bool):
        raise TypeError("event_session")
    _optional_text(value["ack_result"])
    _optional_text(value["ack_phase"])
    for key in ("dp_ids", "encoded_value_lengths"):
        if (
            not isinstance(value[key], list)
            or len(value[key]) > _MAX_EVENTS
            or any(_nonnegative_int(item) != item for item in value[key])
        ):
            raise ValueError("event_numbers")
    if (
        not isinstance(value["dp_types"], list)
        or len(value["dp_types"]) > _MAX_EVENTS
        or not all(
            isinstance(item, str) and len(item) <= 32 for item in value["dp_types"]
        )
    ):
        raise ValueError("event_types")
    return {
        key: value[key]
        for key in (
            "trial",
            "observation_ordinal",
            "origin",
            "kind",
            "event_ordinal",
            "batch_ordinal",
            "dp_ids",
            "dp_types",
            "encoded_value_lengths",
            "exact_session",
            "ack_result",
            "ack_phase",
            "monotonic_ms",
        )
    }


def _clean_request(value: object) -> dict[str, Any]:
    keys = {"trial", "result", "duration_ms"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("request_shape")
    if value["trial"] not in {1, 2} or not isinstance(value["result"], str):
        raise ValueError("request_values")
    _nonnegative_int(value["duration_ms"])
    return {key: value[key] for key in ("trial", "result", "duration_ms")}


def _clean_probe_response(value: object) -> dict[str, Any]:
    keys = {
        "mode",
        "result",
        "cold_request_attempted",
        "retained_request_attempted",
        "request_count",
        "same_session_retained",
        "normal_release_observed",
        "automatic_reconnect_observed",
        "observation_overflow",
        "duration_ms",
        "requests",
        "events",
        "invocation_nonce",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("probe_shape")
    if value["mode"] not in {"cold", "cold_then_retained"} or value["result"] not in {
        "completed",
        "invalid_or_incomplete",
        "invalid_input",
        "precondition_failed",
        "probe_already_active",
        "duplicate_nonce",
        "nonce_capacity_reached",
        "observation_overflow",
        "known_service_error",
        "service_error",
    }:
        raise ValueError("probe_result")
    _nonce(value["invocation_nonce"])
    _nonnegative_int(value["request_count"])
    _nonnegative_int(value["duration_ms"])
    if value["request_count"] > 2 or not all(
        isinstance(value[key], bool)
        for key in (
            "cold_request_attempted",
            "retained_request_attempted",
            "same_session_retained",
            "normal_release_observed",
            "automatic_reconnect_observed",
            "observation_overflow",
        )
    ):
        raise ValueError("probe_flags")
    if (
        not isinstance(value["requests"], list)
        or not isinstance(value["events"], list)
        or len(value["requests"]) > 2
        or len(value["events"]) > _MAX_EVENTS
    ):
        raise ValueError("probe_lists")
    return {
        **{
            key: value[key]
            for key in (
                "mode",
                "result",
                "cold_request_attempted",
                "retained_request_attempted",
                "request_count",
                "same_session_retained",
                "normal_release_observed",
                "automatic_reconnect_observed",
                "observation_overflow",
                "duration_ms",
                "invocation_nonce",
            )
        },
        "requests": [_clean_request(item) for item in value["requests"]],
        "events": [_clean_event(item) for item in value["events"]],
    }


def _clean_preflight_response(value: object) -> dict[str, Any]:
    required = {"result", "protocol_version"}
    if not isinstance(value, dict) or set(value) not in (
        required,
        required | {"nonce"},
    ):
        raise ValueError("preflight_shape")
    if value["result"] != "preflight_ok" or value["protocol_version"] != 1:
        raise ValueError("preflight_result")
    response: dict[str, Any] = {"result": "preflight_ok", "protocol_version": 1}
    if "nonce" in value:
        response["nonce"] = _nonce(value["nonce"])
    return response


def _clean_receipt_response(value: object) -> dict[str, Any]:
    expected = {
        "nonce",
        "known",
        "service_entered",
        "request_handed_to_transport",
        "terminal_class",
        "response_available",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("receipt_shape")
    if not all(
        isinstance(value[key], bool)
        for key in (
            "known",
            "service_entered",
            "request_handed_to_transport",
            "response_available",
        )
    ):
        raise ValueError("receipt_flags")
    terminal = _optional_text(value["terminal_class"])
    return {
        "nonce": _nonce(value["nonce"]),
        "known": value["known"],
        "service_entered": value["service_entered"],
        "request_handed_to_transport": value["request_handed_to_transport"],
        "terminal_class": terminal,
        "response_available": value["response_available"],
    }


def _clean_audit_event(value: object) -> dict[str, Any]:
    expected = {"event_ordinal", "kind", "monotonic_ms", "protocol_category"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("audit_event_shape")
    _nonnegative_int(value["event_ordinal"])
    _nonnegative_int(value["monotonic_ms"])
    if value["kind"] not in {
        "CONNECT_ATTEMPT",
        "GATT_SESSION_CLAIMED",
        "AUTHENTICATED_SESSION",
        "PACKET_SENT",
        "DATAPOINT_WRITE",
        "RECONNECT_SCHEDULED",
        "DISCONNECT",
    }:
        raise ValueError("audit_event_kind")
    if value["protocol_category"] not in {
        None,
        "DEVICE_STATUS",
        "DEVICE_INFO",
        "PAIR",
        "DATAPOINT",
        "OTHER",
    }:
        raise ValueError("audit_event_category")
    return {key: value[key] for key in sorted(expected)}


def _clean_audit_response(value: object) -> dict[str, Any]:
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
    if not isinstance(value, dict) or set(value) not in (
        required,
        required | {"nonce"},
    ):
        raise ValueError("audit_shape")
    if value["result"] != "audit_snapshot" or value["protocol_version"] != 1:
        raise ValueError("audit_result")
    if not isinstance(value["audit_instance_token"], str) or not _NONCE_RE.fullmatch(
        value["audit_instance_token"]
    ):
        raise ValueError("audit_instance_token")
    _nonnegative_int(value["event_ordinal"])
    _nonnegative_int(value["runtime_ms"])
    if not isinstance(value["history_overflow"], bool):
        raise ValueError("audit_overflow")
    counter_keys = {
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
    }
    if (
        not isinstance(value["counters"], dict)
        or set(value["counters"]) != counter_keys
    ):
        raise ValueError("audit_counters")
    if not all(_nonnegative_int(item) == item for item in value["counters"].values()):
        raise ValueError("audit_counter_value")
    if not isinstance(value["events"], list) or len(value["events"]) > 128:
        raise ValueError("audit_events")
    response = {key: value[key] for key in required - {"events", "counters"}}
    response["counters"] = dict(value["counters"])
    response["events"] = [_clean_audit_event(item) for item in value["events"]]
    if "nonce" in value:
        response["nonce"] = _nonce(value["nonce"])
    return response


def sanitize_service_response(
    operation: HelperOperation, response: object
) -> dict[str, Any]:
    """Validate and project only the response schema for one known operation."""
    if operation is HelperOperation.PREFLIGHT:
        return _clean_preflight_response(response)
    if operation is HelperOperation.PROBE:
        return _clean_probe_response(response)
    if operation is HelperOperation.AUDIT:
        return _clean_audit_response(response)
    return _clean_receipt_response(response)


def service_response_from_wrapper(
    operation: HelperOperation, wrapper: object
) -> dict[str, Any]:
    """Discard the wrapper (including changed_states) before returning evidence."""
    if not isinstance(wrapper, dict) or not isinstance(
        wrapper.get("service_response"), dict
    ):
        raise TypeError("service_response")
    return sanitize_service_response(operation, wrapper["service_response"])


def write_sanitized_evidence(path: Path, response: dict[str, Any]) -> None:
    """Atomically write an already-sanitized response; raw wrappers are never stored."""
    encoded = json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as pending:
        pending.write(encoded)
        pending.flush()
        pending_name = Path(pending.name)
    pending_name.replace(path)
    os.chmod(path, 0o600)


def _path_for(operation: HelperOperation) -> str:
    if operation is HelperOperation.PREFLIGHT:
        return "phase_a_status_probe_preflight"
    if operation is HelperOperation.PROBE:
        return "phase_a_status_probe"
    if operation is HelperOperation.AUDIT:
        return "phase_a_status_probe_audit"
    return "phase_a_status_probe_receipt"


def _service_exit(operation: HelperOperation, response: dict[str, Any]) -> HelperExit:
    if operation is HelperOperation.PREFLIGHT:
        return HelperExit.SUCCESS
    if operation is HelperOperation.RECEIPT:
        return HelperExit.SUCCESS if response["known"] else HelperExit.SERVICE_REJECTED
    if operation is HelperOperation.AUDIT:
        return HelperExit.SUCCESS
    if response["result"] == "completed":
        return HelperExit.SUCCESS
    return HelperExit.SERVICE_REJECTED


def _response_nonce(operation: HelperOperation, response: dict[str, Any]) -> str | None:
    """Return the sanitized correlation value from a received service response."""
    key = "invocation_nonce" if operation is HelperOperation.PROBE else "nonce"
    return response.get(key)


def invoke_service(
    operation: HelperOperation,
    endpoint: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    *,
    timeout: float = 180,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> HelperResult:
    """Call every temporary service through one conservative HTTP outcome boundary.

    Input validation fails before a request is built. Once the request is handed
    to the HTTP client, a transport exception is conservatively ambiguous; a
    received but malformed wrapper is instead a deterministic local schema
    failure and is never reported as a hardware invocation outcome.
    """
    submitted_nonce: str | None = None
    try:
        if operation in {HelperOperation.PREFLIGHT, HelperOperation.AUDIT}:
            payload = {"nonce": _nonce(payload.get("nonce", generate_nonce()))}
        elif operation is HelperOperation.RECEIPT:
            payload = {"nonce": _nonce(payload["nonce"])}
        else:
            payload = {
                "config_entry_id": payload["config_entry_id"],
                "mode": payload["mode"],
                "invocation_nonce": _nonce(
                    payload.get("invocation_nonce", generate_nonce())
                ),
            }
            if not isinstance(payload["config_entry_id"], str) or not isinstance(
                payload["mode"], str
            ):
                raise ValueError("probe_input")
        submitted_nonce = (
            payload["invocation_nonce"]
            if operation is HelperOperation.PROBE
            else payload["nonce"]
        )
        request = urllib.request.Request(
            endpoint.rstrip("/")
            + "/api/services/tuya_ble/"
            + _path_for(operation)
            + "?return_response",
            data=json.dumps(payload).encode(),
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
    except (KeyError, TypeError, ValueError):
        return HelperResult(HelperExit.DEFINITELY_NOT_SUBMITTED, "not_submitted")
    try:
        with opener(request, timeout=timeout) as http_response:
            wrapper = json.load(http_response)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return HelperResult(
            HelperExit.AMBIGUOUS_POST_SUBMISSION,
            "transport_ambiguous",
            nonce=submitted_nonce,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return HelperResult(
            HelperExit.SCHEMA_PRIVACY_FAILURE,
            "schema_invalid",
            nonce=submitted_nonce,
        )
    try:
        response = service_response_from_wrapper(operation, wrapper)
    except (TypeError, ValueError, json.JSONDecodeError):
        return HelperResult(
            HelperExit.SCHEMA_PRIVACY_FAILURE,
            "schema_invalid",
            nonce=submitted_nonce,
        )
    if _response_nonce(operation, response) != submitted_nonce:
        return HelperResult(
            HelperExit.SCHEMA_PRIVACY_FAILURE,
            "nonce_mismatch",
            nonce=submitted_nonce,
        )
    exit_code = _service_exit(operation, response)
    outcome = response.get("result", "receipt")
    return HelperResult(exit_code, outcome, response, submitted_nonce)
