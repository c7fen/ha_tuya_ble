"""Temporary, process-local Phase-A integration I/O audit — do not merge.

The singleton is constructed at module import, before config-entry setup can
schedule device startup. It stores only aggregate counters and bounded,
non-identifying event categories. There is no reset or persistence: a Core
restart is the only audit-epoch boundary.
"""

from __future__ import annotations

import re
import secrets
import time
from typing import Any

import voluptuous as vol
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse

from .const import DOMAIN
from .tuya_ble.const import TuyaBLECode

SERVICE_PHASE_A_STATUS_PROBE_AUDIT = "phase_a_status_probe_audit"
EVENT_HISTORY_LIMIT = 128
PROTOCOL_VERSION = 1
ATTR_NONCE = "nonce"
_NONCE_RE = re.compile(r"[0-9a-f]{16,32}\Z")
_SERVICE_DATA_KEY = "_temporary_phase_a_io_audit_service_registered"


def _validate_nonce(value: str) -> str:
    """Accept an optional opaque caller correlation value."""
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise vol.Invalid("nonce must be 16-32 lowercase hexadecimal characters")
    return value


SERVICE_SCHEMA = vol.Schema(
    {vol.Optional(ATTR_NONCE): _validate_nonce}, extra=vol.PREVENT_EXTRA
)


class PhaseAIoAudit:
    """One irreversible, bounded process-local record of integration I/O."""

    def __init__(self) -> None:
        self._started = time.monotonic()
        self._instance_token = secrets.token_hex(16)
        self._event_ordinal = 0
        self._history_overflow = False
        self._events: list[dict[str, int | str | None]] = []
        self._counters = {
            "connect_attempts": 0,
            "gatt_sessions_claimed": 0,
            "authenticated_sessions": 0,
            "packets_sent_total": 0,
            "device_status_requests": 0,
            "device_info_requests": 0,
            "pair_requests": 0,
            "datapoint_write_operations": 0,
            "datapoint_protocol_packets": 0,
            "other_packets": 0,
            "reconnect_schedules": 0,
            "disconnects": 0,
        }

    def _record(self, kind: str, protocol_category: str | None = None) -> None:
        self._event_ordinal += 1
        if len(self._events) >= EVENT_HISTORY_LIMIT:
            self._history_overflow = True
            return
        self._events.append(
            {
                "event_ordinal": self._event_ordinal,
                "kind": kind,
                "monotonic_ms": max(0, int((time.monotonic() - self._started) * 1000)),
                "protocol_category": protocol_category,
            }
        )

    def record_connect_attempt(self) -> None:
        self._counters["connect_attempts"] += 1
        self._record("CONNECT_ATTEMPT")

    def record_gatt_session_claimed(self) -> None:
        self._counters["gatt_sessions_claimed"] += 1
        self._record("GATT_SESSION_CLAIMED")

    def record_authenticated_session(self) -> None:
        self._counters["authenticated_sessions"] += 1
        self._record("AUTHENTICATED_SESSION")

    def record_packet_sent(self, code: TuyaBLECode | None) -> None:
        """Record one actual BLE write using only a finite protocol category."""
        category = {
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS: "DEVICE_STATUS",
            TuyaBLECode.FUN_SENDER_DEVICE_INFO: "DEVICE_INFO",
            TuyaBLECode.FUN_SENDER_PAIR: "PAIR",
            TuyaBLECode.FUN_SENDER_DPS: "DATAPOINT",
            TuyaBLECode.FUN_SENDER_DPS_V4: "DATAPOINT",
        }.get(code, "OTHER")
        self._counters["packets_sent_total"] += 1
        if category == "DEVICE_STATUS":
            self._counters["device_status_requests"] += 1
        elif category == "DEVICE_INFO":
            self._counters["device_info_requests"] += 1
        elif category == "PAIR":
            self._counters["pair_requests"] += 1
        elif category == "DATAPOINT":
            self._counters["datapoint_protocol_packets"] += 1
        else:
            self._counters["other_packets"] += 1
        self._record("PACKET_SENT", category)

    def record_datapoint_write(self) -> None:
        self._counters["datapoint_write_operations"] += 1
        self._record("DATAPOINT_WRITE")

    def record_reconnect_scheduled(self) -> None:
        self._counters["reconnect_schedules"] += 1
        self._record("RECONNECT_SCHEDULED")

    def record_disconnect(self) -> None:
        self._counters["disconnects"] += 1
        self._record("DISCONNECT")

    def snapshot(self, nonce: str | None = None) -> dict[str, Any]:
        """Return a copy-only response; querying does not alter audit state."""
        response: dict[str, Any] = {
            "result": "audit_snapshot",
            "protocol_version": PROTOCOL_VERSION,
            "audit_instance_token": self._instance_token,
            "event_ordinal": self._event_ordinal,
            "history_overflow": self._history_overflow,
            "runtime_ms": max(0, int((time.monotonic() - self._started) * 1000)),
            "counters": dict(self._counters),
            "events": [dict(event) for event in self._events],
        }
        if nonce is not None:
            response["nonce"] = nonce
        return response


# Construction is intentionally at Python-module/process lifetime, not service
# registration, config-entry setup, or the first snapshot.
AUDIT = PhaseAIoAudit()


def record_connect_attempt() -> None:
    AUDIT.record_connect_attempt()


def record_gatt_session_claimed() -> None:
    AUDIT.record_gatt_session_claimed()


def record_authenticated_session() -> None:
    AUDIT.record_authenticated_session()


def record_packet_sent(code: TuyaBLECode | None) -> None:
    AUDIT.record_packet_sent(code)


def record_datapoint_write() -> None:
    AUDIT.record_datapoint_write()


def record_reconnect_scheduled() -> None:
    AUDIT.record_reconnect_scheduled()


def record_disconnect() -> None:
    AUDIT.record_disconnect()


async def _async_handle_phase_a_io_audit(
    call: ServiceCall,
) -> dict[str, Any]:
    """Return only the process snapshot; this handler never resolves a device."""
    return AUDIT.snapshot(call.data.get(ATTR_NONCE))


def async_register_phase_a_io_audit(hass: HomeAssistant) -> None:
    """Register the response-only audit service once without touching devices."""
    if not hasattr(hass, "services"):
        return
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get(_SERVICE_DATA_KEY):
        return
    hass.services.async_register(
        DOMAIN,
        SERVICE_PHASE_A_STATUS_PROBE_AUDIT,
        _async_handle_phase_a_io_audit,
        schema=SERVICE_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
    domain_data[_SERVICE_DATA_KEY] = True
