"""Contract tests for the temporary process-local Phase-A I/O audit."""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice

from custom_components.tuya_ble.const import ConnectionMode
from custom_components.tuya_ble.phase_a_io_audit import (
    EVENT_HISTORY_LIMIT,
    PhaseAIoAudit,
)
from custom_components.tuya_ble.tuya_ble.const import TuyaBLECode
from custom_components.tuya_ble.tuya_ble.tuya_ble import TuyaBLEDevice


_FORBIDDEN = (
    "00:11:22:33:44:55",
    "private-config-entry",
    "private-device-id",
    "lock.front_door",
    "deadbeef",
    "dp-77",
    "private-local-key",
    "private-session-token",
)


def _audit() -> PhaseAIoAudit:
    """Create an isolated audit object; production has one module singleton."""
    return PhaseAIoAudit()


def _device() -> TuyaBLEDevice:
    return TuyaBLEDevice(
        Mock(),
        BLEDevice("synthetic audit device", "00:00:00:00:00:37", {}),
        connection_mode=ConnectionMode.ON_DEMAND.value,
    )


def test_new_process_audit_is_zeroed_opaque_and_has_no_reset_path() -> None:
    first = _audit()
    second = _audit()

    snapshot = first.snapshot()
    assert snapshot["result"] == "audit_snapshot"
    assert snapshot["protocol_version"] == 1
    assert len(snapshot["audit_instance_token"]) == 32
    assert snapshot["audit_instance_token"] != second.snapshot()["audit_instance_token"]
    assert snapshot["event_ordinal"] == 0
    assert snapshot["history_overflow"] is False
    assert snapshot["events"] == []
    assert all(value == 0 for value in snapshot["counters"].values())
    assert not any("reset" in name or "clear" in name for name in dir(first))


def test_audit_counts_boundaries_once_and_only_retains_safe_categories() -> None:
    audit = _audit()
    audit.record_connect_attempt()
    audit.record_gatt_session_claimed()
    audit.record_authenticated_session()
    audit.record_packet_sent(TuyaBLECode.FUN_SENDER_DEVICE_STATUS)
    audit.record_packet_sent(TuyaBLECode.FUN_SENDER_DEVICE_INFO)
    audit.record_packet_sent(TuyaBLECode.FUN_SENDER_PAIR)
    audit.record_packet_sent(TuyaBLECode.FUN_SENDER_DPS)
    audit.record_packet_sent(TuyaBLECode.FUN_SENDER_OTA_START)
    audit.record_datapoint_write()
    audit.record_reconnect_scheduled()
    audit.record_disconnect()

    snapshot = audit.snapshot(nonce="a" * 16)
    assert snapshot["nonce"] == "a" * 16
    assert snapshot["event_ordinal"] == 11
    assert snapshot["counters"] == {
        "connect_attempts": 1,
        "gatt_sessions_claimed": 1,
        "authenticated_sessions": 1,
        "packets_sent_total": 5,
        "device_status_requests": 1,
        "device_info_requests": 1,
        "pair_requests": 1,
        "datapoint_write_operations": 1,
        "datapoint_protocol_packets": 1,
        "other_packets": 1,
        "reconnect_schedules": 1,
        "disconnects": 1,
    }
    assert [event["kind"] for event in snapshot["events"]] == [
        "CONNECT_ATTEMPT",
        "GATT_SESSION_CLAIMED",
        "AUTHENTICATED_SESSION",
        "PACKET_SENT",
        "PACKET_SENT",
        "PACKET_SENT",
        "PACKET_SENT",
        "PACKET_SENT",
        "DATAPOINT_WRITE",
        "RECONNECT_SCHEDULED",
        "DISCONNECT",
    ]
    assert {event.get("protocol_category") for event in snapshot["events"]} == {
        None,
        "DEVICE_STATUS",
        "DEVICE_INFO",
        "PAIR",
        "DATAPOINT",
        "OTHER",
    }
    assert "keepalive_packets" not in snapshot["counters"]


def test_history_is_bounded_but_counters_and_ordinal_never_roll_back() -> None:
    audit = _audit()
    for _ in range(EVENT_HISTORY_LIMIT + 3):
        audit.record_connect_attempt()

    snapshot = audit.snapshot()
    assert snapshot["event_ordinal"] == EVENT_HISTORY_LIMIT + 3
    assert snapshot["counters"]["connect_attempts"] == EVENT_HISTORY_LIMIT + 3
    assert len(snapshot["events"]) == EVENT_HISTORY_LIMIT
    assert snapshot["history_overflow"] is True


def test_snapshots_are_read_only_and_private_values_never_enter_events() -> None:
    audit = _audit()
    audit.record_packet_sent(TuyaBLECode.FUN_SENDER_DPS)
    first = audit.snapshot()
    second = audit.snapshot()

    assert first["event_ordinal"] == second["event_ordinal"] == 1
    rendered = repr(second)
    assert all(value not in rendered for value in _FORBIDDEN)
    assert set(second["events"][0]) == {
        "event_ordinal",
        "kind",
        "monotonic_ms",
        "protocol_category",
    }


def test_transport_and_policy_hooks_are_at_the_required_central_boundaries() -> None:
    """Guard the exact central hooks so hook-removal mutations fail locally."""
    import custom_components.tuya_ble.tuya_ble.tuya_ble as transport

    sources = {
        "connection": inspect.getsource(transport.TuyaBLEDevice._ensure_connected),
        "claim": inspect.getsource(transport.TuyaBLEDevice._claim_connection_session),
        "response": inspect.getsource(
            transport.TuyaBLEDevice._handle_command_or_response
        ),
        "wire": inspect.getsource(transport.TuyaBLEDevice._int_send_packets_locked),
        "dp": inspect.getsource(transport.TuyaBLEDevice._send_datapoints),
        "reconnect": inspect.getsource(
            transport.TuyaBLEDevice._schedule_reconnect_locked
        ),
    }
    assert sources["connection"].index("record_connect_attempt()") < sources[
        "connection"
    ].index("await establish_connection(")
    assert "record_gatt_session_claimed()" in sources["claim"]
    assert "record_authenticated_session()" in sources["response"]
    assert sources["wire"].index("record_packet_sent(") < sources["wire"].index(
        "await client.write_gatt_char("
    )
    assert "record_datapoint_write()" in sources["dp"]
    assert "record_reconnect_scheduled()" in sources["reconnect"]


async def test_exact_claim_and_authentication_hooks_record_once() -> None:
    import custom_components.tuya_ble.tuya_ble.tuya_ble as transport

    device = _device()
    client = Mock(is_connected=True)
    with (
        patch.object(transport, "record_gatt_session_claimed") as claim,
        patch.object(transport, "record_authenticated_session") as auth,
    ):
        token = device._claim_connection_session(client)
        device._notifications_active = True
        device._handle_command_or_response(
            1,
            0,
            TuyaBLECode.FUN_SENDER_PAIR,
            b"\x00",
            session_token=token,
        )

    claim.assert_called_once_with()
    auth.assert_called_once_with()


async def test_wire_and_logical_dp_hooks_do_not_need_real_ble() -> None:
    import custom_components.tuya_ble.tuya_ble.tuya_ble as transport

    device = _device()
    client = Mock(is_connected=True, write_gatt_char=AsyncMock())
    token = device._claim_connection_session(client)
    device._is_paired = True
    device._notifications_active = True
    device._characteristic_write = "synthetic-characteristic"
    with patch.object(transport, "record_packet_sent") as packet:
        await device._int_send_packets_locked(token, [b"private-local-key"])
    packet.assert_called_once_with(None)

    device._protocol_version = 3
    device._send_datapoints_v3 = AsyncMock()
    with patch.object(transport, "record_datapoint_write") as datapoint:
        await device._send_datapoints([77])
    datapoint.assert_called_once_with()


def test_audit_service_and_startup_order_are_snapshot_only_and_early() -> None:
    """The singleton import predates setup; registration never looks up a device."""
    import custom_components.tuya_ble as integration
    import custom_components.tuya_ble.phase_a_io_audit as audit_module

    setup_source = inspect.getsource(integration.async_setup_entry)
    assert "async_register_phase_a_io_audit(hass)" in setup_source
    assert setup_source.index("async_register_phase_a_io_audit(hass)") < setup_source.index(
        "device._startup_task"
    )
    handler_source = inspect.getsource(audit_module._async_handle_phase_a_io_audit)
    assert "snapshot(" in handler_source
    assert "hass.data" not in handler_source
    assert "TuyaBLEDevice" not in handler_source


def test_helper_accepts_only_the_audit_schema_and_never_persists_wrapper_fields() -> None:
    from custom_components.tuya_ble.phase_a_probe_helper import (
        HelperOperation,
        sanitize_service_response,
    )

    response = _audit().snapshot(nonce="b" * 16)
    assert sanitize_service_response(HelperOperation.AUDIT, response) == response
    with pytest.raises(ValueError):
        sanitize_service_response(
            HelperOperation.AUDIT,
            {**response, "changed_states": ["lock.front_door"]},
        )
