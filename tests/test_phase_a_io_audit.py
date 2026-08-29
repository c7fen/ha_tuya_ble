"""Contract tests for the temporary process-local Phase-A I/O audit."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakError, BleakNotFoundError

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


def _always_connected_device() -> TuyaBLEDevice:
    device = _device()
    device._connection_mode = ConnectionMode.ALWAYS_CONNECTED
    return device


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


def test_audit_singleton_is_constructed_at_module_scope_before_registration() -> None:
    """A-M8: moving construction into registration is a contract failure."""
    import custom_components.tuya_ble.phase_a_io_audit as audit_module

    source = Path(audit_module.__file__).read_text(encoding="utf-8")
    module = ast.parse(source)
    singleton = next(
        statement
        for statement in module.body
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "AUDIT"
            for target in statement.targets
        )
    )
    assert isinstance(singleton.value, ast.Call)
    assert isinstance(singleton.value.func, ast.Name)
    assert singleton.value.func.id == "PhaseAIoAudit"

    registration = next(
        statement
        for statement in module.body
        if isinstance(statement, ast.FunctionDef)
        and statement.name == "async_register_phase_a_io_audit"
    )
    registration_source = ast.get_source_segment(source, registration)
    assert singleton.lineno < registration.lineno
    assert registration_source is not None
    assert "PhaseAIoAudit(" not in registration_source
    assert "AUDIT =" not in registration_source


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
        device._handle_command_or_response(
            2,
            0,
            TuyaBLECode.FUN_SENDER_PAIR,
            b"\x00",
            session_token=token,
        )

    claim.assert_called_once_with()
    auth.assert_called_once_with()


async def test_connect_attempt_failure_records_once_without_claiming_session() -> None:
    import custom_components.tuya_ble.tuya_ble.tuya_ble as transport

    device = _device()
    with (
        patch.object(transport, "record_connect_attempt") as attempt,
        patch.object(transport, "record_gatt_session_claimed") as claim,
        patch.object(
            transport,
            "establish_connection",
            AsyncMock(side_effect=BleakNotFoundError()),
        ),
        pytest.raises(BleakNotFoundError),
    ):
        await device._ensure_connected()

    attempt.assert_called_once_with()
    claim.assert_not_called()


async def test_connection_attempt_before_service_registration_is_in_later_snapshot() -> (
    None
):
    """The process audit survives startup activity before service availability."""
    import custom_components.tuya_ble.phase_a_io_audit as audit_module
    import custom_components.tuya_ble.tuya_ble.tuya_ble as transport

    device = _device()
    hass = SimpleNamespace(data={}, services=Mock())
    audit = _audit()
    with (
        patch.object(audit_module, "AUDIT", audit),
        patch.object(
            transport,
            "establish_connection",
            AsyncMock(side_effect=BleakNotFoundError()),
        ),
    ):
        with pytest.raises(BleakNotFoundError):
            await device._ensure_connected()
        assert audit.snapshot()["counters"]["connect_attempts"] == 1
        audit_module.async_register_phase_a_io_audit(hass)
        handler = hass.services.async_register.call_args.args[2]
        later_snapshot = await handler(SimpleNamespace(data={"nonce": "e" * 16}))

    assert later_snapshot["counters"]["connect_attempts"] == 1
    assert later_snapshot["nonce"] == "e" * 16


@pytest.mark.parametrize(
    ("code", "counter"),
    [
        (TuyaBLECode.FUN_SENDER_DEVICE_STATUS, "device_status_requests"),
        (TuyaBLECode.FUN_SENDER_DEVICE_INFO, "device_info_requests"),
        (TuyaBLECode.FUN_SENDER_PAIR, "pair_requests"),
        (TuyaBLECode.FUN_SENDER_DPS, "datapoint_protocol_packets"),
        (TuyaBLECode.FUN_SENDER_OTA_START, "other_packets"),
    ],
)
async def test_wire_hook_records_one_exact_category_per_logical_message(
    code, counter
) -> None:
    import custom_components.tuya_ble.phase_a_io_audit as audit_module
    import custom_components.tuya_ble.tuya_ble.tuya_ble as transport

    device = _device()
    client = Mock(is_connected=True, write_gatt_char=AsyncMock())
    token = device._claim_connection_session(client)
    device._is_paired = True
    device._notifications_active = True
    device._characteristic_write = "synthetic-characteristic"
    audit = _audit()
    with patch.object(audit_module, "AUDIT", audit):
        audit_code_token = transport._OUTGOING_PACKET_AUDIT_CODE.set(code)
        try:
            await device._int_send_packets_locked(
                token,
                [b"private-local-key", b"second-private-fragment"],
            )
        finally:
            transport._OUTGOING_PACKET_AUDIT_CODE.reset(audit_code_token)
    assert client.write_gatt_char.await_count == 2
    snapshot = audit.snapshot()
    assert snapshot["counters"]["packets_sent_total"] == 1
    assert snapshot["counters"][counter] == 1
    assert sum(snapshot["counters"].values()) == 2


async def test_wire_hook_does_not_record_when_no_write_is_possible() -> None:
    import custom_components.tuya_ble.phase_a_io_audit as audit_module
    import custom_components.tuya_ble.tuya_ble.tuya_ble as transport

    device = _device()
    client = Mock(is_connected=False, write_gatt_char=AsyncMock())
    token = device._claim_connection_session(client)
    device._is_paired = True
    device._notifications_active = True
    audit = _audit()
    with patch.object(audit_module, "AUDIT", audit), pytest.raises(BleakError):
        audit_code_token = transport._OUTGOING_PACKET_AUDIT_CODE.set(
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS
        )
        try:
            await device._int_send_packets_locked(token, [b"private-local-key"])
        finally:
            transport._OUTGOING_PACKET_AUDIT_CODE.reset(audit_code_token)
    client.write_gatt_char.assert_not_awaited()
    assert audit.snapshot()["counters"]["packets_sent_total"] == 0


@pytest.mark.parametrize(
    "method_name",
    ["_send_datapoints", "_send_datapoints_no_replay", "_send_datapoints_once"],
)
async def test_each_logical_datapoint_entry_point_records_once(method_name) -> None:
    import custom_components.tuya_ble.tuya_ble.tuya_ble as transport

    device = _device()
    device._protocol_version = 3
    device._send_datapoints_v3 = AsyncMock()
    device._send_packet_once_confirmed = AsyncMock()
    device._encode_datapoints = Mock(return_value=b"synthetic-datapoint")
    with patch.object(transport, "record_datapoint_write") as datapoint:
        await getattr(device, method_name)([77])
    datapoint.assert_called_once_with()


def test_reconnect_audit_counts_initial_and_replacement_tasks_not_guards_or_cancel() -> (
    None
):
    import custom_components.tuya_ble.phase_a_io_audit as audit_module

    device = _always_connected_device()
    created: list[Mock] = []

    def create_policy_task(coroutine):
        coroutine.close()
        task = Mock()
        created.append(task)
        return task

    device._create_policy_task = Mock(side_effect=create_policy_task)
    audit = _audit()
    with patch.object(audit_module, "AUDIT", audit):
        device._schedule_reconnect_locked(1)
        initial = device._reconnect_task
        device._schedule_reconnect_locked(2)
        device._cancel_reconnect_locked()
        device._schedule_reconnect_locked(0)
        device._connection_mode = ConnectionMode.ON_DEMAND
        device._schedule_reconnect_locked(3)

    assert len(created) == 3
    assert audit.snapshot()["counters"]["reconnect_schedules"] == 3
    initial.cancel.assert_called_once_with()
    created[1].cancel.assert_called_once_with()


def test_audit_service_and_startup_order_are_snapshot_only_and_early() -> None:
    """The singleton import predates setup; registration never looks up a device."""
    import custom_components.tuya_ble as integration
    import custom_components.tuya_ble.phase_a_io_audit as audit_module

    setup_source = inspect.getsource(integration.async_setup_entry)
    assert "async_register_phase_a_io_audit(hass)" in setup_source
    assert setup_source.index(
        "async_register_phase_a_io_audit(hass)"
    ) < setup_source.index("device._startup_task")
    handler_source = inspect.getsource(audit_module._async_handle_phase_a_io_audit)
    assert "snapshot(" in handler_source
    assert "hass.data" not in handler_source
    assert "TuyaBLEDevice" not in handler_source


async def test_audit_service_snapshot_is_repeated_read_only_and_never_looks_up_device() -> (
    None
):
    import custom_components.tuya_ble.phase_a_io_audit as audit_module

    audit = _audit()
    audit.record_connect_attempt()
    call = SimpleNamespace(data={"nonce": "c" * 16})
    with patch.object(audit_module, "AUDIT", audit):
        first = await audit_module._async_handle_phase_a_io_audit(call)
        second = await audit_module._async_handle_phase_a_io_audit(call)

    assert first == second
    assert first["counters"]["connect_attempts"] == 1
    assert first["event_ordinal"] == 1


async def test_preflight_receipt_and_invalid_probe_target_preserve_zero_io_audit() -> (
    None
):
    """A-M10: rejected or local-only research calls cannot fabricate I/O."""
    import custom_components.tuya_ble.phase_a_io_audit as audit_module
    from custom_components.tuya_ble.phase_a_probe import (
        _async_handle_phase_a_status_probe,
        _async_handle_phase_a_status_probe_preflight,
        _async_handle_phase_a_status_probe_receipt,
    )

    audit = _audit()
    hass = SimpleNamespace(
        data={},
        config_entries=SimpleNamespace(async_get_entry=lambda _entry_id: None),
    )
    with patch.object(audit_module, "AUDIT", audit):
        preflight = await _async_handle_phase_a_status_probe_preflight(
            hass, SimpleNamespace(data={"nonce": "d" * 16})
        )
        receipt = await _async_handle_phase_a_status_probe_receipt(
            hass, SimpleNamespace(data={"nonce": "d" * 16})
        )
        rejected = await _async_handle_phase_a_status_probe(
            hass,
            SimpleNamespace(
                data={
                    "config_entry_id": "private-config-entry",
                    "mode": "cold",
                }
            ),
        )

    assert preflight["result"] == "preflight_ok"
    assert receipt["known"] is False
    assert rejected["result"] == "precondition_failed"
    snapshot = audit.snapshot()
    assert snapshot["event_ordinal"] == 0
    assert all(value == 0 for value in snapshot["counters"].values())


def test_startup_activity_has_an_audit_epoch_before_later_service_registration() -> (
    None
):
    """Model startup work before service registration through the real singleton."""
    import custom_components.tuya_ble.phase_a_io_audit as audit_module

    audit = _audit()
    hass = SimpleNamespace(data={}, services=Mock())
    with patch.object(audit_module, "AUDIT", audit):
        # A startup callback can cross an instrumented boundary before the
        # response service becomes reachable; module state already exists.
        audit_module.record_connect_attempt()
        before_registration = audit.snapshot()
        audit_module.async_register_phase_a_io_audit(hass)

    assert before_registration["counters"]["connect_attempts"] == 1
    assert before_registration["event_ordinal"] == 1
    hass.services.async_register.assert_called_once()


def test_helper_accepts_only_the_audit_schema_and_never_persists_wrapper_fields() -> (
    None
):
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
