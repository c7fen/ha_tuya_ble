"""Contract tests for the temporary, non-mergeable Phase-A S1 probe."""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from bleak.backends.device import BLEDevice
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import SupportsResponse
from voluptuous import Invalid

from custom_components.tuya_ble.const import (
    DOMAIN,
    ConnectionMode,
    ConnectionPolicyState,
    PendingRelease,
    PendingReleaseReason,
)
from custom_components.tuya_ble.phase_a_probe import (
    _LOCKS_DATA_KEY,
    ATTR_CONFIG_ENTRY_ID,
    ATTR_MODE,
    MODE_COLD,
    MODE_COLD_THEN_RETAINED,
    SERVICE_PHASE_A_STATUS_PROBE,
    SERVICE_SCHEMA,
    _async_handle_phase_a_status_probe,
    async_register_phase_a_status_probe,
    async_run_phase_a_status_probe,
    async_unregister_phase_a_status_probe_if_unused,
)
from custom_components.tuya_ble.tuya_ble.tuya_ble import (
    ConnectionSessionToken,
    StatusObservationEvent,
    TuyaBLEDevice,
)


class _SyntheticClient:
    """Minimal synthetic paired client; never contacts Bluetooth."""

    is_connected = True


class _DisconnectingSyntheticClient:
    """Synthetic client that completes one ordinary physical disconnect."""

    def __init__(self) -> None:
        self.is_connected = True
        self.stop_notify = AsyncMock()

        async def disconnect() -> None:
            self.is_connected = False

        self.disconnect = AsyncMock(side_effect=disconnect)


def _device(
    *,
    product: tuple[str, str] = ("jtmspro", "xqeob8h6"),
    mode: ConnectionMode = ConnectionMode.ON_DEMAND,
    enabled: bool = True,
) -> TuyaBLEDevice:
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice("synthetic-phase-a", "00:00:00:00:00:37", {}),
        connection_mode=mode.value,
        ble_control_enabled=enabled,
    )
    device._device_info = SimpleNamespace(category=product[0], product_id=product[1])
    return device


def _install_successful_update(device: TuyaBLEDevice) -> AsyncMock:
    """Install one synthetic exact-ACK update without transport traffic."""
    calls = 0

    async def update() -> None:
        nonlocal calls
        calls += 1
        token = device._connection_token
        if token is None:
            token = ConnectionSessionToken(_SyntheticClient(), 1)
            device._client = token.client
            device._connection_token = token
            device._connection_epoch = token.epoch
        device._is_paired = True
        device._notifications_active = True
        device._policy_state = ConnectionPolicyState.ON_DEMAND_ACTIVE
        event_ordinal = calls * 2
        for callback in tuple(device._status_observers):
            callback(
                StatusObservationEvent(
                    calls,
                    "explicit",
                    "REQUEST_CREATED",
                    event_ordinal - 1,
                )
            )
            callback(
                StatusObservationEvent(
                    calls,
                    "explicit",
                    "ACK_SUCCESS",
                    event_ordinal,
                    ack_result="success",
                )
            )

    return AsyncMock(side_effect=update)


async def _release_normally(device: TuyaBLEDevice) -> None:
    """Fire the narrow passive normal-release observer after a loop turn."""
    for _ in range(10):
        await asyncio.sleep(0)
        token = device._connection_token
        if token is not None:
            break
    else:
        raise AssertionError("synthetic update did not establish a session")
    device._fire_on_demand_idle_release_callbacks(token)


@pytest.mark.asyncio
async def test_cold_probe_makes_one_update_and_returns_only_sanitized_metadata():
    device = _device()
    device.update = _install_successful_update(device)
    release = asyncio.create_task(_release_normally(device))

    result = await async_run_phase_a_status_probe(device, "cold")
    await release

    assert device.update.await_count == 1
    assert result["request_count"] == 1
    assert result["cold_request_attempted"] is True
    assert result["retained_request_attempted"] is False
    assert result["normal_release_observed"] is True
    assert result["result"] == "completed"
    assert device._status_observers == []
    assert json.loads(json.dumps(result)) == result


@pytest.mark.asyncio
async def test_retained_probe_requires_the_first_exact_ack_and_same_session():
    device = _device()
    device.update = _install_successful_update(device)
    release = asyncio.create_task(_release_normally(device))

    result = await async_run_phase_a_status_probe(device, "cold_then_retained")
    await release

    assert device.update.await_count == 2
    assert result["request_count"] == 2
    assert result["same_session_retained"] is True
    assert [request["result"] for request in result["requests"]] == [
        "ack_success",
        "ack_success",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("product", "mode", "enabled"),
    [
        (("ms", "7a4xvbtt"), ConnectionMode.ON_DEMAND, True),
        (("jtmspro", "different"), ConnectionMode.ON_DEMAND, True),
        (("jtmspro", "xqeob8h6"), ConnectionMode.ALWAYS_CONNECTED, True),
        (("jtmspro", "xqeob8h6"), ConnectionMode.ON_DEMAND, False),
    ],
)
async def test_ineligible_probe_rejects_before_device_status_io(product, mode, enabled):
    device = _device(product=product, mode=mode, enabled=enabled)
    device.update = AsyncMock()

    result = await async_run_phase_a_status_probe(device, "cold")

    assert result["request_count"] == 0
    assert result["result"] == "precondition_failed"
    device.update.assert_not_awaited()


@pytest.mark.asyncio
async def test_connected_or_transitioning_probe_rejects_before_io():
    device = _device()
    device._client = _SyntheticClient()
    device._pending_release = object()
    device.update = AsyncMock()

    result = await async_run_phase_a_status_probe(device, "cold")

    assert result["request_count"] == 0
    device.update.assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_cold_ack_does_not_issue_a_retained_request():
    device = _device()

    async def failed_update() -> None:
        for callback in tuple(device._status_observers):
            callback(StatusObservationEvent(1, "explicit", "REQUEST_CREATED", 1))
            callback(
                StatusObservationEvent(
                    1, "explicit", "ACK_FAILURE", 2, ack_result="failure"
                )
            )
        raise RuntimeError("synthetic failure")

    device.update = AsyncMock(side_effect=failed_update)

    result = await async_run_phase_a_status_probe(device, "cold_then_retained")

    assert device.update.await_count == 1
    assert result["request_count"] == 1
    assert result["retained_request_attempted"] is False


@pytest.mark.asyncio
async def test_response_never_leaks_adversarial_private_material(caplog):
    device = _device()
    device._address = "00:00:00:00:00:37-private-address"
    device._device_info = SimpleNamespace(
        category="jtmspro",
        product_id="xqeob8h6",
        device_id="private-config-entry-and-device-id",
        local_key="private-local-key",
        sec_key="private-sec-key",
    )
    device.update = _install_successful_update(device)
    release = asyncio.create_task(_release_normally(device))

    with caplog.at_level(logging.DEBUG):
        result = await async_run_phase_a_status_probe(device, "cold")
    await release

    rendered = json.dumps(result) + caplog.text
    for forbidden in (
        "private-address",
        "private-config-entry-and-device-id",
        "private-local-key",
        "private-sec-key",
        "private-entity-id",
        "private-raw-bytes",
        "private-dp-value",
    ):
        assert forbidden not in rendered


def test_service_schema_and_response_only_registration_lifecycle():
    """The temporary action has strict input and disappears with the domain."""
    services = SimpleNamespace(async_register=Mock(), async_remove=Mock())
    hass = SimpleNamespace(data={}, services=services)

    assert (
        SERVICE_SCHEMA(
            {ATTR_CONFIG_ENTRY_ID: "synthetic-private-entry", ATTR_MODE: MODE_COLD}
        )[ATTR_MODE]
        == MODE_COLD
    )
    with pytest.raises(Invalid):
        SERVICE_SCHEMA({ATTR_CONFIG_ENTRY_ID: "synthetic-private-entry"})
    with pytest.raises(Invalid):
        SERVICE_SCHEMA(
            {
                ATTR_CONFIG_ENTRY_ID: "synthetic-private-entry",
                ATTR_MODE: "three_requests",
            }
        )

    async_register_phase_a_status_probe(hass)
    _, _, kwargs = services.async_register.mock_calls[0]
    assert kwargs["supports_response"] is SupportsResponse.ONLY
    assert kwargs["schema"] is SERVICE_SCHEMA

    async_unregister_phase_a_status_probe_if_unused(hass)
    services.async_remove.assert_called_once_with(DOMAIN, SERVICE_PHASE_A_STATUS_PROBE)


def _service_hass(device: TuyaBLEDevice, state=ConfigEntryState.LOADED):
    """Return a minimal loaded-entry service environment with no real HA I/O."""
    entry = SimpleNamespace(state=state)
    return SimpleNamespace(
        data={DOMAIN: {"private-entry": SimpleNamespace(device=device)}},
        config_entries=SimpleNamespace(async_get_entry=Mock(return_value=entry)),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("state", (None, ConfigEntryState.SETUP_RETRY))
async def test_missing_or_unloaded_service_target_rejects_without_io(state):
    device = _device()
    device.update = AsyncMock()
    hass = (
        _service_hass(device, state)
        if state is not None
        else SimpleNamespace(
            data={DOMAIN: {}},
            config_entries=SimpleNamespace(async_get_entry=Mock(return_value=None)),
        )
    )
    call = SimpleNamespace(
        data={ATTR_CONFIG_ENTRY_ID: "private-entry", ATTR_MODE: MODE_COLD}
    )

    result = await _async_handle_phase_a_status_probe(hass, call)

    assert result["request_count"] == 0
    device.update.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutate",
    [
        lambda device: setattr(device, "_client", _SyntheticClient()),
        lambda device: setattr(device, "_is_paired", True),
        lambda device: setattr(device, "_active_lease_count", 1),
        lambda device: setattr(device, "_pending_release", object()),
        lambda device: setattr(device, "_reconnect_task", object()),
        lambda device: setattr(device, "_terminal_stopped", True),
        lambda device: setattr(device, "_unload_quiescing", True),
    ],
)
async def test_every_unsafe_cold_runtime_gate_rejects_before_io(mutate):
    device = _device()
    mutate(device)
    device.update = AsyncMock()

    result = await async_run_phase_a_status_probe(device, MODE_COLD)

    assert result["result"] == "precondition_failed"
    assert result["cold_request_attempted"] is False
    assert result["request_count"] == 0
    device.update.assert_not_awaited()


@pytest.mark.asyncio
async def test_connect_or_handshake_failure_is_an_attempt_but_not_a_status_request():
    device = _device()
    device.update = AsyncMock(side_effect=RuntimeError("synthetic connect failure"))

    result = await async_run_phase_a_status_probe(device, MODE_COLD)

    assert result["cold_request_attempted"] is True
    assert result["request_count"] == 0
    assert result["requests"] == []
    device.update.assert_awaited_once()


@pytest.mark.asyncio
async def test_ack_timeout_after_request_creation_counts_once_without_retry():
    device = _device()

    async def timeout_update() -> None:
        token = ConnectionSessionToken(_SyntheticClient(), 1)
        device._client = token.client
        device._connection_token = token
        device._connection_epoch = token.epoch
        device._is_paired = True
        device._notifications_active = True
        for callback in tuple(device._status_observers):
            callback(StatusObservationEvent(1, "explicit", "REQUEST_CREATED", 1))
            callback(
                StatusObservationEvent(
                    1, "explicit", "ACK_TIMEOUT", 2, ack_result="timeout"
                )
            )

    device.update = AsyncMock(side_effect=timeout_update)
    release = asyncio.create_task(_release_normally(device))

    result = await async_run_phase_a_status_probe(device, MODE_COLD_THEN_RETAINED)
    await release

    assert device.update.await_count == 1
    assert result["request_count"] == 1
    assert result["requests"][0]["result"] == "ack_failed"
    assert result["retained_request_attempted"] is False


@pytest.mark.asyncio
async def test_session_replacement_during_first_update_blocks_retained_leg():
    device = _device()
    old_tokens = []

    async def replaced_update() -> None:
        old = ConnectionSessionToken(_SyntheticClient(), 1)
        old_tokens.append(old)
        device._client = old.client
        device._connection_token = old
        device._connection_epoch = old.epoch
        device._is_paired = True
        device._notifications_active = True
        for callback in tuple(device._status_observers):
            callback(StatusObservationEvent(1, "explicit", "REQUEST_CREATED", 1))
            callback(
                StatusObservationEvent(
                    1, "explicit", "ACK_SUCCESS", 2, ack_result="success"
                )
            )
        replacement = ConnectionSessionToken(_SyntheticClient(), 2)
        device._client = replacement.client
        device._connection_token = replacement
        device._connection_epoch = replacement.epoch

    device.update = AsyncMock(side_effect=replaced_update)

    async def release_old_session() -> None:
        while not old_tokens:
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        device._fire_on_demand_idle_release_callbacks(old_tokens[0])

    release = asyncio.create_task(release_old_session())

    result = await async_run_phase_a_status_probe(device, MODE_COLD_THEN_RETAINED)
    await release

    assert device.update.await_count == 1
    assert result["same_session_retained"] is False
    assert result["automatic_reconnect_observed"] is True


@pytest.mark.asyncio
async def test_collector_overflow_prevents_the_retained_leg():
    device = _device()

    async def overflowing_update() -> None:
        token = ConnectionSessionToken(_SyntheticClient(), 1)
        device._client = token.client
        device._connection_token = token
        device._connection_epoch = token.epoch
        device._is_paired = True
        device._notifications_active = True
        for callback in tuple(device._status_observers):
            callback(StatusObservationEvent(1, "explicit", "REQUEST_CREATED", 1))
            callback(
                StatusObservationEvent(
                    1, "explicit", "ACK_SUCCESS", 2, ack_result="success"
                )
            )
            for ordinal in range(3, 67):
                callback(StatusObservationEvent(1, "explicit", "DP_BATCH", ordinal))

    device.update = AsyncMock(side_effect=overflowing_update)
    release = asyncio.create_task(_release_normally(device))

    result = await async_run_phase_a_status_probe(device, MODE_COLD_THEN_RETAINED)
    await release

    assert device.update.await_count == 1
    assert result["observation_overflow"] is True
    assert result["retained_request_attempted"] is False


@pytest.mark.asyncio
async def test_only_the_final_exact_normal_release_completes_the_probe():
    device = _device()
    device.update = _install_successful_update(device)

    async def unrelated_then_exact_release() -> None:
        await asyncio.sleep(0)
        unrelated = ConnectionSessionToken(_SyntheticClient(), 99)
        device._fire_on_demand_idle_release_callbacks(unrelated)
        assert device._on_demand_idle_release_callbacks
        token = device._connection_token
        assert token is not None
        device._fire_on_demand_idle_release_callbacks(token)

    release = asyncio.create_task(unrelated_then_exact_release())
    result = await async_run_phase_a_status_probe(device, MODE_COLD)
    await release

    assert result["normal_release_observed"] is True
    assert result["result"] == "completed"


@pytest.mark.asyncio
async def test_device_reports_only_the_completed_normal_release_with_its_token():
    """The lifecycle observer is not a generic invalidation notification."""
    device = _device()
    client = _DisconnectingSyntheticClient()
    token = ConnectionSessionToken(client, 1)
    device._client = client
    device._connection_token = token
    device._connection_epoch = token.epoch
    device._is_paired = True
    device._notifications_active = True
    device._pending_release = PendingRelease(PendingReleaseReason.ON_DEMAND_IDLE, 0)
    observed = []
    unregister = device.register_on_demand_idle_release_callback(observed.append)

    await device._complete_pending_release()
    unregister()

    assert observed == [token]
    assert device._connection_token is None


@pytest.mark.asyncio
async def test_service_concurrency_rejects_second_call_and_cleans_device_lock():
    device = _device()
    device.update = _install_successful_update(device)
    hass = _service_hass(device)
    call = SimpleNamespace(
        data={ATTR_CONFIG_ENTRY_ID: "private-entry", ATTR_MODE: MODE_COLD}
    )
    first = asyncio.create_task(_async_handle_phase_a_status_probe(hass, call))
    await asyncio.sleep(0)

    second = await _async_handle_phase_a_status_probe(hass, call)
    token = device._connection_token
    assert token is not None
    device._fire_on_demand_idle_release_callbacks(token)
    first_result = await first

    assert second["result"] == "probe_already_active"
    assert second["request_count"] == 0
    assert first_result["request_count"] == 1
    assert hass.data[DOMAIN][_LOCKS_DATA_KEY] == {}


@pytest.mark.asyncio
async def test_cancellation_removes_every_probe_callback_and_never_retries():
    device = _device()
    entered = asyncio.Event()
    release_update = asyncio.Event()

    async def stalled_update() -> None:
        entered.set()
        await release_update.wait()

    device.update = AsyncMock(side_effect=stalled_update)
    task = asyncio.create_task(async_run_phase_a_status_probe(device, MODE_COLD))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert device.update.await_count == 1
    assert device._status_observers == []
    assert device._on_demand_idle_release_callbacks == []
    assert device._connection_state_callbacks == []


@pytest.mark.asyncio
async def test_probe_does_not_write_policy_or_issue_hidden_retained_setup_work():
    device = _device()
    device.update = _install_successful_update(device)
    device.async_update_connection_policy = AsyncMock()
    device.pair = AsyncMock()
    device._update_device_info = AsyncMock()
    device._ensure_connected = AsyncMock()
    release = asyncio.create_task(_release_normally(device))

    result = await async_run_phase_a_status_probe(device, MODE_COLD_THEN_RETAINED)
    await release

    assert result["request_count"] == 2
    device.async_update_connection_policy.assert_not_awaited()
    device.pair.assert_not_awaited()
    device._update_device_info.assert_not_awaited()
    device._ensure_connected.assert_not_awaited()
