"""Contract tests for the temporary, non-mergeable Phase-A S1 probe."""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from bleak.backends.device import BLEDevice

from custom_components.tuya_ble.const import (
    ConnectionMode,
    ConnectionPolicyState,
)
from custom_components.tuya_ble.phase_a_probe import async_run_phase_a_status_probe
from custom_components.tuya_ble.tuya_ble.tuya_ble import (
    ConnectionSessionToken,
    StatusObservationEvent,
    TuyaBLEDevice,
)


class _SyntheticClient:
    """Minimal synthetic paired client; never contacts Bluetooth."""

    is_connected = True


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
    await asyncio.sleep(0)
    device._fire_on_demand_idle_release_callbacks()


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
    ):
        assert forbidden not in rendered
