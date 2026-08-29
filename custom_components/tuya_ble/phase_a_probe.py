"""Temporary, non-mergeable S1 Phase-A Device Status research harness.

This module deliberately has no autonomous scheduling or persistent state.  It
only makes the reviewed ``TuyaBLEDevice.update()`` request observable for a
single, explicitly invoked research service call.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse

from .const import (
    DOMAIN,
    ConnectionMode,
    ConnectionPolicyState,
    EffectiveConnectionPolicy,
)
from .tuya_ble.tuya_ble import StatusObservationEvent, TuyaBLEDevice

SERVICE_PHASE_A_STATUS_PROBE = "phase_a_status_probe"
ATTR_CONFIG_ENTRY_ID = "config_entry_id"
ATTR_MODE = "mode"
MODE_COLD = "cold"
MODE_COLD_THEN_RETAINED = "cold_then_retained"

_MODES = frozenset({MODE_COLD, MODE_COLD_THEN_RETAINED})
_MAX_EVENTS = 64
_RELEASE_CLEANUP_MARGIN_SECONDS = 5.0
_LOCKS_DATA_KEY = "_temporary_phase_a_status_probe_locks"
_SERVICE_DATA_KEY = "_temporary_phase_a_status_probe_service_registered"

SERVICE_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): str,
        vol.Required(ATTR_MODE): vol.In(_MODES),
    },
    extra=vol.PREVENT_EXTRA,
)


class _Collector:
    """Bounded conversion of private observations into safe response records."""

    def __init__(self, device: TuyaBLEDevice, started: float) -> None:
        self._device = device
        self._started = started
        self.events: list[dict[str, Any]] = []
        self.overflow = False
        self._generation_trials: dict[int, int] = {}
        self._next_trial: int | None = None
        self.created_trials: set[int] = set()
        self.ack_success_sessions: dict[int, object] = {}
        self.ack_failure_trials: set[int] = set()

    def expect_trial(self, trial: int) -> None:
        """Associate the next actual status generation with one logical trial."""
        self._next_trial = trial

    def __call__(self, event: StatusObservationEvent) -> None:
        """Collect metadata synchronously; observer failures must not affect BLE."""
        if event.kind == "REQUEST_CREATED" and self._next_trial is not None:
            self._generation_trials[event.observation_ordinal] = self._next_trial
            self._next_trial = None
        trial = self._generation_trials.get(event.observation_ordinal, 0)
        if event.kind == "REQUEST_CREATED" and trial:
            self.created_trials.add(trial)
        if event.kind == "ACK_SUCCESS" and trial and event.exact_session:
            session = self._device._connection_token
            if session is not None:
                self.ack_success_sessions[trial] = session
        elif event.kind in {"ACK_FAILURE", "ACK_TIMEOUT"} and trial:
            self.ack_failure_trials.add(trial)
        if len(self.events) >= _MAX_EVENTS:
            self.overflow = True
            return
        self.events.append(
            {
                "trial": trial,
                "observation_ordinal": event.observation_ordinal,
                "origin": event.origin,
                "kind": event.kind,
                "event_ordinal": event.event_ordinal,
                "batch_ordinal": event.batch_ordinal,
                "dp_ids": list(event.dp_ids),
                "dp_types": list(event.dp_types),
                "encoded_value_lengths": list(event.encoded_value_lengths),
                "exact_session": event.exact_session,
                "ack_result": event.ack_result,
                "ack_phase": event.ack_phase,
                "monotonic_ms": _relative_ms(self._started),
            }
        )


def _relative_ms(started: float) -> int:
    """Return a non-negative monotonic duration without a wall-clock timestamp."""
    return max(0, round((time.monotonic() - started) * 1000))


def _empty_response(mode: str, started: float, result: str) -> dict[str, Any]:
    """Return the fixed, JSON-safe response shape for a no-I/O rejection."""
    return {
        "mode": mode,
        "result": result,
        "cold_request_attempted": False,
        "retained_request_attempted": False,
        "request_count": 0,
        "same_session_retained": False,
        "normal_release_observed": False,
        "automatic_reconnect_observed": False,
        "observation_overflow": False,
        "duration_ms": _relative_ms(started),
        "requests": [],
        "events": [],
    }


async def _is_eligible_cold_idle(device: TuyaBLEDevice) -> bool:
    """Atomically prove the requested S1 runtime is truly cold and idle."""
    async with device._policy_lock:
        return (
            (device.category, device.product_id) == ("jtmspro", "xqeob8h6")
            and device.ble_control_enabled
            and device.connection_mode is ConnectionMode.ON_DEMAND
            and device.effective_policy is EffectiveConnectionPolicy.ON_DEMAND
            and device.policy_state is ConnectionPolicyState.ON_DEMAND_IDLE
            and not device.is_gatt_connected
            and not device.is_authenticated
            and not device.is_connection_active
            and device.active_lease_count == 0
            and device._active_response_drain_count == 0
            and device._connection_token is None
            and device._pending_release is None
            and not device._disconnect_in_progress
            and device._disconnect_idle_event.is_set()
            and not device._idle_disconnect_in_progress
            and device._idle_disconnect_task is None
            and device._reconnect_task is None
            and device._active_reconnect_task is None
            and device._scheduled_reconnect_delay is None
            and device._pending_reconnect_delay is None
            and device._disconnect_retry_task is None
        )


async def _wait_for_normal_release(
    device: TuyaBLEDevice,
    released: asyncio.Future[None],
) -> bool:
    """Wait only for a completed normal On-Demand idle release, never a guess."""
    if not device.is_connection_active:
        return False
    try:
        async with asyncio.timeout(
            device.on_demand_connection_hold_time + _RELEASE_CLEANUP_MARGIN_SECONDS
        ):
            await released
    except TimeoutError:
        return False
    return True


def _request_record(trial: int, result: str, started: float) -> dict[str, Any]:
    """Return one logical-request record without private transport identity."""
    return {
        "trial": trial,
        "result": result,
        "duration_ms": _relative_ms(started),
    }


async def async_run_phase_a_status_probe(
    device: TuyaBLEDevice,
    mode: str,
) -> dict[str, Any]:
    """Run exactly one cold trial, optionally followed by one retained trial.

    This is intentionally called from the service coroutine, not from a
    background task.  ``update()`` returning is not accepted as proof of a
    successful request: the matching private observer must report ACK_SUCCESS.
    """
    started = time.monotonic()
    if mode not in _MODES:
        return _empty_response(mode, started, "invalid_input")
    if not await _is_eligible_cold_idle(device):
        return _empty_response(mode, started, "precondition_failed")

    collector = _Collector(device, started)
    requests: list[dict[str, Any]] = []
    release_future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    first_session: object | None = None
    final_session: object | None = None
    automatic_reconnect = False
    cold_update_invoked = False
    retained_update_invoked = False

    def on_normal_release(session: object) -> None:
        if session is final_session and not release_future.done():
            release_future.set_result(None)

    def on_connection_state(connected: bool) -> None:
        nonlocal automatic_reconnect
        if (
            connected
            and first_session is not None
            and device._connection_token is not first_session
        ):
            automatic_reconnect = True

    unregister_observer = device.register_status_observer(collector)
    unregister_release = device.register_on_demand_idle_release_callback(
        on_normal_release
    )
    unregister_connection = device.register_connection_state_callback(
        on_connection_state
    )
    try:
        collector.expect_trial(1)
        cold_update_invoked = True
        try:
            await device.update()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - deliberately sanitize transport details
            if 1 in collector.created_trials:
                requests.append(_request_record(1, "update_failed", started))
        else:
            if 1 in collector.created_trials:
                first_session = collector.ack_success_sessions.get(1)
                if first_session is not None:
                    requests.append(_request_record(1, "ack_success", started))
                    final_session = first_session
                    if (
                        device.is_connection_active
                        and device._connection_token is not first_session
                    ):
                        automatic_reconnect = True
                elif 1 in collector.ack_failure_trials:
                    requests.append(_request_record(1, "ack_failed", started))
                else:
                    requests.append(_request_record(1, "ack_missing", started))

        same_session_retained = False
        cold_succeeded = (
            len(requests) == 1
            and requests[0]["result"] == "ack_success"
            and first_session is not None
            and device.is_connection_active
            and device._connection_token is first_session
            and not collector.overflow
        )
        if mode == MODE_COLD_THEN_RETAINED and cold_succeeded:
            collector.expect_trial(2)
            retained_update_invoked = True
            try:
                await device.update()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - deliberately sanitize transport details
                if 2 in collector.created_trials:
                    requests.append(_request_record(2, "update_failed", started))
            else:
                if 2 in collector.created_trials:
                    second_session = collector.ack_success_sessions.get(2)
                    same_session_retained = (
                        not collector.overflow
                        and second_session is first_session
                        and device.is_connection_active
                        and device._connection_token is first_session
                    )
                    if same_session_retained:
                        requests.append(_request_record(2, "ack_success", started))
                        final_session = second_session
                    elif 2 in collector.ack_failure_trials:
                        requests.append(_request_record(2, "ack_failed", started))
                    else:
                        requests.append(
                            _request_record(2, "session_not_retained", started)
                        )

        normal_release_observed = (
            await _wait_for_normal_release(device, release_future)
            if final_session is not None
            else False
        )
        completed = (
            bool(requests)
            and all(request["result"] == "ack_success" for request in requests)
            and (mode == MODE_COLD or same_session_retained)
            and normal_release_observed
            and not automatic_reconnect
            and not collector.overflow
        )
        return {
            "mode": mode,
            "result": "completed" if completed else "invalid_or_incomplete",
            "cold_request_attempted": cold_update_invoked,
            "retained_request_attempted": retained_update_invoked,
            "request_count": len(requests),
            "same_session_retained": same_session_retained,
            "normal_release_observed": normal_release_observed,
            "automatic_reconnect_observed": automatic_reconnect,
            "observation_overflow": collector.overflow,
            "duration_ms": _relative_ms(started),
            "requests": requests,
            "events": collector.events,
        }
    finally:
        unregister_connection()
        unregister_release()
        unregister_observer()


def _device_for_service_call(
    hass: HomeAssistant, entry_id: str
) -> TuyaBLEDevice | None:
    """Look up one loaded config entry without retaining its private identifier."""
    entry = hass.config_entries.async_get_entry(entry_id)
    if entry is None or entry.state is not ConfigEntryState.LOADED:
        return None
    data = hass.data.get(DOMAIN, {}).get(entry_id)
    device = getattr(data, "device", None)
    return device if isinstance(device, TuyaBLEDevice) else None


async def _async_handle_phase_a_status_probe(
    hass: HomeAssistant,
    call: ServiceCall,
) -> dict[str, Any]:
    """Run one isolated service call under its dedicated per-device owner."""
    mode: str = call.data[ATTR_MODE]
    started = time.monotonic()
    device = _device_for_service_call(hass, call.data[ATTR_CONFIG_ENTRY_ID])
    if device is None:
        return _empty_response(mode, started, "precondition_failed")
    locks: dict[TuyaBLEDevice, asyncio.Lock] = hass.data[DOMAIN].setdefault(
        _LOCKS_DATA_KEY, {}
    )
    lock = locks.setdefault(device, asyncio.Lock())
    if lock.locked():
        return _empty_response(mode, started, "probe_already_active")
    try:
        async with lock:
            return await async_run_phase_a_status_probe(device, mode)
    finally:
        if not lock.locked() and locks.get(device) is lock:
            locks.pop(device, None)


def async_register_phase_a_status_probe(hass: HomeAssistant) -> None:
    """Register the temporary response-only service once per integration domain."""
    # Narrow synthetic setup tests intentionally use an incomplete hass shape;
    # real Home Assistant always exposes the service registry.
    if not hasattr(hass, "services"):
        return
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get(_SERVICE_DATA_KEY):
        return

    async def handler(call: ServiceCall) -> dict[str, Any]:
        return await _async_handle_phase_a_status_probe(hass, call)

    hass.services.async_register(
        DOMAIN,
        SERVICE_PHASE_A_STATUS_PROBE,
        handler,
        schema=SERVICE_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
    domain_data[_SERVICE_DATA_KEY] = True


def async_unregister_phase_a_status_probe_if_unused(hass: HomeAssistant) -> None:
    """Remove the temporary service after the final Tuya BLE entry unloads."""
    if not hasattr(hass, "services"):
        return
    domain_data = hass.data.get(DOMAIN, {})
    loaded_entries = [key for key in domain_data if not key.startswith("_")]
    if loaded_entries or not domain_data.get(_SERVICE_DATA_KEY):
        return
    hass.services.async_remove(DOMAIN, SERVICE_PHASE_A_STATUS_PROBE)
    domain_data.pop(_SERVICE_DATA_KEY, None)
