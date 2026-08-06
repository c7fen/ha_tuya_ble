"""Current-callback-batch contracts for Last Unlock Method sensors."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from custom_components.tuya_ble import devices, sensor

S1_DEVICE = SimpleNamespace(category="jtmspro", product_id="xqeob8h6")
V1_DEVICE = SimpleNamespace(category="ms", product_id="7a4xvbtt")
LOCK_PRODUCTS = (S1_DEVICE, V1_DEVICE)


def _unlock_methods(device: SimpleNamespace):
    return next(
        mapping.unlock_methods
        for mapping in sensor.get_mapping_by_device(device)
        if mapping.description.key == "last_unlock_method"
    )


class BatchDatapoint:
    """Synthetic datapoint from exactly one device callback batch."""

    def __init__(
        self,
        dp_id: int,
        value: Any = 1,
        *,
        changed_by_device: bool = False,
    ) -> None:
        self.id = dp_id
        self.value = value
        self.changed_by_device = changed_by_device


class LastUnlockHarness:
    """Drive the entity with the coordinator's transient batch contract."""

    def __init__(self, unlock_methods) -> None:
        self.coordinator = SimpleNamespace(connected=True, last_updates=None)
        self.writes: list[bool] = []
        self.entity = SimpleNamespace(
            _unlock_methods=unlock_methods,
            _coordinator=self.coordinator,
            _last_connected=True,
            _attr_native_value=None,
            _attr_extra_state_attributes={},
            async_write_ha_state=lambda: self.writes.append(True),
        )

    def emit(self, *datapoints: BatchDatapoint) -> None:
        self.coordinator.last_updates = list(datapoints)
        sensor.TuyaBLELastUnlockSensor._handle_coordinator_update(self.entity)
        self.coordinator.last_updates = None


def test_coordinator_exposes_batch_only_while_notifying_last_unlock_sensor() -> None:
    """The entity sees the current batch and cannot reuse it on a later update."""
    coordinator = object.__new__(devices.TuyaBLECoordinator)
    coordinator._device = SimpleNamespace(category="unknown", product_id="unknown")
    coordinator._disconnected = False
    coordinator._unsub_disconnect = None
    coordinator.last_updates = None
    writes: list[bool] = []
    entity = SimpleNamespace(
        _unlock_methods=_unlock_methods(S1_DEVICE),
        _coordinator=coordinator,
        _last_connected=True,
        _attr_native_value=None,
        _attr_extra_state_attributes={},
        async_write_ha_state=lambda: writes.append(True),
    )
    coordinator.async_set_updated_data = lambda _: (
        sensor.TuyaBLELastUnlockSensor._handle_coordinator_update(entity)
    )

    coordinator._async_handle_update([BatchDatapoint(12, 4)])
    assert entity._attr_native_value == "fingerprint"
    assert coordinator.last_updates is None

    coordinator._async_handle_update([BatchDatapoint(250, 99)])
    assert entity._attr_native_value == "fingerprint"
    assert len(writes) == 1


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("s1", "v1"))
def test_full_initial_snapshot_does_not_invent_unlock_method(product) -> None:
    """A multi-method initial snapshot is ambiguous and leaves state unknown."""
    harness = LastUnlockHarness(_unlock_methods(product))

    harness.emit(
        *(
            BatchDatapoint(dp_id, changed_by_device=False)
            for dp_id in _unlock_methods(product)
        )
    )

    assert harness.entity._attr_native_value is None
    assert harness.entity._attr_extra_state_attributes == {}
    assert harness.writes == []


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("s1", "v1"))
def test_ambiguous_snapshot_preserves_prior_unlock_event(product) -> None:
    """A later ambiguous snapshot cannot overwrite a recorded event."""
    methods = _unlock_methods(product)
    harness = LastUnlockHarness(methods)
    harness.emit(BatchDatapoint(19, 7))
    previous_attributes = harness.entity._attr_extra_state_attributes.copy()

    harness.emit(*(BatchDatapoint(dp_id, 0) for dp_id in methods))

    assert harness.entity._attr_native_value == "ble"
    assert harness.entity._attr_extra_state_attributes == previous_attributes
    assert len(harness.writes) == 1


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("s1", "v1"))
@pytest.mark.parametrize(
    ("dp_id", "method"),
    ((12, "fingerprint"), (15, "card"), (19, "ble")),
)
def test_single_mapped_candidate_reports_method(product, dp_id, method) -> None:
    """One mapped datapoint is an unambiguous callback-batch event."""
    harness = LastUnlockHarness(_unlock_methods(product))

    harness.emit(BatchDatapoint(dp_id, 8))

    assert harness.entity._attr_native_value == method
    assert harness.entity._attr_extra_state_attributes == {
        "method": method,
        "value": 8,
    }
    assert len(harness.writes) == 1


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("s1", "v1"))
def test_one_changed_candidate_disambiguates_multi_dp_batch(product) -> None:
    """Exactly one device-changed candidate selects the reported method."""
    harness = LastUnlockHarness(_unlock_methods(product))

    harness.emit(
        BatchDatapoint(12, 3),
        BatchDatapoint(15, 4, changed_by_device=True),
    )

    assert harness.entity._attr_native_value == "card"
    assert harness.entity._attr_extra_state_attributes == {
        "method": "card",
        "value": 4,
    }


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("s1", "v1"))
def test_multiple_changed_candidates_remain_ambiguous(product) -> None:
    """Mapping order never resolves a batch containing multiple changed methods."""
    harness = LastUnlockHarness(_unlock_methods(product))
    harness.emit(BatchDatapoint(19, 5))

    harness.emit(
        BatchDatapoint(12, 6, changed_by_device=True),
        BatchDatapoint(15, 7, changed_by_device=True),
    )

    assert harness.entity._attr_native_value == "ble"
    assert harness.entity._attr_extra_state_attributes == {
        "method": "ble",
        "value": 5,
    }
    assert len(harness.writes) == 1


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("s1", "v1"))
def test_repeated_same_method_and_credential_forces_fresh_updates(product) -> None:
    """Two current batches remain two events even when their values match."""
    harness = LastUnlockHarness(_unlock_methods(product))

    harness.emit(BatchDatapoint(12, 9, changed_by_device=False))
    harness.emit(BatchDatapoint(12, 9, changed_by_device=False))

    assert harness.entity._attr_native_value == "fingerprint"
    assert harness.entity._attr_extra_state_attributes == {
        "method": "fingerprint",
        "value": 9,
    }
    assert len(harness.writes) == 2
    entity = object.__new__(sensor.TuyaBLELastUnlockSensor)
    assert entity.force_update is True


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("s1", "v1"))
def test_unmapped_current_batch_preserves_prior_state(product) -> None:
    """A stale mapped datapoint outside the callback batch is never consulted."""
    harness = LastUnlockHarness(_unlock_methods(product))
    harness.emit(BatchDatapoint(12, 2))

    harness.emit(BatchDatapoint(250, 99, changed_by_device=True))

    assert harness.entity._attr_native_value == "fingerprint"
    assert harness.entity._attr_extra_state_attributes == {
        "method": "fingerprint",
        "value": 2,
    }
    assert len(harness.writes) == 1


@pytest.mark.parametrize("product", LOCK_PRODUCTS, ids=("s1", "v1"))
def test_raw_values_never_enter_last_unlock_attributes(product) -> None:
    """Unexpected bytes cannot be copied into Home Assistant state attributes."""
    harness = LastUnlockHarness(_unlock_methods(product))

    harness.emit(BatchDatapoint(12, b"synthetic-non-secret"))

    assert harness.entity._attr_native_value == "fingerprint"
    assert harness.entity._attr_extra_state_attributes == {"method": "fingerprint"}
