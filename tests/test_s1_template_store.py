"""S1 template capture and datapoint-provenance contracts."""

from __future__ import annotations

import base64
import hashlib
from unittest.mock import AsyncMock, Mock

import pytest
from bleak.backends.device import BLEDevice
from homeassistant.core import HomeAssistant

from custom_components.tuya_ble.lock import (
    S1_DP71_MIN_LENGTH,
    TuyaBLES1TemplateStore,
)
from custom_components.tuya_ble.tuya_ble import (
    TuyaBLEDataPointType,
    TuyaBLEDevice,
)

from . import claim_test_session

SYNTHETIC_DEVICE_ID = "synthetic-s1-device"
SYNTHETIC_DP70_SAMPLE_LENGTH = 16
SYNTHETIC_DP70 = hashlib.shake_256(b"tuya-ble-test-only:synthetic-store-dp70").digest(
    SYNTHETIC_DP70_SAMPLE_LENGTH
)
SYNTHETIC_DP71 = hashlib.shake_256(b"tuya-ble-test-only:synthetic-store-dp71").digest(
    S1_DP71_MIN_LENGTH
)


class _BackingStore:
    def __init__(self) -> None:
        self.delayed_saves: list[tuple[object, float]] = []

    def async_delay_save(self, data_func, delay: float = 0) -> None:
        self.delayed_saves.append((data_func, delay))


class _SnapshotInspectingStore:
    """Inspect the exact atomic snapshot handed to persistent storage."""

    def __init__(self, expected_dp70: bytes, expected_dp71: bytes) -> None:
        self.expected_dp70 = base64.b64encode(expected_dp70).decode("ascii")
        self.expected_dp71 = base64.b64encode(expected_dp71).decode("ascii")
        self.observed_complete_pairs: list[bool] = []

    def async_delay_save(self, data_func, delay: float = 0) -> None:
        snapshot = data_func()
        device_data = snapshot.get(SYNTHETIC_DEVICE_ID, {})
        complete_pair = (
            delay == 0
            and set(snapshot) == {SYNTHETIC_DEVICE_ID}
            and isinstance(device_data, dict)
            and device_data.get("dp70_b64") == self.expected_dp70
            and device_data.get("dp71_b64") == self.expected_dp71
        )
        self.observed_complete_pairs.append(complete_pair)
        raise RuntimeError("synthetic persistence scheduling failure")


def _make_device() -> TuyaBLEDevice:
    device = TuyaBLEDevice(
        Mock(),
        BLEDevice(
            name="Synthetic S1",
            address="00:00:00:00:00:01",
            details={},
            rssi=-50,
        ),
    )
    device._send_datapoints = AsyncMock()
    return device


async def test_local_datapoints_are_not_inbound_provenance() -> None:
    """Lazy creation and local writes cannot masquerade as device updates."""
    device = _make_device()
    session_token = claim_test_session(device)
    datapoint = device.datapoints.get_or_create(
        70, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70
    )
    assert datapoint.received_from_device is False

    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70, session_token
    )
    assert datapoint.received_from_device is True

    await datapoint.set_value(SYNTHETIC_DP70)
    assert datapoint.received_from_device is False

    device.datapoints._update_from_device(
        71, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP71, session_token
    )
    assert device.datapoints[71].received_from_device is True
    await device.set_multiple_values({71: SYNTHETIC_DP71})
    assert device.datapoints[71].received_from_device is False


def test_capture_persists_only_valid_inbound_device_templates(
    hass: HomeAssistant,
) -> None:
    """Only structurally valid raw inbound values enter the device-scoped store."""
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, {})

    local_dp70 = device.datapoints.get_or_create(
        70, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70
    )
    assert template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [local_dp70]) is False
    assert backing_store.delayed_saves == []

    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70, session_token
    )
    device.datapoints._update_from_device(
        71, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP71, session_token
    )
    assert (
        template_store.capture_inbound(
            SYNTHETIC_DEVICE_ID,
            [device.datapoints[70], device.datapoints[71]],
        )
        is True
    )
    assert len(backing_store.delayed_saves) == 1
    data_func, delay = backing_store.delayed_saves[0]
    assert delay == 0
    assert data_func() == {
        SYNTHETIC_DEVICE_ID: {
            "category": "jtmspro",
            "product_id": "xqeob8h6",
            "format_version": 1,
            "dp70_b64": base64.b64encode(SYNTHETIC_DP70).decode("ascii"),
            "dp71_b64": base64.b64encode(SYNTHETIC_DP71).decode("ascii"),
        }
    }
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) == (
        SYNTHETIC_DP70,
        SYNTHETIC_DP71,
    )


def test_capture_rejects_wrong_type_length_and_empty_device_id(
    hass: HomeAssistant,
) -> None:
    """Invalid or unscoped inbound updates never enter persistent storage."""
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, {})

    device.datapoints._update_from_device(
        70,
        1.0,
        0,
        TuyaBLEDataPointType.DT_RAW,
        b"",
        session_token,
    )
    device.datapoints._update_from_device(
        71,
        1.0,
        0,
        TuyaBLEDataPointType.DT_STRING,
        "synthetic string",
        session_token,
    )
    updates = [device.datapoints[70], device.datapoints[71]]
    assert template_store.capture_inbound(SYNTHETIC_DEVICE_ID, updates) is False
    assert template_store.capture_inbound("", updates) is False
    assert backing_store.delayed_saves == []


def test_capture_accepts_variable_length_inbound_templates(
    hass: HomeAssistant,
) -> None:
    """Live capture preserves valid nonempty DP70 and extended DP71 templates."""
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, {})
    extended_dp70 = hashlib.shake_256(
        b"tuya-ble-test-only:synthetic-capture-variable-dp70"
    ).digest(29)
    extended_dp71 = hashlib.shake_256(
        b"tuya-ble-test-only:synthetic-capture-variable-dp71"
    ).digest(S1_DP71_MIN_LENGTH + 11)

    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, extended_dp70, session_token
    )
    device.datapoints._update_from_device(
        71, 1.0, 0, TuyaBLEDataPointType.DT_RAW, extended_dp71, session_token
    )

    assert template_store.capture_inbound(
        SYNTHETIC_DEVICE_ID,
        [device.datapoints[70], device.datapoints[71]],
    )
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) == (
        extended_dp70,
        extended_dp71,
    )


def test_capture_accepts_separate_batches_for_the_same_device_only(
    hass: HomeAssistant,
) -> None:
    """DP70 and DP71 may arrive separately but remain in one device record."""
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, {})

    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70, session_token
    )
    assert template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[70]])
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) is None
    assert backing_store.delayed_saves == []

    device.datapoints._update_from_device(
        71, 2.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP71, session_token
    )
    assert template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[71]])
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) == (
        SYNTHETIC_DP70,
        SYNTHETIC_DP71,
    )
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID, session_token.epoch) == (
        SYNTHETIC_DP70,
        SYNTHETIC_DP71,
    )
    assert len(backing_store.delayed_saves) == 1


@pytest.mark.parametrize("partial_dp_id", (70, 71))
def test_partial_current_session_pair_cannot_replace_persisted_half(
    hass: HomeAssistant, partial_dp_id: int
) -> None:
    """A partial refresh remains pending and leaves Pair A unchanged."""
    pair_b_dp70 = hashlib.shake_256(
        b"tuya-ble-test-only:partial-refresh-pair-b-dp70"
    ).digest(SYNTHETIC_DP70_SAMPLE_LENGTH)
    pair_b_dp71 = hashlib.shake_256(
        b"tuya-ble-test-only:partial-refresh-pair-b-dp71"
    ).digest(S1_DP71_MIN_LENGTH)
    persisted = {
        SYNTHETIC_DEVICE_ID: {
            "dp70_b64": base64.b64encode(SYNTHETIC_DP70).decode("ascii"),
            "dp71_b64": base64.b64encode(SYNTHETIC_DP71).decode("ascii"),
        }
    }
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, persisted)
    value = pair_b_dp70 if partial_dp_id == 70 else pair_b_dp71

    device.datapoints._update_from_device(
        partial_dp_id,
        1.0,
        0,
        TuyaBLEDataPointType.DT_RAW,
        value,
        session_token,
    )

    assert template_store.capture_inbound(
        SYNTHETIC_DEVICE_ID, [device.datapoints[partial_dp_id]]
    )
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) == (
        SYNTHETIC_DP70,
        SYNTHETIC_DP71,
    )
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID, session_token.epoch) == (
        SYNTHETIC_DP70,
        SYNTHETIC_DP71,
    )
    assert backing_store.delayed_saves == []


@pytest.mark.parametrize(
    ("partial_dp_id", "partial_type", "partial_value"),
    (
        (70, TuyaBLEDataPointType.DT_RAW, b""),
        (71, TuyaBLEDataPointType.DT_STRING, "synthetic malformed template"),
    ),
)
def test_malformed_current_half_preserves_complete_persisted_pair(
    hass: HomeAssistant,
    partial_dp_id: int,
    partial_type: TuyaBLEDataPointType,
    partial_value: bytes | str,
) -> None:
    """Malformed session material cannot alter the persisted fallback."""
    persisted = {
        SYNTHETIC_DEVICE_ID: {
            "dp70_b64": base64.b64encode(SYNTHETIC_DP70).decode("ascii"),
            "dp71_b64": base64.b64encode(SYNTHETIC_DP71).decode("ascii"),
        }
    }
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, persisted)
    device.datapoints._update_from_device(
        partial_dp_id,
        1.0,
        0,
        partial_type,
        partial_value,
        session_token,
    )

    assert (
        template_store.capture_inbound(
            SYNTHETIC_DEVICE_ID, [device.datapoints[partial_dp_id]]
        )
        is False
    )
    selected_persisted_pair = template_store.templates_for(
        SYNTHETIC_DEVICE_ID, session_token.epoch
    ) == (SYNTHETIC_DP70, SYNTHETIC_DP71)
    assert selected_persisted_pair
    assert backing_store.delayed_saves == []


def test_complete_pair_promotion_exposes_only_one_atomic_store_snapshot(
    hass: HomeAssistant,
) -> None:
    """Even a scheduling failure observes only the complete replacement pair."""
    pair_b_dp70 = hashlib.shake_256(
        b"tuya-ble-test-only:atomic-snapshot-pair-b-dp70"
    ).digest(SYNTHETIC_DP70_SAMPLE_LENGTH)
    pair_b_dp71 = hashlib.shake_256(
        b"tuya-ble-test-only:atomic-snapshot-pair-b-dp71"
    ).digest(S1_DP71_MIN_LENGTH)
    persisted = {
        SYNTHETIC_DEVICE_ID: {
            "dp70_b64": base64.b64encode(SYNTHETIC_DP70).decode("ascii"),
            "dp71_b64": base64.b64encode(SYNTHETIC_DP71).decode("ascii"),
        }
    }
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _SnapshotInspectingStore(pair_b_dp70, pair_b_dp71)
    template_store = TuyaBLES1TemplateStore(hass, backing_store, persisted)

    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, pair_b_dp70, session_token
    )
    assert template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[70]])
    selected_persisted_pair = template_store.templates_for(
        SYNTHETIC_DEVICE_ID, session_token.epoch
    ) == (SYNTHETIC_DP70, SYNTHETIC_DP71)
    assert selected_persisted_pair
    assert backing_store.observed_complete_pairs == []

    device.datapoints._update_from_device(
        71, 2.0, 0, TuyaBLEDataPointType.DT_RAW, pair_b_dp71, session_token
    )
    with pytest.raises(RuntimeError, match="synthetic persistence scheduling failure"):
        template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[71]])

    assert backing_store.observed_complete_pairs == [True]
    selected_replacement_pair = template_store.templates_for(
        SYNTHETIC_DEVICE_ID, session_token.epoch
    ) == (pair_b_dp70, pair_b_dp71)
    assert selected_replacement_pair


def test_new_partial_after_promotion_cannot_mix_with_completed_pair(
    hass: HomeAssistant,
) -> None:
    """A later DP70 starts a new pending pair instead of reusing promoted DP71."""
    pair_b_dp70 = hashlib.shake_256(b"tuya-ble-test-only:promoted-pair-b-dp70").digest(
        SYNTHETIC_DP70_SAMPLE_LENGTH
    )
    pair_b_dp71 = hashlib.shake_256(b"tuya-ble-test-only:promoted-pair-b-dp71").digest(
        S1_DP71_MIN_LENGTH
    )
    pair_c_dp70 = hashlib.shake_256(b"tuya-ble-test-only:pending-pair-c-dp70").digest(
        SYNTHETIC_DP70_SAMPLE_LENGTH
    )
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, {})

    for dp_id, value in ((70, pair_b_dp70), (71, pair_b_dp71)):
        device.datapoints._update_from_device(
            dp_id, 1.0, 0, TuyaBLEDataPointType.DT_RAW, value, session_token
        )
    assert template_store.capture_inbound(
        SYNTHETIC_DEVICE_ID, [device.datapoints[70], device.datapoints[71]]
    )
    assert len(backing_store.delayed_saves) == 1

    device.datapoints._update_from_device(
        70, 2.0, 0, TuyaBLEDataPointType.DT_RAW, pair_c_dp70, session_token
    )
    assert template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[70]])

    assert template_store.templates_for(SYNTHETIC_DEVICE_ID, session_token.epoch) == (
        pair_b_dp70,
        pair_b_dp71,
    )
    assert len(backing_store.delayed_saves) == 1


def test_template_halves_from_different_session_epochs_never_combine(
    hass: HomeAssistant,
) -> None:
    """DP70 from Session 1 cannot pair with DP71 from Session 2."""
    device = _make_device()
    session_one = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, {})
    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70, session_one
    )
    assert template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[70]])

    session_one.client.is_connected = False
    session_two = claim_test_session(device)
    device.datapoints._update_from_device(
        71, 2.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP71, session_two
    )
    assert template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[71]])

    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) is None
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID, session_two.epoch) is None
    assert backing_store.delayed_saves == []


def test_delayed_old_session_update_cannot_restore_pending_readiness(
    hass: HomeAssistant,
) -> None:
    """An update carrying a retired token cannot enter pending state or Store."""
    device = _make_device()
    session_one = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, {})
    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70, session_one
    )

    session_one.client.is_connected = False
    session_two = claim_test_session(device)
    device.datapoints._update_from_device(
        71, 2.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP71, session_two
    )
    assert template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[71]])
    device.datapoints._update_from_device(
        70, 3.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70, session_one
    )

    assert (
        template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[70]])
        is False
    )
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) is None
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID, session_two.epoch) is None
    assert backing_store.delayed_saves == []


def test_capture_rejects_conflicting_stored_product_metadata(
    hass: HomeAssistant,
) -> None:
    """Inbound data cannot bless a record scoped to a conflicting product."""
    conflicting = {
        SYNTHETIC_DEVICE_ID: {
            "category": "jtmspro",
            "product_id": "synthetic-conflicting-product",
        }
    }
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, conflicting)
    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70, session_token
    )

    assert (
        template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[70]])
        is False
    )
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) is None
    assert backing_store.delayed_saves == []


async def test_outgoing_timestamped_dp71_cannot_replace_inbound_template(
    hass: HomeAssistant,
) -> None:
    """A locally rebuilt outgoing DP71 is never persisted as inbound evidence."""
    device = _make_device()
    session_token = claim_test_session(device)
    backing_store = _BackingStore()
    template_store = TuyaBLES1TemplateStore(hass, backing_store, {})
    device.datapoints._update_from_device(
        70, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP70, session_token
    )
    device.datapoints._update_from_device(
        71, 1.0, 0, TuyaBLEDataPointType.DT_RAW, SYNTHETIC_DP71, session_token
    )
    assert template_store.capture_inbound(
        SYNTHETIC_DEVICE_ID,
        [device.datapoints[70], device.datapoints[71]],
    )
    backing_store.delayed_saves.clear()

    outgoing = bytearray(SYNTHETIC_DP71)
    outgoing[13:17] = (1_700_000_321).to_bytes(4, "big")
    await device.datapoints[71].set_value(bytes(outgoing))

    assert (
        template_store.capture_inbound(SYNTHETIC_DEVICE_ID, [device.datapoints[71]])
        is False
    )
    assert template_store.templates_for(SYNTHETIC_DEVICE_ID) == (
        SYNTHETIC_DP70,
        SYNTHETIC_DP71,
    )
    assert backing_store.delayed_saves == []
