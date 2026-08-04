"""Config-entry compatibility tests for the upstream migration."""

from __future__ import annotations

import asyncio
from types import MappingProxyType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from homeassistant.const import (
    CONF_ADDRESS,
    CONF_COUNTRY_CODE,
    CONF_DEVICE_ID,
    CONF_PASSWORD,
    CONF_USERNAME,
)
from homeassistant.exceptions import ConfigEntryError, ConfigEntryNotReady

from custom_components import tuya_ble as integration
from custom_components.tuya_ble.cloud import (
    HASSTuyaBLEDeviceManager,
    normalize_app_type_data,
)
from custom_components.tuya_ble.const import (
    CONF_ACCESS_ID,
    CONF_ACCESS_SECRET,
    CONF_APP_TYPE,
    CONF_AUTH_TYPE,
    CONF_CATEGORY,
    CONF_DEVICE_NAME,
    CONF_ENDPOINT,
    CONF_LEGACY_APP_TYPE,
    CONF_LOCAL_KEY,
    CONF_PRODUCT_ID,
    CONF_PRODUCT_MODEL,
    CONF_PRODUCT_NAME,
    CONF_SEC_KEY,
    CONF_UUID,
    DOMAIN,
)

ADDRESS = "00:11:22:33:44:55"


class SyntheticLegacyEntry:
    """Minimal immutable v0.1.11b2-shaped config entry."""

    def __init__(self, options: dict) -> None:
        self.data = MappingProxyType({CONF_ADDRESS: ADDRESS})
        self.options = MappingProxyType(options)
        self.domain = DOMAIN
        self.entry_id = "synthetic-b2-entry"
        self.title = "Synthetic legacy lock"
        self.unique_id = ADDRESS
        self.version = 1
        self.minor_version = 1
        self.async_on_unload = Mock()
        self.add_update_listener = Mock(return_value=Mock())


def _legacy_options(**overrides) -> dict:
    options = {
        CONF_ENDPOINT: "https://example.invalid",
        CONF_ACCESS_ID: "synthetic-access-id",
        CONF_ACCESS_SECRET: "synthetic-access-secret",
        CONF_AUTH_TYPE: "smart_home",
        CONF_USERNAME: "synthetic-user",
        CONF_PASSWORD: "synthetic-password",
        CONF_COUNTRY_CODE: "1",
        CONF_LEGACY_APP_TYPE: "smartlife",
        CONF_UUID: "synthetic-uuid",
        CONF_LOCAL_KEY: "synthetic-local-key",
        CONF_SEC_KEY: "synthetic-sec-key",
        CONF_DEVICE_ID: "synthetic-device-id",
        CONF_CATEGORY: "jtmspro",
        CONF_PRODUCT_ID: "xqeob8h6",
        CONF_DEVICE_NAME: "Synthetic lock",
        CONF_PRODUCT_MODEL: "Synthetic S1",
        CONF_PRODUCT_NAME: "Synthetic lock",
    }
    options.update(overrides)
    return options


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ({CONF_LEGACY_APP_TYPE: "smartlife"}, "smartlife"),
        ({CONF_APP_TYPE: "tuyaSmart"}, "tuyaSmart"),
        (
            {
                CONF_LEGACY_APP_TYPE: "smartlife",
                CONF_APP_TYPE: "smartlife",
            },
            "smartlife",
        ),
    ),
)
def test_app_type_compatibility_is_in_memory_only(source: dict, expected: str) -> None:
    """Legacy, current, and equal dual-key data normalize without mutation."""
    original = source.copy()

    normalized = normalize_app_type_data(source)

    assert source == original
    assert normalized[CONF_LEGACY_APP_TYPE] == expected
    assert normalized[CONF_APP_TYPE] == expected


def test_synthetic_b2_entry_loads_without_reconfiguration() -> None:
    """A b2-shaped entry reaches platform forwarding with stable stored data."""

    async def exercise() -> None:
        original_options = _legacy_options()
        entry = SyntheticLegacyEntry(original_options)
        forwarded = AsyncMock()
        config_entries = SimpleNamespace(
            async_forward_entry_setups=forwarded,
            async_update_entry=Mock(),
            async_init=AsyncMock(),
        )
        hass = SimpleNamespace(
            data={},
            config_entries=config_entries,
            add_job=Mock(),
            bus=SimpleNamespace(async_listen_once=Mock(return_value=Mock())),
        )
        fake_device = SimpleNamespace(
            initialize=AsyncMock(),
            update=Mock(return_value="scheduled update"),
            stop=AsyncMock(),
            category="jtmspro",
            product_id="xqeob8h6",
            device_id="synthetic-device-id",
            address=ADDRESS,
        )
        managers: list[HASSTuyaBLEDeviceManager] = []
        setup_order: list[str] = []

        def make_manager(fake_hass, data):
            manager = HASSTuyaBLEDeviceManager(fake_hass, data)
            managers.append(manager)
            return manager

        def migration(*_args) -> None:
            setup_order.append("migration")

        async def forward(*_args) -> None:
            setup_order.append("forward")

        forwarded.side_effect = forward
        with (
            patch.object(
                integration.bluetooth,
                "async_ble_device_from_address",
                return_value=object(),
            ),
            patch.object(
                integration, "HASSTuyaBLEDeviceManager", side_effect=make_manager
            ),
            patch.object(integration, "TuyaBLEDevice", return_value=fake_device),
            patch.object(integration, "get_device_product_info", return_value=object()),
            patch.object(
                integration,
                "_async_migrate_s1_motor_state_entity",
                side_effect=migration,
            ),
            patch.object(integration, "TuyaBLECoordinator", return_value=object()),
            patch.object(
                integration.bluetooth,
                "async_register_callback",
                return_value=Mock(),
            ),
        ):
            assert await integration.async_setup_entry(hass, entry) is True

        assert setup_order == ["migration", "forward"]
        assert dict(entry.options) == original_options
        assert dict(entry.data) == {CONF_ADDRESS: ADDRESS}
        assert entry.unique_id == ADDRESS
        assert entry.version == 1
        assert entry.minor_version == 1
        config_entries.async_update_entry.assert_not_called()
        config_entries.async_init.assert_not_awaited()

        manager = managers[0]
        assert manager._data[CONF_LEGACY_APP_TYPE] == "smartlife"
        assert manager._data[CONF_APP_TYPE] == "smartlife"
        manager.login = AsyncMock()
        credentials = await manager.get_device_credentials(ADDRESS)
        assert credentials is not None
        assert credentials.device_id == "synthetic-device-id"
        assert credentials.sec_key == "synthetic-sec-key"
        manager.login.assert_not_awaited()

    asyncio.run(exercise())


def test_conflicting_app_types_fail_before_bluetooth_or_forwarding() -> None:
    """Divergent app-type keys fail closed without revealing either value."""

    async def exercise() -> None:
        entry = SyntheticLegacyEntry(
            _legacy_options(
                **{
                    CONF_LEGACY_APP_TYPE: "legacy-private-value",
                    CONF_APP_TYPE: "current-private-value",
                }
            )
        )
        hass = SimpleNamespace(
            config_entries=SimpleNamespace(async_forward_entry_setups=AsyncMock())
        )

        with (
            patch.object(
                integration.bluetooth, "async_ble_device_from_address"
            ) as bluetooth_lookup,
            patch.object(integration, "HASSTuyaBLEDeviceManager") as manager_factory,
            pytest.raises(ConfigEntryError) as error,
        ):
            await integration.async_setup_entry(hass, entry)

        bluetooth_lookup.assert_not_called()
        manager_factory.assert_not_called()
        hass.config_entries.async_forward_entry_setups.assert_not_awaited()
        assert "legacy-private-value" not in str(error.value)
        assert "current-private-value" not in str(error.value)
        assert dict(entry.options)[CONF_LEGACY_APP_TYPE] == "legacy-private-value"
        assert dict(entry.options)[CONF_APP_TYPE] == "current-private-value"

    asyncio.run(exercise())


def test_missing_device_error_does_not_expose_complete_address() -> None:
    """Discovery failures identify no complete configured BLE address."""

    async def exercise() -> None:
        entry = SyntheticLegacyEntry(_legacy_options())
        hass = SimpleNamespace()

        with (
            patch.object(
                integration.bluetooth,
                "async_ble_device_from_address",
                return_value=None,
            ),
            patch.object(integration, "get_device", new=AsyncMock(return_value=None)),
            pytest.raises(ConfigEntryNotReady) as error,
        ):
            await integration.async_setup_entry(hass, entry)

        assert ADDRESS not in str(error.value)

    asyncio.run(exercise())
