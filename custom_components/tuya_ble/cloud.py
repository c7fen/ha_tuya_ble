"""The Tuya BLE integration."""

from __future__ import annotations

import logging

from dataclasses import dataclass
import json
from typing import Any, Iterable

from homeassistant.const import (
    CONF_ADDRESS,
    CONF_DEVICE_ID,
    CONF_COUNTRY_CODE,
    CONF_PASSWORD,
    CONF_USERNAME,
)

from homeassistant.core import HomeAssistant

from tuya_iot import (
    TuyaOpenAPI,
    AuthType,
)

from .tuya_ble import (
    AbstaractTuyaBLEDeviceManager,
    TuyaBLEDeviceCredentials,
)

from .const import (
    TUYA_DOMAIN,
    CONF_ACCESS_ID,
    CONF_ACCESS_SECRET,
    CONF_APP_TYPE,
    CONF_AUTH_TYPE,
    CONF_ENDPOINT,
    CONF_PRODUCT_MODEL,
    CONF_UUID,
    CONF_LOCAL_KEY,
    CONF_LEGACY_APP_TYPE,
    CONF_SEC_KEY,
    CONF_CATEGORY,
    CONF_PRODUCT_ID,
    CONF_DEVICE_NAME,
    CONF_PRODUCT_NAME,
    CONF_FUNCTIONS,
    CONF_STATUS_RANGE,
    DOMAIN,
    TUYA_API_DEVICES_URL,
    TUYA_API_FACTORY_INFO_URL,
    TUYA_API_DEVICE_SPECIFICATION,
    TUYA_FACTORY_INFO_MAC,
    TUYA_RESPONSE_RESULT,
    TUYA_RESPONSE_SUCCESS,
)

_LOGGER = logging.getLogger(__name__)

# Advertised (possibly random) BLE address -> factory MAC.
_address_aliases: dict[str, str] = {}
_ADV_SERVICE_UUID_FD50 = "0000fd50-0000-1000-8000-00805f9b34fb"
_ADV_SERVICE_UUID_A201 = "0000a201-0000-1000-8000-00805f9b34fb"
_ADV_MANUFACTURER_DATA_ID = 0x07D0


def _advertised_tuya_id(service_data: dict[str, bytes]) -> tuple[bool, bytes | None]:
    """Return (is_tuya, id field) from Tuya A201/FD50 service data."""
    a201 = service_data.get(_ADV_SERVICE_UUID_A201)
    if a201 is not None:
        if len(a201) > 1 and a201[0] == 0:
            return True, bytes(a201[1:])
        return True, None
    fd50 = service_data.get(_ADV_SERVICE_UUID_FD50)
    if fd50 is not None:
        # TuyaOS FD50 layout: frame control (2), id type (1), id length (1), id
        if len(fd50) >= 4 and 0 < fd50[3] <= len(fd50) - 4:
            return True, bytes(fd50[4 : 4 + fd50[3]])
        return True, None
    return False, None


@dataclass
class TuyaCloudCacheItem:
    """A cache model for API keys/credentials"""

    api: TuyaOpenAPI | None
    login: dict[str, Any]
    credentials: dict[str, dict[str, Any]]


CONF_TUYA_LOGIN_KEYS = [
    CONF_ENDPOINT,
    CONF_ACCESS_ID,
    CONF_ACCESS_SECRET,
    CONF_AUTH_TYPE,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_COUNTRY_CODE,
    CONF_APP_TYPE,
]

CONF_TUYA_DEVICE_KEYS = [
    CONF_UUID,
    CONF_LOCAL_KEY,
    CONF_DEVICE_ID,
    CONF_CATEGORY,
    CONF_PRODUCT_ID,
    CONF_DEVICE_NAME,
    CONF_PRODUCT_NAME,
    CONF_PRODUCT_MODEL,
]

_cache: dict[str, TuyaCloudCacheItem] = {}


def normalize_app_type_data(data: dict[str, Any]) -> dict[str, Any]:
    """Return a non-persistent view compatible with both app-type key names."""
    normalized = data.copy()
    has_current = CONF_APP_TYPE in normalized
    has_legacy = CONF_LEGACY_APP_TYPE in normalized

    if (
        has_current
        and has_legacy
        and normalized[CONF_APP_TYPE] != normalized[CONF_LEGACY_APP_TYPE]
    ):
        raise ValueError("Conflicting Tuya application type configuration")

    if has_current:
        normalized[CONF_LEGACY_APP_TYPE] = normalized[CONF_APP_TYPE]
    elif has_legacy:
        normalized[CONF_APP_TYPE] = normalized[CONF_LEGACY_APP_TYPE]

    return normalized


class HASSTuyaBLEDeviceManager(AbstaractTuyaBLEDeviceManager):
    """Cloud connected manager of the Tuya BLE devices credentials."""

    def __init__(self, hass: HomeAssistant, data: dict[str, Any]) -> None:
        assert hass is not None
        self._hass = hass
        self._data = normalize_app_type_data(data)

    @staticmethod
    def _is_login_success(response: dict[Any, Any]) -> bool:
        return bool(response.get(TUYA_RESPONSE_SUCCESS, False))

    @staticmethod
    def _get_cache_key(data: dict[str, Any]) -> str:
        data = normalize_app_type_data(data)
        key_dict = {key: data.get(key) for key in CONF_TUYA_LOGIN_KEYS}
        return json.dumps(key_dict)

    @staticmethod
    def _has_login(data: dict[Any, Any]) -> bool:
        data = normalize_app_type_data(data)
        for key in CONF_TUYA_LOGIN_KEYS:
            if data.get(key) is None:
                return False
        return True

    @staticmethod
    def _has_credentials(data: dict[Any, Any]) -> bool:
        for key in CONF_TUYA_DEVICE_KEYS:
            if data.get(key) is None:
                return False
        return True

    async def _login(self, data: dict[str, Any], add_to_cache: bool) -> dict[Any, Any]:
        """Login into Tuya cloud using credentials from data dictionary."""
        global _cache

        if len(data) == 0:
            return {}

        data = normalize_app_type_data(data)

        api = TuyaOpenAPI(
            endpoint=data.get(CONF_ENDPOINT, ""),
            access_id=data.get(CONF_ACCESS_ID, ""),
            access_secret=data.get(CONF_ACCESS_SECRET, ""),
            auth_type=data.get(CONF_AUTH_TYPE, ""),
        )
        api.set_dev_channel("hass")

        response = await self._hass.async_add_executor_job(
            api.connect,
            data.get(CONF_USERNAME, ""),
            data.get(CONF_PASSWORD, ""),
            data.get(CONF_COUNTRY_CODE, ""),
            data.get(CONF_APP_TYPE, ""),
        )

        if self._is_login_success(response):
            _LOGGER.debug("Tuya cloud login succeeded")
            if add_to_cache:
                auth_type = data[CONF_AUTH_TYPE]
                if isinstance(auth_type, AuthType):
                    data[CONF_AUTH_TYPE] = auth_type.value
                cache_key = self._get_cache_key(data)
                cache_item = _cache.get(cache_key)
                if cache_item:
                    cache_item.api = api
                    cache_item.login = data
                else:
                    _cache[cache_key] = TuyaCloudCacheItem(api, data, {})

        return response

    def _check_login(self) -> bool:
        cache_key = self._get_cache_key(self._data)
        return _cache.get(cache_key) is not None

    async def login(self, add_to_cache: bool = False) -> dict[Any, Any]:
        return await self._login(self._data, add_to_cache)

    async def _fill_cache_item(self, item: TuyaCloudCacheItem) -> None:
        devices_response = await self._hass.async_add_executor_job(
            item.api.get,
            TUYA_API_DEVICES_URL % (item.api.token_info.uid),
        )
        if devices_response.get(TUYA_RESPONSE_RESULT):
            devices = devices_response.get(TUYA_RESPONSE_RESULT)
            if isinstance(devices, Iterable):
                for device in devices:
                    fi_response = await self._hass.async_add_executor_job(
                        item.api.get,
                        TUYA_API_FACTORY_INFO_URL % (device.get("id")),
                    )

                    fi_response_result = fi_response.get(TUYA_RESPONSE_RESULT)
                    if fi_response_result and len(fi_response_result) > 0:
                        factory_info = fi_response_result[0]
                        if factory_info and (TUYA_FACTORY_INFO_MAC in factory_info):
                            raw_mac = factory_info[TUYA_FACTORY_INFO_MAC]
                            if ":" in raw_mac:
                                # API already returned a colon-separated MAC
                                mac = raw_mac.upper()
                            else:
                                mac = ":".join(
                                    raw_mac[i : i + 2] for i in range(0, 12, 2)
                                ).upper()
                            item.credentials[mac] = {
                                CONF_ADDRESS: mac,
                                CONF_UUID: device.get("uuid"),
                                CONF_LOCAL_KEY: device.get("local_key"),
                                CONF_DEVICE_ID: device.get("id"),
                                CONF_CATEGORY: device.get("category"),
                                CONF_PRODUCT_ID: device.get("product_id"),
                                CONF_DEVICE_NAME: device.get("name"),
                                CONF_PRODUCT_MODEL: device.get("model"),
                                CONF_PRODUCT_NAME: device.get("product_name"),
                            }
                            sec_key = device.get("sec_key") or device.get("secKey")
                            if sec_key:
                                item.credentials[mac][CONF_SEC_KEY] = sec_key

                            spec_response = await self._hass.async_add_executor_job(
                                item.api.get,
                                TUYA_API_DEVICE_SPECIFICATION % device.get("id"),
                            )

                            spec_response_result = spec_response.get(
                                TUYA_RESPONSE_RESULT
                            )
                            if spec_response_result:
                                functions = spec_response_result.get("functions")
                                if functions:
                                    item.credentials[mac][CONF_FUNCTIONS] = functions
                                status = spec_response_result.get("status")
                                if status:
                                    item.credentials[mac][CONF_STATUS_RANGE] = status

                            spec_response = await self._hass.async_add_executor_job(
                                item.api.get,
                                TUYA_API_DEVICE_SPECIFICATION % device.get("id"),
                            )

                            spec_response_result = spec_response.get(
                                TUYA_RESPONSE_RESULT
                            )
                            if spec_response_result:
                                functions = spec_response_result.get("functions")
                                if functions:
                                    item.credentials[mac][CONF_FUNCTIONS] = functions
                                status = spec_response_result.get("status")
                                if status:
                                    item.credentials[mac][CONF_STATUS_RANGE] = status

    async def build_cache(self) -> None:
        global _cache
        tuya_config_entries = self._hass.config_entries.async_entries(TUYA_DOMAIN)
        for config_entry in tuya_config_entries:
            data = normalize_app_type_data(dict(config_entry.data))
            key = self._get_cache_key(data)
            item = _cache.get(key)
            if item is None or len(item.credentials) == 0:
                if self._is_login_success(await self._login(data, True)):
                    item = _cache.get(key)
                    if item and len(item.credentials) == 0:
                        await self._fill_cache_item(item)

        ble_config_entries = self._hass.config_entries.async_entries(DOMAIN)
        for config_entry in ble_config_entries:
            data = normalize_app_type_data(dict(config_entry.options))
            key = self._get_cache_key(data)
            item = _cache.get(key)
            if item is None or len(item.credentials) == 0:
                if self._is_login_success(await self._login(data, True)):
                    item = _cache.get(key)
                    if item and len(item.credentials) == 0:
                        await self._fill_cache_item(item)

    def get_login_from_cache(self) -> None:
        global _cache
        for cache_item in _cache.values():
            self._data.update(cache_item.login)
            break

    async def get_device_credentials(
        self,
        address: str,
        force_update: bool = False,
        save_data: bool = False,
    ) -> TuyaBLEDeviceCredentials | None:
        """Get credentials of the Tuya BLE device."""
        global _cache
        item: TuyaCloudCacheItem | None = None
        credentials: dict[str, any] | None = None
        result: TuyaBLEDeviceCredentials | None = None

        if not force_update and self._has_credentials(self._data):
            credentials = self._data.copy()
        else:
            cache_key: str | None = None
            if self._has_login(self._data):
                cache_key = self._get_cache_key(self._data)
            else:
                for key in _cache.keys():
                    if _cache[key].credentials.get(address) is not None:
                        cache_key = key
                        break
            if cache_key:
                item = _cache.get(cache_key)

            if item is None or force_update:
                if self._is_login_success(await self.login(True)):
                    item = _cache.get(cache_key)
                    if item:
                        await self._fill_cache_item(item)

            if item:
                credentials = item.credentials.get(address)
                if credentials is None and address:
                    credentials = self._credentials_for_unknown_address(item, address)

        if credentials:
            sec_key = credentials.get(CONF_SEC_KEY) or self._data.get(CONF_SEC_KEY)
            result = TuyaBLEDeviceCredentials(
                credentials.get(CONF_UUID, ""),
                credentials.get(CONF_LOCAL_KEY, ""),
                credentials.get(CONF_DEVICE_ID, ""),
                credentials.get(CONF_CATEGORY, ""),
                credentials.get(CONF_PRODUCT_ID, ""),
                credentials.get(CONF_DEVICE_NAME, ""),
                credentials.get(CONF_PRODUCT_MODEL, ""),
                credentials.get(CONF_PRODUCT_NAME, ""),
                credentials.get(CONF_FUNCTIONS, []),
                credentials.get(CONF_STATUS_RANGE, []),
                sec_key=sec_key,
            )
            _LOGGER.debug(
                "Retrieved Tuya BLE credentials for category=%s product=%s",
                result.category,
                result.product_id,
            )
            if save_data:
                if item:
                    self._data.update(item.login)
                self._data.update(credentials)
                if sec_key:
                    self._data[CONF_SEC_KEY] = sec_key

        return result

    def _credentials_for_unknown_address(
        self, item: TuyaCloudCacheItem, address: str
    ) -> dict[str, Any] | None:
        """Map an advertised address that is not a factory MAC.

        Some TuyaOS FD50 products (e.g. LP40) advertise a random resolvable
        private address. Match via encrypted UUID in manufacturer data when
        possible, otherwise by elimination among unmatched supported devices.
        """
        address = address.upper()
        try:
            mac = _address_aliases.get(address)
            if mac is None or mac not in item.credentials:
                mac = self._match_advertisement(item, address)
            if mac is None:
                return None
            _address_aliases[address] = mac
            credentials = dict(item.credentials[mac])
            credentials[CONF_ADDRESS] = address
            return credentials
        except Exception:  # noqa: BLE001 - never break the regular lookup
            _LOGGER.debug("Advertisement based credential lookup failed", exc_info=True)
            return None

    def _match_advertisement(
        self, item: TuyaCloudCacheItem, address: str
    ) -> str | None:
        import hashlib

        from Crypto.Cipher import AES
        from homeassistant.components import bluetooth

        from .devices import devices_database

        info = bluetooth.async_last_service_info(self._hass, address, False)
        if info is None:
            return None
        is_tuya, adv_id = _advertised_tuya_id(info.service_data or {})
        if not is_tuya:
            return None

        manufacturer_data = (info.manufacturer_data or {}).get(
            _ADV_MANUFACTURER_DATA_ID
        )
        if adv_id and manufacturer_data and len(manufacturer_data) >= 22:
            key = hashlib.md5(adv_id).digest()
            raw_uuid = AES.new(key, AES.MODE_CBC, key).decrypt(
                bytes(manufacturer_data[6:22])
            )
            uuid = raw_uuid.decode("utf-8", "ignore")
            for mac, cred in item.credentials.items():
                if cred.get(CONF_UUID) == uuid:
                    _LOGGER.info("Matched Tuya BLE device by advertised uuid")
                    return mac

        product_filter: str | None = None
        if adv_id:
            try:
                text = adv_id.decode("ascii")
                if text.isalnum():
                    product_filter = text
            except UnicodeDecodeError:
                pass

        configured: set[str] = set()
        configured_ids: set[str] = set()
        for entry in self._hass.config_entries.async_entries(DOMAIN):
            if entry_address := entry.data.get(CONF_ADDRESS):
                configured.add(str(entry_address).upper())
            if device_id := entry.options.get(CONF_DEVICE_ID):
                configured_ids.add(device_id)
        candidates: list[str] = []
        for mac, cred in item.credentials.items():
            category_info = devices_database.get(cred.get(CONF_CATEGORY))
            if category_info is None or (
                cred.get(CONF_PRODUCT_ID) not in category_info.products
            ):
                continue
            if product_filter and cred.get(CONF_PRODUCT_ID) != product_filter:
                continue
            if mac in configured or cred.get(CONF_DEVICE_ID) in configured_ids:
                continue
            if mac in _address_aliases.values():
                continue
            if bluetooth.async_address_present(self._hass, mac, False):
                continue
            candidates.append(mac)
        if len(candidates) == 1:
            _LOGGER.warning(
                "Tuya BLE address %s is not a factory MAC; using the only "
                "unmatched supported cloud device (%s)",
                address,
                item.credentials[candidates[0]].get(CONF_DEVICE_NAME),
            )
            return candidates[0]
        _LOGGER.debug(
            "Advertisement lookup for %s found %d candidates",
            address,
            len(candidates),
        )
        return None

    async def async_get_device_raw_status(
        self, device_id: str, codes: tuple[str, ...]
    ) -> dict[str, bytes]:
        """Return selected raw DP values from the Tuya cloud device status."""
        import base64

        cache_key = self._get_cache_key(self._data)
        item = _cache.get(cache_key)
        if item is None or item.api is None:
            if not self._is_login_success(await self._login(self._data, True)):
                return {}
            item = _cache.get(self._get_cache_key(self._data))
            if item is None or item.api is None:
                return {}
        response = await self._hass.async_add_executor_job(
            item.api.get, f"/v1.0/devices/{device_id}/status"
        )
        if not self._is_login_success(response):
            if not self._is_login_success(await self._login(self._data, True)):
                return {}
            item = _cache.get(self._get_cache_key(self._data))
            if item is None or item.api is None:
                return {}
            response = await self._hass.async_add_executor_job(
                item.api.get, f"/v1.0/devices/{device_id}/status"
            )
        result: dict[str, bytes] = {}
        for status in response.get(TUYA_RESPONSE_RESULT) or []:
            code = status.get("code")
            value = status.get("value")
            if code in codes and isinstance(value, str) and value:
                try:
                    result[code] = base64.b64decode(value, validate=True)
                except ValueError:
                    continue
        return result

    async def async_get_lock_issued_config(self, device_id: str) -> dict[str, Any]:
        """GET /v1.0/devices/{id}/door-lock/issued-config (BLE check material)."""
        cache_key = self._get_cache_key(self._data)
        item = _cache.get(cache_key)
        if item is None or item.api is None:
            if not self._is_login_success(await self._login(self._data, True)):
                return {}
            item = _cache.get(self._get_cache_key(self._data))
            if item is None or item.api is None:
                return {}
        path = f"/v1.0/devices/{device_id}/door-lock/issued-config"
        response = await self._hass.async_add_executor_job(item.api.get, path)
        if not self._is_login_success(response):
            if not self._is_login_success(await self._login(self._data, True)):
                return {}
            item = _cache.get(self._get_cache_key(self._data))
            if item is None or item.api is None:
                return {}
            response = await self._hass.async_add_executor_job(item.api.get, path)
        result = response.get(TUYA_RESPONSE_RESULT)
        return result if isinstance(result, dict) else {}

    @property
    def data(self) -> dict[str, Any]:
        return self._data
