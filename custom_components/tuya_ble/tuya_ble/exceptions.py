from __future__ import annotations

from homeassistant.exceptions import ServiceValidationError

from ..const import DOMAIN


class TuyaBLEError(Exception):
    """Base class for Tuya BLE errors."""


class TuyaBLEEnumValueError(TuyaBLEError):
    """Raised when value assigned to DP_ENUM datapoint has unexpected type."""

    def __init__(self) -> None:
        super().__init__("Value of DP_ENUM datapoint must be unsigned integer")


class TuyaBLEDataFormatError(TuyaBLEError):
    """Raised when data in Tuya BLE structures formatted in wrong way."""

    def __init__(self) -> None:
        super().__init__("Incoming packet is formatted in wrong way")


class TuyaBLEDataCRCError(TuyaBLEError):
    """Raised when data packet has invalid CRC."""

    def __init__(self) -> None:
        super().__init__("Incoming packet has invalid CRC")


class TuyaBLEDataLengthError(TuyaBLEError):
    """Raised when data packet has invalid length."""

    def __init__(self) -> None:
        super().__init__("Incoming packet has invalid length")


class TuyaBLEDeviceError(TuyaBLEError):
    """Raised when Tuya BLE device returned error in response to command."""

    def __init__(self, code: int) -> None:
        super().__init__(("BLE deice returned error code %s") % (code))


class TuyaBLECommandUnconfirmedError(TuyaBLEError):
    """Raised when an at-most-once command has no valid success response."""

    def __init__(self) -> None:
        super().__init__("BLE command was not confirmed by the device")


class TuyaBLEControlSuspendedError(ServiceValidationError):
    """Raised when Home Assistant BLE control is persistently suspended."""

    def __init__(self) -> None:
        super().__init__(
            "Home Assistant BLE control is suspended.",
            translation_domain=DOMAIN,
            translation_key="ble_control_suspended",
        )


class TuyaBLEConnectionUnavailableError(ServiceValidationError):
    """Raised when a policy-approved connection cannot be established."""

    def __init__(self) -> None:
        super().__init__(
            "The Bluetooth connection is unavailable.",
            translation_domain=DOMAIN,
            translation_key="ble_connection_unavailable",
        )


class TuyaBLEPolicyTransitionError(ServiceValidationError):
    """Raised when a connection-policy transition cannot complete safely."""

    def __init__(self) -> None:
        super().__init__(
            "The Bluetooth connection policy could not be changed safely.",
            translation_domain=DOMAIN,
            translation_key="ble_policy_transition_failed",
        )
