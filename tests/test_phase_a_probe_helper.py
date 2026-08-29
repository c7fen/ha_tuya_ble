"""Regression tests for the repository-owned temporary Phase-A HTTP helper."""

from __future__ import annotations

import json
import stat
import urllib.error
from copy import deepcopy
from pathlib import Path

import pytest

from custom_components.tuya_ble.phase_a_probe_helper import (
    HelperExit,
    HelperOperation,
    invoke_service,
    sanitize_service_response,
    service_response_from_wrapper,
    write_sanitized_evidence,
)


def _real_probe_response() -> dict[str, object]:
    """Return a valid response with optional observer fields set to None."""
    return {
        "mode": "cold",
        "result": "invalid_or_incomplete",
        "cold_request_attempted": True,
        "retained_request_attempted": False,
        "request_count": 1,
        "same_session_retained": False,
        "normal_release_observed": False,
        "automatic_reconnect_observed": False,
        "observation_overflow": False,
        "duration_ms": 1,
        "requests": [{"trial": 1, "result": "ack_missing", "duration_ms": 1}],
        "events": [
            {
                "trial": 1,
                "observation_ordinal": 1,
                "origin": "status",
                "kind": "REQUEST_CREATED",
                "event_ordinal": 1,
                "batch_ordinal": None,
                "dp_ids": [],
                "dp_types": [],
                "encoded_value_lengths": [],
                "exact_session": False,
                "ack_result": None,
                "ack_phase": None,
                "monotonic_ms": 1,
            }
        ],
        "invocation_nonce": "d" * 16,
    }


def test_real_response_with_optional_none_event_fields_is_not_ambiguous():
    """The C01 optional-field shape is schema-valid, not exit-78 ambiguity."""
    response = sanitize_service_response(HelperOperation.PROBE, _real_probe_response())

    assert response["events"][0]["batch_ordinal"] is None
    assert response["events"][0]["ack_result"] is None
    assert response["events"][0]["ack_phase"] is None


def test_wrapper_discards_changed_states_before_evidence_is_written(tmp_path):
    """Only the allowlisted service response reaches local evidence."""
    wrapper = {
        "service_response": {
            "result": "preflight_ok",
            "protocol_version": 1,
            "nonce": "e" * 16,
        },
        "changed_states": [{"entity_id": "private.entity", "state": "private"}],
    }

    response = service_response_from_wrapper(HelperOperation.PREFLIGHT, wrapper)
    evidence = tmp_path / "preflight.json"
    write_sanitized_evidence(evidence, response)

    rendered = evidence.read_text(encoding="utf-8")
    assert json.loads(rendered) == response
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o600
    assert "changed_states" not in rendered
    assert "private.entity" not in rendered


def test_no_input_preflight_response_is_valid_but_not_helper_acceptable():
    """A direct no-input service call is valid; helper calls always correlate it."""
    assert sanitize_service_response(
        HelperOperation.PREFLIGHT,
        {"result": "preflight_ok", "protocol_version": 1},
    ) == {"result": "preflight_ok", "protocol_version": 1}


@pytest.mark.parametrize(
    ("operation", "response", "expected"),
    [
        (
            HelperOperation.PREFLIGHT,
            {"result": "preflight_ok", "protocol_version": 1, "nonce": "f" * 16},
            HelperExit.SUCCESS,
        ),
        (HelperOperation.PROBE, _real_probe_response(), HelperExit.SERVICE_REJECTED),
        (
            HelperOperation.RECEIPT,
            {
                "nonce": "f" * 16,
                "known": False,
                "service_entered": False,
                "request_handed_to_transport": False,
                "terminal_class": None,
                "response_available": False,
            },
            HelperExit.SERVICE_REJECTED,
        ),
    ],
)
def test_valid_service_outcomes_have_non_overlapping_exit_classes(
    operation, response, expected
):
    assert sanitize_service_response(operation, response)
    assert expected in {
        HelperExit.SUCCESS,
        HelperExit.SERVICE_REJECTED,
    }


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ("completed", HelperExit.SUCCESS),
        ("precondition_failed", HelperExit.SERVICE_REJECTED),
        ("invalid_or_incomplete", HelperExit.SERVICE_REJECTED),
        ("observation_overflow", HelperExit.SERVICE_REJECTED),
        ("known_service_error", HelperExit.SERVICE_REJECTED),
        ("nonce_capacity_reached", HelperExit.SERVICE_REJECTED),
    ],
)
def test_real_probe_result_classes_are_explicit_and_non_overlapping(result, expected):
    """Mocked real responses cannot collapse known results into exit 78."""
    response = deepcopy(_real_probe_response())
    response["result"] = result
    wrapper = {"service_response": response}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(wrapper).encode()

    outcome = invoke_service(
        HelperOperation.PROBE,
        "http://supervisor/core",
        {
            "config_entry_id": "in-memory-only",
            "mode": "cold",
            "invocation_nonce": "d" * 16,
        },
        {},
        opener=lambda *_args, **_kwargs: _Response(),
    )

    assert outcome.exit_code is expected
    assert outcome.outcome == result


@pytest.mark.parametrize(
    ("operation", "payload", "response"),
    [
        (
            HelperOperation.PREFLIGHT,
            {"nonce": "a" * 16},
            {"result": "preflight_ok", "protocol_version": 1, "nonce": "b" * 16},
        ),
        (
            HelperOperation.PROBE,
            {
                "config_entry_id": "in-memory-only",
                "mode": "cold",
                "invocation_nonce": "a" * 16,
            },
            {**_real_probe_response(), "invocation_nonce": "b" * 16},
        ),
        (
            HelperOperation.RECEIPT,
            {"nonce": "a" * 16},
            {
                "nonce": "b" * 16,
                "known": False,
                "service_entered": False,
                "request_handed_to_transport": False,
                "terminal_class": None,
                "response_available": False,
            },
        ),
    ],
)
def test_received_nonce_mismatch_is_local_schema_failure(operation, payload, response):
    """A response is accepted only when it exactly echoes the submitted nonce."""
    wrapper = {"service_response": response}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(wrapper).encode()

    outcome = invoke_service(
        operation,
        "http://supervisor/core",
        payload,
        {},
        opener=lambda *_args, **_kwargs: _Response(),
    )

    assert outcome.exit_code is HelperExit.SCHEMA_PRIVACY_FAILURE
    assert outcome.outcome == "nonce_mismatch"


def test_malformed_json_is_deterministic_schema_failure():
    """Malformed received JSON cannot escape or become transport ambiguity."""

    class _MalformedResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b"not-json"

    outcome = invoke_service(
        HelperOperation.PREFLIGHT,
        "http://supervisor/core",
        {"nonce": "a" * 16},
        {},
        opener=lambda *_args, **_kwargs: _MalformedResponse(),
    )

    assert outcome.exit_code is HelperExit.SCHEMA_PRIVACY_FAILURE


def test_received_transport_ambiguous_result_is_schema_failure_not_exit_78():
    """Exit 78 belongs only to an HTTP transport exception after handoff."""
    response = deepcopy(_real_probe_response())
    response["result"] = "transport_ambiguous"
    wrapper = {"service_response": response}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(wrapper).encode()

    outcome = invoke_service(
        HelperOperation.PROBE,
        "http://supervisor/core",
        {
            "config_entry_id": "in-memory-only",
            "mode": "cold",
            "invocation_nonce": "d" * 16,
        },
        {},
        opener=lambda *_args, **_kwargs: _Response(),
    )

    assert outcome.exit_code is HelperExit.SCHEMA_PRIVACY_FAILURE


def test_helper_distinguishes_not_submitted_ambiguity_and_schema_failure():
    """Transport and local parser outcomes remain distinct without BLE claims."""
    not_submitted = invoke_service(
        HelperOperation.PROBE,
        "http://supervisor/core",
        {"mode": "cold", "invocation_nonce": "a" * 16},
        {},
    )
    ambiguous = invoke_service(
        HelperOperation.PREFLIGHT,
        "http://supervisor/core",
        {"nonce": "a" * 16},
        {},
        opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            urllib.error.URLError("synthetic")
        ),
    )

    class _BadResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"changed_states":["not-a-service-response"]}'

    schema_invalid = invoke_service(
        HelperOperation.PREFLIGHT,
        "http://supervisor/core",
        {"nonce": "a" * 16},
        {},
        opener=lambda *_args, **_kwargs: _BadResponse(),
    )

    assert not_submitted.exit_code is HelperExit.DEFINITELY_NOT_SUBMITTED
    assert ambiguous.exit_code is HelperExit.AMBIGUOUS_POST_SUBMISSION
    assert ambiguous.nonce == "a" * 16
    assert schema_invalid.exit_code is HelperExit.SCHEMA_PRIVACY_FAILURE


def test_ambiguous_omitted_nonce_is_generated_before_http_handoff():
    """An operator can perform receipt lookup without an automatic retry."""
    outcome = invoke_service(
        HelperOperation.PREFLIGHT,
        "http://supervisor/core",
        {},
        {},
        opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            urllib.error.URLError("synthetic")
        ),
    )

    assert outcome.exit_code is HelperExit.AMBIGUOUS_POST_SUBMISSION
    assert outcome.nonce is not None
    assert len(outcome.nonce) == 32
    assert set(outcome.nonce) <= set("0123456789abcdef")


def test_cli_does_not_accept_private_config_entry_id_in_argv():
    """The temporary CLI receives a probe target only through private process env."""
    script = (
        Path(__file__).parents[1] / "scripts" / "phase_a_status_probe_helper.py"
    ).read_text(encoding="utf-8")

    assert "--config-entry-id" not in script
    assert "PHASE_A_STATUS_PROBE_CONFIG_ENTRY_ID" in script
