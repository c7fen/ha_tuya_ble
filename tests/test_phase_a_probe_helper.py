"""Regression tests for the repository-owned temporary Phase-A HTTP helper."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
import urllib.error
from copy import deepcopy
from io import BytesIO
from pathlib import Path

import pytest

from scripts.phase_a_status_probe_lib import (
    HelperExit,
    HelperOperation,
    invoke_service,
    main,
    sanitize_service_response,
    service_response_from_wrapper,
    write_sanitized_evidence,
)


def test_standalone_cli_rejects_invalid_nonce_without_runtime_import() -> None:
    """P0 must be classified before any HA-package import or HTTP handoff."""
    script = Path(__file__).parents[1] / "scripts" / "phase_a_status_probe_helper.py"

    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            str(script),
            "preflight",
            "--nonce",
            "not-a-valid-nonce",
        ],
        check=False,
        capture_output=True,
        text=True,
        env={"SUPERVISOR_TOKEN": "synthetic-token"},
    )

    assert completed.returncode == HelperExit.DEFINITELY_NOT_SUBMITTED
    assert completed.stdout == '{"outcome":"not_submitted"}\n'
    assert completed.stderr == ""


def test_standalone_library_import_graph_excludes_integration_runtime() -> None:
    """The administration client remains importable with only stdlib modules."""
    scripts = Path(__file__).parents[1] / "scripts"
    program = (
        "import sys;sys.path.insert(0,sys.argv[1]);"
        "import phase_a_status_probe_lib;"
        "blocked=('custom_components.tuya_ble','homeassistant','bleak','voluptuous','Crypto');"
        "assert not any(name == prefix or name.startswith(prefix + '.') "
        "for name in sys.modules for prefix in blocked)"
    )

    completed = subprocess.run(
        [sys.executable, "-S", "-c", program, str(scripts)],
        check=False,
        capture_output=True,
        text=True,
        env={},
    )

    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""


def test_invalid_nonce_does_not_invoke_http_opener() -> None:
    """Local nonce validation remains ahead of HTTP handoff."""
    opener_calls = 0

    def opener(*_args, **_kwargs):
        nonlocal opener_calls
        opener_calls += 1
        raise AssertionError("HTTP opener must not run")

    result = invoke_service(
        HelperOperation.PREFLIGHT,
        "http://invalid.example",
        {"nonce": "not-a-valid-nonce"},
        {},
        opener=opener,
    )

    assert result.exit_code is HelperExit.DEFINITELY_NOT_SUBMITTED
    assert result.outcome == "not_submitted"
    assert opener_calls == 0


@pytest.mark.parametrize("nonce", ("", "not-a-valid-nonce"))
def test_cli_invalid_nonce_never_reaches_http_opener(nonce, capsys) -> None:
    """Every syntactically invalid CLI nonce is rejected before transport."""
    opener_calls = 0

    def opener(*_args, **_kwargs):
        nonlocal opener_calls
        opener_calls += 1
        raise AssertionError("HTTP opener must not run")

    exit_code = main(
        ["preflight", "--nonce", nonce],
        environ={"SUPERVISOR_TOKEN": "synthetic-token"},
        opener=opener,
    )
    captured = capsys.readouterr()

    assert exit_code == HelperExit.DEFINITELY_NOT_SUBMITTED
    assert captured.out == '{"outcome":"not_submitted"}\n'
    assert captured.err == ""
    assert opener_calls == 0


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


def _audit_response(nonce: str) -> dict[str, object]:
    return {
        "result": "audit_snapshot",
        "protocol_version": 1,
        "audit_instance_token": "a" * 32,
        "event_ordinal": 0,
        "history_overflow": False,
        "runtime_ms": 0,
        "counters": {
            "connect_attempts": 0,
            "gatt_sessions_claimed": 0,
            "authenticated_sessions": 0,
            "packets_sent_total": 0,
            "device_status_requests": 0,
            "device_info_requests": 0,
            "pair_requests": 0,
            "datapoint_write_operations": 0,
            "datapoint_protocol_packets": 0,
            "other_packets": 0,
            "reconnect_schedules": 0,
            "disconnects": 0,
        },
        "events": [],
        "nonce": nonce,
    }


def _preflight_opener(nonce: str, seen: list[object]):
    """Return a synthetic, sanitized preflight wrapper without network access."""

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(
                {
                    "service_response": {
                        "result": "preflight_ok",
                        "protocol_version": 1,
                        "nonce": nonce,
                    }
                }
            ).encode()

    def opener(request, **_kwargs):
        seen.append(request)
        return _Response()

    return opener


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


def test_audit_helper_invocation_correlates_nonce_and_discards_wrapper_before_evidence(
    tmp_path,
):
    """Audit uses the shared helper transport and cannot retain wrapper state."""
    nonce = "c" * 16
    seen = []
    wrapper = {
        "service_response": _audit_response(nonce),
        "changed_states": [{"entity_id": "private.entity", "state": "private"}],
    }

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(wrapper).encode()

    def opener(request, **_kwargs):
        seen.append(request)
        return _Response()

    result = invoke_service(
        HelperOperation.AUDIT,
        "http://supervisor/core",
        {"nonce": nonce},
        {"Authorization": "Bearer private-token"},
        opener=opener,
    )
    assert result.exit_code is HelperExit.SUCCESS
    assert result.nonce == nonce
    assert result.response == _audit_response(nonce)
    assert seen[0].full_url.endswith(
        "/tuya_ble/phase_a_status_probe_audit?return_response"
    )

    evidence = tmp_path / "audit.json"
    write_sanitized_evidence(evidence, result.response)
    rendered = evidence.read_text(encoding="utf-8")
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


@pytest.mark.parametrize("http_status", (400, 404, 500))
def test_r62f_received_http_error_is_definitive_service_rejection(http_status):
    """A received HTTP response is not unknown-response transport ambiguity."""
    nonce = "a" * 16
    private_endpoint = "http://private-endpoint.invalid"
    private_body = b"private response body"
    private_reason = "private reason phrase"
    private_headers = {"X-Private": "private header value"}

    def reject(request, **_kwargs):
        raise urllib.error.HTTPError(
            request.full_url,
            http_status,
            private_reason,
            private_headers,
            BytesIO(private_body),
        )

    outcome = invoke_service(
        HelperOperation.PREFLIGHT,
        private_endpoint,
        {"nonce": nonce},
        {},
        opener=reject,
    )

    assert outcome.exit_code is HelperExit.SERVICE_REJECTED
    assert outcome.outcome == "http_rejected"
    assert outcome.nonce == nonce
    assert outcome.http_status == http_status
    assert outcome.response is None
    rendered = repr(outcome)
    assert private_body.decode() not in rendered
    assert private_reason not in rendered
    assert private_headers["X-Private"] not in rendered
    assert private_endpoint not in rendered


@pytest.mark.parametrize("http_status", (399, 600, True))
def test_r62f_http_rejection_requires_bounded_non_boolean_status(http_status):
    """An invalid synthetic HTTPError code cannot cross the bounded projection."""
    outcome = invoke_service(
        HelperOperation.PREFLIGHT,
        "http://supervisor/core",
        {"nonce": "f" * 16},
        {},
        opener=lambda request, **_kwargs: (_ for _ in ()).throw(
            urllib.error.HTTPError(request.full_url, http_status, "", {}, None)
        ),
    )

    assert outcome.exit_code is HelperExit.SCHEMA_PRIVACY_FAILURE
    assert outcome.outcome == "schema_invalid"
    assert outcome.http_status is None


@pytest.mark.parametrize(
    "error",
    (
        urllib.error.URLError("synthetic transport"),
        TimeoutError("synthetic timeout"),
        OSError("synthetic os transport"),
    ),
)
def test_r62f_true_transport_exceptions_remain_ambiguous(error):
    """No response status is invented for unresolved transport failures."""
    outcome = invoke_service(
        HelperOperation.PREFLIGHT,
        "http://supervisor/core",
        {"nonce": "b" * 16},
        {},
        opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )

    assert outcome.exit_code is HelperExit.AMBIGUOUS_POST_SUBMISSION
    assert outcome.outcome == "transport_ambiguous"
    assert outcome.http_status is None


def test_r62f_http_rejection_cli_is_minimal_and_writes_no_evidence(tmp_path, capsys):
    """Only outcome, nonce, and numeric status cross the rejection boundary."""
    nonce = "c" * 16
    private_body = b"private response body"
    private_reason = "private reason phrase"
    private_header = "private header value"
    evidence_root = tmp_path / "private-evidence-root"

    def reject(request, **_kwargs):
        raise urllib.error.HTTPError(
            request.full_url,
            422,
            private_reason,
            {"X-Private": private_header},
            BytesIO(private_body),
        )

    exit_code = main(
        ["preflight", "--nonce", nonce, "--evidence-label", "A0"],
        environ={"SUPERVISOR_TOKEN": "synthetic-token"},
        evidence_root=evidence_root,
        opener=reject,
    )
    captured = capsys.readouterr()

    assert exit_code == HelperExit.SERVICE_REJECTED
    assert json.loads(captured.out) == {
        "outcome": "http_rejected",
        "nonce": nonce,
        "http_status": 422,
    }
    assert captured.err == ""
    assert not evidence_root.exists()
    for private_value in (private_body.decode(), private_reason, private_header):
        assert private_value not in captured.out
        assert private_value not in captured.err


def test_r62f_success_and_invalid_input_contracts_remain_unchanged():
    """The new rejection split neither changes success nor submits invalid input."""
    nonce = "d" * 16
    opener_calls = 0

    def success(*args, **kwargs):
        nonlocal opener_calls
        opener_calls += 1
        return _preflight_opener(nonce, [])(*args, **kwargs)

    accepted = invoke_service(
        HelperOperation.PREFLIGHT,
        "http://supervisor/core",
        {"nonce": nonce},
        {},
        opener=success,
    )
    rejected_before_http = invoke_service(
        HelperOperation.PREFLIGHT,
        "http://supervisor/core",
        {"nonce": "invalid"},
        {},
        opener=success,
    )

    assert accepted.exit_code is HelperExit.SUCCESS
    assert accepted.outcome == "preflight_ok"
    assert accepted.http_status is None
    assert rejected_before_http.exit_code is HelperExit.DEFINITELY_NOT_SUBMITTED
    assert rejected_before_http.outcome == "not_submitted"
    assert rejected_before_http.http_status is None
    assert opener_calls == 1


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
    scripts = Path(__file__).parents[1] / "scripts"
    script = (scripts / "phase_a_status_probe_helper.py").read_text(encoding="utf-8")
    library = (scripts / "phase_a_status_probe_lib.py").read_text(encoding="utf-8")

    assert "--config-entry-id" not in script
    assert "--endpoint" not in script
    assert "--evidence" not in script
    assert "--config-entry-id" not in library
    assert "--endpoint" not in library
    assert "PHASE_A_STATUS_PROBE_CONFIG_ENTRY_ID" in library


@pytest.mark.parametrize(
    "forbidden_argument",
    ("--endpoint", "--evidence", "--config-entry-id"),
)
def test_cli_rejects_private_argv_without_traceback(forbidden_argument, capsys) -> None:
    """Routes, paths, and ConfigEntry IDs are never accepted on the CLI."""
    exit_code = main(
        ["preflight", forbidden_argument, "private-cli-sentinel"],
        environ={"SUPERVISOR_TOKEN": "synthetic-token"},
    )
    captured = capsys.readouterr()

    assert exit_code == HelperExit.DEFINITELY_NOT_SUBMITTED
    assert captured.out == '{"outcome":"not_submitted"}\n'
    assert captured.err == ""
    assert "private-cli-sentinel" not in captured.out


@pytest.mark.parametrize("argv", (("-h",), ("--help",)))
def test_cli_help_flags_remain_inside_the_sanitized_output_boundary(
    argv, capsys
) -> None:
    """Help must not bypass the CLI's single-JSON-output privacy contract."""
    exit_code = main(list(argv), environ={"SUPERVISOR_TOKEN": "synthetic-token"})
    captured = capsys.readouterr()

    assert exit_code == HelperExit.DEFINITELY_NOT_SUBMITTED
    assert captured.out == '{"outcome":"not_submitted"}\n'
    assert captured.err == ""


def test_cli_writes_only_labeled_private_evidence_without_metadata_leaks(
    tmp_path, capsys
) -> None:
    """The output and persisted response omit protected runtime metadata."""
    nonce = "a" * 16
    root = tmp_path / "private-evidence-root"
    root.mkdir(mode=0o755)
    seen: list[object] = []
    private_endpoint = "http://private-endpoint.invalid"
    private_config_entry = "private-config-entry"
    private_token = "private-token"

    exit_code = main(
        ["preflight", "--nonce", nonce, "--evidence-label", "A0"],
        environ={
            "SUPERVISOR_TOKEN": private_token,
            "PHASE_A_STATUS_PROBE_CONFIG_ENTRY_ID": private_config_entry,
        },
        endpoint=private_endpoint,
        evidence_root=root,
        opener=_preflight_opener(nonce, seen),
    )
    captured = capsys.readouterr()
    evidence = root / "preflight-A0.json"
    rendered = evidence.read_text(encoding="utf-8")

    assert exit_code == HelperExit.SUCCESS
    assert json.loads(captured.out) == {
        "outcome": "preflight_ok",
        "nonce": nonce,
        "evidence_written": True,
    }
    assert captured.err == ""
    assert seen
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o600
    assert list(root.glob("*.json")) == [evidence]
    assert not list(root.glob("*.tmp"))
    for private_value in (
        private_endpoint,
        str(root),
        private_config_entry,
        private_token,
    ):
        assert private_value not in captured.out
        assert private_value not in captured.err
        assert private_value not in rendered


def test_cli_uses_fixed_supervisor_proxy_without_endpoint_argv(capsys) -> None:
    """The supported CLI route is internal and not an operator argument."""
    nonce = "b" * 16
    seen: list[object] = []

    exit_code = main(
        ["preflight", "--nonce", nonce],
        environ={"SUPERVISOR_TOKEN": "synthetic-token"},
        opener=_preflight_opener(nonce, seen),
    )
    captured = capsys.readouterr()

    assert exit_code == HelperExit.SUCCESS
    assert captured.err == ""
    assert seen[0].full_url.startswith("http://supervisor/core/")


def test_invalid_evidence_label_is_not_submitted_or_written(tmp_path, capsys) -> None:
    """A path-shaped label is rejected before HTTP and filesystem handoff."""
    opener_calls = 0

    def opener(*_args, **_kwargs):
        nonlocal opener_calls
        opener_calls += 1
        raise AssertionError("HTTP opener must not run")

    exit_code = main(
        ["preflight", "--nonce", "c" * 16, "--evidence-label", "../private"],
        environ={"SUPERVISOR_TOKEN": "synthetic-token"},
        evidence_root=tmp_path / "private-evidence-root",
        opener=opener,
    )
    captured = capsys.readouterr()

    assert exit_code == HelperExit.DEFINITELY_NOT_SUBMITTED
    assert captured.out == '{"outcome":"not_submitted"}\n'
    assert captured.err == ""
    assert opener_calls == 0
    assert not (tmp_path / "private-evidence-root").exists()


def test_injected_empty_environment_does_not_fall_back_to_process_environment(
    monkeypatch, capsys
) -> None:
    """Test injection cannot accidentally consume an ambient protected token."""
    opener_calls = 0
    monkeypatch.setenv("SUPERVISOR_TOKEN", "ambient-private-token")

    def opener(*_args, **_kwargs):
        nonlocal opener_calls
        opener_calls += 1
        raise AssertionError("HTTP opener must not run")

    exit_code = main(["preflight"], environ={}, opener=opener)
    captured = capsys.readouterr()

    assert exit_code == HelperExit.DEFINITELY_NOT_SUBMITTED
    assert captured.out == '{"outcome":"not_submitted"}\n'
    assert captured.err == ""
    assert opener_calls == 0


def test_evidence_write_error_is_sanitized_and_uses_exit_67(tmp_path, capsys) -> None:
    """Expected local privacy-storage failures do not expose a traceback or path."""
    nonce = "d" * 16
    blocked_root = tmp_path / "private-evidence-root"
    blocked_root.write_text("not a directory", encoding="utf-8")

    exit_code = main(
        ["preflight", "--nonce", nonce, "--evidence-label", "A0"],
        environ={"SUPERVISOR_TOKEN": "synthetic-token"},
        evidence_root=blocked_root,
        opener=_preflight_opener(nonce, []),
    )
    captured = capsys.readouterr()

    assert exit_code == HelperExit.SCHEMA_PRIVACY_FAILURE
    assert captured.out == (
        '{"outcome":"evidence_write_failed","nonce":"' + nonce + '"}\n'
    )
    assert captured.err == ""
    assert str(blocked_root) not in captured.out


def test_symlink_evidence_root_is_rejected_without_following_it(
    tmp_path, capsys
) -> None:
    """A private evidence root cannot be redirected through a symlink."""
    nonce = "e" * 16
    real_root = tmp_path / "private-real-root"
    real_root.mkdir()
    link_root = tmp_path / "private-evidence-root"
    link_root.symlink_to(real_root, target_is_directory=True)

    exit_code = main(
        ["preflight", "--nonce", nonce, "--evidence-label", "A0"],
        environ={"SUPERVISOR_TOKEN": "synthetic-token"},
        evidence_root=link_root,
        opener=_preflight_opener(nonce, []),
    )
    captured = capsys.readouterr()

    assert exit_code == HelperExit.SCHEMA_PRIVACY_FAILURE
    assert captured.out == (
        '{"outcome":"evidence_write_failed","nonce":"' + nonce + '"}\n'
    )
    assert captured.err == ""
    assert not list(real_root.iterdir())


def test_orchestration_runbook_uses_only_sanitized_contract_placeholders() -> None:
    """The documented orchestration boundary never embeds a route or path command."""
    document = (
        Path(__file__).parents[1] / "docs" / "phase-a-status-probe.md"
    ).read_text(encoding="utf-8")
    contract = document.split("## Temporary orchestration privacy contract", 1)[1]

    assert "set -x" in contract
    assert "opaque SSH configuration alias" in contract
    assert "umask 077" in contract
    assert "sanitized labels" in contract
    assert "http://" not in contract
    assert "--endpoint" not in contract
    assert "--evidence " not in contract
    assert "--config-entry-id" not in contract
