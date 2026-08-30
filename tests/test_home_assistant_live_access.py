"""Synthetic regressions for the local-only Home Assistant access helper."""

from __future__ import annotations

import ast
import io
import json
import os
import stat
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from tools import home_assistant_live_access as access

SYNTHETIC_PRIVATE_ROUTE_SENTINEL = "synthetic-private-route-sentinel.invalid"
SYNTHETIC_PRIVATE_INSTRUCTION_SENTINEL = "synthetic-private-instruction-sentinel"
SYNTHETIC_FORBIDDEN_TRANSCRIPT_SENTINELS = (
    "synthetic-config-entry-id-sentinel",
    "synthetic-device-id-sentinel",
    "synthetic-entity-id-sentinel",
    "synthetic-supervisor-token-sentinel",
    "synthetic-authorization-header-sentinel",
    "synthetic-ssh-agent-environment-sentinel",
    "synthetic-private-key-sentinel",
    "/synthetic/private/absolute/evidence/path-sentinel",
)


def _relevant(issue: object) -> bool:
    return isinstance(issue, dict) and issue.get("scope") == "integration"


def _critical(issue: object) -> bool:
    return isinstance(issue, dict) and issue.get("severity") == "critical"


def _private_spec(target: str = SYNTHETIC_PRIVATE_ROUTE_SENTINEL) -> io.StringIO:
    return io.StringIO(
        "PRIVATE_WRAPPER = "
        + repr(
            {
                "route": access.PRIVATE_ROUTE_ID,
                "argv": ["ssh", target],
            }
        )
    )


def _collect(response: str) -> access.RepairsGateResult:
    return access.collect_repairs_gate(
        access.RepairsGate.INITIAL, response, _relevant, _critical
    )


def _resolution_response(issues: list[object]) -> str:
    """Return the complete synthetic Supervisor response used by ``--raw-json``."""
    return json.dumps(
        {
            "result": "ok",
            "data": {
                "unsupported": [],
                "unhealthy": [],
                "issues": issues,
                "suggestions": [],
                "checks": [],
            },
        }
    )


def test_s_m1_official_supervisor_envelope_empty_issues_is_shape_valid() -> None:
    """S-M1: the complete Supervisor wrapper is the canonical transport."""
    response = _resolution_response([])
    decoded = access.decode_repairs_response(response)
    result = _collect(response)

    assert decoded == access.DecodedRepairs(shape_valid=True, issues=())
    assert result.shape_valid is True
    assert result.classification == access.ADMISSION_VALID
    assert result.aggregate == access.RepairsAggregate(0, 0)
    assert asdict(access.repairs_evidence(result)) == {
        "shape_valid": True,
        "relevant_count": 0,
        "critical_count": 0,
    }


def test_s_m2_supervisor_envelope_preserves_issues_for_aggregation() -> None:
    """S-M2: strict internal decode preserves valid entries, public result does not."""
    issue = {"scope": "integration", "severity": "critical"}
    response = _resolution_response([issue])
    decoded = access.decode_repairs_response(response)
    result = _collect(response)

    assert decoded == access.DecodedRepairs(shape_valid=True, issues=(issue,))
    assert result.aggregate == access.RepairsAggregate(1, 1)
    assert "scope" not in repr(access.repairs_evidence(result))


@pytest.mark.parametrize(
    ("name", "response"),
    [
        ("S-M3", '{"issues": []}'),
        ("S-M4", "[]"),
        ("S-M5", '{"data": {"issues": []}}'),
        ("S-M6", '{"result": "error", "data": {"issues": []}}'),
        ("S-M7", '{"result": "ok"}'),
        ("S-M8", '{"result": "ok", "data": null}'),
        ("S-M9", '{"result": "ok", "data": {}}'),
        ("S-M10", '{"result": "ok", "data": {"issues": null}}'),
        ("S-M11", '{"result": "ok", "data": {"issues": {}}}'),
        ("S-M12", "{"),
    ],
)
def test_repairs_invalid_shapes_fail_closed_without_empty_issue_fallback(
    name: str, response: str
) -> None:
    """S-M3 through S-M12: invalid shapes never become an empty list."""
    decoded = access.decode_repairs_response(response)
    result = _collect(response)

    assert name.startswith("S-M")
    assert decoded.shape_valid is False
    assert decoded.issues is None
    assert result.shape_valid is False
    assert result.classification == access.ADMISSION_COLLECTOR
    assert result.code == access.REPAIRS_RESPONSE_SHAPE_INVALID
    assert result.aggregate is None
    assert asdict(access.repairs_evidence(result)) == {
        "shape_valid": False,
        "relevant_count": None,
        "critical_count": None,
    }


def test_s_m13_unknown_wrapper_and_data_fields_are_accepted() -> None:
    """S-M13: only the mandatory Supervisor envelope shape is constrained."""
    decoded = access.decode_repairs_response(
        json.dumps(
            {
                "result": "ok",
                "future_wrapper": {},
                "data": {"issues": [], "future_data": {}},
            }
        )
    )

    assert decoded == access.DecodedRepairs(shape_valid=True, issues=())


def test_s_m14_and_s_m15_source_rejects_old_shape_and_permissive_fallbacks() -> None:
    """S-M14/15: reject old top-level parsing and every empty-list fallback."""
    source = Path(access.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    fallback_get_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "payload"
    ]
    list_or_empty = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.IfExp)
        and isinstance(node.orelse, ast.List)
        and not node.orelse.elts
    ]

    assert not fallback_get_calls
    assert not list_or_empty
    assert '"issues" not in payload' not in source
    assert '"result" not in payload' in source


def test_all_represented_gates_use_the_same_strict_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Initial, post-activation, and post-rollback share one decoder path."""
    calls: list[str] = []
    original_decoder = access.decode_repairs_response

    def traced_decoder(response: str) -> access.DecodedRepairs:
        calls.append("decode")
        return original_decoder(response)

    monkeypatch.setattr(access, "decode_repairs_response", traced_decoder)
    responses = {gate: _resolution_response([]) for gate in access.RepairsGate}
    results = access.collect_represented_repairs_gates(responses, _relevant, _critical)

    assert [result.gate for result in results] == list(access.RepairsGate)
    assert all(result.shape_valid for result in results)
    assert calls == ["decode", "decode", "decode"]


def test_b_m1_to_b_m10_private_pty_broker_hides_banner_and_preserves_session(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Synthetic child proves private startup, login-shell, commands, and close output."""
    child = r"""
import os
import sys

if not os.isatty(0):
    raise SystemExit("SYNTHETIC_PIPE_REGRESSION")
print("SYNTHETIC_IPV4_SENTINEL=192.0.2.37", flush=True)
print("SYNTHETIC_IPV6_SENTINEL=2001:db8::37", flush=True)
print("SYNTHETIC_PRIVATE_HOST_SENTINEL=private-host.invalid", flush=True)
print("SYNTHETIC_HOME_ASSISTANT_URL_SENTINEL=http://private-host.invalid:8123", flush=True)
print("SYNTHETIC_OBSERVER_URL_SENTINEL=http://observer.invalid", flush=True)
print("REMOTE_PROMPT", flush=True)
for line in sys.stdin:
    command = line.strip()
    if command == "exec bash -li":
        print("LOGIN_PROMPT", flush=True)
    elif command.startswith("ha resolution info --raw-json; printf"):
        print('{"result": "ok", "data": {"issues": []}}', flush=True)
        print("__HA_INTERACTIVE_COMMAND_DONE__", flush=True)
    elif command == "exit":
        print("SYNTHETIC_CLOSE_TARGET_SENTINEL=private-host.invalid", flush=True)
        break
"""
    broker = access.PrivateInteractiveSessionBroker(
        [sys.executable, "-u", "-c", child],
        remote_ready_marker=b"REMOTE_PROMPT",
        login_ready_marker=b"LOGIN_PROMPT",
        timeout_seconds=1,
    )

    assert broker.open() == access.BrokerState.SESSION_ACTIVE
    assert broker.execute(
        access.ResolutionInfoCommand(access.RepairsGate.INITIAL, _relevant, _critical)
    ) == access.RepairsEvidence(shape_valid=True, relevant_count=0, critical_count=0)
    broker.close()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + repr(broker)
    assert "HA_INTERACTIVE_SESSION_READY" in rendered
    assert all(
        sentinel not in rendered
        for sentinel in (
            "SYNTHETIC_IPV4_SENTINEL",
            "SYNTHETIC_IPV6_SENTINEL",
            "SYNTHETIC_PRIVATE_HOST_SENTINEL",
            "SYNTHETIC_HOME_ASSISTANT_URL_SENTINEL",
            "SYNTHETIC_OBSERVER_URL_SENTINEL",
            "SYNTHETIC_CLOSE_TARGET_SENTINEL",
        )
    )


def test_b_m8_timeout_discards_private_startup_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """B-M8: timeout is generic and never dumps the private captured banner."""
    child = r"""
import os
import sys

assert os.isatty(0)
print("SYNTHETIC_TIMEOUT_PRIVATE_BANNER_SENTINEL=private-host.invalid", flush=True)
for _ in sys.stdin:
    pass
"""
    broker = access.PrivateInteractiveSessionBroker(
        [sys.executable, "-u", "-c", child],
        remote_ready_marker=b"NEVER_ARRIVES",
        login_ready_marker=b"LOGIN_PROMPT",
        timeout_seconds=0.05,
    )

    with pytest.raises(access.SessionBrokerError) as error:
        broker.open()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + str(error.value) + repr(broker)
    assert "PRIVATE_INTERACTIVE_SESSION_TIMEOUT" in rendered
    assert "SYNTHETIC_TIMEOUT_PRIVATE_BANNER_SENTINEL" not in rendered
    assert broker.state is access.BrokerState.CLOSED


def test_o_m6_private_instruction_never_reaches_bootstrap_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """O-M6: bootstrap reports a fixed status, never private recipe text."""
    os.chmod(tmp_path, 0o700)
    private_spec_path = tmp_path / "private-spec.py"
    private_spec_path.write_text(
        _private_spec(SYNTHETIC_PRIVATE_INSTRUCTION_SENTINEL).getvalue(),
        encoding="utf-8",
    )

    assert (
        access.main(
            [
                "bootstrap",
                "--private-spec",
                str(private_spec_path),
                "--wrapper",
                str(tmp_path / "wrapper"),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert SYNTHETIC_PRIVATE_INSTRUCTION_SENTINEL not in output
    assert "PRIVATE_WRAPPER_BOOTSTRAPPED" in output


def test_o_m7_private_target_never_reaches_validation_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """O-M7: static validation emits status/reason codes, never the target."""
    os.chmod(tmp_path, 0o700)
    wrapper = tmp_path / "wrapper"
    access.bootstrap_private_wrapper(_private_spec(), wrapper)

    assert access.main(["validate", "--wrapper", str(wrapper)]) == 0
    output = capsys.readouterr().out
    assert SYNTHETIC_PRIVATE_ROUTE_SENTINEL not in output
    assert "PRIVATE_WRAPPER_VALID" in output


def test_o_m8_validation_rejects_0755_wrapper_and_returns_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """O-M8: non-owner-only wrappers are invalid and cannot report success."""
    os.chmod(tmp_path, 0o700)
    wrapper = tmp_path / "wrapper"
    access.bootstrap_private_wrapper(_private_spec(), wrapper)
    os.chmod(wrapper, 0o755)

    assert access.main(["validate", "--wrapper", str(wrapper)]) == 1
    assert "PRIVATE_WRAPPER_INVALID" in capsys.readouterr().out


def test_o_m9_broker_has_no_network_or_unbounded_terminal_passthrough() -> None:
    """O-M9: the broker may start the local wrapper but never opens a network API."""
    tree = ast.parse(Path(access.__file__).read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    assert not imported_roots & {"socket", "urllib", "requests", "http"}
    assert not called_attributes & {
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "system",
        "popen",
    }


def test_o_m10_public_results_do_not_retain_private_host_or_path(
    tmp_path: Path,
) -> None:
    """O-M10: target and local wrapper path are absent from public evidence."""
    os.chmod(tmp_path, 0o700)
    wrapper = tmp_path / "private-wrapper-path-sentinel"
    access.bootstrap_private_wrapper(_private_spec(), wrapper)
    result = access.validate_private_wrapper(wrapper)

    rendered = repr(result)
    assert SYNTHETIC_PRIVATE_ROUTE_SENTINEL not in rendered
    assert str(wrapper) not in rendered


def test_transcript_privacy_regression_excludes_all_forbidden_categories() -> None:
    """Public aggregate evidence excludes every synthetic private category."""
    response = json.dumps(
        {
            "issues": [
                {
                    "scope": "integration",
                    "severity": "critical",
                    "synthetic_private_values": SYNTHETIC_FORBIDDEN_TRANSCRIPT_SENTINELS,
                }
            ]
        }
    )

    rendered = repr(access.repairs_evidence(_collect(response)))

    assert all(
        sentinel not in rendered
        for sentinel in SYNTHETIC_FORBIDDEN_TRANSCRIPT_SENTINELS
    )


def test_wrapper_validation_rejects_shell_metacharacters_and_symlinks(
    tmp_path: Path,
) -> None:
    """The direct exec command accepts only a simple private alias."""
    os.chmod(tmp_path, 0o700)
    with pytest.raises(ValueError, match="PRIVATE_WRAPPER_COMMAND_INVALID"):
        access.bootstrap_private_wrapper(_private_spec("alias;touch"), tmp_path / "bad")

    source = tmp_path / "source"
    source.write_text("#!/bin/sh\nexec ssh harmless-alias\n", encoding="utf-8")
    os.chmod(source, 0o700)
    symlink = tmp_path / "link"
    symlink.symlink_to(source)
    assert "SYMLINK" in access.validate_private_wrapper(symlink).reasons
