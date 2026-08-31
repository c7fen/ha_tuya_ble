"""Synthetic regressions for the local-only Home Assistant access helper."""

from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import io
import json
import os
import pty
import select
import shutil
import subprocess
import sys
import time
import traceback
from dataclasses import FrozenInstanceError, asdict, replace
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


_VALID_FRAMED_OBJECT = b'{"result":"ok","data":{"issues":[]}}'


@pytest.mark.parametrize(
    ("name", "payload", "accepted"),
    [
        ("J-M1", _VALID_FRAMED_OBJECT, True),
        ("J-M2", b"\r\n  " + _VALID_FRAMED_OBJECT + b" \t\r\n", True),
        ("J-M3", b"{BROKEN " + _VALID_FRAMED_OBJECT, False),
        ("J-M4", b"WARNING " + _VALID_FRAMED_OBJECT, False),
        ("J-M5", _VALID_FRAMED_OBJECT + b" TRAILING", False),
        ("J-M6", _VALID_FRAMED_OBJECT + b"\n" + _VALID_FRAMED_OBJECT, False),
        (
            "J-M7",
            b'{"outer":BROKEN,"nested":' + _VALID_FRAMED_OBJECT + b"}",
            False,
        ),
        ("J-M8", b"[" + _VALID_FRAMED_OBJECT + b"]", False),
        ("J-M9", b"\x1b[31m" + _VALID_FRAMED_OBJECT, False),
        ("J-M10", b"\xff" + _VALID_FRAMED_OBJECT, False),
        (
            "J-M11",
            b'{"result":"ok","data":{"issues":[],"note":"{still json}"}}',
            True,
        ),
        ("J-M12", b" \t\r\n", False),
        ("J-M13", b"", False),
        ("J-M14", b'{"result":"error","data":{"issues":[]}}', True),
    ],
)
def test_j_m1_to_j_m14_exact_framed_json_object_extraction(
    name: str, payload: bytes, accepted: bool
) -> None:
    """J-M1--14: only one complete framed JSON object crosses the boundary."""
    extracted = access._extract_exact_framed_json_object(payload)

    assert name.startswith("J-M")
    assert (extracted is not None) is accepted
    if extracted is not None:
        assert isinstance(json.loads(extracted), dict)


def test_j_m14_extraction_and_supervisor_semantics_remain_separate() -> None:
    """J-M14: a complete error envelope extracts but fails semantic decoding."""
    extracted = access._extract_exact_framed_json_object(
        b'{"result":"error","data":{"issues":[]}}'
    )

    assert extracted is not None
    assert access.decode_repairs_response(extracted) == access.DecodedRepairs(
        shape_valid=False, issues=None
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
        ("S-M7", '{"result": 1, "data": {"issues": []}}'),
        ("S-M8", '{"result": "ok"}'),
        ("S-M9", '{"result": "ok", "data": null}'),
        ("S-M10", '{"result": "ok", "data": []}'),
        ("S-M11", '{"result": "ok", "data": "wrong"}'),
        ("S-M12", '{"result": "ok", "data": {}}'),
        ("S-M13", '{"result": "ok", "data": {"issues": null}}'),
        ("S-M14", '{"result": "ok", "data": {"issues": {}}}'),
        ("S-M15", '{"result": "ok", "data": {"issues": "wrong"}}'),
        ("S-M16", "{"),
    ],
)
def test_repairs_invalid_shapes_fail_closed_without_empty_issue_fallback(
    name: str, response: str
) -> None:
    """S-M3 through S-M16: invalid shapes never become an empty list."""
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


def _fake_spawn(child: str):
    """Return the narrow spawn seam used to test without executing a wrapper."""

    def spawn(_: Path) -> tuple[int, int]:
        child_pid, master_fd = pty.fork()
        if child_pid == 0:
            os.execv(sys.executable, [sys.executable, "-u", "-c", child])
        return child_pid, master_fd

    return spawn


_RESPONSIVE_PTY_CHILD = r"""
import os
import re
import sys

assert os.isatty(0)
assert os.tcgetpgrp(0) == os.getpgrp()
print("SYNTHETIC_BANNER_IPV4=192.0.2.37", flush=True)
print("SYNTHETIC_BANNER_IPV6=2001:db8::37", flush=True)
print("SYNTHETIC_BANNER_HOST=private-host.invalid", flush=True)
print("SYNTHETIC_BANNER_URL=http://private-host.invalid:8123", flush=True)
print("SYNTHETIC_BANNER_OBSERVER=http://observer.invalid", flush=True)
login = False
for line in sys.stdin:
    if line.strip() == "exec bash -li":
        login = True
        continue
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if "HA_BROKER_REMOTE" in line and values:
        print("\x1e" + values[0] + "\x1f", flush=True)
    elif "HA_BROKER_LOGIN" in line and values and login:
        print("\x1e" + values[0] + "\x1f", flush=True)
    elif "ha resolution info --raw-json" in line and login and len(values) == 2:
        print("\x1e" + values[0] + "\x1f", flush=True)
        print('{"result": "ok", "data": {"issues": []}}', flush=True)
        print("\x1e" + values[1] + "\x1f", flush=True)
    elif line.strip() == "exit":
        print("SYNTHETIC_CLOSE_TARGET=private-host.invalid", flush=True)
        break
"""


def _resolution_pty_child(payload: bytes) -> str:
    """Return a controlling-PTY child that emits one synthetic framed payload."""
    return (
        "_PAYLOAD = "
        + repr(payload)
        + "\n"
        + r"""
import os
import re
import sys

assert os.isatty(0)
assert os.tcgetpgrp(0) == os.getpgrp()
login = False

def emit_frame(value):
    os.write(1, b"\x1e" + value.encode("ascii") + b"\x1f")

for line in sys.stdin:
    if line.strip() == "exec bash -li":
        login = True
        continue
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if "HA_BROKER_REMOTE" in line and values:
        emit_frame(values[0])
    elif "HA_BROKER_LOGIN" in line and values and login:
        emit_frame(values[0])
    elif "ha resolution info --raw-json" in line and login and len(values) == 2:
        emit_frame(values[0])
        os.write(1, _PAYLOAD)
        emit_frame(values[1])
    elif line.strip() == "exit":
        break
"""
    )


def _broker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    child: str,
    *,
    max_capture_bytes: int = 64 * 1024,
):
    wrapper = tmp_path / "SYNTHETIC_REAL_WRAPPER_MUST_NOT_RUN"
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda path: access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ()),
    )
    monkeypatch.setattr(access, "_spawn_private_wrapper", _fake_spawn(child))
    return access.PrivateInteractiveSessionBroker(
        wrapper,
        timeout_seconds=0.2,
        max_capture_bytes=max_capture_bytes,
    )


@pytest.mark.parametrize(
    ("name", "payload", "expected"),
    [
        (
            "E-M1",
            _VALID_FRAMED_OBJECT,
            access.RepairsEvidence(True, 0, 0),
        ),
        (
            "E-M2",
            b"{BROKEN " + _VALID_FRAMED_OBJECT,
            access.RepairsEvidence(False, None, None),
        ),
        (
            "E-M3",
            b"WARNING " + _VALID_FRAMED_OBJECT,
            access.RepairsEvidence(False, None, None),
        ),
        (
            "E-M4",
            _VALID_FRAMED_OBJECT + b"\n" + _VALID_FRAMED_OBJECT,
            access.RepairsEvidence(False, None, None),
        ),
        (
            "E-M5",
            b"\r\n \t" + _VALID_FRAMED_OBJECT + b" \t\r\n",
            access.RepairsEvidence(True, 0, 0),
        ),
    ],
)
def test_e_m1_to_e_m5_broker_enforces_exact_framed_json_boundary(
    name: str,
    payload: bytes,
    expected: access.RepairsEvidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """E-M1--5: framed PTY payloads cross extraction and semantic validation."""
    broker = _broker(monkeypatch, tmp_path, _resolution_pty_child(payload))

    assert broker.open() is access.BrokerState.SESSION_ACTIVE
    try:
        evidence = broker._collect_resolution_info(
            access.RepairsGate.INITIAL,
            _capability=_r32_controller_minted_capability(
                broker, access.LifecycleAction.INITIAL_REPAIRS
            ),
        )
    finally:
        broker.close()

    assert name.startswith("E-M")
    assert evidence == expected


def test_malformed_inner_envelope_never_becomes_empty_valid_evidence() -> None:
    """A valid-looking inner object cannot rescue a malformed framed payload."""
    extracted = access._extract_exact_framed_json_object(
        b"{BROKEN " + _VALID_FRAMED_OBJECT
    )
    result = access.collect_repairs_gate(
        access.RepairsGate.INITIAL,
        extracted if extracted is not None else "",
        _relevant,
        _critical,
    )
    evidence = access.repairs_evidence(result)

    assert evidence == access.RepairsEvidence(False, None, None)
    assert evidence != access.RepairsEvidence(True, 0, 0)


def test_rejected_framed_payload_is_never_emitted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Rejected private payload bytes never reach output, errors, or evidence."""
    sentinel = "SYNTHETIC_REJECTED_PRIVATE_PAYLOAD_SENTINEL"
    payload = sentinel.encode("ascii") + b" " + _VALID_FRAMED_OBJECT
    broker = _broker(monkeypatch, tmp_path, _resolution_pty_child(payload))

    broker.open()
    evidence = broker._collect_resolution_info(
        access.RepairsGate.INITIAL,
        _capability=_r32_controller_minted_capability(
            broker, access.LifecycleAction.INITIAL_REPAIRS
        ),
    )
    broker.close()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + repr(broker) + repr(evidence)
    assert evidence == access.RepairsEvidence(False, None, None)
    assert sentinel not in rendered


@pytest.mark.parametrize(
    "name,sentinel",
    [
        ("B-M1", "SYNTHETIC_BANNER_IPV4"),
        ("B-M2", "SYNTHETIC_BANNER_IPV6"),
        ("B-M3", "SYNTHETIC_BANNER_HOST"),
        ("B-M4", "SYNTHETIC_BANNER_URL"),
        ("B-M5", "SYNTHETIC_BANNER_OBSERVER"),
        ("B-M6", "SYNTHETIC_CLOSE_TARGET"),
    ],
)
def test_b_m1_to_b_m6_private_pty_output_never_reaches_transcript(
    name: str,
    sentinel: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """B-M1--6: banner/close leakage and pipe substitution are detected."""
    broker = _broker(monkeypatch, tmp_path, _RESPONSIVE_PTY_CHILD)

    assert broker.open() is access.BrokerState.SESSION_ACTIVE
    assert broker._collect_resolution_info(
        access.RepairsGate.INITIAL,
        _capability=_r32_controller_minted_capability(
            broker, access.LifecycleAction.INITIAL_REPAIRS
        ),
    ) == access.RepairsEvidence(shape_valid=True, relevant_count=0, critical_count=0)
    assert broker._collect_resolution_info(
        access.RepairsGate.POST_ACTIVATION,
        _capability=_r32_controller_minted_capability(
            broker, access.LifecycleAction.POST_ACTIVATION_REPAIRS
        ),
    ) == access.RepairsEvidence(shape_valid=True, relevant_count=0, critical_count=0)
    broker.close()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + repr(broker)
    assert name.startswith("B-M")
    assert access.HA_INTERACTIVE_SESSION_READY in rendered
    assert sentinel not in rendered


def test_b_m7_wrapper_is_validated_then_spawned_without_arguments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M7: only a validated wrapper path reaches the production spawn seam."""
    wrapper = tmp_path / "synthetic-wrapper-path"
    validated: list[Path] = []
    spawned: list[Path] = []
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda path: (
            validated.append(path)
            or access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ())
        ),
    )

    def fake_spawn(path: Path) -> tuple[int, int]:
        spawned.append(path)
        return _fake_spawn(_RESPONSIVE_PTY_CHILD)(path)

    monkeypatch.setattr(access, "_spawn_private_wrapper", fake_spawn)
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.2)
    broker.open()
    broker.close()

    assert validated == [wrapper, wrapper]
    assert spawned == [wrapper]


def test_b_m7_revalidates_wrapper_immediately_before_spawn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M7: a wrapper invalidated after construction is never spawned."""
    wrapper = tmp_path / "synthetic-wrapper-path"
    validation_calls = 0
    spawned: list[Path] = []

    def validate(_: Path) -> access.WrapperValidationResult:
        nonlocal validation_calls
        validation_calls += 1
        status = (
            access.PRIVATE_WRAPPER_VALID
            if validation_calls == 1
            else access.PRIVATE_WRAPPER_INVALID
        )
        return access.WrapperValidationResult(status, ())

    monkeypatch.setattr(access, "validate_private_wrapper", validate)
    monkeypatch.setattr(
        access, "_spawn_private_wrapper", lambda path: spawned.append(path)
    )
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.2)

    with pytest.raises(access.SessionBrokerError, match="WRAPPER_INVALID"):
        broker.open()

    assert validation_calls == 2
    assert spawned == []


def test_b_m7_wrapper_contents_never_reach_retained_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """B-M7: wrapper-source leakage is detected even when launch otherwise works."""
    private_content = "SYNTHETIC_WRAPPER_CONTENT_PRIVATE_TARGET_SENTINEL"
    wrapper = tmp_path / "synthetic-wrapper-content"
    wrapper.write_text(
        "#!/bin/sh\n# " + private_content + "\nexit 99\n",
        encoding="utf-8",
    )
    os.chmod(wrapper, 0o700)
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda path: access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ()),
    )
    monkeypatch.setattr(
        access, "_spawn_private_wrapper", _fake_spawn(_RESPONSIVE_PTY_CHILD)
    )
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.2)

    broker.open()
    evidence = broker._collect_resolution_info(
        access.RepairsGate.INITIAL,
        _capability=_r32_controller_minted_capability(
            broker, access.LifecycleAction.INITIAL_REPAIRS
        ),
    )
    broker.close()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + repr(broker) + repr(evidence)
    assert private_content not in rendered


def test_b_m9_login_readiness_requires_verified_interactive_login_bash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M9: ignoring ``exec bash -li`` cannot be rescued by a generic frame."""
    child = r"""
import os
import re
import sys

assert os.isatty(0)
for line in sys.stdin:
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if "HA_BROKER_REMOTE" in line and values:
        print("\x1e" + values[0] + "\x1f", flush=True)
    elif line.strip() == "exec bash -li":
        # A shell that ignores this must never be admitted as login Bash.
        continue
    elif line.startswith("printf ") and "HA_BROKER_LOGIN" in line and values:
        # This models the rejected generic post-exec challenge fallback.
        print("\x1e" + values[0] + "\x1f", flush=True)
"""
    broker = _broker(monkeypatch, tmp_path, child)

    with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
        broker.open()

    source = Path(access.__file__).read_text(encoding="utf-8")
    assert "BASH_VERSION" in source
    assert "shopt -q login_shell" in source
    assert "case $- in *i*" in source
    assert 'self._challenge("LOGIN")' not in source


def test_b_m6_production_spawn_has_a_controlling_tty(tmp_path: Path) -> None:
    """B-M6: the unpatched production primitive gives its child a controlling TTY."""
    wrapper = tmp_path / "synthetic-controlling-tty"
    wrapper.write_text(
        "#!/bin/sh\n"
        "exec python3 -c 'import os; "
        "assert os.isatty(0); "
        "assert os.tcgetpgrp(0) == os.getpgrp(); "
        'print("SYNTHETIC_CONTROLLING_TTY_OK", flush=True)\'\n',
        encoding="utf-8",
    )
    os.chmod(wrapper, 0o700)

    child_pid, master_fd = access._spawn_private_wrapper(wrapper)
    try:
        readable, _, _ = select.select([master_fd], [], [], 1)
        assert readable
        assert b"SYNTHETIC_CONTROLLING_TTY_OK" in os.read(master_fd, 4096)
        assert os.waitpid(child_pid, 0)[0] == child_pid
    finally:
        os.close(master_fd)


@pytest.mark.parametrize("name,child", [("B-M8", ""), ("B-M9", "")])
def test_b_m8_and_b_m9_static_banner_or_prompt_cannot_fake_challenges(
    name: str,
    child: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """B-M8/9: errors are generic and shell readiness needs fresh challenges."""
    if name == "B-M8":
        child = r"""
import os
import re
import sys
assert os.isatty(0)
print("SYNTHETIC_TIMEOUT_PRIVATE_START=private-host.invalid", flush=True)
for _ in sys.stdin:
    pass
"""
    else:
        child = r"""
import os
import re
import sys
assert os.isatty(0)
print("SYNTHETIC_STATIC_PROMPT=READY", flush=True)
for line in sys.stdin:
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if "HA_BROKER_REMOTE" in line and values:
        print("\x1e" + values[0] + "\x1f", flush=True)
    # Deliberately never acknowledge the post-exec login-shell challenge.
"""
    broker = _broker(monkeypatch, tmp_path, child)

    with pytest.raises(access.SessionBrokerError) as error:
        broker.open()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err + str(error.value) + repr(broker)
    assert name.startswith("B-M")
    assert "PRIVATE_INTERACTIVE_SESSION_TIMEOUT" in rendered
    assert "SYNTHETIC_" not in rendered
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_b_m10_real_wrapper_is_never_executed_by_synthetic_tests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M10: a fake child can run only through the private spawn seam."""
    wrapper = tmp_path / "SYNTHETIC_REAL_WRAPPER_MUST_NOT_RUN"
    marker = tmp_path / "SYNTHETIC_REAL_WRAPPER_RAN"
    wrapper.write_text(
        "#!/bin/sh\nprintf x > '" + str(marker) + "'\n",
        encoding="utf-8",
    )
    os.chmod(wrapper, 0o700)
    spawns: list[Path] = []
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda path: access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ()),
    )

    def fake_spawn(path: Path) -> tuple[int, int]:
        spawns.append(path)
        return _fake_spawn(_RESPONSIVE_PTY_CHILD)(path)

    monkeypatch.setattr(access, "_spawn_private_wrapper", fake_spawn)
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.2)
    broker.open()
    broker.close()
    assert spawns == [wrapper]
    assert not marker.exists()


@pytest.mark.parametrize(
    ("name", "child"),
    [
        ("B-M8-START", None),
        (
            "B-M8-EXIT",
            "raise SystemExit('SYNTHETIC_CHILD_EXIT_PRIVATE_SENTINEL')",
        ),
    ],
)
def test_b_m8_exception_paths_never_retain_private_failure_context(
    name: str,
    child: str | None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """B-M8: spawn and child-exit errors expose only generic broker classes."""
    private_sentinel = "SYNTHETIC_START_PRIVATE_SENTINEL"
    if child is None:
        wrapper = tmp_path / "synthetic-wrapper"
        monkeypatch.setattr(
            access,
            "validate_private_wrapper",
            lambda path: access.WrapperValidationResult(
                access.PRIVATE_WRAPPER_VALID, ()
            ),
        )

        def fail_spawn(_: Path) -> tuple[int, int]:
            raise OSError(private_sentinel)

        monkeypatch.setattr(access, "_spawn_private_wrapper", fail_spawn)
        broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.05)
        forbidden = private_sentinel
    else:
        broker = _broker(monkeypatch, tmp_path, child)
        forbidden = "SYNTHETIC_CHILD_EXIT_PRIVATE_SENTINEL"

    with pytest.raises(access.SessionBrokerError) as error:
        broker.open()

    rendered = "".join(traceback.format_exception(error.type, error.value, error.tb))
    context = repr(error.value.__context__)
    assert name.startswith("B-M8")
    assert forbidden not in str(error.value)
    assert forbidden not in repr(error.value)
    assert forbidden not in context
    assert forbidden not in rendered
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_b_m8_output_limit_precedes_a_valid_frame(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B-M8: a valid frame after over-limit private bytes fails closed."""
    child = r"""
import os
import re
import sys

assert os.isatty(0)
for line in sys.stdin:
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if values:
        print("SYNTHETIC_OVER_LIMIT_PRIVATE_BYTES" * 4, flush=True)
        print("\x1e" + values[0] + "\x1f", flush=True)
"""
    broker = _broker(monkeypatch, tmp_path, child, max_capture_bytes=8)

    with pytest.raises(access.SessionBrokerError, match="OUTPUT_LIMIT") as error:
        broker.open()

    assert "SYNTHETIC_OVER_LIMIT_PRIVATE_BYTES" not in str(error.value)


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
    assert not imported_roots & {"socket", "urllib", "requests", "http"}
    source = Path(access.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "DEVNULL" not in source
    assert "def execute(" not in source
    assert hasattr(access.PrivateInteractiveSessionBroker, "_collect_resolution_info")


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
    response = _resolution_response(
        [
            {
                "scope": "integration",
                "severity": "critical",
                "synthetic_private_values": SYNTHETIC_FORBIDDEN_TRANSCRIPT_SENTINELS,
            }
        ]
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


def _r30_manifest(
    state_name: str = "CANDIDATE",
    *,
    helper_digest: str | None = None,
) -> object:
    helper = b"synthetic helper source\n"
    library = b"synthetic helper library\n"
    integration = b"synthetic integration source\n"
    entry_type = access.SourceManifestEntry
    state = getattr(access.SourceState, state_name)
    entries = [
        entry_type(
            "integration/__init__.py",
            len(integration),
            hashlib.sha256(integration).hexdigest(),
        )
    ]
    if state_name == "CANDIDATE":
        entries.extend(
            (
                entry_type(
                    "helper/phase_a_status_probe_helper.py",
                    len(helper),
                    helper_digest or hashlib.sha256(helper).hexdigest(),
                ),
                entry_type(
                    "helper/phase_a_status_probe_lib.py",
                    len(library),
                    hashlib.sha256(library).hexdigest(),
                ),
            )
        )
    return access.SourceManifest(state, tuple(entries))


def _r30_files(
    state_name: str = "CANDIDATE", *, symlink: bool = False
) -> tuple[object, ...]:
    entry_type = access.SourceBundleFile
    files = [entry_type("integration/__init__.py", b"synthetic integration source\n")]
    if state_name == "CANDIDATE":
        files.extend(
            (
                entry_type(
                    "helper/phase_a_status_probe_helper.py",
                    b"synthetic helper source\n",
                    regular_file=not symlink,
                ),
                entry_type(
                    "helper/phase_a_status_probe_lib.py",
                    b"synthetic helper library\n",
                ),
            )
        )
    return tuple(files)


@pytest.fixture(autouse=True)
def _synthetic_r30_source_authorities(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> None:
    """Keep synthetic source acceptance explicit and separate from Git authorities."""
    monkeypatch.setattr(access, "_LIFECYCLE_STATE_ROOT", tmp_path / "lifecycle")
    monkeypatch.setattr(
        access,
        "_DISABLE_DURABLE_LIFECYCLE_FOR_TESTS",
        not request.node.name.startswith(
            ("test_r33_", "test_r35_reconstruction_", "test_r36_")
        ),
    )
    if not request.node.name.startswith(
        ("test_r30_", "test_r32_", "test_r33_", "test_r35_", "test_r36_")
    ):
        return
    for state_name in ("CANDIDATE", "RESTORE"):
        manifest = _r30_manifest(state_name)
        monkeypatch.setitem(
            access._AUTHORITY_MANIFEST_DIGESTS,
            manifest.state.value,
            access._source_manifest_digest(manifest.entries),
        )


def _zero_audit_snapshot(**changes: object) -> object:
    values = {
        "protocol_version": 1,
        "audit_instance_token": "a" * 32,
        "event_ordinal": 0,
        "history_overflow": False,
        "runtime_ms": 1,
        "counters": tuple((name, 0) for name in access.AUDIT_COUNTER_NAMES),
        "events": (),
        "nonce": "b" * 16,
    }
    values.update(changes)
    return access.AuditSnapshot(**values)


def test_r30_no_generic_command_api_and_exact_operation_allowlist() -> None:
    """R30-1/2: callers can express only reviewed bounded operations."""
    forbidden = {
        "run_command",
        "shell",
        "exec_remote",
        "execute",
        "write_stdin",
        "read_stdout",
    }
    assert not forbidden.intersection(dir(access.PrivateInteractiveSessionBroker))
    assert {item.value for item in access.BoundedOperation} == {
        "backup",
        "transfer",
        "install",
        "source_inventory",
        "core_check",
        "restart_core",
        "core_readiness",
        "service_inventory",
        "phase_a_helper",
        "restore",
        "restore_backup",
        "reconcile_backup",
        "reconcile_backup_creation",
    }
    public_callables = {
        name
        for name, value in vars(access.PrivateInteractiveSessionBroker).items()
        if not name.startswith("_") and callable(value)
    }
    assert public_callables == {"open", "close"}
    for method_name in public_callables:
        parameters = inspect.signature(
            getattr(access.PrivateInteractiveSessionBroker, method_name)
        ).parameters
        assert not set(parameters) & {
            "command",
            "argv",
            "remote_path",
            "endpoint",
            "service_name",
        }


def test_r30_unknown_operation_rejected_before_remote_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R30-2: even the private dispatcher rejects strings before PTY I/O."""
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    writes: list[str] = []
    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__write_wire", writes.append
    )

    with pytest.raises(access.SessionBrokerError, match="OPERATION_INVALID"):
        broker._PrivateInteractiveSessionBroker__execute_bounded_operation(
            "arbitrary", {}
        )

    assert writes == []


def test_r30_probe_is_unrepresentable_and_rejected_before_remote_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R30-3: PROBE never reaches command construction or the PTY."""
    assert {item.value for item in access.PhaseAOperation} == {
        "preflight",
        "audit",
        "receipt",
    }
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    writes: list[access._PrivateWirePacket] = []
    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__write_wire", writes.append
    )

    with pytest.raises(access.SessionBrokerError, match="HELPER_OPERATION_INVALID"):
        broker._invoke_phase_a("probe")

    assert writes == []


def test_r30_source_bundle_wrong_manifest_rejected() -> None:
    """R30-4: every byte must match the trusted local manifest."""
    manifest = _r30_manifest(helper_digest="0" * 64)

    with pytest.raises(
        access.SourceBundleError, match="(?:AUTHORITY|MANIFEST)_MISMATCH"
    ):
        access.build_source_bundle(access.SourceState.CANDIDATE, _r30_files(), manifest)


def test_r30_self_consistent_forged_manifest_rejected_by_git_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller cannot bless arbitrary allowed-path bytes as exact PR #45 source."""
    manifest = _r30_manifest()
    monkeypatch.setitem(
        access._AUTHORITY_MANIFEST_DIGESTS,
        access.SourceState.CANDIDATE.value,
        "4b7d4222c57377a29961d35a7427ebc1b6dd032a82a9274a63a0f0269e13a20e",
    )

    with pytest.raises(access.SourceBundleError, match="AUTHORITY_MISMATCH"):
        access.build_source_bundle(access.SourceState.CANDIDATE, _r30_files(), manifest)


def test_r30_authority_valid_manifest_still_rejects_changed_file_bytes() -> None:
    """Per-file digests remain an independent gate after authority admission."""
    manifest = _r30_manifest()
    files = list(_r30_files())
    files[0] = access.SourceBundleFile(
        "integration/__init__.py", b"changed but allowed-path source\n"
    )

    with pytest.raises(access.SourceBundleError, match="MANIFEST_MISMATCH"):
        access.build_source_bundle(access.SourceState.CANDIDATE, tuple(files), manifest)


def test_r30_source_bundle_unexpected_file_rejected() -> None:
    """R30-5: helper slots and integration-relative files are closed."""
    files = _r30_files() + (
        access.SourceBundleFile("helper/arbitrary.py", b"unexpected\n"),
    )

    with pytest.raises(access.SourceBundleError, match="UNEXPECTED_FILE"):
        access.build_source_bundle(access.SourceState.CANDIDATE, files, _r30_manifest())


def test_r30_source_bundle_symlink_entry_rejected() -> None:
    """R30-6: transfer manifests can contain regular files only."""
    with pytest.raises(access.SourceBundleError, match="REGULAR_FILES_ONLY"):
        access.build_source_bundle(
            access.SourceState.CANDIDATE, _r30_files(symlink=True), _r30_manifest()
        )


def test_r30_source_bundle_rejects_traversal_and_duplicate_entries() -> None:
    """Bounded deployment slots cannot encode a path escape or overwrite."""
    traversal = access.SourceBundleFile("integration/../private", b"x")
    duplicate = _r30_files() + (_r30_files()[0],)

    with pytest.raises(access.SourceBundleError, match="UNEXPECTED_FILE"):
        access.build_source_bundle(
            access.SourceState.CANDIDATE,
            _r30_files() + (traversal,),
            _r30_manifest(),
        )
    with pytest.raises(access.SourceBundleError, match="DUPLICATE_FILE"):
        access.build_source_bundle(
            access.SourceState.CANDIDATE, duplicate, _r30_manifest()
        )


def test_r30_source_bundle_repr_hides_content_and_paths() -> None:
    """R30-16/18: bundle data and deployment layout never enter repr."""
    bundle = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    rendered = repr(bundle)

    assert "synthetic helper" not in rendered
    assert "phase_a_status_probe" not in rendered
    assert "integration/" not in rendered


def test_r30_source_inventory_mismatch_is_not_success() -> None:
    """R30-7: partial or contaminated source cannot become a match."""
    result = access._parse_source_inventory_result(
        {
            "expected_count": 3,
            "observed_count": 3,
            "manifest_match": False,
            "unexpected_count": 1,
            "missing_count": 1,
        }
    )

    assert result.manifest_match is False
    assert result.unexpected_count == 1
    assert result.missing_count == 1

    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_source_inventory_result(
            {
                "expected_count": 3,
                "observed_count": 2,
                "manifest_match": True,
                "unexpected_count": 0,
                "missing_count": 1,
            }
        )


@pytest.mark.parametrize(
    "payload",
    (
        {},
        {"http_status": 200, "result": "error", "check_passed": True},
        {"http_status": 503, "result": "ok", "check_passed": True},
        {"http_status": 200, "result": "ok", "check_passed": False},
        {"http_status": 200, "result": ["ok"], "check_passed": True},
    ),
)
def test_r30_core_check_malformed_or_error_never_passes(payload: object) -> None:
    """R30-8/9: authoritative Core-check success requires every exact gate."""
    result = access._parse_core_check_result(payload, attempt_ordinal=1)

    assert result.check_passed is False


def test_r30_core_check_exact_success_contract() -> None:
    """A 2xx JSON result=ok is the only accepted Core-check proof."""
    result = access._parse_core_check_result(
        {"http_status": 200, "result": "ok", "check_passed": True},
        attempt_ordinal=2,
    )

    assert result == access.CoreCheckResult(2, 200, "ok", True, None)


def test_r30_restart_operation_has_no_retry_loop() -> None:
    """R30-10: one call submits at most one Core restart."""
    source = Path(access.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    restart = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_restart_core"
    )

    assert not any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(restart))


def test_r30_restart_replay_rejected_before_second_remote_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One activated source state can submit at most one restart."""
    broker = _r32_unbound_real_broker()
    calls: list[object] = []

    def execute(operation: object, _value: object, *, _capability: object) -> bytes:
        calls.append(operation)
        return b'{"submitted":true,"accepted":true}'

    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__execute_bounded_operation", execute
    )
    capability = _r32_controller_minted_capability(
        broker, access.LifecycleAction.ACTIVATION_RESTART
    )

    assert broker._restart_core(_capability=capability).accepted is True
    with pytest.raises(access.SessionBrokerError, match="ALREADY_SUBMITTED"):
        broker._restart_core(_capability=capability)
    assert calls == [access.BoundedOperation.RESTART_CORE]


def test_r30_service_inventory_mismatch_fails_closed() -> None:
    """R30-11: temporary-service presence and absence are exact aggregates."""
    present = access._parse_service_inventory_result(
        {
            "expected_present_count": 4,
            "observed_present_count": 3,
            "all_expected_present": False,
            "expected_absent_count": 0,
            "observed_absent_count": 0,
            "all_expected_absent": True,
        }
    )
    absent = access._parse_service_inventory_result(
        {
            "expected_present_count": 0,
            "observed_present_count": 0,
            "all_expected_present": True,
            "expected_absent_count": 4,
            "observed_absent_count": 3,
            "all_expected_absent": False,
        }
    )

    assert present.all_expected_present is False
    assert absent.all_expected_absent is False


@pytest.mark.parametrize(
    "private_output",
    (
        b"not-json",
        b"{}",
        b'{"exit_code":78,"outcome":"transport_ambiguous"} trailing',
        b'\x1b[31m{"exit_code":65,"outcome":"not_submitted"}',
        b"".join(
            (
                b'{"exit_code":65,"outcome":"not_submitted"}\n',
                b'{"exit_code":65,"outcome":"not_submitted"}',
            )
        ),
    ),
)
def test_r30_helper_malformed_or_contaminated_output_fails(
    private_output: bytes,
) -> None:
    """R30-12/17: helper output accepts one exact framed JSON object only."""
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(access.PhaseAOperation.PREFLIGHT, private_output)


def test_r30_helper_exit_78_preserved_without_replay_permission() -> None:
    """R30-13: ambiguity is terminal evidence, never retry authorization."""
    nonce = "c" * 16
    result = access._parse_phase_a_result(
        access.PhaseAOperation.PREFLIGHT,
        json.dumps(
            {
                "exit_code": 78,
                "outcome": "transport_ambiguous",
                "nonce": nonce,
            }
        ).encode(),
    )

    assert result.exit_code == 78
    assert result.outcome == "transport_ambiguous"
    assert result.nonce == nonce
    assert not hasattr(result, "retry")


def test_r30_helper_exit_78_invocation_is_not_replayed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One ambiguous helper operation causes exactly one remote dispatch."""
    broker = _r32_unbound_real_broker()
    calls: list[object] = []

    def execute(
        operation: object,
        _value: object,
        *,
        detail: str,
        _capability: object,
    ) -> bytes:
        calls.append((operation, detail))
        return b'{"exit_code":78,"outcome":"transport_ambiguous","nonce":"aaaaaaaaaaaaaaaa"}'

    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__execute_bounded_operation", execute
    )
    result = broker._invoke_phase_a(
        access.PhaseAOperation.PREFLIGHT,
        nonce="a" * 16,
        _capability=_r32_controller_minted_capability(
            broker, access.LifecycleAction.PREFLIGHT
        ),
    )

    assert result.exit_code == 78
    assert calls == [(access.BoundedOperation.PHASE_A_HELPER, "preflight")]


def test_r30_raw_helper_wrapper_keys_are_rejected() -> None:
    """A raw REST wrapper or changed state can never become a public result."""
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            access.PhaseAOperation.PREFLIGHT,
            b'{"exit_code":0,"outcome":"preflight_ok","nonce":"aaaaaaaaaaaaaaaa","changed_states":[]}',
        )


@pytest.mark.parametrize(
    ("operation", "outcome"),
    (
        ("PREFLIGHT", "receipt"),
        ("AUDIT", "preflight_ok"),
        ("RECEIPT", "audit_snapshot"),
    ),
)
def test_r30_helper_cross_operation_success_rejected(
    operation: str, outcome: str
) -> None:
    """An exit-zero result is valid only for the operation that produced it."""
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            getattr(access.PhaseAOperation, operation),
            json.dumps(
                {"exit_code": 0, "outcome": outcome, "nonce": "a" * 16}
            ).encode(),
        )


def test_r30_helper_nonce_mismatch_rejected() -> None:
    """A stale helper response cannot satisfy a fresh invocation."""
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            access.PhaseAOperation.PREFLIGHT,
            b'{"exit_code":0,"outcome":"preflight_ok","nonce":"aaaaaaaaaaaaaaaa"}',
            expected_nonce="b" * 16,
        )


def test_r30_invalid_nonce_preflight_contract_is_local_not_submitted() -> None:
    """P0 requires the exact helper exit-65 projection."""
    result = access._parse_phase_a_result(
        access.PhaseAOperation.PREFLIGHT,
        b'{"exit_code":65,"outcome":"not_submitted"}',
    )

    assert result.exit_code == 65
    assert result.outcome == "not_submitted"
    assert result.nonce is None
    assert result.preflight is None


def test_r30_audit_comparison_detects_every_zero_io_change() -> None:
    """R30-14: ordinal, counters, and events are compared without equivalence guesses."""
    before = _zero_audit_snapshot()
    changed_counters = list(before.counters)
    changed_counters[0] = (changed_counters[0][0], 1)

    ordinal = access.compare_audit_snapshots(
        before, _zero_audit_snapshot(event_ordinal=1)
    )
    counters = access.compare_audit_snapshots(
        before, _zero_audit_snapshot(counters=tuple(changed_counters))
    )
    events = access.compare_audit_snapshots(
        before,
        _zero_audit_snapshot(
            events=(("event_ordinal", 1),),
        ),
    )

    assert ordinal.ordinal_unchanged is False
    assert counters.counters_unchanged is False
    assert events.events_unchanged is False
    assert ordinal.zero_io_unchanged is False
    assert counters.zero_io_unchanged is False
    assert events.zero_io_unchanged is False
    assert ordinal.same_instance is True
    assert ordinal.no_overflow is True


def test_r30_restore_requires_restore_authority_manifest() -> None:
    """R30-15: candidate source can never be passed as the PR #41 restore authority."""
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    broker = object.__new__(access.PrivateInteractiveSessionBroker)

    with pytest.raises(access.SourceBundleError, match="RESTORE_MANIFEST_REQUIRED"):
        broker._restore_source(candidate)


def test_r30_remote_program_contains_fixed_endpoints_and_no_probe_dispatch() -> None:
    """The internal program fixes paths/endpoints and contains no helper PROBE branch."""
    source = access._REMOTE_CONTROL_PROGRAM

    assert "http://supervisor/core/check" in source
    assert "http://supervisor/core/restart" in source
    assert "phase_a_status_probe_helper.py" in source
    assert "operation == 'probe'" not in source
    assert '"probe"' not in source
    assert "arbitrary" not in source
    assert "renameat2" in source
    assert "RENAME_EXCHANGE" not in source or "2" in source
    assert "api/config" in source
    assert "loaded = bool(SERVICES" not in source
    helper_start = source.index("def invoke_helper")
    helper_end = source.index("def restore_backup")
    helper_source = source[helper_start:helper_end]
    assert "operation not in {'preflight', 'audit'}" in helper_source
    assert "'probe'" not in helper_source
    restart_start = source.index("def restart_core")
    restart_end = source.index("def service_names")
    assert (
        source[restart_start:restart_end].count(
            "request_json('http://supervisor/core/restart', 'POST')"
        )
        == 1
    )
    compile(source, "<synthetic-r30-remote-program>", "exec")


def test_r30_private_backup_restore_is_fixed_and_typed() -> None:
    """The safety backup has a named fallback operation without a path argument."""
    signature = inspect.signature(
        access.PrivateInteractiveSessionBroker._restore_private_backup
    )

    assert tuple(signature.parameters) == ("self", "manifest", "_capability")
    assert signature.parameters["_capability"].kind is inspect.Parameter.KEYWORD_ONLY
    assert access.BoundedOperation.RESTORE_BACKUP.value == "restore_backup"


def _run_synthetic_remote_program(
    tmp_path: Path,
    operation: str,
    value: dict[str, object],
    *,
    source_replacements: dict[str, str] | None = None,
    expected_crash_code: int | None = None,
) -> dict[str, object]:
    """Execute the exact remote program with only fixed roots/fingerprints replaced."""
    candidate = _r30_manifest()
    restore = _r30_manifest("RESTORE")
    source = access._REMOTE_CONTROL_PROGRAM.replace(
        "ROOT = Path('/config')", f"ROOT = Path({str(tmp_path)!r})"
    )
    source = source.replace(
        "4b7d4222c57377a29961d35a7427ebc1b6dd032a82a9274a63a0f0269e13a20e",
        access._source_manifest_digest(candidate.entries),
    ).replace(
        "2d1dd79288b90f0d12c5c35449e6ed5d02c53433335dedd68377c81809731ac2",
        access._source_manifest_digest(restore.entries),
    )
    for original, replacement in (source_replacements or {}).items():
        assert original in source
        source = source.replace(original, replacement)
    encoded = base64.b64encode(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    ).decode()
    chunks = [
        encoded[index : index + access._TRANSFER_CHUNK_SIZE]
        for index in range(0, len(encoded), access._TRANSFER_CHUNK_SIZE)
    ]
    completed = subprocess.run(
        [sys.executable, "-c", source, operation],
        input=str(len(chunks)) + "\n" + "\n".join(chunks) + "\n",
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
        env={},
    )
    if expected_crash_code is not None:
        assert completed.returncode == expected_crash_code
        assert completed.stdout == ""
        assert completed.stderr == ""
        return {}
    assert completed.returncode == 0
    assert completed.stderr == ""
    result = json.loads(completed.stdout)
    assert isinstance(result, dict)
    return result


def test_r30_remote_program_synthetic_atomic_install_and_restore(
    tmp_path: Path,
) -> None:
    """The transmitted program performs a real one-tree lifecycle without network."""
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    restore = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )

    backup = _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())
    transfer = _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )
    install = _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )

    assert backup["manifest_match"] is True
    assert transfer["manifest_match"] is True
    assert install["manifest_match"] is True
    helper = integration / ".phase_a_tools"
    assert helper.is_dir()
    assert {path.name for path in helper.iterdir()} == {
        "phase_a_status_probe_helper.py",
        "phase_a_status_probe_lib.py",
    }

    restore_transfer = _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(restore)
    )
    restored = _run_synthetic_remote_program(
        tmp_path,
        "restore",
        {"manifest": access._manifest_payload(restore.manifest)},
    )

    assert restore_transfer["manifest_match"] is True
    assert restored["manifest_match"] is True
    assert not helper.exists()
    assert (integration / "__init__.py").read_bytes() == (
        b"synthetic integration source\n"
    )


def test_r30_remote_transfer_rejects_tampered_content_before_staging(
    tmp_path: Path,
) -> None:
    """Remote post-transfer digest verification rejects an altered encoded file."""
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    value = access._bundle_payload(candidate)
    files = value["files"]
    assert isinstance(files, list)
    files[0]["content"] = base64.b64encode(b"tampered source\n").decode()

    result = _run_synthetic_remote_program(tmp_path, "transfer", value)

    assert result == {"error_class": "OPERATION_FAILED"}
    assert not (tmp_path / ".ha_tuya_ble_r30_stage").exists()


def test_r30_remote_authority_rejected_before_filesystem_mutation(
    tmp_path: Path,
) -> None:
    """A wrong commit cannot reach remote staging even with valid file hashes."""
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    value = access._bundle_payload(candidate)
    manifest = value["manifest"]
    assert isinstance(manifest, dict)
    manifest["authority_commit"] = "0" * 40

    result = _run_synthetic_remote_program(tmp_path, "transfer", value)

    assert result == {"error_class": "OPERATION_FAILED"}
    assert not (tmp_path / ".ha_tuya_ble_r30_stage").exists()


_R30_LIFECYCLE_CHILD = r"""
import json
import os
import re
import sys
import termios

assert os.isatty(0)
assert os.tcgetpgrp(0) == os.getpgrp()
login = False
restart_count = 0

responses = {
    "backup": {
        "success": True,
        "file_count": 3,
        "manifest_match": True,
        "regular_files_only": True,
        "lifecycle_generation": "b" * 32,
        "source_generation": "b" * 32,
        "backup_generation": "c" * 32,
        "manifest_identity": "__RESTORE_DIGEST__",
        "backup_digest": "d" * 64,
    },
    "transfer": {"success": True, "file_count": 3, "manifest_match": True, "regular_files_only": True},
    "install": {"installation_success": True, "expected_file_count": 3, "installed_file_count": 3, "manifest_match": True},
    "source_inventory": {"expected_count": 3, "observed_count": 3, "manifest_match": True, "unexpected_count": 0, "missing_count": 0},
    "core_check": {"http_status": 200, "result": "ok", "check_passed": True},
    "core_readiness": {"core_reachable": True, "core_running": True, "integration_loaded": True, "timed_out": False},
}

def emit(value):
    os.write(1, b"\x1e" + value.encode("ascii") + b"\x1f")

for line in sys.stdin:
    values = re.findall(r"HA_BROKER_[A-Z_]+:[0-9a-f]+", line)
    if "HA_BROKER_REMOTE" in line and values:
        emit(values[0])
    elif line.strip() == "exec bash -li":
        login = True
    elif "HA_BROKER_LOGIN" in line and values and login:
        emit(values[0])
    elif "HA_BROKER_ECHO_OFF" in line and values and login:
        attributes = termios.tcgetattr(0)
        attributes[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, attributes)
        emit(values[0])
    elif "ha resolution info --raw-json" in line and len(values) == 2:
        emit(values[0])
        print('{"result":"ok","data":{"issues":[]}}', flush=True)
        emit(values[1])
    elif "HA_R30_OPERATION=" in line and len(values) == 2:
        operation = re.search(r"HA_R30_OPERATION=([a-z_]+)", line).group(1)
        expected_count = 1 if "HA_R30_DETAIL=restore" in line else 3
        emit(values[0])
        if operation == "restart_core":
            restart_count += 1
            response = {"submitted": True, "accepted": True}
        elif operation == "service_inventory":
            absent = "expected_absent" in line
            response = {
                "expected_present_count": 0 if absent else 4,
                "observed_present_count": 0 if absent else 4,
                "all_expected_present": True,
                "expected_absent_count": 4 if absent else 0,
                "observed_absent_count": 4 if absent else 0,
                "all_expected_absent": True,
            }
        elif operation == "phase_a_helper":
            if "invalid_nonce" in line:
                response = {"exit_code": 65, "outcome": "not_submitted"}
            elif "audit" in line:
                response = {
                    "exit_code": 0,
                    "outcome": "audit_snapshot",
                    "nonce": "b" * 16,
                    "audit": {
                        "result": "audit_snapshot",
                        "protocol_version": 1,
                        "audit_instance_token": "a" * 32,
                        "event_ordinal": 0,
                        "history_overflow": False,
                        "runtime_ms": 1,
                        "counters": {name: 0 for name in __COUNTERS__},
                        "events": [],
                        "nonce": "b" * 16,
                    },
                }
            else:
                response = {
                    "exit_code": 0,
                    "outcome": "preflight_ok",
                    "nonce": "b" * 16,
                    "preflight": {
                        "result": "preflight_ok",
                        "protocol_version": 1,
                        "nonce": "b" * 16,
                    },
                }
        elif operation == "transfer":
            response = {"success": True, "file_count": expected_count, "manifest_match": True, "regular_files_only": True}
        elif operation == "install":
            response = {"installation_success": True, "expected_file_count": expected_count, "installed_file_count": expected_count, "manifest_match": True}
        elif operation == "source_inventory":
            response = {"expected_count": expected_count, "observed_count": expected_count, "manifest_match": True, "unexpected_count": 0, "missing_count": 0}
        elif operation == "restore":
            response = {"installation_success": True, "expected_file_count": expected_count, "installed_file_count": expected_count, "manifest_match": True}
        else:
            response = responses[operation]
        print(json.dumps(response, separators=(",", ":")), flush=True)
        emit(values[1])
    elif line.strip() == "exit":
        assert restart_count == 2
        break
""".replace(
    "__COUNTERS__", repr(access.AUDIT_COUNTER_NAMES)
).replace(
    "__RESTORE_DIGEST__",
    access._source_manifest_digest(_r30_manifest("RESTORE").entries),
)


def test_r30_synthetic_controlling_pty_full_safe_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """R30-19/20: the complete lifecycle uses one fake controlling PTY and no network."""
    spawns: list[Path] = []
    wrapper = tmp_path / "SYNTHETIC_REAL_WRAPPER_MUST_NOT_RUN"
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda path: access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ()),
    )

    def spawn(path: Path) -> tuple[int, int]:
        spawns.append(path)
        return _fake_spawn(_R30_LIFECYCLE_CHILD)(path)

    monkeypatch.setattr(access, "_spawn_private_wrapper", spawn)
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.5)
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    restore = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )

    assert broker.open() is access.BrokerState.SESSION_ACTIVE

    def capability(action: access.LifecycleAction) -> object:
        return _r32_controller_minted_capability(broker, action)

    assert broker._collect_resolution_info(
        access.RepairsGate.INITIAL,
        _capability=capability(access.LifecycleAction.INITIAL_REPAIRS),
    ).shape_valid
    assert broker._create_private_backup(
        restore.manifest, _capability=capability(access.LifecycleAction.BACKUP)
    ).success
    assert broker._transfer_source_bundle(
        candidate,
        _capability=capability(access.LifecycleAction.CANDIDATE_TRANSFER),
    ).manifest_match
    assert broker._install_staged_source(
        candidate.manifest,
        _capability=capability(access.LifecycleAction.CANDIDATE_INSTALL),
    ).manifest_match
    assert broker._verify_source_inventory(
        candidate.manifest,
        _capability=capability(access.LifecycleAction.CANDIDATE_INVENTORY),
    ).manifest_match
    assert broker._check_core(
        1,
        _capability=capability(access.LifecycleAction.CANDIDATE_CORE_CHECK_1),
    ).check_passed
    assert broker._restart_core(
        _capability=capability(access.LifecycleAction.ACTIVATION_RESTART)
    ).accepted
    assert broker._wait_for_core_readiness(
        _capability=capability(access.LifecycleAction.CANDIDATE_READINESS)
    ).integration_loaded
    assert broker._inventory_temporary_services(
        access.ServiceExpectation.PRESENT,
        _capability=capability(access.LifecycleAction.SERVICES_PRESENT),
    ).all_expected_present
    a0 = broker._invoke_phase_a(
        access.PhaseAOperation.AUDIT,
        nonce="b" * 16,
        evidence_label=access.AuditLabel.A0,
        _capability=capability(access.LifecycleAction.A0),
    )
    assert a0.audit is not None
    assert (
        broker._run_invalid_nonce_preflight(
            _capability=capability(access.LifecycleAction.P0)
        ).exit_code
        == 65
    )
    ap0 = broker._invoke_phase_a(
        access.PhaseAOperation.AUDIT,
        nonce="b" * 16,
        evidence_label=access.AuditLabel.AP0,
        _capability=capability(access.LifecycleAction.AP0),
    )
    assert access.compare_audit_snapshots(a0.audit, ap0.audit).zero_io_unchanged
    assert (
        broker._invoke_phase_a(
            access.PhaseAOperation.PREFLIGHT,
            nonce="b" * 16,
            _capability=capability(access.LifecycleAction.PREFLIGHT),
        ).exit_code
        == 0
    )
    a1 = broker._invoke_phase_a(
        access.PhaseAOperation.AUDIT,
        nonce="b" * 16,
        evidence_label=access.AuditLabel.A1,
        _capability=capability(access.LifecycleAction.A1),
    )
    assert a1.audit is not None
    a2 = broker._invoke_phase_a(
        access.PhaseAOperation.AUDIT,
        nonce="b" * 16,
        evidence_label=access.AuditLabel.A2,
        _capability=capability(access.LifecycleAction.A2),
    )
    assert a2.audit is not None
    assert broker._restore_source(
        restore,
        _transfer_capability=capability(access.LifecycleAction.RESTORE_TRANSFER),
        _install_capability=capability(access.LifecycleAction.RESTORE_INSTALL),
    ).manifest_match
    assert broker._check_core(
        1,
        _capability=capability(access.LifecycleAction.RESTORE_CORE_CHECK_1),
    ).check_passed
    assert broker._restart_core(
        _capability=capability(access.LifecycleAction.REMOVAL_RESTART)
    ).accepted
    assert broker._wait_for_core_readiness(
        _capability=capability(access.LifecycleAction.RESTORE_READINESS)
    ).integration_loaded
    assert broker._verify_source_inventory(
        restore.manifest,
        _capability=capability(access.LifecycleAction.RESTORE_INVENTORY),
    ).manifest_match
    assert broker._inventory_temporary_services(
        access.ServiceExpectation.ABSENT,
        _capability=capability(access.LifecycleAction.SERVICES_ABSENT),
    ).all_expected_absent
    assert broker._collect_resolution_info(
        access.RepairsGate.POST_ROLLBACK,
        _capability=capability(access.LifecycleAction.POST_RESTORE_REPAIRS),
    ).shape_valid
    broker.close()

    assert spawns == [wrapper]
    assert broker.state is access.BrokerState.CLOSED


@pytest.mark.parametrize(
    "spec",
    (
        {"route": access.PRIVATE_ROUTE_ID, "argv": ["sh", "fixed"]},
        {
            "route": access.PRIVATE_ROUTE_ID,
            "argv": ["ssh", "fixed", "remote-command"],
        },
        {
            "route": access.PRIVATE_ROUTE_ID,
            "argv": ["ssh", "-oProxyCommand=fixed", "fixed"],
        },
    ),
)
def test_r30_wrapper_rejects_generic_executable_and_arbitrary_argv(
    spec: dict[str, object],
) -> None:
    """The private wrapper cannot hide a shell, option, or remote command."""
    with pytest.raises(ValueError, match="PRIVATE_WRAPPER_COMMAND_INVALID"):
        access._validate_private_command(spec)


@pytest.mark.parametrize("failure_mode", ("rejected", "exception"))
def test_r30_restart_allowance_consumed_on_every_first_dispatch(
    failure_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lost or rejected first result cannot authorize a second restart."""
    broker = _r32_unbound_real_broker()
    calls = 0

    def execute(_operation: object, _value: object, *, _capability: object) -> bytes:
        nonlocal calls
        calls += 1
        if failure_mode == "exception":
            raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")
        return b'{"submitted":false,"accepted":false}'

    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__execute_bounded_operation", execute
    )
    capability = _r32_controller_minted_capability(
        broker, access.LifecycleAction.ACTIVATION_RESTART
    )

    if failure_mode == "exception":
        with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
            broker._restart_core(_capability=capability)
    else:
        assert broker._restart_core(_capability=capability).submitted is False
    with pytest.raises(access.SessionBrokerError, match="ALREADY_SUBMITTED"):
        broker._restart_core(_capability=capability)
    assert calls == 1


def test_r30_echo_suppression_must_succeed_before_operation_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed stty transition cannot release program or bundle bytes."""
    broker = _r32_unbound_real_broker()
    broker._echo_disabled = False
    writes: list[str] = []

    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__write_wire", writes.append
    )

    def fail_read(_frame: bytes, **_kwargs: object) -> bytes:
        raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")

    monkeypatch.setattr(broker, "_read_until", fail_read)

    with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
        broker._ensure_echo_disabled()
    assert len(writes) == 1
    assert writes[0].payload.startswith(b"stty -echo && ")
    assert b"python3" not in writes[0].payload
    assert broker._echo_disabled is False


def test_r30_audit_comparison_detects_instance_and_overflow_changes() -> None:
    """Aggregate equality fails for a changed instance or overflow state."""
    before = _zero_audit_snapshot()
    instance = access.compare_audit_snapshots(
        before, _zero_audit_snapshot(audit_instance_token="c" * 32)
    )
    overflow = access.compare_audit_snapshots(
        before, _zero_audit_snapshot(history_overflow=True)
    )

    assert instance.same_instance is False
    assert instance.zero_io_unchanged is False
    assert overflow.no_overflow is False
    assert overflow.zero_io_unchanged is False


def test_r30_remote_tree_authority_rejected_before_filesystem_mutation(
    tmp_path: Path,
) -> None:
    """A wrong tree cannot reach remote staging with valid file hashes."""
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    value = access._bundle_payload(candidate)
    manifest = value["manifest"]
    assert isinstance(manifest, dict)
    manifest["authority_tree"] = "0" * 40

    result = _run_synthetic_remote_program(tmp_path, "transfer", value)

    assert result == {"error_class": "OPERATION_FAILED"}
    assert not (tmp_path / ".ha_tuya_ble_r30_stage").exists()


def test_r30_activation_uses_atomic_exchange_without_live_tree_removal() -> None:
    """Candidate and restore activation both use the one-tree exchange primitive."""
    source = access._REMOTE_CONTROL_PROGRAM
    activate = source[source.index("def activate") : source.index("def headers")]

    assert "exchange(staged, INTEGRATION)" in activate
    assert "remove(INTEGRATION)" not in activate
    assert "replace_root_relative(staged, INTEGRATION)" in activate


def test_r30_private_backup_fallback_is_consumed_once(tmp_path: Path) -> None:
    """Fallback restoration deletes the displaced candidate and cannot toggle back."""
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    original = b"synthetic integration source\n"
    (integration / "__init__.py").write_bytes(original)
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )

    assert _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())[
        "manifest_match"
    ]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]

    restored = _run_synthetic_remote_program(
        tmp_path, "restore_backup", _r36_backup_payload()
    )
    repeated = _run_synthetic_remote_program(
        tmp_path, "restore_backup", _r36_backup_payload()
    )

    assert restored["manifest_match"] is True
    assert repeated == {"error_class": "OPERATION_FAILED"}
    assert (integration / "__init__.py").read_bytes() == original
    assert not (integration / ".phase_a_tools").exists()
    assert (tmp_path / ".ha_tuya_ble_r36_backup").is_dir()


def test_r30_backup_cleanup_failure_remains_consumed(tmp_path: Path) -> None:
    """A reconciled fallback marker makes a successful exchange non-replayable."""
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    original = b"synthetic integration source\n"
    (integration / "__init__.py").write_bytes(original)
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    assert _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())[
        "manifest_match"
    ]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]

    restored = _run_synthetic_remote_program(
        tmp_path, "restore_backup", _r36_backup_payload()
    )
    repeated = _run_synthetic_remote_program(
        tmp_path, "restore_backup", _r36_backup_payload()
    )

    assert restored["manifest_match"] is True
    assert repeated == {"error_class": "OPERATION_FAILED"}
    assert (integration / "__init__.py").read_bytes() == original
    marker = json.loads(
        (tmp_path / ".ha_tuya_ble_r36_backup.consumed").read_text(encoding="ascii")
    )
    assert marker["phase"] == "reconciled"


def test_r30_backup_post_exchange_failure_requires_separate_reconciliation(
    tmp_path: Path,
) -> None:
    """A failed fallback retains ambiguity and only reconciliation may continue."""
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    assert _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())[
        "manifest_match"
    ]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]

    failed = _run_synthetic_remote_program(
        tmp_path,
        "restore_backup",
        _r36_backup_payload(),
        source_replacements={
            "            installed = inventory_deployment_fd(installed_fd)\n": (
                "            raise ValueError('synthetic_after_exchange')\n"
            )
        },
    )

    assert failed == {"error_class": "OPERATION_FAILED"}
    assert not (integration / ".phase_a_tools").exists()
    marker = tmp_path / ".ha_tuya_ble_r36_backup.consumed"
    assert json.loads(marker.read_text(encoding="ascii"))["phase"] == "possibly_applied"
    assert _run_synthetic_remote_program(
        tmp_path, "restore_backup", _r36_backup_payload()
    ) == {"error_class": "OPERATION_FAILED"}
    reconciled = _run_synthetic_remote_program(
        tmp_path, "reconcile_backup", _r36_backup_payload()
    )
    assert reconciled == {
        "file_count": 1,
        "manifest_match": True,
        "phase": "reconciled",
        "restoration_applied": True,
    }
    assert not (integration / ".phase_a_tools").exists()


def test_r30_authoritative_restore_keeps_monotonic_tombstone_across_new_backup(
    tmp_path: Path,
) -> None:
    """PR #41 consumption stays durable; a later backup cannot evict it."""
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    restore = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    assert _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())[
        "manifest_match"
    ]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(restore)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "restore",
        {"manifest": access._manifest_payload(restore.manifest)},
    )["manifest_match"]

    assert _run_synthetic_remote_program(
        tmp_path, "restore_backup", _r36_backup_payload()
    ) == {"error_class": "OPERATION_FAILED"}
    marker = tmp_path / ".ha_tuya_ble_r30_restore.consumed"
    assert marker.is_file()
    assert _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload()) == {
        "error_class": "OPERATION_FAILED"
    }
    assert marker.exists()


@pytest.mark.parametrize(
    ("crash_point", "expected_phase", "reconciled_phase", "restored"),
    (
        ("before_exchange", "intent_recorded", "reconciled_candidate", False),
        ("after_exchange", "possibly_applied", "reconciled", True),
    ),
)
def test_r33_s_fallback_process_loss_is_reconciled_without_blind_replay(
    crash_point: str,
    expected_phase: str,
    reconciled_phase: str,
    restored: bool,
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    original = b"synthetic integration source\n"
    (integration / "__init__.py").write_bytes(original)
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    assert _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())[
        "manifest_match"
    ]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]
    replacements = {
        "before_exchange": {
            "        write_fallback_phase('intent_recorded', identity)\n"
            "        pending = ROOT / ": (
                "        write_fallback_phase('intent_recorded', identity)\n"
                "        os._exit(91)\n"
                "        pending = ROOT / "
            )
        },
        "after_exchange": {
            "            installed_fd = publish_directory_bound(pending, INTEGRATION)\n": (
                "            installed_fd = publish_directory_bound(pending, INTEGRATION)\n"
                "            os._exit(91)\n"
            )
        },
    }[crash_point]

    _run_synthetic_remote_program(
        tmp_path,
        "restore_backup",
        _r36_backup_payload(),
        source_replacements=replacements,
        expected_crash_code=91,
    )
    marker = tmp_path / ".ha_tuya_ble_r36_backup.consumed"
    assert json.loads(marker.read_text(encoding="ascii"))["phase"] == expected_phase
    assert _run_synthetic_remote_program(
        tmp_path, "restore_backup", _r36_backup_payload()
    ) == {"error_class": "OPERATION_FAILED"}

    reconciled = _run_synthetic_remote_program(
        tmp_path, "reconcile_backup", _r36_backup_payload()
    )

    assert reconciled["phase"] == reconciled_phase
    assert reconciled["restoration_applied"] is restored
    assert (integration / "__init__.py").read_bytes() == original
    assert (integration / ".phase_a_tools").exists() is (not restored)
    assert json.loads(marker.read_text(encoding="ascii"))["phase"] == expected_phase


def test_r36_fallback_exchange_requires_live_parent_directory_fsync(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    payload = _r36_backup_payload()
    assert _run_synthetic_remote_program(tmp_path, "backup", payload)["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]

    failed = _run_synthetic_remote_program(
        tmp_path,
        "restore_backup",
        payload,
        source_replacements={
            "        os.fsync(destination_parent)\n": (
                "        raise OSError(5, 'synthetic live parent fsync')\n"
            )
        },
    )

    assert failed == {"error_class": "OPERATION_FAILED"}
    marker = tmp_path / ".ha_tuya_ble_r36_backup.consumed"
    assert json.loads(marker.read_text(encoding="ascii"))["phase"] == (
        "possibly_applied"
    )
    reconciled = _run_synthetic_remote_program(tmp_path, "reconcile_backup", payload)
    assert reconciled["phase"] == "reconciled"
    assert reconciled["restoration_applied"] is True


def test_r36_fallback_rejects_backup_package_path_swap_before_exchange(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    original = b"synthetic integration source\n"
    (integration / "__init__.py").write_bytes(original)
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    payload = _r36_backup_payload()
    assert _run_synthetic_remote_program(tmp_path, "backup", payload)["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]

    failed = _run_synthetic_remote_program(
        tmp_path,
        "restore_backup",
        payload,
        source_replacements={
            "        identity = read_backup_identity_fd(value, package_fd)\n": (
                "        identity = read_backup_identity_fd(value, package_fd)\n"
                "        moved = BACKUP.with_name(BACKUP.name + '.swapped')\n"
                "        BACKUP.rename(moved)\n"
                "        shutil.copytree(moved, BACKUP)\n"
                "        (BACKUP / 'integration' / '__init__.py').write_bytes("
                "b'synthetic hostile package\\n')\n"
            )
        },
    )

    assert failed == {"error_class": "OPERATION_FAILED"}
    assert (integration / "__init__.py").read_bytes() == original
    assert (integration / ".phase_a_tools").is_dir()
    assert not (tmp_path / ".ha_tuya_ble_r36_backup.consumed").exists()


def test_r36_fallback_rejects_live_parent_swap_before_durable_sync(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    payload = _r36_backup_payload()
    assert _run_synthetic_remote_program(tmp_path, "backup", payload)["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]

    failed = _run_synthetic_remote_program(
        tmp_path,
        "restore_backup",
        payload,
        source_replacements={
            "        os.fsync(source_parent)\n": (
                "        if destination == INTEGRATION:\n"
                "            displaced = ROOT / 'synthetic-displaced-parent'\n"
                "            destination.parent.rename(displaced)\n"
                "            destination.parent.mkdir(mode=0o700)\n"
                "        os.fsync(source_parent)\n"
            )
        },
    )

    assert failed == {"error_class": "OPERATION_FAILED"}
    marker = tmp_path / ".ha_tuya_ble_r36_backup.consumed"
    assert json.loads(marker.read_text(encoding="ascii"))["phase"] == (
        "possibly_applied"
    )


@pytest.mark.parametrize(
    ("operation", "needle"),
    (
        (
            "backup",
            "        package_fd = publish_noreplace(pending, BACKUP, pending_fd)\n",
        ),
        (
            "backup",
            (
                "        published_identity = read_backup_identity_fd("
                "value, package_fd)\n"
            ),
        ),
        (
            "reconcile_backup_creation",
            (
                "        identity = read_backup_identity_fd(value, package_fd)\n"
                "        source_fd = open_relative_directory(package_fd, "
                "('integration',))\n"
            ),
        ),
    ),
)
def test_r36_backup_publication_and_adoption_reject_package_inode_swap(
    operation: str, needle: str, tmp_path: Path
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    payload = _r36_backup_payload()
    if operation == "reconcile_backup_creation":
        assert _run_synthetic_remote_program(tmp_path, "backup", payload)[
            "manifest_match"
        ]
    last_line = needle.splitlines()[-1]
    indentation = last_line[: len(last_line) - len(last_line.lstrip())]
    replacement = (
        needle + indentation + "moved = BACKUP.with_name(BACKUP.name + '.swapped')\n"
    )
    replacement += (
        f"{indentation}BACKUP.rename(moved)\n"
        f"{indentation}shutil.copytree(moved, BACKUP)\n"
    )
    failed = _run_synthetic_remote_program(
        tmp_path,
        operation,
        payload,
        source_replacements={needle: replacement},
    )

    assert failed == {"error_class": "OPERATION_FAILED"}


def test_r36_fallback_post_marker_swap_downgrades_reconciliation(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    payload = _r36_backup_payload()
    assert _run_synthetic_remote_program(tmp_path, "backup", payload)["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]

    failed = _run_synthetic_remote_program(
        tmp_path,
        "restore_backup",
        payload,
        source_replacements={
            "            write_fallback_phase('reconciled', identity)\n"
            "            try:\n": (
                "            write_fallback_phase('reconciled', identity)\n"
                "            moved = INTEGRATION.with_name("
                "INTEGRATION.name + '.swapped')\n"
                "            INTEGRATION.rename(moved)\n"
                "            shutil.copytree(moved, INTEGRATION)\n"
                "            try:\n"
            )
        },
    )

    assert failed == {"error_class": "OPERATION_FAILED"}
    marker = tmp_path / ".ha_tuya_ble_r36_backup.consumed"
    assert json.loads(marker.read_text(encoding="ascii"))["phase"] == (
        "possibly_applied"
    )


def test_r33_s_controller_uses_distinct_fallback_reconciliation_permit() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    broker.queue(
        "backup_fallback",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.restore_private_backup_fallback(restore.manifest)

    result = controller.reconcile_private_backup_fallback(restore.manifest)

    assert result.phase == "reconciled"
    assert controller._journal._record["fallback_phase"] == "reconciled"
    assert (
        access.LifecycleAction.BACKUP_FALLBACK in controller._journal.consumed_actions
    )
    assert (
        access.LifecycleAction.BACKUP_FALLBACK_RECONCILE
        in controller._journal.consumed_actions
    )
    assert [name for name, _ in broker.calls].count("backup_fallback") == 1
    assert [name for name, _ in broker.calls].count("backup_reconcile") == 1


def test_r30_broker_backup_fence_consumed_before_failed_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost fallback result cannot authorize a second remote exchange."""
    broker = _r32_unbound_real_broker()
    calls = 0

    def execute(_operation: object, _value: object, *, _capability: object) -> bytes:
        nonlocal calls
        calls += 1
        raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")

    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__execute_bounded_operation", execute
    )
    capability = _r32_controller_minted_capability(
        broker, access.LifecycleAction.BACKUP_FALLBACK
    )
    restore_manifest = _r30_manifest("RESTORE")

    with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
        broker._restore_private_backup(restore_manifest, _capability=capability)
    with pytest.raises(access.SourceBundleError, match="ALREADY_CONSUMED"):
        broker._restore_private_backup(restore_manifest, _capability=capability)
    assert calls == 1


class _R32ScriptedBroker:
    """Synthetic broker double exposing only the controller's internal adapter API."""

    def __init__(self) -> None:
        self.state = access.BrokerState.SESSION_ACTIVE
        self._session_generation = object()
        self._controller_binding: (
            tuple[object, access._CapabilityIssuer, object, object] | None
        ) = None
        self.calls: list[tuple[str, object]] = []
        self.responses: dict[str, list[object]] = {}
        self._pending_capability: access._LifecycleCapability | None = None

    def _register_lifecycle_controller(
        self,
        controller: object,
        lifecycle_generation: object,
        session_generation: object,
    ) -> object:
        if (
            self.state is not access.BrokerState.SESSION_ACTIVE
            or self._session_generation is not session_generation
            or self._controller_binding is not None
        ):
            raise access.SessionBrokerError("SYNTHETIC_CONTROLLER_BINDING_INVALID")
        issuer = access._CapabilityIssuer(object(), [], [])
        self._controller_binding = (
            controller,
            issuer,
            lifecycle_generation,
            session_generation,
        )
        return issuer

    def _consume_capability(
        self,
        capability: object,
        *actions: access.LifecycleAction,
    ) -> None:
        binding = self._controller_binding
        if (
            type(capability) is not access._LifecycleCapability
            or binding is None
            or capability.controller is not binding[0]
            or capability.issuer is not binding[1].identity
            or capability.lifecycle_generation is not binding[2]
            or capability.session_generation is not binding[3]
            or self._session_generation is not binding[3]
            or capability.action not in actions
            or not any(capability is issued for issued in binding[1].issued)
            or any(capability is consumed for consumed in binding[1].consumed)
        ):
            raise access.SessionBrokerError("SYNTHETIC_CAPABILITY_INVALID")
        binding[1].consumed.append(capability)
        if getattr(self, "_durable_lifecycle_test", False) is True:
            self._pending_capability = capability

    def queue(self, name: str, *responses: object) -> None:
        self.responses.setdefault(name, []).extend(responses)

    def _next(self, name: str, detail: object, default: object) -> object:
        self.calls.append((name, detail))
        queued = self.responses.get(name, [])
        value = queued.pop(0) if queued else default
        if inspect.isfunction(value):
            value = value(detail)
        if isinstance(value, BaseException):
            self._pending_capability = None
            raise value
        capability = self._pending_capability
        self._pending_capability = None
        if getattr(self, "_durable_lifecycle_test", False) is True:
            assert capability is not None
            access._bind_evidence_origin(value, capability)
        return value

    def _collect_resolution_info(
        self,
        gate: access.RepairsGate,
        *,
        _capability: object = None,
    ) -> access.RepairsEvidence:
        self._consume_capability(
            _capability,
            {
                access.RepairsGate.INITIAL: access.LifecycleAction.INITIAL_REPAIRS,
                access.RepairsGate.POST_ACTIVATION: (
                    access.LifecycleAction.POST_ACTIVATION_REPAIRS
                ),
                access.RepairsGate.POST_ROLLBACK: (
                    access.LifecycleAction.POST_RESTORE_REPAIRS
                ),
            }[gate],
        )
        return self._next(
            "repairs",
            gate,
            access.RepairsEvidence(True, 0, 0),
        )

    def _create_private_backup(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.BackupResult:
        assert manifest.state is access.SourceState.RESTORE
        self._consume_capability(_capability, access.LifecycleAction.BACKUP)
        assert isinstance(_capability, access._LifecycleCapability)
        capability = _capability
        return self._next(
            "backup",
            None,
            access.BackupResult(
                True,
                3,
                True,
                True,
                str(capability.lifecycle_generation),
                str(capability.source_generation),
                "c" * 32,
                access._source_manifest_digest(manifest.entries),
                "d" * 64,
            ),
        )

    def _reconcile_private_backup_creation(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.BackupResult:
        assert manifest.state is access.SourceState.RESTORE
        self._consume_capability(_capability, access.LifecycleAction.BACKUP_RECONCILE)
        assert isinstance(_capability, access._LifecycleCapability)
        return self._next(
            "backup_creation_reconcile",
            None,
            access.BackupResult(
                True,
                len(manifest.entries),
                True,
                True,
                str(_capability.lifecycle_generation),
                str(_capability.source_generation),
                "c" * 32,
                access._source_manifest_digest(manifest.entries),
                "d" * 64,
            ),
        )

    def _transfer_source_bundle(
        self, bundle: access.SourceBundle, *, _capability: object = None
    ) -> access.TransferResult:
        self._consume_capability(
            _capability,
            (
                access.LifecycleAction.CANDIDATE_TRANSFER
                if bundle.state is access.SourceState.CANDIDATE
                else access.LifecycleAction.RESTORE_TRANSFER
            ),
        )
        return self._next(
            "transfer",
            bundle.state,
            access.TransferResult(True, len(bundle.files), True, True),
        )

    def _install_staged_source(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.InstallResult:
        self._consume_capability(_capability, access.LifecycleAction.CANDIDATE_INSTALL)
        return self._next(
            "install_candidate",
            manifest.state,
            access.InstallResult(
                True, len(manifest.entries), len(manifest.entries), True
            ),
        )

    def _install_staged_restore(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.InstallResult:
        self._consume_capability(_capability, access.LifecycleAction.RESTORE_INSTALL)
        return self._next(
            "install_restore",
            manifest.state,
            access.InstallResult(
                True, len(manifest.entries), len(manifest.entries), True
            ),
        )

    def _verify_source_inventory(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.SourceInventoryResult:
        self._consume_capability(
            _capability,
            (
                access.LifecycleAction.CANDIDATE_INVENTORY
                if manifest.state is access.SourceState.CANDIDATE
                else access.LifecycleAction.RESTORE_INVENTORY
            ),
        )
        count = len(manifest.entries)
        return self._next(
            "inventory",
            manifest.state,
            access.SourceInventoryResult(count, count, True, 0, 0),
        )

    def _check_core(
        self, attempt_ordinal: int, *, _capability: object = None
    ) -> access.CoreCheckResult:
        self._consume_capability(
            _capability,
            access.LifecycleAction.CANDIDATE_CORE_CHECK_1,
            access.LifecycleAction.CANDIDATE_CORE_CHECK_2,
            access.LifecycleAction.RESTORE_CORE_CHECK_1,
            access.LifecycleAction.RESTORE_CORE_CHECK_2,
        )
        return self._next(
            "core_check",
            attempt_ordinal,
            access.CoreCheckResult(attempt_ordinal, 200, "ok", True, None),
        )

    def _restart_core(self, *, _capability: object = None) -> access.RestartResult:
        self._consume_capability(
            _capability,
            access.LifecycleAction.ACTIVATION_RESTART,
            access.LifecycleAction.REMOVAL_RESTART,
        )
        return self._next("restart", None, access.RestartResult(True, True))

    def _wait_for_core_readiness(
        self, *, _capability: object = None
    ) -> access.CoreReadinessResult:
        self._consume_capability(
            _capability,
            access.LifecycleAction.CANDIDATE_READINESS,
            access.LifecycleAction.RESTORE_READINESS,
        )
        return self._next(
            "readiness",
            None,
            access.CoreReadinessResult(True, True, True, False),
        )

    def _inventory_temporary_services(
        self, expectation: access.ServiceExpectation, *, _capability: object = None
    ) -> access.ServiceInventoryResult:
        self._consume_capability(
            _capability,
            (
                access.LifecycleAction.SERVICES_PRESENT
                if expectation is access.ServiceExpectation.PRESENT
                else access.LifecycleAction.SERVICES_ABSENT
            ),
        )
        if expectation is access.ServiceExpectation.PRESENT:
            default = access.ServiceInventoryResult(4, 4, True, 0, 0, True)
        else:
            default = access.ServiceInventoryResult(0, 0, True, 4, 4, True)
        return self._next("services", expectation, default)

    def _invoke_phase_a(
        self,
        operation: access.PhaseAOperation,
        *,
        nonce: str | None = None,
        evidence_label: access.AuditLabel | None = None,
        _capability: object = None,
    ) -> access.PhaseAResult:
        if operation is access.PhaseAOperation.AUDIT:
            action = {
                access.AuditLabel.A0: access.LifecycleAction.A0,
                access.AuditLabel.AP0: access.LifecycleAction.AP0,
                access.AuditLabel.A1: access.LifecycleAction.A1,
                access.AuditLabel.A2: access.LifecycleAction.A2,
            }[evidence_label]
            self._consume_capability(_capability, action)
        elif operation is access.PhaseAOperation.PREFLIGHT:
            self._consume_capability(_capability, access.LifecycleAction.PREFLIGHT)
        else:
            raise access.SessionBrokerError("PHASE_A_HELPER_OPERATION_INVALID")
        if operation is access.PhaseAOperation.AUDIT:
            default = access.PhaseAResult(
                operation=operation,
                exit_code=0,
                outcome="audit_snapshot",
                nonce=nonce,
                audit=_zero_audit_snapshot(nonce=nonce),
            )
        elif operation is access.PhaseAOperation.PREFLIGHT:
            default = access.PhaseAResult(
                operation=operation,
                exit_code=0,
                outcome="preflight_ok",
                nonce=nonce,
                preflight=access.PreflightResponse("preflight_ok", 1, nonce),
            )
        else:
            raise access.SessionBrokerError("PHASE_A_HELPER_OPERATION_INVALID")
        return self._next("helper", (operation, nonce, evidence_label), default)

    def _run_invalid_nonce_preflight(
        self, *, _capability: object = None
    ) -> access.PhaseAResult:
        self._consume_capability(_capability, access.LifecycleAction.P0)
        return self._next(
            "p0",
            None,
            access.PhaseAResult(access.PhaseAOperation.PREFLIGHT, 65, "not_submitted"),
        )

    def _restore_private_backup(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.InstallResult:
        assert manifest.state is access.SourceState.RESTORE
        self._consume_capability(_capability, access.LifecycleAction.BACKUP_FALLBACK)
        return self._next(
            "backup_fallback",
            None,
            access.InstallResult(True, 1, 1, True),
        )

    def _reconcile_private_backup(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.FallbackReconciliationResult:
        assert manifest.state is access.SourceState.RESTORE
        self._consume_capability(
            _capability, access.LifecycleAction.BACKUP_FALLBACK_RECONCILE
        )
        return self._next(
            "backup_reconcile",
            None,
            access.FallbackReconciliationResult("reconciled", True, True, 1),
        )


def _r32_bundles() -> tuple[access.SourceBundle, access.SourceBundle]:
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    restore = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    return candidate, restore


_R32_ACTION_PREDECESSORS = {
    access.LifecycleAction.INITIAL_REPAIRS: frozenset({access.LifecycleState.BASELINE}),
    access.LifecycleAction.BACKUP: frozenset(
        {access.LifecycleState.INITIAL_REPAIRS_PASS}
    ),
    access.LifecycleAction.BACKUP_RECONCILE: frozenset(
        {access.LifecycleState.RECOVERY_REQUIRED}
    ),
    access.LifecycleAction.CANDIDATE_TRANSFER: frozenset(
        {access.LifecycleState.BACKUP_VERIFIED}
    ),
    access.LifecycleAction.CANDIDATE_INSTALL: frozenset(
        {access.LifecycleState.CANDIDATE_STAGED}
    ),
    access.LifecycleAction.CANDIDATE_INVENTORY: frozenset(
        {access.LifecycleState.CANDIDATE_INSTALLED}
    ),
    access.LifecycleAction.CANDIDATE_CORE_CHECK_1: frozenset(
        {access.LifecycleState.CANDIDATE_INVENTORY_VERIFIED}
    ),
    access.LifecycleAction.CANDIDATE_CORE_CHECK_2: frozenset(
        {access.LifecycleState.CANDIDATE_INVENTORY_VERIFIED}
    ),
    access.LifecycleAction.ACTIVATION_RESTART: frozenset(
        {access.LifecycleState.CANDIDATE_CORE_CHECKED}
    ),
    access.LifecycleAction.CANDIDATE_READINESS: frozenset(
        {access.LifecycleState.ACTIVATION_RESTART_CONSUMED}
    ),
    access.LifecycleAction.SERVICES_PRESENT: frozenset(
        {access.LifecycleState.CANDIDATE_READY}
    ),
    access.LifecycleAction.POST_ACTIVATION_REPAIRS: frozenset(
        {access.LifecycleState.RESEARCH_SERVICES_PRESENT}
    ),
    access.LifecycleAction.A0: frozenset(
        {access.LifecycleState.POST_ACTIVATION_REPAIRS_PASS}
    ),
    access.LifecycleAction.P0: frozenset({access.LifecycleState.A0_COLLECTED}),
    access.LifecycleAction.AP0: frozenset({access.LifecycleState.P0_COMPLETED}),
    access.LifecycleAction.PREFLIGHT: frozenset({access.LifecycleState.AP0_COLLECTED}),
    access.LifecycleAction.A1: frozenset(
        {access.LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED}
    ),
    access.LifecycleAction.RESEARCH_FINAL: frozenset(
        {access.LifecycleState.A1_COLLECTED}
    ),
    access.LifecycleAction.A2: frozenset(
        {access.LifecycleState.RESEARCH_FINAL_VALIDATED}
    ),
    access.LifecycleAction.RESTORE_TRANSFER: frozenset(
        {
            access.LifecycleState.A2_COLLECTED,
            access.LifecycleState.ROLLBACK_REQUIRED,
            access.LifecycleState.RECOVERY_REQUIRED,
        }
    ),
    access.LifecycleAction.RESTORE_INSTALL: frozenset(
        {access.LifecycleState.RESTORE_STAGED}
    ),
    access.LifecycleAction.RESTORE_INVENTORY: frozenset(
        {access.LifecycleState.PR41_RESTORED}
    ),
    access.LifecycleAction.RESTORE_CORE_CHECK_1: frozenset(
        {access.LifecycleState.RESTORE_INVENTORY_VERIFIED}
    ),
    access.LifecycleAction.RESTORE_CORE_CHECK_2: frozenset(
        {access.LifecycleState.RESTORE_INVENTORY_VERIFIED}
    ),
    access.LifecycleAction.REMOVAL_RESTART: frozenset(
        {access.LifecycleState.RESTORE_CORE_CHECKED}
    ),
    access.LifecycleAction.RESTORE_READINESS: frozenset(
        {access.LifecycleState.REMOVAL_RESTART_CONSUMED}
    ),
    access.LifecycleAction.SERVICES_ABSENT: frozenset(
        {access.LifecycleState.PR41_READY}
    ),
    access.LifecycleAction.POST_RESTORE_REPAIRS: frozenset(
        {access.LifecycleState.RESEARCH_SERVICES_ABSENT}
    ),
    access.LifecycleAction.FINAL_ACCEPTANCE: frozenset(
        {access.LifecycleState.POST_RESTORE_REPAIRS_PASS}
    ),
    access.LifecycleAction.BACKUP_FALLBACK: frozenset(
        {access.LifecycleState.ROLLBACK_REQUIRED}
    ),
    access.LifecycleAction.BACKUP_FALLBACK_RECONCILE: frozenset(
        {
            access.LifecycleState.ROLLBACK_REQUIRED,
            access.LifecycleState.RECOVERY_REQUIRED,
        }
    ),
}


def test_r32_action_capability_predecessor_mapping_is_exact_and_immutable() -> None:
    assert access._LIFECYCLE_ACTION_PREDECESSORS == _R32_ACTION_PREDECESSORS
    assert set(access._LIFECYCLE_ACTION_PREDECESSORS) == set(access.LifecycleAction)
    with pytest.raises(TypeError):
        access._LIFECYCLE_ACTION_PREDECESSORS[access.LifecycleAction.BACKUP] = (
            frozenset({access.LifecycleState.BASELINE})
        )


@pytest.mark.parametrize("entrypoint", ("_dispatch", "__dispatch_action"))
@pytest.mark.parametrize("action", tuple(access.LifecycleAction))
def test_r32_private_dispatch_cannot_mint_capability_from_wrong_state(
    action: access.LifecycleAction,
    entrypoint: str,
) -> None:
    controller, broker = _r32_controller()
    allowed = _R32_ACTION_PREDECESSORS[action]
    wrong_state = next(state for state in access.LifecycleState if state not in allowed)
    controller._state = wrong_state
    callbacks: list[object] = []

    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        if entrypoint == "_dispatch":
            controller._dispatch(
                action,
                lambda capability: callbacks.append(capability),
                _dispatch_token=(
                    controller._FullPreflightLifecycleController__dispatch_token
                ),
            )
        else:
            controller._FullPreflightLifecycleController__dispatch_action(
                action, lambda capability: callbacks.append(capability)
            )

    assert controller.state is wrong_state
    assert controller._permits[action].consumed is False
    assert callbacks == []
    assert broker.calls == []


@pytest.mark.parametrize("action", tuple(access.LifecycleAction))
def test_r32_private_dispatch_mints_only_from_each_exact_predecessor(
    action: access.LifecycleAction,
) -> None:
    for predecessor in _R32_ACTION_PREDECESSORS[action]:
        controller, broker = _r32_controller()
        controller._state = predecessor

        capability = controller._FullPreflightLifecycleController__dispatch_action(
            action, lambda minted: minted
        )

        assert capability.action is action
        assert controller._permits[action].consumed is True
        assert broker.calls == []


def _r32_unbound_real_broker() -> access.PrivateInteractiveSessionBroker:
    """Return an active synthetic broker shell without opening a PTY."""
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    broker._state = access.BrokerState.SESSION_ACTIVE
    broker._session_generation = object()
    broker._active_source_state = access.SourceState.CANDIDATE
    broker._restarted_states = set()
    broker._backup_restore_attempted = False
    broker._echo_disabled = True
    broker._master_fd = 123
    broker._child_pid = 456
    broker._residual = bytearray()
    broker._timeout_seconds = 1.0
    broker._max_capture_bytes = 4096
    broker._controller_binding = None
    broker._PrivateInteractiveSessionBroker__wire_issuer = object()
    return broker


def _r32_controller_minted_capability(
    broker: access.PrivateInteractiveSessionBroker,
    action: access.LifecycleAction,
) -> object:
    """Capture one capability through the controller's guarded dispatch path."""
    controller = getattr(broker, "_synthetic_test_controller", None)
    if controller is None:
        controller = access.FullPreflightLifecycleController(broker)
        broker._synthetic_test_controller = controller
    controller._state = next(iter(access._LIFECYCLE_ACTION_PREDECESSORS[action]))
    dispatch_token = controller._FullPreflightLifecycleController__dispatch_token
    return controller._dispatch(
        action,
        lambda capability: capability,
        broker_evidence=False,
        _dispatch_token=dispatch_token,
    )


def test_r32_direct_raw_writer_and_bounded_dispatch_require_distinct_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neither arbitrary PTY text nor a bounded action accepts a raw caller."""
    broker = _r32_unbound_real_broker()
    writes: list[bytes] = []
    monkeypatch.setattr(access.os, "write", lambda _fd, value: writes.append(value))

    assert not hasattr(broker, "_write_private")
    with pytest.raises(access.SessionBrokerError, match="WRITE_SCOPE_INVALID"):
        broker._PrivateInteractiveSessionBroker__write_wire(
            access._PrivateWirePacket(b"synthetic arbitrary PTY text\n", object())
        )
    with pytest.raises(access.SessionBrokerError, match="CAPABILITY_INVALID"):
        broker._PrivateInteractiveSessionBroker__execute_bounded_operation(
            access.BoundedOperation.BACKUP, {}
        )

    assert writes == []


@pytest.mark.parametrize(
    ("name", "invoke"),
    (
        (
            "repairs",
            lambda broker, candidate, restore: broker._collect_resolution_info(
                access.RepairsGate.INITIAL
            ),
        ),
        (
            "backup",
            lambda broker, candidate, restore: broker._create_private_backup(
                restore.manifest
            ),
        ),
        (
            "candidate transfer",
            lambda broker, candidate, restore: broker._transfer_source_bundle(
                candidate
            ),
        ),
        (
            "candidate install",
            lambda broker, candidate, restore: broker._install_staged_source(
                candidate.manifest
            ),
        ),
        (
            "candidate inventory",
            lambda broker, candidate, restore: broker._verify_source_inventory(
                candidate.manifest
            ),
        ),
        (
            "Core check",
            lambda broker, candidate, restore: broker._check_core(1),
        ),
        (
            "restart",
            lambda broker, candidate, restore: broker._restart_core(),
        ),
        (
            "readiness",
            lambda broker, candidate, restore: broker._wait_for_core_readiness(),
        ),
        (
            "services",
            lambda broker, candidate, restore: broker._inventory_temporary_services(
                access.ServiceExpectation.PRESENT
            ),
        ),
        (
            "helper",
            lambda broker, candidate, restore: broker._invoke_phase_a(
                access.PhaseAOperation.PREFLIGHT
            ),
        ),
        (
            "P0",
            lambda broker, candidate, restore: broker._run_invalid_nonce_preflight(),
        ),
        (
            "restore install",
            lambda broker, candidate, restore: broker._install_staged_restore(
                restore.manifest
            ),
        ),
        (
            "combined restore",
            lambda broker, candidate, restore: broker._restore_source(restore),
        ),
        (
            "backup fallback",
            lambda broker, candidate, restore: broker._restore_private_backup(
                restore.manifest
            ),
        ),
    ),
)
def test_r32_every_live_broker_adapter_rejects_direct_calls_before_dispatch(
    name: str,
    invoke: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Underscore-private adapter names are not an authorization boundary."""
    broker = _r32_unbound_real_broker()
    candidate, restore = _r32_bundles()
    broker_calls: list[str] = []

    def unexpected_bounded_call(*_args: object, **_kwargs: object) -> bytes:
        broker_calls.append("bounded")
        raise AssertionError("direct adapter reached bounded dispatch")

    def unexpected_write(*_args: object, **_kwargs: object) -> None:
        broker_calls.append("write")
        raise AssertionError("direct adapter reached PTY write")

    monkeypatch.setattr(
        broker,
        "_PrivateInteractiveSessionBroker__execute_bounded_operation",
        unexpected_bounded_call,
    )
    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__write_wire", unexpected_write
    )

    with pytest.raises(access.SessionBrokerError, match="CAPABILITY_INVALID"):
        invoke(broker, candidate, restore)

    assert broker_calls == [], name


def test_r32_capability_is_action_session_generation_and_broker_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A captured capability cannot be redirected across any binding dimension."""
    broker = _r32_unbound_real_broker()
    capability = _r32_controller_minted_capability(
        broker, access.LifecycleAction.BACKUP
    )
    writes: list[str] = []
    monkeypatch.setattr(
        broker,
        "_PrivateInteractiveSessionBroker__write_wire",
        lambda *_args, **_kwargs: writes.append("write"),
    )
    monkeypatch.setattr(broker, "_read_until", lambda *_args, **_kwargs: b"{}")

    with pytest.raises(access.SessionBrokerError, match="CAPABILITY_INVALID"):
        broker._PrivateInteractiveSessionBroker__execute_bounded_operation(
            access.BoundedOperation.RESTART_CORE, {}, _capability=capability
        )
    assert writes == []

    original_session = broker._session_generation
    broker._session_generation = object()
    with pytest.raises(access.SessionBrokerError, match="CAPABILITY_INVALID"):
        broker._PrivateInteractiveSessionBroker__execute_bounded_operation(
            access.BoundedOperation.BACKUP, {}, _capability=capability
        )
    broker._session_generation = original_session
    assert writes == []

    with pytest.raises(FrozenInstanceError):
        capability.lifecycle_generation = object()
    assert writes == []

    other_broker = _r32_unbound_real_broker()
    with pytest.raises(access.SessionBrokerError, match="CAPABILITY_INVALID"):
        other_broker._PrivateInteractiveSessionBroker__execute_bounded_operation(
            access.BoundedOperation.BACKUP, {}, _capability=capability
        )
    assert writes == []


def test_r32_capability_and_raw_write_scope_are_distinct_one_shot_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bounded use consumes a capability; it can never become a raw-write token."""
    broker = _r32_unbound_real_broker()
    capability = _r32_controller_minted_capability(
        broker, access.LifecycleAction.BACKUP
    )
    writes: list[object] = []
    monkeypatch.setattr(
        broker,
        "_PrivateInteractiveSessionBroker__write_wire",
        lambda *_args, **_kwargs: writes.append("bounded"),
    )
    monkeypatch.setattr(broker, "_read_until", lambda *_args, **_kwargs: b"{}")
    monkeypatch.setattr(access.os, "write", lambda *_args: writes.append("raw"))

    broker._PrivateInteractiveSessionBroker__execute_bounded_operation(
        access.BoundedOperation.BACKUP, {}, _capability=capability
    )
    writes_after_first_use = list(writes)
    controller = broker._synthetic_test_controller

    assert controller._permits[access.LifecycleAction.BACKUP].consumed is True

    with pytest.raises(access.SessionBrokerError, match="CAPABILITY_INVALID"):
        broker._PrivateInteractiveSessionBroker__execute_bounded_operation(
            access.BoundedOperation.BACKUP, {}, _capability=capability
        )
    forged = access._LifecycleCapability(
        capability.controller,
        capability.issuer,
        capability.lifecycle_generation,
        capability.source_generation,
        capability.session_generation,
        capability.action,
        object(),
    )
    with pytest.raises(access.SessionBrokerError, match="CAPABILITY_INVALID"):
        broker._PrivateInteractiveSessionBroker__execute_bounded_operation(
            access.BoundedOperation.BACKUP, {}, _capability=forged
        )
    with pytest.raises(access.SessionBrokerError, match="WRITE_SCOPE_INVALID"):
        access.PrivateInteractiveSessionBroker._PrivateInteractiveSessionBroker__write_wire(
            broker,
            access._PrivateWirePacket(b"synthetic arbitrary PTY text\n", capability),
        )

    assert writes == writes_after_first_use


def _r32_controller(
    broker: _R32ScriptedBroker | None = None,
) -> tuple[object, _R32ScriptedBroker]:
    scripted = broker or _R32ScriptedBroker()
    controller = access.FullPreflightLifecycleController(scripted)
    return controller, scripted


def _r33_controller(
    broker: _R32ScriptedBroker | None = None,
) -> tuple[object, _R32ScriptedBroker]:
    scripted = broker or _R32ScriptedBroker()
    scripted._durable_lifecycle_test = True
    controller = access.FullPreflightLifecycleController(scripted)
    return controller, scripted


def _r33_advance_to_candidate_core() -> tuple[object, _R32ScriptedBroker]:
    controller, broker = _r33_controller()
    candidate, _ = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(_r32_bundles()[1].manifest)
    controller.stage_candidate(candidate)
    controller.install_candidate(candidate.manifest)
    controller.verify_candidate_inventory(candidate.manifest)
    controller.check_candidate_core()
    return controller, broker


def _r33_advance_to_ap0() -> tuple[object, _R32ScriptedBroker]:
    controller, broker = _r33_advance_to_candidate_core()
    controller.restart_for_candidate()
    controller.await_candidate_readiness()
    controller.verify_research_services_present()
    controller.admit_post_activation_repairs()
    controller.collect_a0()
    controller.run_p0()
    controller.collect_ap0()
    return controller, broker


def _r32_advance_to_post_activation_repairs() -> tuple[object, _R32ScriptedBroker]:
    controller, broker = _r32_controller()
    candidate, _ = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(_r32_bundles()[1].manifest)
    controller.stage_candidate(candidate)
    controller.install_candidate(candidate.manifest)
    controller.verify_candidate_inventory(candidate.manifest)
    controller.check_candidate_core()
    controller.restart_for_candidate()
    controller.await_candidate_readiness()
    controller.verify_research_services_present()
    controller.admit_post_activation_repairs()
    return controller, broker


def _r32_advance_to_a2() -> tuple[object, _R32ScriptedBroker]:
    controller, broker = _r32_advance_to_post_activation_repairs()
    controller.collect_a0()
    controller.run_p0()
    controller.collect_ap0()
    controller.run_non_probe_preflight()
    controller.collect_a1()
    controller.validate_research_final()
    controller.collect_a2()
    return controller, broker


def _r32_complete_restore_tail(
    controller: object, restore: access.SourceBundle
) -> object:
    controller.stage_restore(restore)
    controller.restore_pr41(restore.manifest)
    controller.verify_restore_inventory(restore.manifest)
    controller.check_restore_core()
    controller.restart_for_restore()
    controller.await_restore_readiness()
    controller.verify_research_services_absent()
    controller.admit_post_restore_repairs()
    return controller.complete()


@pytest.mark.parametrize(
    ("case", "payload", "expected"),
    (
        ("C1-M1", {"http_status": 200, "result": "ok", "check_passed": True}, True),
        ("C1-M2", {"http_status": 200, "result": "ok", "check_passed": False}, False),
        ("C1-M3", {"http_status": 200, "result": "ok"}, False),
        ("C1-M4", {"http_status": 200, "result": "ok", "check_passed": None}, False),
        ("C1-M5", {"http_status": 200, "result": "ok", "check_passed": 1}, False),
        ("C1-M6", {"http_status": 200, "result": "ok", "check_passed": "true"}, False),
        ("C1-M7", {"http_status": 200, "result": "error", "check_passed": True}, False),
        ("C1-M8", {"http_status": 503, "result": "ok", "check_passed": True}, False),
        ("C1-M9", "malformed-json", False),
    ),
)
def test_r32_c1_m1_to_m9_authoritative_core_check_matrix(
    case: str, payload: object, expected: bool
) -> None:
    result = access._parse_core_check_result(payload, attempt_ordinal=1)

    assert result.check_passed is expected, case


def test_r32_c1_m10_remote_core_check_never_synthesizes_authoritative_body_field() -> (
    None
):
    source = access._REMOTE_CONTROL_PROGRAM
    core_check = source[
        source.index("def core_check") : source.index("def restart_core")
    ]

    assert "authoritative = body.get('check_passed')" in core_check
    assert "'check_passed': authoritative" in core_check
    assert "passed = 200 <= status < 300 and result == 'ok'" not in core_check


def test_r32_core_check_completed_generic_error_is_typed_fail_not_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _r32_unbound_real_broker()
    monkeypatch.setattr(
        broker,
        "_PrivateInteractiveSessionBroker__execute_bounded_operation",
        lambda _operation, _value, **_kwargs: (
            b'{"http_status":0,"result":"error","error_class":"REQUEST_FAILED"}'
        ),
    )

    result = broker._check_core(
        1,
        _capability=_r32_controller_minted_capability(
            broker, access.LifecycleAction.CANDIDATE_CORE_CHECK_1
        ),
    )

    assert result == access.CoreCheckResult(1, 0, "error", False, "REQUEST_FAILED")


def test_r32_core_check_specialized_payload_rejects_non_allowlisted_fields() -> None:
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._exact_core_check_payload(
            b'{"http_status":0,"result":"error","error_class":"REQUEST_FAILED",'
            b'"private_detail":"forbidden"}'
        )


@pytest.mark.parametrize(
    ("case", "response"),
    (
        (
            "C2-M1",
            access.PhaseAResult(
                access.PhaseAOperation.PREFLIGHT,
                0,
                "preflight_ok",
                "a" * 16,
                access.PreflightResponse("preflight_ok", 1, "a" * 16),
            ),
        ),
        (
            "C2-M2",
            access.PhaseAResult(
                access.PhaseAOperation.PREFLIGHT, 66, "rejected", "a" * 16
            ),
        ),
        (
            "C2-M3",
            access.PhaseAResult(
                access.PhaseAOperation.PREFLIGHT, 67, "schema_invalid", "a" * 16
            ),
        ),
        (
            "C2-M4",
            access.PhaseAResult(
                access.PhaseAOperation.PREFLIGHT, 78, "transport_ambiguous", "a" * 16
            ),
        ),
        ("C2-M5", access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")),
    ),
)
def test_r32_c2_m1_to_m5_helper_permit_is_consumed_before_every_dispatch_outcome(
    case: str, response: object
) -> None:
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.AP0_COLLECTED
    broker.queue("helper", response)

    try:
        controller.run_non_probe_preflight()
    except access.LifecycleControllerError:
        pass
    controller._state = access.LifecycleState.AP0_COLLECTED
    call_count = len(broker.calls)

    with pytest.raises(access.LifecycleControllerError, match="PERMIT_CONSUMED"):
        controller.run_non_probe_preflight()
    assert len(broker.calls) == call_count, case


def test_r32_c2_m6_p0_stage_consumed_but_proves_no_http_submission() -> None:
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.A0_COLLECTED

    result = controller.run_p0()
    controller._state = access.LifecycleState.A0_COLLECTED

    assert result.exit_code == 65
    assert result.outcome == "not_submitted"
    assert result.nonce is None
    assert result.preflight is None
    with pytest.raises(access.LifecycleControllerError, match="PERMIT_CONSUMED"):
        controller.run_p0()
    assert [name for name, _ in broker.calls] == ["p0"]


def test_r32_c2_m6_invalid_transition_does_not_consume_or_write() -> None:
    controller, broker = _r32_controller()

    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        controller.run_p0()
    assert broker.calls == []


def test_r32_c2_m7_and_m8_preflight_ambiguity_has_no_receipt_reconciliation() -> None:
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.AP0_COLLECTED
    ambiguous = access.PhaseAResult(
        access.PhaseAOperation.PREFLIGHT,
        78,
        "transport_ambiguous",
        "a" * 16,
    )
    broker.queue("helper", ambiguous)

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.run_non_probe_preflight()
    assert not hasattr(access.LifecycleAction, "RECEIPT")
    assert not hasattr(controller, "lookup_ambiguous_receipt")
    assert [detail[0] for name, detail in broker.calls if name == "helper"] == [
        access.PhaseAOperation.PREFLIGHT,
    ]
    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        controller.run_non_probe_preflight()


def test_r32_c2_m9_and_m10_source_consumes_permit_before_helper_dispatch() -> None:
    source = inspect.getsource(access.FullPreflightLifecycleController)

    consume = source.index("permit.consume(")
    mint = source.index("capability = _LifecycleCapability(", consume)
    dispatch = source.index("callback(capability)", mint)
    assert consume < dispatch
    assert consume < mint < dispatch
    assert "PERMIT_CONSUMED" in source


@pytest.mark.parametrize(
    "state",
    (
        "BASELINE",
        "INITIAL_REPAIRS_PASS",
        "BACKUP_VERIFIED",
        "CANDIDATE_STAGED",
        "CANDIDATE_INSTALLED",
        "CANDIDATE_INVENTORY_VERIFIED",
        "CANDIDATE_CORE_CHECKED",
        "ACTIVATION_RESTART_CONSUMED",
        "CANDIDATE_READY",
        "RESEARCH_SERVICES_PRESENT",
    ),
)
def test_r32_c3_a0_rejected_before_post_activation_repairs(state: str) -> None:
    controller, broker = _r32_controller()
    controller._state = getattr(access.LifecycleState, state)

    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        controller.collect_a0()
    assert broker.calls == []


@pytest.mark.parametrize(
    "evidence",
    (
        access.RepairsEvidence(False, None, None),
        access.RepairsEvidence(True, 1, 0),
        access.RepairsEvidence(True, 0, 1),
    ),
)
def test_r32_c3_a0_rejected_after_malformed_or_nonzero_repairs(
    evidence: access.RepairsEvidence,
) -> None:
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.RESEARCH_SERVICES_PRESENT
    broker.queue("repairs", evidence)

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.admit_post_activation_repairs()
    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        controller.collect_a0()


def test_r32_c3_a0_only_after_complete_activation_admission() -> None:
    controller, broker = _r32_advance_to_post_activation_repairs()

    snapshot = controller.collect_a0()

    assert snapshot.history_overflow is False
    assert controller.state is access.LifecycleState.A0_COLLECTED
    assert broker.calls[-1][0] == "helper"


def test_r32_c4_exact_success_state_sequence() -> None:
    assert tuple(
        item.value for item in access.LifecycleState if not item.is_failure
    ) == (
        "BASELINE",
        "INITIAL_REPAIRS_PASS",
        "BACKUP_VERIFIED",
        "CANDIDATE_STAGED",
        "CANDIDATE_INSTALLED",
        "CANDIDATE_INVENTORY_VERIFIED",
        "CANDIDATE_CORE_CHECKED",
        "ACTIVATION_RESTART_CONSUMED",
        "CANDIDATE_READY",
        "RESEARCH_SERVICES_PRESENT",
        "POST_ACTIVATION_REPAIRS_PASS",
        "A0_COLLECTED",
        "P0_COMPLETED",
        "AP0_COLLECTED",
        "NON_PROBE_PREFLIGHT_COMPLETED",
        "A1_COLLECTED",
        "RESEARCH_FINAL_VALIDATED",
        "A2_COLLECTED",
        "RESTORE_STAGED",
        "PR41_RESTORED",
        "RESTORE_INVENTORY_VERIFIED",
        "RESTORE_CORE_CHECKED",
        "REMOVAL_RESTART_CONSUMED",
        "PR41_READY",
        "RESEARCH_SERVICES_ABSENT",
        "POST_RESTORE_REPAIRS_PASS",
        "COMPLETE_NORMAL",
        "RESTORED_AFTER_ABORT",
    )


@pytest.mark.parametrize(
    ("case", "state", "method"),
    (
        ("L-M1", "CANDIDATE_INSTALLED", "check_candidate_core"),
        ("L-M2", "CANDIDATE_INVENTORY_VERIFIED", "restart_for_candidate"),
        ("L-M3", "CANDIDATE_CORE_CHECKED", "await_candidate_readiness"),
        ("L-M4", "RESEARCH_SERVICES_PRESENT", "collect_a0"),
        ("L-M6", "A0_COLLECTED", "collect_ap0"),
        ("L-M7", "AP0_COLLECTED", "collect_a1"),
        ("L-M8", "A1_COLLECTED", "stage_restore"),
        ("L-M9", "PR41_RESTORED", "collect_a2"),
    ),
)
def test_r32_c4_lifecycle_skip_matrix_rejected_before_broker_dispatch(
    case: str, state: str, method: str
) -> None:
    controller, broker = _r32_controller()
    controller._state = getattr(access.LifecycleState, state)
    args = (_r32_bundles()[1],) if method == "stage_restore" else ()

    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        getattr(controller, method)(*args)
    assert broker.calls == [], case


def test_r32_c4_l_m5_p0_cannot_repeat_even_if_state_is_rewound() -> None:
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.A0_COLLECTED
    controller.run_p0()
    controller._state = access.LifecycleState.A0_COLLECTED

    with pytest.raises(access.LifecycleControllerError, match="PERMIT_CONSUMED"):
        controller.run_p0()
    assert len(broker.calls) == 1


def test_r32_c4_l_m16_ambiguous_restart_consumes_permit_before_dispatch() -> None:
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.CANDIDATE_CORE_CHECKED
    broker.queue(
        "restart", access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")
    )

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.restart_for_candidate()
    controller._state = access.LifecycleState.CANDIDATE_CORE_CHECKED
    call_count = len(broker.calls)

    with pytest.raises(access.LifecycleControllerError, match="PERMIT_CONSUMED"):
        controller.restart_for_candidate()
    assert len(broker.calls) == call_count


def test_r32_c4_l_m15_to_m18_no_replay_probe_or_generic_shell_surface() -> None:
    broker_callables = {
        name
        for name, value in vars(access.PrivateInteractiveSessionBroker).items()
        if not name.startswith("_") and callable(value)
    }
    controller_parameters = {
        name
        for value in vars(access.FullPreflightLifecycleController).values()
        if callable(value)
        for name in inspect.signature(value).parameters
    }

    assert broker_callables == {"open", "close"}
    assert "PROBE" not in access.PhaseAOperation.__members__
    assert not controller_parameters.intersection(
        {"command", "argv", "endpoint", "service_name", "operation", "label", "nonce"}
    )


_R32_FINAL_PROOF_VALUES = {
    "source_manifest_match": True,
    "research_files_absent": True,
    "core_check_passed": True,
    "restart_consumed": True,
    "restart_dispatched": True,
    "restart_submitted": True,
    "restart_accepted": True,
    "core_reachable": True,
    "core_running": True,
    "integration_loaded": True,
    "core_not_timed_out": True,
    "research_services_absent": True,
    "repairs_shape_valid": True,
    "repairs_relevant_zero": True,
    "repairs_critical_zero": True,
}


@pytest.mark.parametrize("predicate", tuple(_R32_FINAL_PROOF_VALUES))
def test_r32_c5_each_mandatory_final_restore_predicate_is_required(
    predicate: str,
) -> None:
    values = dict(_R32_FINAL_PROOF_VALUES)
    values[predicate] = False
    proof = access.FinalRestoreProof(**values)

    assert proof.complete is False, predicate


def test_r32_c5_typed_final_proof_has_no_defaults_and_complete_proof_passes() -> None:
    signature = inspect.signature(access.FinalRestoreProof)
    assert all(
        parameter.default is inspect.Parameter.empty
        for parameter in signature.parameters.values()
    )

    proof = access.FinalRestoreProof(**_R32_FINAL_PROOF_VALUES)

    assert proof.complete is True


@pytest.mark.parametrize(
    ("case", "queued_name", "failure", "state"),
    (
        (
            "candidate core check fail",
            "core_check",
            access.CoreCheckResult(1, 200, "ok", False, "CHECK_FAILED"),
            "CANDIDATE_INVENTORY_VERIFIED",
        ),
        (
            "post-activation Repairs fail",
            "repairs",
            access.RepairsEvidence(False, None, None),
            "RESEARCH_SERVICES_PRESENT",
        ),
        (
            "helper exit 78",
            "helper",
            access.PhaseAResult(
                access.PhaseAOperation.PREFLIGHT,
                78,
                "transport_ambiguous",
                "a" * 16,
            ),
            "AP0_COLLECTED",
        ),
        (
            "A1 comparison fail",
            "helper",
            access.PhaseAResult(
                operation=access.PhaseAOperation.AUDIT,
                exit_code=0,
                outcome="audit_snapshot",
                nonce="a" * 16,
                audit=_zero_audit_snapshot(event_ordinal=1, nonce="a" * 16),
            ),
            "NON_PROBE_PREFLIGHT_COMPLETED",
        ),
        (
            "A2 failure",
            "helper",
            access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_PROTOCOL"),
            "RESEARCH_FINAL_VALIDATED",
        ),
    ),
)
def test_r32_representative_post_install_failures_enter_ordered_pr41_rollback(
    case: str,
    queued_name: str,
    failure: object,
    state: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(access.secrets, "token_hex", lambda _length=16: "a" * 16)
    controller, broker = _r32_controller()
    controller._state = getattr(access.LifecycleState, state)
    if state in {"NON_PROBE_PREFLIGHT_COMPLETED", "RESEARCH_FINAL_VALIDATED"}:
        controller._snapshots = {
            access.AuditLabel.A0: _zero_audit_snapshot(),
            access.AuditLabel.AP0: _zero_audit_snapshot(),
            access.AuditLabel.A1: _zero_audit_snapshot(),
        }
    broker.queue(queued_name, failure)
    operation = {
        "CANDIDATE_INVENTORY_VERIFIED": controller.check_candidate_core,
        "RESEARCH_SERVICES_PRESENT": controller.admit_post_activation_repairs,
        "AP0_COLLECTED": controller.run_non_probe_preflight,
        "NON_PROBE_PREFLIGHT_COMPLETED": controller.collect_a1,
        "RESEARCH_FINAL_VALIDATED": controller.collect_a2,
    }[state]

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        operation()
    assert controller.state is access.LifecycleState.ROLLBACK_REQUIRED, case

    _, restore = _r32_bundles()
    proof = _r32_complete_restore_tail(controller, restore)
    assert proof.complete is True
    assert controller.state is access.LifecycleState.RESTORED_AFTER_ABORT


def test_r33_core_check_completed_failure_and_transport_ambiguity_never_replay() -> (
    None
):
    completed, completed_broker = _r32_controller()
    completed._state = access.LifecycleState.CANDIDATE_INVENTORY_VERIFIED
    completed_broker.queue(
        "core_check", access.CoreCheckResult(1, 200, "ok", False, "CHECK_FAILED")
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        completed.check_candidate_core()
    with pytest.raises(access.LifecycleControllerError):
        completed.check_candidate_core()
    assert [
        detail for name, detail in completed_broker.calls if name == "core_check"
    ] == [1]

    ambiguous, ambiguous_broker = _r32_controller()
    ambiguous._state = access.LifecycleState.CANDIDATE_INVENTORY_VERIFIED
    ambiguous_broker.queue(
        "core_check", access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        ambiguous.check_candidate_core()
    with pytest.raises(access.LifecycleControllerError):
        ambiguous.check_candidate_core()
    assert [
        detail for name, detail in ambiguous_broker.calls if name == "core_check"
    ] == [1]


def test_r32_terminal_broker_timeout_requires_explicit_fresh_rollback_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = _r32_unbound_real_broker()
    calls = 0

    def terminal_timeout(
        _operation: object, _value: object, **_kwargs: object
    ) -> bytes:
        nonlocal calls
        calls += 1
        broker._state = access.BrokerState.CLOSED
        broker._session_generation = None
        raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")

    monkeypatch.setattr(
        broker,
        "_PrivateInteractiveSessionBroker__execute_bounded_operation",
        terminal_timeout,
    )
    controller = access.FullPreflightLifecycleController(broker)
    controller._state = access.LifecycleState.CANDIDATE_INVENTORY_VERIFIED
    lifecycle_generation = controller._lifecycle_generation

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.check_candidate_core()
    assert controller.state is access.LifecycleState.ROLLBACK_REQUIRED
    assert calls == 1
    assert (
        controller._permits[access.LifecycleAction.CANDIDATE_CORE_CHECK_2].consumed
        is False
    )

    fresh = _R32ScriptedBroker()
    controller.bind_rollback_session(fresh)
    assert (
        controller._permits[access.LifecycleAction.RESTORE_TRANSFER].session_generation
        is fresh._session_generation
    )
    assert (
        controller._permits[
            access.LifecycleAction.CANDIDATE_CORE_CHECK_2
        ].session_generation
        is not fresh._session_generation
    )
    _, restore = _r32_bundles()
    proof = _r32_complete_restore_tail(controller, restore)

    assert proof.complete is True
    assert controller.state is access.LifecycleState.RESTORED_AFTER_ABORT
    assert controller._lifecycle_generation is lifecycle_generation
    assert (
        controller._permits[access.LifecycleAction.CANDIDATE_CORE_CHECK_1].consumed
        is True
    )
    assert (
        controller._permits[access.LifecycleAction.CANDIDATE_CORE_CHECK_2].consumed
        is False
    )


def test_r32_helper_78_session_loss_rebinds_rollback_tail_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(access.secrets, "token_hex", lambda _length=16: "a" * 16)
    controller, original = _r32_controller()
    controller._state = access.LifecycleState.AP0_COLLECTED
    original.queue(
        "helper",
        access.PhaseAResult(
            access.PhaseAOperation.PREFLIGHT,
            78,
            "transport_ambiguous",
            "a" * 16,
        ),
    )

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.run_non_probe_preflight()
    consumed_before = {
        action for action, permit in controller._permits.items() if permit.consumed
    }
    original.state = access.BrokerState.CLOSED
    original._session_generation = None
    fresh = _R32ScriptedBroker()

    controller.bind_rollback_session(fresh)
    assert consumed_before == {
        action for action, permit in controller._permits.items() if permit.consumed
    }
    _, restore = _r32_bundles()
    proof = _r32_complete_restore_tail(controller, restore)

    assert proof.complete is True
    assert consumed_before <= {
        action for action, permit in controller._permits.items() if permit.consumed
    }
    assert [detail[0] for name, detail in original.calls if name == "helper"] == [
        access.PhaseAOperation.PREFLIGHT
    ]
    assert [detail[0] for name, detail in fresh.calls if name == "helper"] == []


def test_r32_rollback_session_rebind_rejects_same_old_inactive_and_early_brokers() -> (
    None
):
    controller, original = _r32_controller()
    fresh = _R32ScriptedBroker()

    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        controller.bind_rollback_session(fresh)

    controller._state = access.LifecycleState.ROLLBACK_REQUIRED
    with pytest.raises(access.LifecycleControllerError, match="BINDING_INVALID"):
        controller.bind_rollback_session(original)

    inactive = _R32ScriptedBroker()
    inactive.state = access.BrokerState.CLOSED
    with pytest.raises(access.LifecycleControllerError, match="BINDING_INVALID"):
        controller.bind_rollback_session(inactive)

    old_generation = _R32ScriptedBroker()
    old_generation._session_generation = original._session_generation
    with pytest.raises(access.LifecycleControllerError, match="BINDING_INVALID"):
        controller.bind_rollback_session(old_generation)

    assert original.calls == []
    assert fresh.calls == []
    assert inactive.calls == []
    assert old_generation.calls == []


def test_r32_initial_and_final_repairs_require_shape_and_exact_zero_counts() -> None:
    for evidence in (
        access.RepairsEvidence(False, None, None),
        access.RepairsEvidence(True, 1, 0),
        access.RepairsEvidence(True, 0, 1),
    ):
        controller, broker = _r32_controller()
        broker.queue("repairs", evidence)
        with pytest.raises(access.LifecycleControllerError, match="ADMISSION_FAILED"):
            controller.admit_initial_repairs()
        assert controller.state is access.LifecycleState.BASELINE


def test_r32_service_admission_validates_exact_counts_not_result_booleans() -> None:
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.CANDIDATE_READY
    broker.queue(
        "services",
        access.ServiceInventoryResult(4, 3, True, 0, 0, True),
    )

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.verify_research_services_present()


@pytest.mark.parametrize(
    ("result", "result_type"),
    (
        (access.TransferResult(True, 2, True, True), access.TransferResult),
        (access.InstallResult(True, 2, 2, True), access.InstallResult),
        (access.InstallResult(True, 3, 2, True), access.InstallResult),
    ),
)
def test_r32_bundle_admission_rejects_self_consistent_wrong_reported_count(
    result: object, result_type: type[object]
) -> None:
    assert (
        access.FullPreflightLifecycleController._bundle_result_pass(
            result, 3, result_type
        )
        is False
    )


def test_r32_inventory_admission_rejects_self_consistent_wrong_reported_count() -> None:
    result = access.SourceInventoryResult(2, 2, True, 0, 0)

    assert access.FullPreflightLifecycleController._inventory_pass(result, 3) is False


def test_r32_direct_broker_helper_bypass_is_unavailable_before_pty_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    writes: list[str] = []
    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__write_wire", writes.append
    )

    for name in ("invoke_phase_a", "collect_resolution_info", "restart_core"):
        with pytest.raises(AttributeError):
            getattr(broker, name)
    assert writes == []


def test_r32_synthetic_controlling_pty_full_controller_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """One fake controlling PTY proves the exact 27-step controller path."""
    wrapper = tmp_path / "SYNTHETIC_REAL_WRAPPER_MUST_NOT_RUN"
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda _path: access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ()),
    )
    monkeypatch.setattr(
        access, "_spawn_private_wrapper", _fake_spawn(_R30_LIFECYCLE_CHILD)
    )
    monkeypatch.setattr(access.secrets, "token_hex", lambda _length=16: "b" * 16)
    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=0.5)
    candidate, restore = _r32_bundles()

    assert broker.open() is access.BrokerState.SESSION_ACTIVE
    controller = access.FullPreflightLifecycleController(broker)
    controller.admit_initial_repairs()
    controller.create_backup(_r32_bundles()[1].manifest)
    controller.stage_candidate(candidate)
    controller.install_candidate(candidate.manifest)
    controller.verify_candidate_inventory(candidate.manifest)
    controller.check_candidate_core()
    controller.restart_for_candidate()
    controller.await_candidate_readiness()
    controller.verify_research_services_present()
    controller.admit_post_activation_repairs()
    controller.collect_a0()
    controller.run_p0()
    controller.collect_ap0()
    controller.run_non_probe_preflight()
    controller.collect_a1()
    controller.validate_research_final()
    controller.collect_a2()
    proof = _r32_complete_restore_tail(controller, restore)
    broker.close()

    assert proof.complete is True
    assert controller.state is access.LifecycleState.COMPLETE
    assert broker.state is access.BrokerState.CLOSED


def test_r33_red_recovery_restore_has_distinct_terminal() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(_r32_bundles()[1].manifest)
    controller.stage_candidate(candidate)
    broker.queue(
        "install_candidate",
        access.InstallResult(False, 4, 0, False),
    )

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    proof = _r32_complete_restore_tail(controller, restore)

    assert proof.complete is True
    assert controller.state is access.LifecycleState.RESTORED_AFTER_ABORT


def test_r33_red_new_controller_cannot_refresh_restart_permit() -> None:
    first, first_broker = _r33_advance_to_candidate_core()
    first.restart_for_candidate()
    first.close()

    second, second_broker = _r33_controller()
    assert second.state is access.LifecycleState.RECOVERY_REQUIRED
    with pytest.raises(AttributeError, match="RECOVERY_ONLY"):
        second.restart_for_candidate()

    assert [name for name, _ in first_broker.calls].count("restart") == 1
    assert [name for name, _ in second_broker.calls].count("restart") == 0


def test_r33_red_exit_78_remains_consumed_after_reconstruction() -> None:
    first, first_broker = _r33_advance_to_ap0()
    first_broker.queue(
        "helper",
        access.PhaseAResult(
            access.PhaseAOperation.PREFLIGHT,
            78,
            "transport_ambiguous",
            "a" * 16,
        ),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        first.run_non_probe_preflight()
    first.close()

    second, second_broker = _r33_controller()
    assert second.state is access.LifecycleState.RECOVERY_REQUIRED
    with pytest.raises(AttributeError, match="RECOVERY_ONLY"):
        second.run_non_probe_preflight()
    assert [name for name, _ in second_broker.calls].count("helper") == 0


def test_r33_red_controller_rejects_truthy_core_check_result() -> None:
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.CANDIDATE_INVENTORY_VERIFIED
    broker.queue("core_check", access.CoreCheckResult(1, 200, "ok", 1, None))

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.check_candidate_core()


def test_r33_red_stale_core_evidence_cannot_advance_new_lifecycle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stale = access.CoreCheckResult(1, 200, "ok", True, None)
    first, first_broker = _r33_controller()
    candidate, _ = _r32_bundles()
    first.admit_initial_repairs()
    first.create_backup(_r32_bundles()[1].manifest)
    first.stage_candidate(candidate)
    first.install_candidate(candidate.manifest)
    first.verify_candidate_inventory(candidate.manifest)
    first_broker.queue("core_check", stale)
    assert first.check_candidate_core() is stale
    first.close()

    monkeypatch.setattr(access, "_LIFECYCLE_STATE_ROOT", tmp_path / "second")
    second, second_broker = _r33_controller()
    second.admit_initial_repairs()
    second.create_backup(_r32_bundles()[1].manifest)
    second.stage_candidate(candidate)
    second.install_candidate(candidate.manifest)
    second.verify_candidate_inventory(candidate.manifest)
    second_broker.queue("core_check", stale)
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        second.check_candidate_core()
    assert second.state is not access.LifecycleState.CANDIDATE_CORE_CHECKED


@pytest.mark.parametrize("field_name", tuple(_R32_FINAL_PROOF_VALUES))
@pytest.mark.parametrize("invalid", (1, 0, "true", "false", object(), None))
def test_r33_red_final_restore_proof_rejects_non_boolean_predicates(
    field_name: str,
    invalid: object,
) -> None:
    values = dict(_R32_FINAL_PROOF_VALUES)
    values[field_name] = invalid
    assert access.FinalRestoreProof(**values).complete is False


def test_r33_red_repairs_rejects_bool_integer_lookalikes() -> None:
    assert (
        access.FullPreflightLifecycleController._repairs_pass(
            access.RepairsEvidence(1, False, 0)
        )
        is False
    )


def test_r33_red_direct_state_assignment_is_not_predecessor_proof() -> None:
    controller, broker = _r33_controller()
    controller._state = access.LifecycleState.POST_ACTIVATION_REPAIRS_PASS

    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        controller.collect_a0()
    assert broker.calls == []


def test_r33_red_capability_is_immutable_and_cannot_be_relabelled() -> None:
    broker = _r32_unbound_real_broker()
    capability = _r32_controller_minted_capability(
        broker, access.LifecycleAction.INITIAL_REPAIRS
    )

    with pytest.raises((AttributeError, FrozenInstanceError)):
        capability.action = access.LifecycleAction.ACTIVATION_RESTART


def test_r33_red_snapshot_generation_mismatch_blocks_research_final() -> None:
    controller, broker = _r32_controller()
    generation = object()
    controller._state = access.LifecycleState.A1_COLLECTED
    controller._candidate_activation_generation = generation
    controller._snapshots = {
        label: _zero_audit_snapshot()
        for label in (
            access.AuditLabel.A0,
            access.AuditLabel.AP0,
            access.AuditLabel.A1,
        )
    }
    controller._snapshot_generations = {
        access.AuditLabel.A0: generation,
        access.AuditLabel.AP0: generation,
        access.AuditLabel.A1: object(),
    }
    controller._preflight_result = access.PhaseAResult(
        access.PhaseAOperation.PREFLIGHT,
        0,
        "preflight_ok",
        "a" * 16,
        access.PreflightResponse("preflight_ok", 1, "a" * 16),
    )
    passing = access.AuditComparison(True, True, True, True, True)
    controller._audit_comparisons = {
        (access.AuditLabel.A0, access.AuditLabel.AP0): passing,
        (access.AuditLabel.AP0, access.AuditLabel.A1): passing,
    }

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.validate_research_final()
    assert [name for name, _ in broker.calls] == []


def _r33_drive_complete_research() -> tuple[object, _R32ScriptedBroker]:
    controller, broker = _r33_advance_to_ap0()
    controller.run_non_probe_preflight()
    controller.collect_a1()
    controller.validate_research_final()
    controller.collect_a2()
    return controller, broker


def test_r33_t_m1_complete_normal_requires_full_same_generation_history() -> None:
    controller, _broker = _r33_drive_complete_research()
    _, restore = _r32_bundles()

    proof = _r32_complete_restore_tail(controller, restore)

    assert proof.complete is True
    assert controller.state is access.LifecycleState.COMPLETE_NORMAL
    assert (
        tuple(
            access.LifecycleState(item["stage"])
            for item in controller._journal.transitions
        )[:-1]
        == access._NORMAL_LIFECYCLE_HISTORY
    )


@pytest.mark.parametrize(
    "failure_stage",
    ("candidate_install", "p0", "preflight", "a1_validation", "a2"),
)
def test_r33_t_m2_to_t_m6_abort_then_full_restore_is_not_research_success(
    failure_stage: str,
) -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(_r32_bundles()[1].manifest)
    controller.stage_candidate(candidate)
    if failure_stage == "candidate_install":
        broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
        with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
            controller.install_candidate(candidate.manifest)
    else:
        controller.install_candidate(candidate.manifest)
    if failure_stage != "candidate_install":
        controller.verify_candidate_inventory(candidate.manifest)
        controller.check_candidate_core()
        controller.restart_for_candidate()
        controller.await_candidate_readiness()
        controller.verify_research_services_present()
        controller.admit_post_activation_repairs()
        controller.collect_a0()
        if failure_stage == "p0":
            broker.queue(
                "p0",
                access.PhaseAResult(
                    access.PhaseAOperation.PREFLIGHT, 0, "invalid", None, True
                ),
            )
            with pytest.raises(
                access.LifecycleControllerError, match="ROLLBACK_REQUIRED"
            ):
                controller.run_p0()
        else:
            controller.run_p0()
            controller.collect_ap0()
            if failure_stage == "preflight":
                broker.queue(
                    "helper",
                    lambda detail: access.PhaseAResult(
                        access.PhaseAOperation.PREFLIGHT,
                        78,
                        "transport_ambiguous",
                        detail[1],
                    ),
                )
                with pytest.raises(
                    access.LifecycleControllerError, match="ROLLBACK_REQUIRED"
                ):
                    controller.run_non_probe_preflight()
            else:
                controller.run_non_probe_preflight()
                if failure_stage == "a1_validation":
                    broker.queue(
                        "helper",
                        lambda detail: access.PhaseAResult(
                            operation=access.PhaseAOperation.AUDIT,
                            exit_code=0,
                            outcome="audit_snapshot",
                            nonce=detail[1],
                            audit=_zero_audit_snapshot(
                                event_ordinal=1, nonce=detail[1]
                            ),
                        ),
                    )
                    with pytest.raises(
                        access.LifecycleControllerError, match="ROLLBACK_REQUIRED"
                    ):
                        controller.collect_a1()
                else:
                    controller.collect_a1()
                    controller.validate_research_final()
                    broker.queue(
                        "helper",
                        access.SessionBrokerError(
                            "PRIVATE_INTERACTIVE_SESSION_PROTOCOL"
                        ),
                    )
                    with pytest.raises(
                        access.LifecycleControllerError, match="ROLLBACK_REQUIRED"
                    ):
                        controller.collect_a2()

    proof = _r32_complete_restore_tail(controller, restore)

    assert proof.complete is True
    assert controller.state is access.LifecycleState.RESTORED_AFTER_ABORT
    assert controller.state is not access.LifecycleState.COMPLETE_NORMAL


def test_r33_t_m7_restoration_failure_is_a_distinct_terminal() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(_r32_bundles()[1].manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    controller.stage_restore(restore)
    broker.queue("install_restore", access.InstallResult(False, 1, 0, False))

    with pytest.raises(access.LifecycleControllerError, match="RESTORE_FAILED"):
        controller.restore_pr41(restore.manifest)

    assert controller.state is access.LifecycleState.RESTORE_FAILED
    assert controller.state not in {
        access.LifecycleState.COMPLETE_NORMAL,
        access.LifecycleState.RESTORED_AFTER_ABORT,
    }


def test_r33_journal_is_owner_private_atomic_and_strictly_versioned(
    tmp_path: Path,
) -> None:
    controller, _broker = _r33_controller()
    root = access._LIFECYCLE_STATE_ROOT
    assert root == tmp_path / "lifecycle"
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    lock_path = root / access._LIFECYCLE_LOCK_NAME

    assert root.stat().st_mode & 0o777 == 0o700
    assert journal_path.stat().st_mode & 0o777 == 0o600
    assert lock_path.stat().st_mode & 0o777 == 0o600
    record = json.loads(journal_path.read_text(encoding="ascii"))
    assert record["schema_version"] == access._LIFECYCLE_JOURNAL_SCHEMA
    assert not any(root.glob(".journal-*.tmp"))
    assert {
        "lifecycle_generation",
        "consumed_operations",
        "restart_tombstones",
        "helper_tombstones",
        "core_check_attempts",
        "evidence_identities",
        "source_generation",
    } <= set(record)
    controller.close()


def test_r33_second_controller_same_process_cannot_dispatch() -> None:
    first, _first_broker = _r33_controller()
    second_broker = _R32ScriptedBroker()
    second_broker._durable_lifecycle_test = True

    with pytest.raises(access.LifecycleControllerError, match="OWNER_ACTIVE"):
        access.FullPreflightLifecycleController(second_broker)

    assert second_broker.calls == []
    first.close()


def test_r33_second_process_cannot_acquire_active_lifecycle(tmp_path: Path) -> None:
    first, _broker = _r33_controller()
    root = tmp_path / "lifecycle"
    script = """
import pathlib
import sys
from tools import home_assistant_live_access as access
access._LIFECYCLE_STATE_ROOT = pathlib.Path(sys.argv[1])
try:
    access._DurableLifecycleJournal()
except access.LifecycleControllerError as error:
    raise SystemExit(0 if str(error) == 'LIFECYCLE_OWNER_ACTIVE' else 3)
raise SystemExit(4)
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(root)],
        cwd=Path(access.__file__).parent.parent,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""
    first.close()


@pytest.mark.parametrize(
    "payload",
    (
        b"{}",
        b'{"schema_version":1,"schema_version":1}',
        b"[]",
        b"not-json",
    ),
)
def test_r33_malformed_or_duplicate_key_journal_fails_closed(
    payload: bytes, tmp_path: Path
) -> None:
    root = tmp_path / "lifecycle"
    root.mkdir(mode=0o700)
    journal = root / access._LIFECYCLE_JOURNAL_NAME
    journal.write_bytes(payload)
    journal.chmod(0o600)

    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal()


def test_r33_symlink_state_directory_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    root = tmp_path / "lifecycle"
    root.symlink_to(target, target_is_directory=True)

    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal()


def test_r33_complete_invalid_action_state_matrix_is_side_effect_free() -> None:
    class ProbeJournal:
        def __init__(self, state: access.LifecycleState) -> None:
            self.state = state
            self.recovery_mode = False
            self.intents = 0

        def record_intent(self, *_args: object, **_kwargs: object) -> None:
            self.intents += 1

    checked = 0
    for action in access.LifecycleAction:
        allowed = access._LIFECYCLE_ACTION_PREDECESSORS[action]
        for state in access.LifecycleState:
            if state in allowed:
                continue
            controller, broker = _r32_controller()
            journal = ProbeJournal(state)
            controller._journal = journal
            consumed_before = {
                item for item, permit in controller._permits.items() if permit.consumed
            }
            callbacks: list[object] = []

            with pytest.raises(
                access.LifecycleControllerError, match="TRANSITION_INVALID"
            ):
                controller._dispatch(
                    action,
                    lambda capability, callbacks=callbacks: callbacks.append(
                        capability
                    ),
                    _dispatch_token=(
                        controller._FullPreflightLifecycleController__dispatch_token
                    ),
                )

            assert journal.state is state
            assert journal.intents == 0
            assert consumed_before == {
                item for item, permit in controller._permits.items() if permit.consumed
            }
            assert callbacks == []
            assert broker.calls == []
            checked += 1

    assert checked == sum(
        len(access.LifecycleState) - len(allowed)
        for allowed in access._LIFECYCLE_ACTION_PREDECESSORS.values()
    )


def test_r33_complete_normal_dominance_fixed_point_model() -> None:
    assert set(access._LIFECYCLE_ACTION_PREDECESSORS) == set(access.LifecycleAction)
    assert set(access._LIFECYCLE_ACTION_SUCCESSORS) == set(access.LifecycleAction)
    required = access._NORMAL_LIFECYCLE_HISTORY
    reachable: set[tuple[access.LifecycleState, int, bool]] = {
        (access.LifecycleState.BASELINE, 1, False)
    }
    changed = True
    while changed:
        changed = False
        for state, prefix, recovery in tuple(reachable):
            for action in access.LifecycleAction:
                if state not in access._LIFECYCLE_ACTION_PREDECESSORS[action]:
                    continue
                for successor in access._LIFECYCLE_ACTION_SUCCESSORS[action]:
                    next_prefix = prefix
                    if prefix < len(required) and successor is required[prefix]:
                        next_prefix += 1
                    if successor is access.LifecycleState.COMPLETE_NORMAL and (
                        recovery or next_prefix != len(required)
                    ):
                        continue
                    item = (successor, next_prefix, recovery)
                    if item not in reachable:
                        reachable.add(item)
                        changed = True
            if state not in {
                access.LifecycleState.COMPLETE_NORMAL,
                access.LifecycleState.RESTORED_AFTER_ABORT,
                access.LifecycleState.RESTORE_FAILED,
                access.LifecycleState.MANUAL_RECOVERY_REQUIRED,
            }:
                item = (access.LifecycleState.ROLLBACK_REQUIRED, prefix, True)
                if item not in reachable:
                    reachable.add(item)
                    changed = True

    normal = [
        item for item in reachable if item[0] is access.LifecycleState.COMPLETE_NORMAL
    ]
    assert normal
    assert all(
        prefix == len(required) and recovery is False for _, prefix, recovery in normal
    )
    assert any(
        state is access.LifecycleState.RESTORED_AFTER_ABORT or recovery
        for state, _prefix, recovery in reachable
    )


def _assert_r33_reconstructed_recovery_only(
    first: object,
    expected: access.LifecycleState = access.LifecycleState.RECOVERY_REQUIRED,
) -> tuple[object, _R32ScriptedBroker]:
    first.close()
    second, broker = _r33_controller()
    assert second.state is expected
    for name in second._RECOVERY_HIDDEN_ENTRYPOINTS:
        assert not hasattr(second, name)
    assert broker.calls == []
    return second, broker


def test_r33_r_m1_helper_submission_survives_reconstruction() -> None:
    first, first_broker = _r33_advance_to_candidate_core()
    first.restart_for_candidate()
    first.await_candidate_readiness()
    first.verify_research_services_present()
    first.admit_post_activation_repairs()
    first.collect_a0()
    first.run_p0()
    assert [name for name, _ in first_broker.calls].count("p0") == 1

    second, second_broker = _assert_r33_reconstructed_recovery_only(first)

    assert access.LifecycleAction.P0 in second._journal.consumed_actions
    assert [name for name, _ in second_broker.calls].count("p0") == 0


def test_r33_r_m4_candidate_install_enters_recovery_only_after_loss() -> None:
    first, _broker = _r33_controller()
    candidate, _restore = _r32_bundles()
    first.admit_initial_repairs()
    first.create_backup(_r32_bundles()[1].manifest)
    first.stage_candidate(candidate)
    first.install_candidate(candidate.manifest)

    second, _second_broker = _assert_r33_reconstructed_recovery_only(first)

    assert access.LifecycleAction.CANDIDATE_INSTALL in second._journal.consumed_actions


def test_r33_r_m5_restore_install_loss_never_reopens_research() -> None:
    first, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    first.admit_initial_repairs()
    first.create_backup(_r32_bundles()[1].manifest)
    first.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        first.install_candidate(candidate.manifest)
    first.stage_restore(restore)
    first.restore_pr41(restore.manifest)

    second, _second_broker = _assert_r33_reconstructed_recovery_only(
        first, access.LifecycleState.PR41_RESTORED
    )

    assert access.LifecycleAction.RESTORE_INSTALL in second._journal.consumed_actions
    assert not hasattr(second, "install_candidate")


def test_r35_reconstruction_committed_restore_tail_survives_each_process_loss() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(_r32_bundles()[1].manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)

    controller.stage_restore(restore)

    def reconstruct(expected: access.LifecycleState) -> object:
        nonlocal controller
        controller.close()
        controller, reconstructed_broker = _r33_controller()
        assert controller.state is expected
        assert controller._journal.recovery_mode is True
        assert reconstructed_broker.calls == []
        return controller

    reconstruct(access.LifecycleState.RESTORE_STAGED)
    controller.restore_pr41(restore.manifest)
    reconstruct(access.LifecycleState.PR41_RESTORED)
    controller.verify_restore_inventory(restore.manifest)
    reconstruct(access.LifecycleState.RESTORE_INVENTORY_VERIFIED)
    controller.check_restore_core()
    reconstruct(access.LifecycleState.RESTORE_CORE_CHECKED)
    controller.restart_for_restore()
    reconstruct(access.LifecycleState.REMOVAL_RESTART_CONSUMED)
    controller.await_restore_readiness()
    reconstruct(access.LifecycleState.PR41_READY)
    controller.verify_research_services_absent()
    reconstruct(access.LifecycleState.RESEARCH_SERVICES_ABSENT)
    controller.admit_post_restore_repairs()
    reconstruct(access.LifecycleState.POST_RESTORE_REPAIRS_PASS)

    proof = controller.complete()

    assert proof.complete is True
    assert controller.state is access.LifecycleState.RESTORED_AFTER_ABORT


def test_r33_r_m6_removal_restart_cannot_replay_after_loss() -> None:
    first, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    first.admit_initial_repairs()
    first.create_backup(_r32_bundles()[1].manifest)
    first.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        first.install_candidate(candidate.manifest)
    first.stage_restore(restore)
    first.restore_pr41(restore.manifest)
    first.verify_restore_inventory(restore.manifest)
    first.check_restore_core()
    first.restart_for_restore()
    assert [name for name, _ in broker.calls].count("restart") == 1

    second, second_broker = _assert_r33_reconstructed_recovery_only(
        first, access.LifecycleState.REMOVAL_RESTART_CONSUMED
    )

    with pytest.raises(access.LifecycleControllerError):
        second.restart_for_restore()
    assert access.LifecycleAction.REMOVAL_RESTART in second._journal.consumed_actions
    assert [name for name, _ in second_broker.calls].count("restart") == 0


def test_r33_r_m7_active_unfinished_lifecycle_rejects_new_owner_then_recovers() -> None:
    first, _broker = _r33_advance_to_candidate_core()
    competing_broker = _R32ScriptedBroker()
    competing_broker._durable_lifecycle_test = True
    with pytest.raises(access.LifecycleControllerError, match="OWNER_ACTIVE"):
        access.FullPreflightLifecycleController(competing_broker)
    assert competing_broker.calls == []

    second, _second_broker = _assert_r33_reconstructed_recovery_only(first)
    assert second.state is access.LifecycleState.RECOVERY_REQUIRED


def _r33_issue_evidence_case(
    case: str, stale: object | None = None
) -> tuple[object, _R32ScriptedBroker, object]:
    controller, broker = _r33_controller()
    candidate, _restore = _r32_bundles()
    box: dict[str, object] = {}

    def chosen(default: object) -> object:
        value = default if stale is None else stale
        box["evidence"] = value
        return value

    if case == "repairs":
        broker.queue("repairs", chosen(access.RepairsEvidence(True, 0, 0)))
        controller.admit_initial_repairs()
        return controller, broker, box["evidence"]

    controller.admit_initial_repairs()
    controller.create_backup(_r32_bundles()[1].manifest)
    controller.stage_candidate(candidate)
    controller.install_candidate(candidate.manifest)
    if case == "inventory":
        count = len(candidate.manifest.entries)
        broker.queue(
            "inventory",
            chosen(access.SourceInventoryResult(count, count, True, 0, 0)),
        )
        controller.verify_candidate_inventory(candidate.manifest)
        return controller, broker, box["evidence"]

    controller.verify_candidate_inventory(candidate.manifest)
    if case == "core":
        broker.queue(
            "core_check", chosen(access.CoreCheckResult(1, 200, "ok", True, None))
        )
        controller.check_candidate_core()
        return controller, broker, box["evidence"]

    controller.check_candidate_core()
    controller.restart_for_candidate()
    if case == "readiness":
        broker.queue(
            "readiness",
            chosen(access.CoreReadinessResult(True, True, True, False)),
        )
        controller.await_candidate_readiness()
        return controller, broker, box["evidence"]

    controller.await_candidate_readiness()
    if case == "services":
        broker.queue(
            "services", chosen(access.ServiceInventoryResult(4, 4, True, 0, 0, True))
        )
        controller.verify_research_services_present()
        return controller, broker, box["evidence"]

    controller.verify_research_services_present()
    controller.admit_post_activation_repairs()

    def audit_response(detail: object) -> object:
        if stale is not None:
            box["evidence"] = stale
            return stale
        nonce = detail[1]
        value = access.PhaseAResult(
            operation=access.PhaseAOperation.AUDIT,
            exit_code=0,
            outcome="audit_snapshot",
            nonce=nonce,
            audit=_zero_audit_snapshot(nonce=nonce),
        )
        box["evidence"] = value
        return value

    if case == "a0":
        broker.queue("helper", audit_response)
        controller.collect_a0()
        return controller, broker, box["evidence"]

    controller.collect_a0()
    controller.run_p0()
    if case == "ap0":
        broker.queue("helper", audit_response)
        controller.collect_ap0()
        return controller, broker, box["evidence"]

    controller.collect_ap0()
    controller.run_non_probe_preflight()
    if case == "a1":
        broker.queue("helper", audit_response)
        controller.collect_a1()
        return controller, broker, box["evidence"]

    controller.collect_a1()
    controller.validate_research_final()
    broker.queue("helper", audit_response)
    controller.collect_a2()
    return controller, broker, box["evidence"]


@pytest.mark.parametrize(
    "case",
    ("repairs", "inventory", "core", "readiness", "services", "a0", "ap0", "a1", "a2"),
)
def test_r33_stale_evidence_matrix_rejects_new_lifecycle_source_and_session(
    case: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first, _first_broker, stale = _r33_issue_evidence_case(case)
    first.close()
    monkeypatch.setattr(access, "_LIFECYCLE_STATE_ROOT", tmp_path / "second")

    with pytest.raises(
        (access.LifecycleControllerError, access.SessionBrokerError),
        match="(ADMISSION_FAILED|ROLLBACK_REQUIRED|EVIDENCE_REUSED)",
    ):
        _r33_issue_evidence_case(case, stale)


def test_r33_candidate_inventory_cannot_be_reused_as_restored_source_evidence() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(_r32_bundles()[1].manifest)
    controller.stage_candidate(candidate)
    controller.install_candidate(candidate.manifest)
    count = len(candidate.manifest.entries)
    stale = access.SourceInventoryResult(count, count, True, 0, 0)
    broker.queue("inventory", stale)
    controller.verify_candidate_inventory(candidate.manifest)
    broker.queue(
        "core_check", access.CoreCheckResult(1, 200, "ok", False, "CHECK_FAILED")
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.check_candidate_core()
    controller.stage_restore(restore)
    controller.restore_pr41(restore.manifest)
    broker.queue("inventory", stale)

    with pytest.raises(
        (access.LifecycleControllerError, access.SessionBrokerError),
        match="(RESTORE_FAILED|EVIDENCE_REUSED)",
    ):
        controller.verify_restore_inventory(restore.manifest)

    assert controller.state is access.LifecycleState.RESTORE_FAILED


@pytest.mark.parametrize(
    "dimension",
    (
        "lifecycle_generation",
        "source_generation",
        "session_generation",
        "action",
        "audit_instance",
        "evidence_generation",
    ),
)
def test_r33_snapshot_origin_generation_mutation_matrix(dimension: str) -> None:
    controller, _broker = _r33_advance_to_ap0()
    controller.run_non_probe_preflight()
    controller.collect_a1()
    origin, generation = controller._snapshot_origins[access.AuditLabel.A1]
    if dimension == "evidence_generation":
        generation = controller._snapshot_origins[access.AuditLabel.A0][1]
    else:
        replacement: object
        if dimension == "action":
            replacement = access.LifecycleAction.A0
        elif dimension == "audit_instance":
            replacement = "synthetic-other-audit-instance"
        else:
            replacement = object()
        origin = replace(origin, **{dimension: replacement})
    controller._snapshot_origins[access.AuditLabel.A1] = (origin, generation)

    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.validate_research_final()


def test_r33_a2_origin_completes_same_lifecycle_source_audit_chain() -> None:
    controller, _broker = _r33_drive_complete_research()
    origins = controller._snapshot_origins

    assert tuple(origins) == (
        access.AuditLabel.A0,
        access.AuditLabel.AP0,
        access.AuditLabel.A1,
        access.AuditLabel.A2,
    )
    assert len({origin.audit_instance for origin, _ in origins.values()}) == 1
    assert len({origin.lifecycle_generation for origin, _ in origins.values()}) == 1
    assert len({origin.source_generation for origin, _ in origins.values()}) == 1
    generations = [generation for _origin, generation in origins.values()]
    assert generations == sorted(generations)
    assert len(generations) == len(set(generations))


def test_r33_internal_pty_surface_has_only_typed_name_mangled_sink() -> None:
    broker_class = access.PrivateInteractiveSessionBroker
    assert not hasattr(broker_class, "_write_private")
    assert not hasattr(broker_class, "_execute_bounded_operation")
    sink = broker_class._PrivateInteractiveSessionBroker__write_wire
    sink_parameters = inspect.signature(sink).parameters
    assert tuple(sink_parameters) == ("self", "packet")
    assert sink_parameters["packet"].annotation in {
        access._PrivateWirePacket,
        "_PrivateWirePacket",
    }
    dispatcher = (
        broker_class._PrivateInteractiveSessionBroker__execute_bounded_operation
    )
    dispatcher_parameters = inspect.signature(dispatcher).parameters
    assert "command" not in dispatcher_parameters
    assert "argv" not in dispatcher_parameters
    assert dispatcher_parameters["operation"].annotation in {
        access.BoundedOperation,
        "BoundedOperation",
    }

    source = Path(access.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    broker_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "PrivateInteractiveSessionBroker"
    )
    writers = {
        method.name
        for method in broker_node.body
        if isinstance(method, ast.FunctionDef)
        and any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "os"
            and call.func.attr == "write"
            for call in ast.walk(method)
        )
    }
    assert writers == {"__write_wire"}
    controller_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "FullPreflightLifecycleController"
    )
    assert not any(
        isinstance(node, ast.Name) and node.id == "_PrivateWirePacket"
        for node in ast.walk(controller_node)
    )


def test_r33_every_submission_action_has_all_crash_window_orderings() -> None:
    class SyntheticCrash(BaseException):
        pass

    class ProbeJournal:
        def __init__(self, state: access.LifecycleState, crash_at: str | None) -> None:
            self.state = state
            self.recovery_mode = state is access.LifecycleState.RECOVERY_REQUIRED
            self.crash_at = crash_at
            self.phases: list[str] = []
            self.consumed: list[access.LifecycleAction] = []

        def record_intent(
            self, action: access.LifecycleAction, **_kwargs: object
        ) -> None:
            if self.crash_at == "before_intent":
                raise SyntheticCrash
            self.consumed.append(action)
            self.phases.append("intent_durable")
            if self.crash_at == "after_intent":
                raise SyntheticCrash

        def record_dispatch_started(self, _action: access.LifecycleAction) -> None:
            self.phases.append("dispatch_started")

        def record_ambiguous(self, _action: access.LifecycleAction) -> None:
            self.phases.append("ambiguous")

        def record_result(
            self, _action: access.LifecycleAction, **_kwargs: object
        ) -> int:
            if self.crash_at == "before_result":
                raise SyntheticCrash
            self.phases.append("result_durable")
            if self.crash_at == "after_result":
                raise SyntheticCrash
            return 1

        def transition(self, state: access.LifecycleState, **_kwargs: object) -> None:
            self.phases.append("transition_committed")
            self.state = state

    minimum = {
        access.LifecycleAction.BACKUP,
        access.LifecycleAction.CANDIDATE_TRANSFER,
        access.LifecycleAction.CANDIDATE_INSTALL,
        access.LifecycleAction.ACTIVATION_RESTART,
        access.LifecycleAction.A0,
        access.LifecycleAction.P0,
        access.LifecycleAction.AP0,
        access.LifecycleAction.PREFLIGHT,
        access.LifecycleAction.A1,
        access.LifecycleAction.A2,
        access.LifecycleAction.RESTORE_TRANSFER,
        access.LifecycleAction.RESTORE_INSTALL,
        access.LifecycleAction.REMOVAL_RESTART,
        access.LifecycleAction.BACKUP_FALLBACK,
        access.LifecycleAction.BACKUP_FALLBACK_RECONCILE,
    }
    risky = {
        access.LifecycleAction(value)
        for value in access._DurableLifecycleJournal._RISKY_ACTIONS
    }
    assert minimum <= risky

    for action in sorted(risky, key=lambda item: item.value):
        predecessor = next(iter(access._LIFECYCLE_ACTION_PREDECESSORS[action]))
        for crash_at, expected_phases, callback_count in (
            ("before_intent", [], 0),
            ("after_intent", ["intent_durable"], 0),
            (
                "during_dispatch",
                ["intent_durable", "dispatch_started", "ambiguous"],
                1,
            ),
            ("before_result", ["intent_durable", "dispatch_started"], 1),
            (
                "after_result",
                ["intent_durable", "dispatch_started", "result_durable"],
                1,
            ),
        ):
            controller, broker = _r32_controller()
            journal = ProbeJournal(predecessor, crash_at)
            controller._journal = journal
            callbacks = 0

            def callback(_capability: object, crash_at: str = crash_at) -> object:
                nonlocal callbacks
                callbacks += 1
                if crash_at == "during_dispatch":
                    raise SyntheticCrash
                return object()

            with pytest.raises(SyntheticCrash):
                controller._dispatch(
                    action,
                    callback,
                    broker_evidence=False,
                    _dispatch_token=(
                        controller._FullPreflightLifecycleController__dispatch_token
                    ),
                )

            assert journal.phases == expected_phases, (action, crash_at)
            assert callbacks == callback_count
            assert journal.consumed == ([] if crash_at == "before_intent" else [action])
            assert broker.calls == []

        controller, broker = _r32_controller()
        journal = ProbeJournal(predecessor, None)
        controller._journal = journal
        controller._dispatch(
            action,
            lambda _capability: object(),
            broker_evidence=False,
            _dispatch_token=(
                controller._FullPreflightLifecycleController__dispatch_token
            ),
        )
        successor = next(
            (
                state
                for state in access._LIFECYCLE_ACTION_SUCCESSORS[action]
                if state is predecessor
            ),
            next(iter(access._LIFECYCLE_ACTION_SUCCESSORS[action])),
        )
        controller._advance(successor, action)
        assert journal.phases == [
            "intent_durable",
            "dispatch_started",
            "result_durable",
            "transition_committed",
        ]
        assert journal.state is successor
        assert broker.calls == []


def test_r33_every_submission_phase_reconstructs_as_recovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    normal_actions = (
        access.LifecycleAction.INITIAL_REPAIRS,
        access.LifecycleAction.BACKUP,
        access.LifecycleAction.CANDIDATE_TRANSFER,
        access.LifecycleAction.CANDIDATE_INSTALL,
        access.LifecycleAction.CANDIDATE_INVENTORY,
        access.LifecycleAction.CANDIDATE_CORE_CHECK_1,
        access.LifecycleAction.ACTIVATION_RESTART,
        access.LifecycleAction.CANDIDATE_READINESS,
        access.LifecycleAction.SERVICES_PRESENT,
        access.LifecycleAction.POST_ACTIVATION_REPAIRS,
        access.LifecycleAction.A0,
        access.LifecycleAction.P0,
        access.LifecycleAction.AP0,
        access.LifecycleAction.PREFLIGHT,
        access.LifecycleAction.A1,
        access.LifecycleAction.RESEARCH_FINAL,
        access.LifecycleAction.A2,
        access.LifecycleAction.RESTORE_TRANSFER,
        access.LifecycleAction.RESTORE_INSTALL,
        access.LifecycleAction.RESTORE_INVENTORY,
        access.LifecycleAction.RESTORE_CORE_CHECK_1,
        access.LifecycleAction.REMOVAL_RESTART,
        access.LifecycleAction.RESTORE_READINESS,
        access.LifecycleAction.SERVICES_ABSENT,
        access.LifecycleAction.POST_RESTORE_REPAIRS,
    )
    assert len(normal_actions) + 1 == len(access._NORMAL_LIFECYCLE_HISTORY)

    def durable_action(
        journal: access._DurableLifecycleJournal,
        action: access.LifecycleAction,
        successor: access.LifecycleState,
    ) -> None:
        source = journal.source_generation
        if action in access._CANDIDATE_SOURCE_ACTIONS:
            source = journal._record["pr45_source"]["generation"]
        elif action in access._PR41_BOUND_ACTIONS:
            source = journal._record["pr41_restore"]["generation"]
        nonce = "a" * 16 if action is access.LifecycleAction.PREFLIGHT else None
        journal.record_intent(action, source_generation=source, nonce=nonce)
        journal.record_dispatch_started(action)
        generation = journal.record_result(
            action,
            lifecycle_generation=journal.lifecycle_generation,
            source_generation=source,
            session_generation="b" * 32,
            issuance_identity=hashlib.sha256(action.value.encode()).hexdigest()[:32],
            audit_instance=None,
            nonce=nonce,
        )
        journal.transition(
            successor,
            action=action,
            source_generation=source,
            evidence_generation=generation,
        )

    risky = tuple(
        sorted(
            (
                access.LifecycleAction(value)
                for value in access._DurableLifecycleJournal._RISKY_ACTIONS
            ),
            key=lambda item: item.value,
        )
    )
    for action in risky:
        for phase in ("intent_durable", "dispatch_started", "result_durable"):
            root = tmp_path / action.value / phase
            monkeypatch.setattr(access, "_LIFECYCLE_STATE_ROOT", root)
            journal = access._DurableLifecycleJournal()
            predecessors = access._LIFECYCLE_ACTION_PREDECESSORS[action]
            normal_predecessors = [
                state
                for state in access._NORMAL_LIFECYCLE_HISTORY
                if state in predecessors
            ]
            if normal_predecessors:
                target_state = normal_predecessors[0]
                target_index = access._NORMAL_LIFECYCLE_HISTORY.index(target_state)
                for index, seed_action in enumerate(normal_actions[:target_index]):
                    durable_action(
                        journal,
                        seed_action,
                        access._NORMAL_LIFECYCLE_HISTORY[index + 1],
                    )
            else:
                durable_action(
                    journal,
                    access.LifecycleAction.INITIAL_REPAIRS,
                    access.LifecycleState.INITIAL_REPAIRS_PASS,
                )
                durable_action(
                    journal,
                    access.LifecycleAction.BACKUP,
                    access.LifecycleState.BACKUP_VERIFIED,
                )
                recovery_state = (
                    access.LifecycleState.RECOVERY_REQUIRED
                    if action is access.LifecycleAction.BACKUP_RECONCILE
                    else access.LifecycleState.ROLLBACK_REQUIRED
                )
                journal.transition(
                    recovery_state,
                    action=None,
                    source_generation=journal.source_generation,
                    evidence_generation=None,
                    recovery=True,
                )
            source = journal.source_generation
            if action in access._CANDIDATE_SOURCE_ACTIONS:
                source = journal._record["pr45_source"]["generation"]
            elif action in access._PR41_BOUND_ACTIONS:
                source = journal._record["pr41_restore"]["generation"]
            nonce = "d" * 16 if action is access.LifecycleAction.PREFLIGHT else None
            journal.record_intent(action, source_generation=source, nonce=nonce)
            if phase in {"dispatch_started", "result_durable"}:
                journal.record_dispatch_started(action)
            if phase == "result_durable":
                evidence = (
                    access.BackupResult(
                        True,
                        1,
                        True,
                        True,
                        lifecycle_generation=journal.lifecycle_generation,
                        source_generation=source,
                        backup_generation="1" * 32,
                        manifest_identity="2" * 64,
                        backup_digest="3" * 64,
                    )
                    if action is access.LifecycleAction.BACKUP_RECONCILE
                    else (
                        access.FallbackReconciliationResult("reconciled", True, True, 1)
                        if action is access.LifecycleAction.BACKUP_FALLBACK_RECONCILE
                        else None
                    )
                )
                journal.record_result(
                    action,
                    lifecycle_generation=journal.lifecycle_generation,
                    source_generation=source,
                    session_generation="e" * 32,
                    issuance_identity="f" * 32,
                    audit_instance=None,
                    nonce=nonce,
                    evidence=evidence,
                )
            journal.close()

            reconstructed = access._DurableLifecycleJournal()

            if (
                action is access.LifecycleAction.BACKUP_FALLBACK_RECONCILE
                and phase == "result_durable"
            ):
                expected_state = access.LifecycleState.PR41_RESTORED
            elif action in access._RESTORE_SOURCE_ACTIONS:
                expected_state = access.LifecycleState.RESTORE_FAILED
            else:
                expected_state = access.LifecycleState.RECOVERY_REQUIRED
            assert reconstructed.state is expected_state
            assert action in reconstructed.consumed_actions
            expected_operation_phase = (
                "transition_committed"
                if action is access.LifecycleAction.BACKUP_FALLBACK_RECONCILE
                and phase == "result_durable"
                else (
                    "transition_committed"
                    if action is access.LifecycleAction.BACKUP_RECONCILE
                    and phase == "result_durable"
                    else phase
                )
            )
            assert (
                reconstructed._record["operations"][-1]["phase"]
                == expected_operation_phase
            )
            reconstructed.close()


def test_r35_cr_m1_exact_pr45_unknown_receipt_remains_unknown() -> None:
    """PR45 PREFLIGHT(N) -> RECEIPT(N) is an honest unknown/exit-66 result."""
    nonce = "d" * 16
    result = access._parse_phase_a_result(
        access.PhaseAOperation.RECEIPT,
        json.dumps(
            {
                "exit_code": 66,
                "outcome": "receipt",
                "nonce": nonce,
                "receipt": {
                    "nonce": nonce,
                    "known": False,
                    "service_entered": False,
                    "request_handed_to_transport": False,
                    "terminal_class": None,
                    "response_available": False,
                },
            }
        ).encode(),
        expected_nonce=nonce,
    )

    assert result.exit_code == 66
    assert result.receipt == access.ReceiptResponse(
        nonce=nonce,
        known=False,
        service_entered=False,
        request_handed_to_transport=False,
        terminal_class=None,
        response_available=False,
    )


@pytest.mark.parametrize("terminal_class", (True, "x" * 65))
def test_r35_receipt_terminal_class_matches_exact_pr45_text_bound(
    terminal_class: object,
) -> None:
    nonce = "d" * 16
    payload = {
        "exit_code": 0,
        "outcome": "receipt",
        "nonce": nonce,
        "receipt": {
            "nonce": nonce,
            "known": True,
            "service_entered": True,
            "request_handed_to_transport": False,
            "terminal_class": terminal_class,
            "response_available": False,
        },
    }

    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            access.PhaseAOperation.RECEIPT,
            json.dumps(payload).encode(),
            expected_nonce=nonce,
        )


@pytest.mark.parametrize("terminal_class", (None, "", "x" * 64))
def test_r35_receipt_terminal_class_accepts_exact_pr45_text_domain(
    terminal_class: str | None,
) -> None:
    nonce = "d" * 16
    payload = {
        "exit_code": 0,
        "outcome": "receipt",
        "nonce": nonce,
        "receipt": {
            "nonce": nonce,
            "known": True,
            "service_entered": True,
            "request_handed_to_transport": False,
            "terminal_class": terminal_class,
            "response_available": False,
        },
    }

    result = access._parse_phase_a_result(
        access.PhaseAOperation.RECEIPT,
        json.dumps(payload).encode(),
        expected_nonce=nonce,
    )

    assert result.receipt is not None
    assert result.receipt.terminal_class == terminal_class


@pytest.mark.parametrize(
    "payload",
    (
        b'{"exit_code":true,"outcome":"preflight_ok","nonce":"dddddddddddddddd","preflight":{"result":"preflight_ok","protocol_version":1,"nonce":"dddddddddddddddd"}}',
        b'{"exit_code":0,"outcome":"preflight_ok","nonce":"dddddddddddddddd","preflight":{"result":"preflight_ok","protocol_version":true,"nonce":"dddddddddddddddd"}}',
        b'{"exit_code":0,"outcome":"preflight_ok","nonce":"dddddddddddddddd","preflight":{"result":"preflight_ok","protocol_version":1,"nonce":"dddddddddddddddd"},"extra":false}',
        b'{"exit_code":0,"exit_code":0,"outcome":"preflight_ok","nonce":"dddddddddddddddd","preflight":{"result":"preflight_ok","protocol_version":1,"nonce":"dddddddddddddddd"}}',
    ),
)
def test_r35_helper_schema_rejects_bool_extra_and_duplicate_fields(
    payload: bytes,
) -> None:
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            access.PhaseAOperation.PREFLIGHT,
            payload,
            expected_nonce="d" * 16,
        )


@pytest.mark.parametrize("protocol_version", (True, 1.0, "1"))
def test_r35_audit_schema_requires_result_and_exact_integer_protocol(
    protocol_version: object,
) -> None:
    nonce = "d" * 16
    payload = {
        "exit_code": 0,
        "outcome": "audit_snapshot",
        "nonce": nonce,
        "audit": {
            "result": "audit_snapshot",
            "protocol_version": protocol_version,
            "audit_instance_token": "a" * 32,
            "event_ordinal": 0,
            "history_overflow": False,
            "runtime_ms": 0,
            "counters": {name: 0 for name in access.AUDIT_COUNTER_NAMES},
            "events": [],
            "nonce": nonce,
        },
    }
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            access.PhaseAOperation.AUDIT,
            json.dumps(payload).encode(),
            expected_nonce=nonce,
        )


def test_r35_cr_m2_unknown_receipt_is_not_a_mandatory_normal_gate() -> None:
    """The normal lifecycle advances directly from PREFLIGHT evidence to A1."""
    controller, broker = _r32_advance_to_post_activation_repairs()
    controller.collect_a0()
    controller.run_p0()
    controller.collect_ap0()
    controller.run_non_probe_preflight()

    controller.collect_a1()

    assert controller.state is access.LifecycleState.A1_COLLECTED
    assert all(
        detail[0] is not access.PhaseAOperation.RECEIPT
        for name, detail in broker.calls
        if name == "helper"
    )


def test_r35_cr_m3_normal_lifecycle_cannot_fabricate_known_receipt() -> None:
    """Shared receipt parsing is not normal-lifecycle transition authority."""
    assert access.PhaseAOperation.RECEIPT.value == "receipt"
    assert "RECEIPT" not in access.LifecycleAction.__members__
    assert "AMBIGUOUS_RECEIPT" not in access.LifecycleAction.__members__
    assert "NON_PROBE_RECEIPT_COMPLETED" not in access.LifecycleState.__members__
    assert not hasattr(
        access.FullPreflightLifecycleController, "lookup_non_probe_receipt"
    )
    assert not hasattr(
        access.FullPreflightLifecycleController, "lookup_ambiguous_receipt"
    )


def test_r35_cr_m4_probe_remains_non_representable() -> None:
    """A receipt must never be manufactured by exposing device-capable PROBE."""
    assert "PROBE" not in access.PhaseAOperation.__members__
    assert "PROBE" not in access.LifecycleAction.__members__
    assert "probe" not in {operation.value for operation in access.PhaseAOperation}


def test_r35_cr_m5_pr45_preflight_success_has_no_receipt_dependency() -> None:
    """The exact normal sequence reaches A2 without a receipt operation."""
    controller, broker = _r32_advance_to_post_activation_repairs()
    controller.collect_a0()
    controller.run_p0()
    controller.collect_ap0()
    controller.run_non_probe_preflight()
    controller.collect_a1()
    controller.validate_research_final()
    controller.collect_a2()

    assert controller.state is access.LifecycleState.A2_COLLECTED
    assert [detail[0] for name, detail in broker.calls if name == "helper"] == [
        access.PhaseAOperation.AUDIT,
        access.PhaseAOperation.AUDIT,
        access.PhaseAOperation.PREFLIGHT,
        access.PhaseAOperation.AUDIT,
        access.PhaseAOperation.AUDIT,
    ]


def test_r35_fixed_point_normal_history_excludes_receipt_and_requires_full_tail() -> (
    None
):
    history = access._NORMAL_LIFECYCLE_HISTORY
    assert access.LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED in history
    assert access.LifecycleState.A1_COLLECTED in history
    assert history.index(access.LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED) + 1 == (
        history.index(access.LifecycleState.A1_COLLECTED)
    )
    assert all("RECEIPT" not in state.name for state in history)
    assert history[-1] is access.LifecycleState.POST_RESTORE_REPAIRS_PASS


def test_r35_exact_pr45_service_inventory_names_are_pinned() -> None:
    source = access._REMOTE_CONTROL_PROGRAM
    for service in (
        "phase_a_status_probe",
        "phase_a_status_probe_preflight",
        "phase_a_status_probe_receipt",
        "phase_a_status_probe_audit",
    ):
        assert repr(service) in source


def test_r35_reconstruction_preflight_ambiguity_is_recovery_only() -> None:
    first, broker = _r33_advance_to_ap0()
    broker.queue(
        "helper",
        access.PhaseAResult(
            access.PhaseAOperation.PREFLIGHT,
            78,
            "transport_ambiguous",
            "a" * 16,
        ),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        first.run_non_probe_preflight()
    first.close()

    reconstructed, second_broker = _r33_controller()
    assert reconstructed.state is access.LifecycleState.RECOVERY_REQUIRED
    assert access.LifecycleAction.PREFLIGHT in reconstructed._journal.consumed_actions
    with pytest.raises(AttributeError, match="RECOVERY_ONLY"):
        reconstructed.run_non_probe_preflight()
    assert not [call for call in second_broker.calls if call[0] == "helper"]
    reconstructed.close()


def test_r35_transfer_rejects_noncanonical_base64_before_staging(
    tmp_path: Path,
) -> None:
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    value = access._bundle_payload(candidate)
    files = value["files"]
    assert isinstance(files, list)
    files[0]["content"] = "not-base64!"

    result = _run_synthetic_remote_program(tmp_path, "transfer", value)

    assert result == {"error_class": "OPERATION_FAILED"}
    assert not (tmp_path / ".ha_tuya_ble_r30_stage").exists()


@pytest.mark.parametrize(
    "mutation",
    (
        "mandatory_receipt_reintroduced",
        "synthetic_known_receipt_accepted",
        "probe_invoked_for_receipt",
        "unknown_receipt_advances_a1",
        "failed_preflight_advances_a1",
        "preflight_replayed_after_ambiguity",
        "normal_path_requires_receipt",
    ),
)
def test_r35_mutation_contract_guards(mutation: str) -> None:
    source = inspect.getsource(access.FullPreflightLifecycleController)
    remote = access._REMOTE_CONTROL_PROGRAM
    if mutation == "mandatory_receipt_reintroduced":
        assert "RECEIPT" not in access.LifecycleAction.__members__
    elif mutation == "synthetic_known_receipt_accepted":
        assert "lookup_non_probe_receipt" not in source
        assert "_receipt_result" not in source
    elif mutation == "probe_invoked_for_receipt":
        helper = remote[
            remote.index("def invoke_helper") : remote.index("def restore_backup")
        ]
        assert "'probe'" not in helper
        assert "'receipt'" not in helper
    elif mutation == "unknown_receipt_advances_a1":
        assert access._LIFECYCLE_ACTION_PREDECESSORS[access.LifecycleAction.A1] == (
            frozenset({access.LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED})
        )
        assert "RECEIPT" not in access.LifecycleState.__members__
    elif mutation == "failed_preflight_advances_a1":
        controller, broker = _r32_controller()
        controller._state = access.LifecycleState.AP0_COLLECTED
        broker.queue(
            "helper",
            access.PhaseAResult(
                access.PhaseAOperation.PREFLIGHT,
                67,
                "schema_invalid",
                "a" * 16,
            ),
        )
        with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
            controller.run_non_probe_preflight()
        with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
            controller.collect_a1()
    elif mutation == "preflight_replayed_after_ambiguity":
        controller, broker = _r32_controller()
        controller._state = access.LifecycleState.AP0_COLLECTED
        broker.queue(
            "helper",
            access.PhaseAResult(
                access.PhaseAOperation.PREFLIGHT,
                78,
                "transport_ambiguous",
                "a" * 16,
            ),
        )
        with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
            controller.run_non_probe_preflight()
        with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
            controller.run_non_probe_preflight()
        assert len([call for call in broker.calls if call[0] == "helper"]) == 1
    elif mutation == "normal_path_requires_receipt":
        assert all(
            "RECEIPT" not in state.name for state in access._NORMAL_LIFECYCLE_HISTORY
        )
    else:  # pragma: no cover - the parameter tuple is closed above
        raise AssertionError(mutation)


def _r36_backup_payload(
    *, lifecycle_generation: str = "a" * 32, source_generation: str = "b" * 32
) -> dict[str, object]:
    return {
        "lifecycle_generation": lifecycle_generation,
        "source_generation": source_generation,
        "source_state": "PR41_BASELINE",
        "manifest": access._manifest_payload(_r30_manifest("RESTORE")),
    }


def test_r36_d_m1_missing_journal_with_anchor_never_recreates_baseline(
    tmp_path: Path,
) -> None:
    first = access._DurableLifecycleJournal()
    root = tmp_path / "lifecycle"
    anchor = access._lifecycle_anchor_path(root)
    journal = root / access._LIFECYCLE_JOURNAL_NAME
    assert anchor.is_file()
    first.close()
    journal.unlink()

    with pytest.raises(
        access.LifecycleControllerError, match="RECOVERY_REQUIRED_MISSING_JOURNAL"
    ):
        access._DurableLifecycleJournal()

    assert not journal.exists()


def test_r36_anchor_persisted_before_journal_failure_blocks_fresh_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def reject_journal(
        _journal: access._DurableLifecycleJournal, _record: dict[str, object]
    ) -> None:
        raise access.LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID")

    monkeypatch.setattr(
        access._DurableLifecycleJournal, "_write_record", reject_journal
    )
    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal()

    root = tmp_path / "lifecycle"
    assert access._lifecycle_anchor_path(root).is_file()
    assert not (root / access._LIFECYCLE_JOURNAL_NAME).exists()
    with pytest.raises(
        access.LifecycleControllerError, match="RECOVERY_REQUIRED_MISSING_JOURNAL"
    ):
        access._DurableLifecycleJournal()


def test_r36_journal_without_anchor_is_inconsistent_not_baseline(
    tmp_path: Path,
) -> None:
    journal = access._DurableLifecycleJournal()
    root = tmp_path / "lifecycle"
    access._lifecycle_anchor_path(root).unlink()
    journal.close()

    with pytest.raises(access.LifecycleControllerError, match="ANCHOR_MISSING"):
        access._DurableLifecycleJournal()


def test_r36_d_m8_journal_revision_is_exact_and_monotonic(tmp_path: Path) -> None:
    controller, _broker = _r33_controller()
    root = tmp_path / "lifecycle"
    journal = root / access._LIFECYCLE_JOURNAL_NAME
    initial = json.loads(journal.read_text(encoding="ascii"))
    assert type(initial["revision"]) is int
    assert initial["revision"] == 0

    controller.admit_initial_repairs()
    advanced = json.loads(journal.read_text(encoding="ascii"))
    assert advanced["revision"] > initial["revision"]

    rollback = dict(advanced)
    rollback["revision"] = advanced["revision"] - 1
    with pytest.raises(
        access.LifecycleControllerError, match="JOURNAL_REVISION_INVALID"
    ):
        controller._journal._write_record(rollback)
    controller.close()


@pytest.mark.parametrize("error_number", (28, 5, 30))
def test_r36_journal_write_errors_never_advance_authoritative_revision(
    error_number: int, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal = access._DurableLifecycleJournal()
    root = tmp_path / "lifecycle"
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    before = json.loads(journal_path.read_text(encoding="ascii"))

    def fail_write(_descriptor: int, _payload: bytes) -> int:
        raise OSError(error_number, "synthetic persistence failure")

    monkeypatch.setattr(os, "write", fail_write)
    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        journal.record_intent(
            access.LifecycleAction.INITIAL_REPAIRS,
            source_generation=journal.source_generation,
            nonce=None,
        )

    after = json.loads(journal_path.read_text(encoding="ascii"))
    assert after == before
    journal.close()


@pytest.mark.parametrize("failure", ("file_fsync", "dir_fsync", "replace"))
def test_r36_journal_publish_failures_never_report_durable_transition(
    failure: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal = access._DurableLifecycleJournal()
    root = tmp_path / "lifecycle"
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    before = json.loads(journal_path.read_text(encoding="ascii"))
    if failure == "replace":
        monkeypatch.setattr(
            os,
            "replace",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError(5, "synthetic replace failure")
            ),
        )
    else:
        real_fsync = os.fsync

        def fail_fsync(descriptor: int) -> None:
            if failure == "dir_fsync" and descriptor == journal._root_fd:
                raise OSError(5, "synthetic directory fsync failure")
            if failure == "file_fsync" and descriptor != journal._root_fd:
                raise OSError(5, "synthetic file fsync failure")
            real_fsync(descriptor)

        monkeypatch.setattr(os, "fsync", fail_fsync)

    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        journal.record_intent(
            access.LifecycleAction.INITIAL_REPAIRS,
            source_generation=journal.source_generation,
            nonce=None,
        )

    after = json.loads(journal_path.read_text(encoding="ascii"))
    if failure == "dir_fsync":
        assert after["revision"] == before["revision"] + 1
    else:
        assert after == before
    assert journal._record["revision"] == before["revision"]
    journal.close()


def test_r36_verified_backup_identity_is_bound_in_journal_and_anchor(
    tmp_path: Path,
) -> None:
    controller, _broker = _r33_controller()
    _candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    result = controller.create_backup(restore.manifest)
    root = tmp_path / "lifecycle"
    journal = json.loads(
        (root / access._LIFECYCLE_JOURNAL_NAME).read_text(encoding="ascii")
    )
    anchor = json.loads(access._lifecycle_anchor_path(root).read_text(encoding="ascii"))

    assert journal["baseline_backup_identity"] == anchor["baseline_backup_identity"]
    assert journal["baseline_backup_identity"] == {
        "lifecycle_generation": result.lifecycle_generation,
        "source_generation": result.source_generation,
        "pr41_commit": access.PR41_RESTORE_COMMIT,
        "pr41_tree": access.PR41_RESTORE_TREE,
        "backup_generation": result.backup_generation,
        "manifest_identity": result.manifest_identity,
        "backup_digest": result.backup_digest,
    }
    assert anchor["root_revision"] == journal["revision"]
    controller.close()


def test_r36_d_m2_candidate_content_cannot_become_pr41_backup(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic candidate source\n")

    result = _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())

    assert result == {"error_class": "OPERATION_FAILED"}
    assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()


def test_r36_second_or_post_candidate_backup_is_rejected_before_dispatch() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)

    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        controller.create_backup(restore.manifest)

    assert [name for name, _detail in broker.calls].count("backup") == 1
    controller.close()


def test_r36_d_m3_to_m5_backup_is_one_bound_atomic_package(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    content = b"synthetic integration source\n"
    (integration / "__init__.py").write_bytes(content)
    first_payload = _r36_backup_payload()

    created = _run_synthetic_remote_program(tmp_path, "backup", first_payload)
    package = tmp_path / ".ha_tuya_ble_r36_backup"
    metadata_path = package / "metadata.json"
    assert created["success"] is True
    assert package.is_dir()
    assert metadata_path.is_file()
    metadata = json.loads(metadata_path.read_text(encoding="ascii"))
    assert metadata["lifecycle_generation"] == first_payload["lifecycle_generation"]
    assert metadata["source_generation"] == first_payload["source_generation"]
    assert metadata["pr41_commit"] == access.PR41_RESTORE_COMMIT
    assert metadata["pr41_tree"] == access.PR41_RESTORE_TREE
    before = {
        path.relative_to(package).as_posix(): path.read_bytes()
        for path in package.rglob("*")
        if path.is_file()
    }

    repeated = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(lifecycle_generation="c" * 32),
    )

    assert repeated == {"error_class": "OPERATION_FAILED"}
    assert before == {
        path.relative_to(package).as_posix(): path.read_bytes()
        for path in package.rglob("*")
        if path.is_file()
    }
    assert not (tmp_path / ".ha_tuya_ble_r30_backup.identity").exists()


def test_r36_m21_foreign_lifecycle_backup_package_is_rejected(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    for root in (first_root, second_root):
        integration = root / "custom_components" / "tuya_ble"
        integration.mkdir(parents=True)
        (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    assert _run_synthetic_remote_program(
        first_root,
        "backup",
        _r36_backup_payload(lifecycle_generation="a" * 32),
    )["manifest_match"]
    shutil.copytree(
        first_root / ".ha_tuya_ble_r36_backup",
        second_root / ".ha_tuya_ble_r36_backup",
    )

    rejected = _run_synthetic_remote_program(
        second_root,
        "restore_backup",
        _r36_backup_payload(lifecycle_generation="c" * 32),
    )

    assert rejected == {"error_class": "OPERATION_FAILED"}
    assert not (second_root / ".ha_tuya_ble_r36_backup.consumed").exists()


@pytest.mark.parametrize("authority_field", ("authority_commit", "authority_tree"))
def test_r36_backup_rejects_altered_pr41_authority_before_publication(
    authority_field: str, tmp_path: Path
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    payload = _r36_backup_payload()
    payload["manifest"][authority_field] = "0" * 40

    result = _run_synthetic_remote_program(tmp_path, "backup", payload)

    assert result == {"error_class": "OPERATION_FAILED"}
    assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()


def test_r36_backup_tamper_is_rejected_without_consuming_package(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    payload = _r36_backup_payload()
    assert _run_synthetic_remote_program(tmp_path, "backup", payload)["manifest_match"]
    backed_up = tmp_path / ".ha_tuya_ble_r36_backup" / "integration" / "__init__.py"
    backed_up.write_bytes(b"synthetic altered backup source\n")

    result = _run_synthetic_remote_program(tmp_path, "restore_backup", payload)

    assert result == {"error_class": "OPERATION_FAILED"}
    assert not (tmp_path / ".ha_tuya_ble_r36_backup.consumed").exists()


def test_r36_restore_requires_exact_journal_bound_backup_generation_and_digest(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    payload = _r36_backup_payload()
    created = _run_synthetic_remote_program(tmp_path, "backup", payload)
    bound = {
        **payload,
        "backup_generation": created["backup_generation"],
        "manifest_identity": created["manifest_identity"],
        "backup_digest": created["backup_digest"],
    }
    metadata_path = tmp_path / ".ha_tuya_ble_r36_backup" / "metadata.json"
    replacement = json.loads(metadata_path.read_text(encoding="ascii"))
    replacement["backup_generation"] = "e" * 32
    unsigned = {
        key: value for key, value in replacement.items() if key != "backup_digest"
    }
    replacement["backup_digest"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    metadata_path.write_text(
        json.dumps(replacement, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )

    result = _run_synthetic_remote_program(tmp_path, "restore_backup", bound)

    assert result == {"error_class": "OPERATION_FAILED"}
    assert not (tmp_path / ".ha_tuya_ble_r36_backup.consumed").exists()


@pytest.mark.parametrize("crash_point", ("before_publish", "after_publish"))
def test_r36_backup_publication_crash_has_no_split_identity_state(
    crash_point: str, tmp_path: Path
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    injection = {
        "before_publish": (
            "        package_fd = publish_noreplace(pending, BACKUP, pending_fd)\n",
            "        os._exit(91)\n",
            91,
        ),
        "after_publish": (
            "        package_fd = publish_noreplace(pending, BACKUP, pending_fd)\n",
            (
                "        package_fd = publish_noreplace(pending, BACKUP, pending_fd)\n"
                "        os._exit(92)\n"
            ),
            92,
        ),
    }[crash_point]

    _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={injection[0]: injection[1]},
        expected_crash_code=injection[2],
    )
    package = tmp_path / ".ha_tuya_ble_r36_backup"

    if crash_point == "before_publish":
        assert not package.exists()
    else:
        assert (package / "metadata.json").is_file()
        assert _run_synthetic_remote_program(
            tmp_path, "backup", _r36_backup_payload()
        ) == {"error_class": "OPERATION_FAILED"}


def test_r36_backup_rejects_pending_swap_after_bound_recursive_fsync(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")

    failed = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={
            "        synced_inodes = sync_directory_fd(pending_fd)\n"
            "        if read_backup_identity_fd(value, pending_fd) != metadata:\n": (
                "        synced_inodes = sync_directory_fd(pending_fd)\n"
                "        moved = pending.with_name(pending.name + '.swapped')\n"
                "        pending.rename(moved)\n"
                "        shutil.copytree(moved, pending)\n"
                "        if read_backup_identity_fd(value, pending_fd) != metadata:\n"
            )
        },
    )

    assert failed == {"error_class": "OPERATION_FAILED"}
    assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()


def test_r36_backup_rejects_child_swap_after_bound_recursive_fsync(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")

    failed = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={
            "        synced_inodes = sync_directory_fd(pending_fd)\n"
            "        if read_backup_identity_fd(value, pending_fd) != metadata:\n": (
                "        synced_inodes = sync_directory_fd(pending_fd)\n"
                "        child = pending / 'integration'\n"
                "        moved = pending / 'integration.swapped'\n"
                "        child.rename(moved)\n"
                "        shutil.copytree(moved, child)\n"
                "        if read_backup_identity_fd(value, pending_fd) != metadata:\n"
            )
        },
    )

    assert failed == {"error_class": "OPERATION_FAILED"}


@pytest.mark.parametrize(
    ("source_replacements", "published"),
    (
        (
            {
                "        synced_inodes = sync_directory_fd(pending_fd)\n": (
                    "        raise OSError(5, 'synthetic file fsync')\n"
                )
            },
            False,
        ),
        (
            {
                "def sync_root():\n": (
                    "def sync_root():\n"
                    "    raise OSError(30, 'synthetic directory fsync')\n"
                )
            },
            True,
        ),
        (
            {
                "def publish_noreplace(source, destination, source_fd):\n": (
                    "def publish_noreplace(source, destination, source_fd):\n"
                    "    raise OSError(5, 'synthetic rename failure')\n"
                )
            },
            False,
        ),
    ),
)
def test_r36_backup_persistence_failures_never_publish_success(
    source_replacements: dict[str, str], published: bool, tmp_path: Path
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")

    result = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements=source_replacements,
    )

    assert result == {"error_class": "OPERATION_FAILED"}
    package = tmp_path / ".ha_tuya_ble_r36_backup"
    assert package.exists() is published
    if published:
        assert (
            _run_synthetic_remote_program(
                tmp_path, "reconcile_backup_creation", _r36_backup_payload()
            )["success"]
            is True
        )


def test_r36_backup_metadata_short_writes_are_completed_before_publication(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    short_write = (
        "written = os.write(\n"
        "                    descriptor,\n"
        "                    payload[offset : offset + max(1, (len(payload) - offset) // 2)],\n"
        "                )"
    )

    result = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={
            "written = os.write(descriptor, payload[offset:])": short_write
        },
    )

    assert result["success"] is True
    assert (
        _run_synthetic_remote_program(
            tmp_path, "reconcile_backup_creation", _r36_backup_payload()
        )["success"]
        is True
    )


def test_r36_published_backup_result_loss_is_read_only_reconcilable(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    payload = _r36_backup_payload()
    _run_synthetic_remote_program(
        tmp_path,
        "backup",
        payload,
        source_replacements={
            "        package_fd = publish_noreplace(pending, BACKUP, pending_fd)\n": (
                "        package_fd = publish_noreplace(pending, BACKUP, pending_fd)\n"
                "        os._exit(92)\n"
            )
        },
        expected_crash_code=92,
    )

    reconciled = _run_synthetic_remote_program(
        tmp_path, "reconcile_backup_creation", payload
    )

    assert reconciled["success"] is True
    assert reconciled["lifecycle_generation"] == payload["lifecycle_generation"]
    assert reconciled["source_generation"] == payload["source_generation"]
    assert (tmp_path / ".ha_tuya_ble_r36_backup" / "metadata.json").is_file()


def test_r36_controller_adopts_published_backup_after_lost_result() -> None:
    controller, broker = _r33_controller()
    _candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    broker.queue(
        "backup",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="BACKUP_VERIFICATION"):
        controller.create_backup(restore.manifest)
    controller.close()

    reconstructed, reconstructed_broker = _r33_controller()
    assert reconstructed.state is access.LifecycleState.RECOVERY_REQUIRED
    result = reconstructed.reconcile_backup_creation(restore.manifest)

    assert result.success is True
    assert reconstructed.state is access.LifecycleState.BACKUP_VERIFIED
    assert reconstructed._journal.recovery_mode is False
    assert reconstructed._journal._record["baseline_backup_identity"] is not None
    assert [name for name, _ in reconstructed_broker.calls] == [
        "backup_creation_reconcile"
    ]
    reconstructed.close()


def test_r36_d_m6_open_root_fd_remains_authority_after_path_swap(
    tmp_path: Path,
) -> None:
    journal = access._DurableLifecycleJournal()
    root = tmp_path / "lifecycle"
    moved = tmp_path / "original-lifecycle"
    root.rename(moved)
    root.mkdir(mode=0o700)

    with pytest.raises(
        access.LifecycleControllerError, match="ANCHOR_INVALID|MISSING_JOURNAL"
    ):
        access._DurableLifecycleJournal()
    assert not (root / access._LIFECYCLE_JOURNAL_NAME).exists()

    journal.record_intent(
        access.LifecycleAction.INITIAL_REPAIRS,
        source_generation=journal.source_generation,
        nonce=None,
    )

    original = json.loads(
        (moved / access._LIFECYCLE_JOURNAL_NAME).read_text(encoding="ascii")
    )
    assert original["consumed_operations"] == [
        access.LifecycleAction.INITIAL_REPAIRS.value
    ]
    assert not (root / access._LIFECYCLE_JOURNAL_NAME).exists()
    journal.close()


def test_r36_open_parent_and_root_fds_survive_parent_path_replacement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parent = tmp_path / "state-parent"
    root = parent / "lifecycle"
    monkeypatch.setattr(access, "_LIFECYCLE_STATE_ROOT", root)
    journal = access._DurableLifecycleJournal()
    moved_parent = tmp_path / "retained-parent"
    parent.rename(moved_parent)
    parent.mkdir(mode=0o700)
    (parent / "lifecycle").mkdir(mode=0o700)

    journal.record_intent(
        access.LifecycleAction.INITIAL_REPAIRS,
        source_generation=journal.source_generation,
        nonce=None,
    )

    retained = json.loads(
        (moved_parent / "lifecycle" / access._LIFECYCLE_JOURNAL_NAME).read_text(
            encoding="ascii"
        )
    )
    assert retained["operations"][-1]["action"] == "initial_repairs"
    assert not (parent / "lifecycle" / access._LIFECYCLE_JOURNAL_NAME).exists()
    journal.close()


@pytest.mark.parametrize(
    "critical_name",
    (access._LIFECYCLE_LOCK_NAME, access._LIFECYCLE_JOURNAL_NAME),
)
def test_r36_stable_root_rejects_lock_and_journal_symlinks(
    critical_name: str, tmp_path: Path
) -> None:
    root = tmp_path / "lifecycle"
    root.mkdir(mode=0o700)
    target = tmp_path / "synthetic-target"
    target.write_text("synthetic\n", encoding="ascii")
    (root / critical_name).symlink_to(target)

    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal()


def test_r36_failed_lock_admission_releases_stable_root_owner(
    tmp_path: Path,
) -> None:
    root = tmp_path / "lifecycle"
    root.mkdir(mode=0o700)
    target = tmp_path / "synthetic-target"
    target.write_text("synthetic\n", encoding="ascii")
    lock = root / access._LIFECYCLE_LOCK_NAME
    lock.symlink_to(target)

    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal()

    lock.unlink()
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    journal = access._DurableLifecycleJournal()
    journal.close()


def test_r36_constructor_cleanup_closes_root_when_unlock_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "lifecycle"
    root.mkdir(mode=0o700)
    target = tmp_path / "synthetic-target"
    target.write_text("synthetic\n", encoding="ascii")
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    journal_path.symlink_to(target)
    real_flock = access.fcntl.flock

    def interrupt_unlock(descriptor: int, operation: int) -> None:
        if operation == access.fcntl.LOCK_UN:
            raise InterruptedError("synthetic unlock interruption")
        real_flock(descriptor, operation)

    monkeypatch.setattr(access.fcntl, "flock", interrupt_unlock)
    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal()

    monkeypatch.setattr(access.fcntl, "flock", real_flock)
    journal_path.unlink()
    journal = access._DurableLifecycleJournal()
    journal.close()


@pytest.mark.parametrize("critical_name", ("lock", "anchor"))
def test_r36_regular_open_closes_descriptor_when_fstat_fails(
    critical_name: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "lifecycle"
    root.mkdir(mode=0o700)
    expected_name = access._LIFECYCLE_LOCK_NAME
    cleanup_path: Path | None = None
    if critical_name == "anchor":
        cleanup_path = access._lifecycle_anchor_path(root)
        cleanup_path.write_text("{}", encoding="ascii")
        cleanup_path.chmod(0o600)
        expected_name = cleanup_path.name
    real_open = access.os.open
    real_fstat = access.os.fstat
    opened: list[int] = []

    def track_open(path: object, *args: object, **kwargs: object) -> int:
        descriptor = real_open(path, *args, **kwargs)
        if path == expected_name:
            opened.append(descriptor)
        return descriptor

    def fail_target_fstat(descriptor: int) -> os.stat_result:
        if opened and descriptor == opened[-1]:
            raise OSError(access.errno.EIO, "synthetic fstat failure")
        return real_fstat(descriptor)

    monkeypatch.setattr(access.os, "open", track_open)
    monkeypatch.setattr(access.os, "fstat", fail_target_fstat)
    with pytest.raises(access.LifecycleControllerError):
        access._DurableLifecycleJournal()

    assert opened
    with pytest.raises(OSError, match="Bad file descriptor"):
        real_fstat(opened[-1])
    monkeypatch.setattr(access.os, "open", real_open)
    monkeypatch.setattr(access.os, "fstat", real_fstat)
    if cleanup_path is not None:
        cleanup_path.unlink()
    journal = access._DurableLifecycleJournal()
    journal.close()


def test_r36_replacing_locked_filename_cannot_create_second_owner(
    tmp_path: Path,
) -> None:
    first = access._DurableLifecycleJournal()
    root = tmp_path / "lifecycle"
    lock = root / access._LIFECYCLE_LOCK_NAME
    lock.unlink()
    replacement = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(replacement)

    with pytest.raises(access.LifecycleControllerError, match="OWNER_ACTIVE"):
        access._DurableLifecycleJournal()

    first.record_intent(
        access.LifecycleAction.INITIAL_REPAIRS,
        source_generation=first.source_generation,
        nonce=None,
    )
    first.close()


@pytest.mark.parametrize(
    "operation_label",
    (
        "lifecycle_ownership",
        "backup_creation",
        "candidate_install",
        "activation_restart",
        "preflight",
        "restore",
        "removal_restart",
    ),
)
def test_r36_eight_process_contention_has_one_authoritative_owner(
    operation_label: str, tmp_path: Path
) -> None:
    root = tmp_path / operation_label
    start_at = time.time() + 0.75
    script = """
import pathlib
import sys
import time
from tools import home_assistant_live_access as access
access._LIFECYCLE_STATE_ROOT = pathlib.Path(sys.argv[1])
deadline = float(sys.argv[2])
while time.time() < deadline:
    pass
try:
    journal = access._DurableLifecycleJournal()
except access.LifecycleControllerError:
    raise SystemExit(0)
print('OWNER', flush=True)
time.sleep(0.5)
journal.close()
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(root), str(start_at)],
            cwd=Path(access.__file__).parent.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(8)
    ]
    completed = [process.communicate(timeout=5) for process in processes]

    assert sum(stdout == "OWNER\n" for stdout, _stderr in completed) == 1
    assert all(process.returncode == 0 for process in processes)
    assert all(stderr == "" for _stdout, stderr in completed)
    source = inspect.getsource(access._DurableLifecycleJournal.__init__)
    assert source.index("self._acquire_lock()") < source.index("self._read_anchor()")
    assert source.index("self._acquire_lock()") < source.index("self._read_record()")


def test_r36_d_m7_fallback_lost_result_has_monotonic_reconciliation_state() -> None:
    assert {
        "AVAILABLE",
        "INTENT_DURABLE",
        "DISPATCH_POSSIBLE",
        "RECONCILIATION_REQUIRED",
        "RECONCILED_PR41",
        "RECONCILED_CANDIDATE",
        "RECONCILED_UNKNOWN",
    } <= set(access.FallbackPhase.__members__)
    assert access._FALLBACK_PHASE_SUCCESSORS[
        access.FallbackPhase.RECONCILIATION_REQUIRED
    ] == frozenset(
        {
            access.FallbackPhase.RECONCILED_PR41,
            access.FallbackPhase.RECONCILED_CANDIDATE,
            access.FallbackPhase.RECONCILED_UNKNOWN,
        }
    )


def test_r36_d_m7_lost_reconciliation_result_resumes_same_bounded_action() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    broker.queue(
        "backup_fallback",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.restore_private_backup_fallback(restore.manifest)
    broker.queue(
        "backup_reconcile",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.reconcile_private_backup_fallback(restore.manifest)
    controller.close()

    reconstructed, reconstructed_broker = _r33_controller()
    result = reconstructed.reconcile_private_backup_fallback(restore.manifest)

    assert result.phase == "reconciled"
    assert reconstructed._journal._record["fallback_phase"] == "reconciled"
    assert reconstructed._journal._record["fallback_reconciliation_attempts"] == 2
    assert [
        item["action"] for item in reconstructed._journal._record["operations"]
    ].count(access.LifecycleAction.BACKUP_FALLBACK_RECONCILE.value) == 1
    assert [name for name, _ in reconstructed_broker.calls] == ["backup_reconcile"]
    reconstructed.close()


def test_r36_reconciliation_result_and_continuation_are_one_journal_commit() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    broker.queue(
        "backup_fallback",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.restore_private_backup_fallback(restore.manifest)

    result = controller.reconcile_private_backup_fallback(restore.manifest)

    assert result.phase == "reconciled"
    assert controller.state is access.LifecycleState.PR41_RESTORED
    assert (
        controller._journal._record["operations"][-1]["phase"] == "transition_committed"
    )
    controller.close()
    reconstructed, reconstructed_broker = _r33_controller()
    assert reconstructed.state is access.LifecycleState.PR41_RESTORED
    assert reconstructed_broker.calls == []
    reconstructed.close()


def test_r36_fallback_reconciliation_exact_candidate_routes_to_primary_restore() -> (
    None
):
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    broker.queue(
        "backup_fallback",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.restore_private_backup_fallback(restore.manifest)
    broker.queue(
        "backup_reconcile",
        access.FallbackReconciliationResult(
            "reconciled_candidate", False, False, len(candidate.manifest.entries)
        ),
    )

    result = controller.reconcile_private_backup_fallback(restore.manifest)

    assert result.phase == "reconciled_candidate"
    assert controller.state is access.LifecycleState.ROLLBACK_REQUIRED
    assert (
        controller._journal._record["fallback_phase"]
        == access.FallbackPhase.RECONCILED_CANDIDATE.value
    )
    assert not controller._permits[access.LifecycleAction.RESTORE_TRANSFER].consumed
    controller.stage_restore(restore)
    assert controller.state is access.LifecycleState.RESTORE_STAGED
    controller.close()


def test_r36_fallback_reconciliation_unknown_is_distinct_retained_terminal() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 4, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    broker.queue(
        "backup_fallback",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.restore_private_backup_fallback(restore.manifest)
    broker.queue(
        "backup_reconcile",
        access.FallbackReconciliationResult("reconciled_unknown", False, False, 0),
    )

    result = controller.reconcile_private_backup_fallback(restore.manifest)

    assert result.phase == "reconciled_unknown"
    assert controller.state is access.LifecycleState.MANUAL_RECOVERY_REQUIRED
    root = access._LIFECYCLE_STATE_ROOT
    record = json.loads(
        (root / access._LIFECYCLE_JOURNAL_NAME).read_text(encoding="ascii")
    )
    assert record["terminal"] == access.LifecycleState.MANUAL_RECOVERY_REQUIRED.value
    assert record["fallback_phase"] == access.FallbackPhase.RECONCILED_UNKNOWN.value
    with pytest.raises(access.LifecycleControllerError, match="TERMINAL_RETAINED"):
        access._DurableLifecycleJournal()


def test_r36_m27_older_valid_journal_is_rejected_by_anchor_revision(
    tmp_path: Path,
) -> None:
    journal = access._DurableLifecycleJournal()
    root = tmp_path / "lifecycle"
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    old = journal_path.read_bytes()
    journal.record_intent(
        access.LifecycleAction.INITIAL_REPAIRS,
        source_generation=journal.source_generation,
        nonce=None,
    )
    journal.close()
    journal_path.write_bytes(old)
    journal_path.chmod(0o600)

    with pytest.raises(access.LifecycleControllerError, match="REVISION_INVALID"):
        access._DurableLifecycleJournal()


def test_r36_m28_deleted_terminal_journal_never_reopens_baseline() -> None:
    controller, _broker = _r33_drive_complete_research()
    _candidate, restore = _r32_bundles()
    _r32_complete_restore_tail(controller, restore)
    root = access._LIFECYCLE_STATE_ROOT
    assert root is not None
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    assert anchor_path.is_file()
    journal_path.unlink()

    with pytest.raises(
        access.LifecycleControllerError, match="RECOVERY_REQUIRED_MISSING_JOURNAL"
    ):
        access._DurableLifecycleJournal()

    assert not journal_path.exists()


_R36_LEDGER_DETECTOR_INVENTORY = {
    1: "test_r36_journal_publish_failures_never_report_durable_transition[file_fsync]",
    2: "test_r36_journal_publish_failures_never_report_durable_transition[dir_fsync]",
    3: "test_r36_eight_process_contention_has_one_authoritative_owner[lifecycle_ownership]",
    4: "test_r36_eight_process_contention_has_one_authoritative_owner[backup_creation]",
    5: "test_r33_malformed_or_duplicate_key_journal_fails_closed",
    6: "test_r33_r_m1_helper_submission_survives_reconstruction",
    7: "test_r33_r_m6_removal_restart_cannot_replay_after_loss",
    8: "test_r33_every_submission_phase_reconstructs_as_recovery",
    9: "test_r36_d_m7_fallback_lost_result_has_monotonic_reconciliation_state",
    10: "test_r33_stale_evidence_matrix_rejects_new_lifecycle_source_and_session",
    11: "test_r33_red_recovery_restore_has_distinct_terminal",
    12: "test_r33_journal_is_owner_private_atomic_and_strictly_versioned",
    13: "test_r36_second_or_post_candidate_backup_is_rejected_before_dispatch",
    14: "test_r36_second_or_post_candidate_backup_is_rejected_before_dispatch",
    15: "test_r36_d_m3_to_m5_backup_is_one_bound_atomic_package",
    16: "test_r36_verified_backup_identity_is_bound_in_journal_and_anchor",
    17: "test_r35_reconstruction_preflight_ambiguity_is_recovery_only",
    18: "test_r35_fixed_point_normal_history_excludes_receipt_and_requires_full_tail",
    19: "test_r36_d_m1_missing_journal_with_anchor_never_recreates_baseline",
    20: "test_r36_d_m2_candidate_content_cannot_become_pr41_backup",
    21: "test_r36_m21_foreign_lifecycle_backup_package_is_rejected",
    22: "test_r36_backup_publication_crash_has_no_split_identity_state[before_publish]",
    23: "test_r36_d_m3_to_m5_backup_is_one_bound_atomic_package",
    24: "test_r36_d_m6_open_root_fd_remains_authority_after_path_swap",
    25: "test_r36_d_m7_lost_reconciliation_result_resumes_same_bounded_action",
    26: "test_r36_d_m8_journal_revision_is_exact_and_monotonic",
    27: "test_r36_m27_older_valid_journal_is_rejected_by_anchor_revision",
    28: "test_r36_m28_deleted_terminal_journal_never_reopens_baseline",
}


def test_r36_combined_ledger_detector_inventory_is_complete() -> None:
    """Inventory detector coverage; this is not source-mutant execution evidence."""
    assert tuple(_R36_LEDGER_DETECTOR_INVENTORY) == tuple(range(1, 29))
    for detector in _R36_LEDGER_DETECTOR_INVENTORY.values():
        function_name = detector.partition("[")[0]
        assert function_name in globals(), detector
        assert callable(globals()[function_name]), detector
