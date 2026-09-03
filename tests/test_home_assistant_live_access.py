"""Synthetic regressions for the local-only Home Assistant access helper."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import http.client
import inspect
import io
import json
import os
import pty
import select
import shutil
import stat
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, asdict, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import pytest_socket

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
            (
                "test_r33_",
                "test_r35_reconstruction_",
                "test_r36_",
                "test_r44_",
                "test_r47_",
                "test_r50_",
                "test_r57_",
                "test_r59_",
                "test_r61_",
                "test_r62_",
                "test_r62c_",
                "test_r62f_",
                "test_r63s_",
                "test_r63t_",
                "test_r65_",
                "test_r65e_",
                "test_r65g_",
                "test_r65h_",
                "test_r66a_",
            )
        ),
    )
    if not request.node.name.startswith(
        (
            "test_r30_",
            "test_r32_",
            "test_r33_",
            "test_r35_",
            "test_r36_",
            "test_r44_",
            "test_r47_",
            "test_r50_",
            "test_r53_",
            "test_r55_",
            "test_r56_",
            "test_r57_",
            "test_r59_",
            "test_r61_",
            "test_r62_",
            "test_r62c_",
            "test_r62f_",
            "test_r63s_",
            "test_r63t_",
        )
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
        "inspect_retained_backup",
        "retire_retained_backup",
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
        "c1599dcd1cdc1201cd320c316059159a1948d5f58d4bdaa4c64ea3c4a0390075",
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
            "observed_managed_count": 3,
            "manifest_match": False,
            "unexpected_count": 1,
            "missing_count": 1,
            "content_mismatch_count": 0,
            "runtime_cache_file_count": 0,
            "managed_manifest_identity": "a" * 64,
            "root_profile": "DIRECT_CONFIG",
        }
    )

    assert result.manifest_match is False
    assert result.unexpected_count == 1
    assert result.missing_count == 1

    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_source_inventory_result(
            {
                "expected_count": 3,
                "observed_managed_count": 2,
                "manifest_match": True,
                "unexpected_count": 0,
                "missing_count": 1,
                "content_mismatch_count": 0,
                "runtime_cache_file_count": 0,
                "managed_manifest_identity": "a" * 64,
                "root_profile": "DIRECT_CONFIG",
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
        {"http_status": 200, "result": "ok"},
        attempt_ordinal=2,
    )

    assert result == access.CoreCheckResult(
        2,
        200,
        "ok",
        True,
        None,
        access.CoreCheckResponseContract.CURRENT_RESULT_OK,
    )


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
        return (
            b'{"dispatch_outcome":"RESPONSE_ACCEPTED","http_status":200,'
            b'"failure_reason":null}'
        )

    monkeypatch.setattr(
        broker, "_PrivateInteractiveSessionBroker__execute_bounded_operation", execute
    )
    capability = _r32_controller_minted_capability(
        broker, access.LifecycleAction.ACTIVATION_RESTART
    )

    assert broker._restart_core(_capability=capability).response_accepted is True
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
    assert "phase_a_status_probe_helper.py" in source
    assert "elif operation == 'probe'" not in source
    assert "elif operation == 'remote_phase_a_inventory'" in source
    assert '"probe"' not in source
    assert "arbitrary" not in source
    assert "renameat2" in source
    assert "RENAME_EXCHANGE" not in source or "2" in source
    assert "api/config" in source
    assert "loaded = bool(SERVICES" not in source
    helper_start = source.index("def invoke_helper")
    helper_end = source.index("def research_evidence_path")
    helper_source = source[helper_start:helper_end]
    assert "operation not in {'preflight', 'audit'}" in helper_source
    assert "'probe'" not in helper_source
    restart_start = source.index("def restart_core")
    restart_end = source.index("def service_names")
    restart_source = source[restart_start:restart_end]
    assert restart_source.count("http.client.HTTPConnection") == 1
    assert "connection.connect()" in restart_source
    assert "connection.endheaders()" in restart_source
    assert "connection.getresponse()" in restart_source
    compile(source, "<synthetic-r30-remote-program>", "exec")


def _r59_remote_program(source: str) -> str:
    """Extract the embedded remote control program without its CLI dispatch."""
    if source.lstrip().startswith("import base64"):
        return source[: source.index("operation = sys.argv[1]")]
    tree = ast.parse(source)
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_REMOTE_CONTROL_PROGRAM"
            for target in node.targets
        )
    )
    program = ast.literal_eval(assignment.value)
    assert isinstance(program, str)
    return program[: program.index("operation = sys.argv[1]")]


@contextmanager
def _r59_delayed_restart_server() -> (
    Generator[tuple[ThreadingHTTPServer, threading.Event, threading.Event]]
):
    """Serve one complete POST while deliberately withholding its response."""
    received = threading.Event()
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            assert self.path == "/core/restart"
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received.set()
            release.wait(2)
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"result":"ok","data":{}}')
            except BrokenPipeError:
                pass

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, received, release
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def _r59_exact_parent_source() -> str | None:
    """Return the pinned RED baseline only when this checkout contains it."""
    result = subprocess.run(
        [
            "git",
            "show",
            "557ac0bc83a52ac70344e85233603984de1c1ae0:tools/home_assistant_live_access.py",
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def test_r59_response_loss_dispatch_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R2: a current full POST can time out only after it was dispatched."""
    pytest_socket.enable_socket()
    monkeypatch.setenv("SUPERVISOR_TOKEN", "synthetic-r59-token")
    try:
        with _r59_delayed_restart_server() as (server, received, _release):
            current_namespace: dict[str, object] = {"__name__": "r59_candidate_repro"}
            exec(  # noqa: S102 - execute the candidate embedded transport in isolation
                compile(
                    _r59_remote_program(access._REMOTE_CONTROL_PROGRAM),
                    "<r59-candidate>",
                    "exec",
                ),
                current_namespace,
            )
            current_namespace["RESTART_RESPONSE_TIMEOUT_SECONDS"] = 0.05
            original_connection = http.client.HTTPConnection
            current_namespace["http"].client.HTTPConnection = (  # type: ignore[index,union-attr]
                lambda _host, timeout=None: original_connection(
                    "127.0.0.1", server.server_port, timeout=timeout
                )
            )
            try:
                assert current_namespace["restart_core"]() == {
                    "dispatch_outcome": "DISPATCHED_RESPONSE_UNKNOWN",
                    "http_status": None,
                    "failure_reason": "RESPONSE_TIMEOUT",
                }
                assert received.wait(1)
            finally:
                current_namespace["http"].client.HTTPConnection = original_connection  # type: ignore[index,union-attr]
    finally:
        pytest_socket.disable_socket()


def test_r59_parent_red_and_response_loss_dispatch_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R1: preserve the exact parent RED reproduction when history is present."""
    parent_source = _r59_exact_parent_source()
    if parent_source is None:
        pytest.skip("R59 exact historical parent is unavailable in this checkout")

    pytest_socket.enable_socket()
    try:
        with _r59_delayed_restart_server() as (server, received, _release):
            endpoint = f"http://127.0.0.1:{server.server_port}"
            monkeypatch.setenv("SUPERVISOR_TOKEN", "synthetic-r59-token")
            parent_program = (
                _r59_remote_program(parent_source)
                .replace("http://supervisor", endpoint)
                .replace("timeout=30", "timeout=0.05")
            )
            parent_namespace: dict[str, object] = {"__name__": "r59_parent_repro"}
            exec(  # noqa: S102 - execute the pinned parent transport in this test only
                compile(parent_program, "<r59-exact-parent>", "exec"), parent_namespace
            )
            assert parent_namespace["restart_core"]() == {
                "submitted": False,
                "accepted": False,
            }
            assert received.wait(1)
    finally:
        pytest_socket.disable_socket()


def test_r60_delayed_restart_server_cleanup_on_error() -> None:
    """The synthetic server is closed even when its owning test raises."""
    pytest_socket.enable_socket()
    try:
        with (
            pytest.raises(RuntimeError, match="synthetic-r60-error"),
            _r59_delayed_restart_server(),
        ):
            raise RuntimeError("synthetic-r60-error")
    finally:
        pytest_socket.disable_socket()


@pytest.mark.parametrize(
    ("payload", "outcome"),
    (
        (
            {
                "dispatch_outcome": "RESPONSE_ACCEPTED",
                "http_status": 200,
                "failure_reason": None,
            },
            access.RestartDispatchOutcome.RESPONSE_ACCEPTED,
        ),
        (
            {
                "dispatch_outcome": "RESPONSE_REJECTED",
                "http_status": 503,
                "failure_reason": "HTTP_REJECTED",
            },
            access.RestartDispatchOutcome.RESPONSE_REJECTED,
        ),
        (
            {
                "dispatch_outcome": "DEFINITELY_NOT_DISPATCHED",
                "http_status": None,
                "failure_reason": "CONNECT_FAILED",
            },
            access.RestartDispatchOutcome.DEFINITELY_NOT_DISPATCHED,
        ),
        (
            {
                "dispatch_outcome": "DISPATCHED_RESPONSE_UNKNOWN",
                "http_status": None,
                "failure_reason": "RESPONSE_CLOSED",
            },
            access.RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
        ),
    ),
)
def test_r59_restart_results_are_fixed_and_private_data_free(
    payload: dict[str, object], outcome: access.RestartDispatchOutcome
) -> None:
    """R3-R8/R18: each transport class has one bounded representation."""
    result = access._parse_restart_result(payload)

    assert result.dispatch_outcome is outcome
    assert "exception" not in repr(result).lower()
    assert "token" not in repr(result).lower()


def test_r59_restart_outer_deadline_contains_transport_deadline() -> None:
    """R9: the broker cannot cut off the inner dispatch classification."""
    assert (
        access.RESTART_OPERATION_RESPONSE_DEADLINE_SECONDS
        > access.RESTART_TRANSPORT_RESPONSE_DEADLINE_SECONDS
    )
    assert (
        access.RESTART_RECONCILIATION_DEADLINE_SECONDS
        > access.RESTART_OPERATION_RESPONSE_DEADLINE_SECONDS
    )


def test_r59_candidate_response_unknown_reconciles_only_from_runtime_evidence() -> None:
    """R10-R12: a lost response advances only through readiness and services."""
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.CANDIDATE_CORE_CHECKED
    broker.queue(
        "restart",
        access.RestartResult(
            access.RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
            None,
            access.RestartFailureReason.RESPONSE_TIMEOUT,
        ),
    )

    result = controller.restart_for_candidate()
    assert result.dispatched_response_unknown
    controller.await_candidate_readiness()
    controller.verify_research_services_present()

    assert controller.state is access.LifecycleState.RESEARCH_SERVICES_PRESENT
    assert [name for name, _ in broker.calls].count("restart") == 1


def test_r59_candidate_response_unknown_without_services_enters_restore() -> None:
    """R12: transport ambiguity cannot substitute for runtime PR45 evidence."""
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.CANDIDATE_CORE_CHECKED
    broker.queue(
        "restart",
        access.RestartResult(
            access.RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
            None,
            access.RestartFailureReason.RESPONSE_CLOSED,
        ),
    )
    broker.queue(
        "services",
        access.ServiceInventoryResult(4, 0, False, 0, 0, True),
    )

    controller.restart_for_candidate()
    controller.await_candidate_readiness()
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.verify_research_services_present()

    assert controller.state is access.LifecycleState.ROLLBACK_REQUIRED
    assert [name for name, _ in broker.calls].count("restart") == 1


def test_r59_restore_response_unknown_requires_effect_proof() -> None:
    """R14-R16: accepted and reconciled restore effects both retain strict proof."""
    controller, broker = _r32_controller()
    _candidate, restore = _r32_bundles()
    controller._state = access.LifecycleState.PR41_RESTORED
    controller._restore_manifest = restore.manifest
    controller.verify_restore_inventory(restore.manifest)
    controller.check_restore_core()
    broker.queue(
        "restart",
        access.RestartResult(
            access.RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
            None,
            access.RestartFailureReason.RESPONSE_TIMEOUT,
        ),
    )
    controller.restart_for_restore()
    controller.await_restore_readiness()
    controller.verify_research_services_absent()
    controller.admit_post_restore_repairs()

    proof = controller.complete()

    assert proof.restart_dispatch_acceptable is True
    assert proof.restart_effect_proven is True
    assert proof.complete is True


def test_r59_reconstructed_response_unknown_restart_is_not_replayed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """R13/P: durable dispatch metadata resumes readiness with the permit spent."""
    monkeypatch.setattr(access, "_LIFECYCLE_STATE_ROOT", tmp_path / "lifecycle")
    first, first_broker = _r33_advance_to_candidate_core()
    first_broker.queue(
        "restart",
        access.RestartResult(
            access.RestartDispatchOutcome.DISPATCHED_RESPONSE_UNKNOWN,
            None,
            access.RestartFailureReason.RESPONSE_TIMEOUT,
        ),
    )
    first.restart_for_candidate()
    first.close()

    second, second_broker = _r33_controller()
    assert second.state is access.LifecycleState.ACTIVATION_RESTART_CONSUMED
    assert second._permits[access.LifecycleAction.ACTIVATION_RESTART].consumed
    second.await_candidate_readiness()
    with pytest.raises(
        access.LifecycleControllerError, match="(?:PERMIT_CONSUMED|TRANSITION_INVALID)"
    ):
        second.restart_for_candidate()

    assert [name for name, _ in first_broker.calls].count("restart") == 1
    assert [name for name, _ in second_broker.calls].count("restart") == 0


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
        "c1599dcd1cdc1201cd320c316059159a1948d5f58d4bdaa4c64ea3c4a0390075",
        access._source_manifest_digest(candidate.entries),
    ).replace(
        "2d1dd79288b90f0d12c5c35449e6ed5d02c53433335dedd68377c81809731ac2",
        access._source_manifest_digest(restore.entries),
    )
    for original, replacement in (source_replacements or {}).items():
        assert source.count(original) == 1
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


def _assert_remote_failure(result: object) -> None:
    assert isinstance(result, dict)
    assert set(result) == {"error_class", "error_scope", "error_reason"}
    assert result["error_class"] == "OPERATION_FAILED"
    assert access.RemoteFailureScope(result["error_scope"])
    assert access.RemoteFailureReason(result["error_reason"])


_REMOTE_ROOT_CANDIDATES = """ROOT_CANDIDATES = (
    ('DIRECT_CONFIG', ROOT),
    ('HOMEASSISTANT_CONFIG', Path('/homeassistant')),
    ('SUPERVISOR_HOMEASSISTANT', Path('/mnt/data/supervisor/homeassistant')),
)"""


def _remote_root_candidates(
    candidates: tuple[tuple[str, Path], ...],
) -> dict[str, str]:
    rendered = (
        "ROOT_CANDIDATES = (\n"
        + "".join(
            f"    ({profile!r}, Path({str(path)!r})),\n" for profile, path in candidates
        )
        + ")"
    )
    return {_REMOTE_ROOT_CANDIDATES: rendered}


def _write_remote_source(root: Path, bundle: access.SourceBundle) -> None:
    integration = root / "custom_components" / "tuya_ble"
    for source_file in bundle.files:
        relative = Path(source_file.relative_path)
        destination = (
            integration.joinpath(*relative.parts[1:])
            if relative.parts[0] == "integration"
            else integration / ".phase_a_tools" / relative.name
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source_file.content)


def _r53_local_pty_source_inspection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    root_exists: bool,
    operation: access.BoundedOperation = access.BoundedOperation.SOURCE_INVENTORY,
    result_emission: str | None = None,
    invalid_deployment: bool = False,
    installed_state: access.SourceState | None = access.SourceState.CANDIDATE,
    source_replacements: dict[str, str] | None = None,
    runtime_cache_paths: tuple[Path, ...] = (),
) -> object:
    replacement_bin = tmp_path / "bin"
    replacement_bin.mkdir()
    replacement_bash = replacement_bin / "bash"
    replacement_bash.write_text(
        "#!/bin/sh\nexec /bin/bash --noprofile --norc -il\n", encoding="ascii"
    )
    replacement_bash.chmod(0o700)
    wrapper = tmp_path / "wrapper"
    wrapper.write_text(
        f"#!/bin/sh\nPATH={replacement_bin}:/usr/bin:/bin\nexport PATH\n"
        "exec /bin/bash --noprofile --norc -i\n",
        encoding="ascii",
    )
    wrapper.chmod(0o700)
    monkeypatch.setattr(
        access,
        "validate_private_wrapper",
        lambda _path: access.WrapperValidationResult(access.PRIVATE_WRAPPER_VALID, ()),
    )

    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    restore = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    root = tmp_path if root_exists else tmp_path / "missing-config-root"
    if root_exists:
        if installed_state is access.SourceState.CANDIDATE:
            _write_remote_source(root, candidate)
        elif installed_state is access.SourceState.RESTORE:
            _write_remote_source(root, restore)
        else:
            integration_root = root / "custom_components" / "tuya_ble"
            integration_root.mkdir(parents=True)
            (integration_root / "synthetic.py").write_text(
                "synthetic other\n", encoding="ascii"
            )
        integration_root = root / "custom_components" / "tuya_ble"
        for relative in runtime_cache_paths:
            cache = integration_root / relative
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_bytes(b"\xa7\r\r\n\x00synthetic-runtime-bytecode\x00")
        if invalid_deployment:
            (integration_root / "synthetic-invalid-entry").symlink_to("__init__.py")
    remote_program = access._REMOTE_CONTROL_PROGRAM.replace(
        "ROOT = Path('/config')", f"ROOT = Path({str(root)!r})"
    )
    remote_program = remote_program.replace(
        "c1599dcd1cdc1201cd320c316059159a1948d5f58d4bdaa4c64ea3c4a0390075",
        access._source_manifest_digest(candidate.manifest.entries),
    ).replace(
        "2d1dd79288b90f0d12c5c35449e6ed5d02c53433335dedd68377c81809731ac2",
        access._source_manifest_digest(_r30_manifest("RESTORE").entries),
    )
    if result_emission is not None:
        original_emission = (
            "print(json.dumps(result, separators=(',', ':'), sort_keys=True), "
            "flush=True)"
        )
        assert remote_program.count(original_emission) == 1
        remote_program = remote_program.replace(original_emission, result_emission)
    for original, replacement in (source_replacements or {}).items():
        assert remote_program.count(original) == 1
        remote_program = remote_program.replace(original, replacement)
    monkeypatch.setattr(access, "_REMOTE_CONTROL_PROGRAM", remote_program)

    broker = access.PrivateInteractiveSessionBroker(wrapper, timeout_seconds=2.0)
    controller = None
    try:
        assert broker.open() is access.BrokerState.SESSION_ACTIVE
        if operation is access.BoundedOperation.SOURCE_INVENTORY:
            controller = access.FullPreflightLifecycleController(broker)
            result = controller.inspect_current_source(
                candidate.manifest, restore.manifest
            )
        elif operation is access.BoundedOperation.BACKUP:
            result = broker._create_private_backup(
                _r30_manifest("RESTORE"),
                _capability=_r32_controller_minted_capability(
                    broker, access.LifecycleAction.BACKUP
                ),
            )
        elif operation is access.BoundedOperation.TRANSFER:
            result = broker._transfer_source_bundle(
                candidate,
                _capability=_r32_controller_minted_capability(
                    broker, access.LifecycleAction.CANDIDATE_TRANSFER
                ),
            )
        else:
            raise AssertionError("unsupported synthetic R53 operation")
    finally:
        if controller is not None:
            controller.close()
        broker.close()
    return result


def test_r55_successful_source_inventory_has_no_failure_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The exact source-inventory program crosses the production PTY framing path."""
    result = _r53_local_pty_source_inspection(monkeypatch, tmp_path, root_exists=True)

    assert result == access.CurrentSourceInventoryResult(
        access.CurrentSourceClassification.EXACT_PR45,
        access.SourceInventoryResult(
            3,
            3,
            True,
            0,
            0,
            access.RemoteRootProfile.DIRECT_CONFIG,
            managed_manifest_identity=access._source_manifest_digest(
                _r30_manifest().entries
            ),
        ),
    )
    assert result.remote_failure_scope is None
    assert result.remote_failure_reason is None


def test_r53_remote_startup_failure_is_not_malformed_framing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = _r53_local_pty_source_inspection(monkeypatch, tmp_path, root_exists=False)

    assert result.classification is access.CurrentSourceClassification.INDETERMINATE
    assert result.failure_stage is access.DispatchFailureStage.RESPONSE_PARSE
    assert result.failure_class.value == "remote_operation"


def test_r55_root_failure_has_bounded_remote_diagnosis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = _r53_local_pty_source_inspection(monkeypatch, tmp_path, root_exists=False)

    assert result.classification is access.CurrentSourceClassification.INDETERMINATE
    assert result.failure_stage is access.DispatchFailureStage.RESPONSE_PARSE
    assert result.failure_class is access.DispatchFailureClass.REMOTE_OPERATION
    assert result.remote_failure_scope is access.RemoteFailureScope.ROOT
    assert result.remote_failure_reason is access.RemoteFailureReason.ROOT_UNRESOLVED


def test_r55_malformed_request_has_bounded_remote_diagnosis(tmp_path: Path) -> None:
    (tmp_path / "custom_components").mkdir()
    source = access._REMOTE_CONTROL_PROGRAM.replace(
        "ROOT = Path('/config')", f"ROOT = Path({str(tmp_path)!r})"
    )
    completed = subprocess.run(
        [sys.executable, "-c", source, "source_inventory"],
        input="1\nnot-base64\n",
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
        env={},
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "error_class": "OPERATION_FAILED",
        "error_scope": "REQUEST",
        "error_reason": "PAYLOAD",
    }


def test_r55_manifest_authority_failure_has_bounded_remote_diagnosis(
    tmp_path: Path,
) -> None:
    (tmp_path / "custom_components").mkdir()
    payload = {"manifest": access._manifest_payload(_r30_manifest("RESTORE"))}
    payload["manifest"]["authority_commit"] = "0" * 40

    result = _run_synthetic_remote_program(tmp_path, "source_inventory", payload)

    assert result == {
        "error_class": "OPERATION_FAILED",
        "error_scope": "SOURCE_INVENTORY",
        "error_reason": "AUTHORITY",
    }


def test_r55_source_inventory_file_shape_failure_has_bounded_diagnosis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = _r53_local_pty_source_inspection(
        monkeypatch, tmp_path, root_exists=True, invalid_deployment=True
    )

    assert isinstance(result, access.CurrentSourceInventoryResult)
    assert result.classification is access.CurrentSourceClassification.INDETERMINATE
    assert result.failure_stage is access.DispatchFailureStage.RESPONSE_PARSE
    assert result.failure_class is access.DispatchFailureClass.REMOTE_OPERATION
    assert result.remote_failure_scope is access.RemoteFailureScope.SOURCE_INVENTORY
    assert result.remote_failure_reason is access.RemoteFailureReason.REGULAR_FILE


@pytest.mark.parametrize(
    ("profile", "path_name"),
    (
        ("DIRECT_CONFIG", "config"),
        ("HOMEASSISTANT_CONFIG", "homeassistant"),
        ("SUPERVISOR_HOMEASSISTANT", "supervisor-homeassistant"),
    ),
)
def test_r56_supported_root_profiles_resolve_exactly(
    tmp_path: Path,
    profile: str,
    path_name: str,
) -> None:
    root = tmp_path / path_name
    restore = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    _write_remote_source(root, restore)

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(restore.manifest)},
        source_replacements=_remote_root_candidates(((profile, root),)),
    )

    assert result["root_profile"] == profile
    assert result["manifest_match"] is True


def test_r56_no_supported_root_is_bounded_unresolved(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(_r30_manifest("RESTORE"))},
        source_replacements=_remote_root_candidates((("DIRECT_CONFIG", missing),)),
    )

    assert result == {
        "error_class": "OPERATION_FAILED",
        "error_scope": "ROOT",
        "error_reason": "ROOT_UNRESOLVED",
    }


def test_r56_multiple_supported_roots_are_bounded_ambiguous(tmp_path: Path) -> None:
    first = tmp_path / "config"
    second = tmp_path / "homeassistant"
    (first / "custom_components").mkdir(parents=True)
    (second / "custom_components").mkdir(parents=True)

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(_r30_manifest("RESTORE"))},
        source_replacements=_remote_root_candidates(
            (("DIRECT_CONFIG", first), ("HOMEASSISTANT_CONFIG", second))
        ),
    )

    assert result == {
        "error_class": "OPERATION_FAILED",
        "error_scope": "ROOT",
        "error_reason": "ROOT_AMBIGUOUS",
    }


def test_r56_symlink_root_candidate_is_bounded_invalid(tmp_path: Path) -> None:
    real = tmp_path / "real"
    (real / "custom_components").mkdir(parents=True)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(_r30_manifest("RESTORE"))},
        source_replacements=_remote_root_candidates((("DIRECT_CONFIG", linked),)),
    )

    assert result == {
        "error_class": "OPERATION_FAILED",
        "error_scope": "ROOT",
        "error_reason": "ROOT_INVALID",
    }


def test_r56_existing_false_positive_root_is_not_accepted(tmp_path: Path) -> None:
    false_root = tmp_path / "not-home-assistant"
    false_root.mkdir()

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(_r30_manifest("RESTORE"))},
        source_replacements=_remote_root_candidates((("DIRECT_CONFIG", false_root),)),
    )

    assert result["error_reason"] == "ROOT_UNRESOLVED"
    assert str(false_root) not in json.dumps(result)


@pytest.mark.parametrize(
    ("state", "expected_profile", "expected_match"),
    (
        (access.SourceState.RESTORE, "HOMEASSISTANT_CONFIG", True),
        (access.SourceState.CANDIDATE, "HOMEASSISTANT_CONFIG", True),
    ),
)
def test_r56_exact_sources_inventory_through_resolved_root(
    tmp_path: Path,
    state: access.SourceState,
    expected_profile: str,
    expected_match: bool,
) -> None:
    root = tmp_path / "homeassistant"
    label = "RESTORE" if state is access.SourceState.RESTORE else "CANDIDATE"
    bundle = access.build_source_bundle(
        state,
        _r30_files(label),
        _r30_manifest(label),
    )
    _write_remote_source(root, bundle)

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(bundle.manifest)},
        source_replacements=_remote_root_candidates(((expected_profile, root),)),
    )

    assert result["root_profile"] == expected_profile
    assert result["manifest_match"] is expected_match


def test_r56_other_source_inventory_through_resolved_root(tmp_path: Path) -> None:
    root = tmp_path / "homeassistant"
    integration = root / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "synthetic.py").write_text("synthetic other\n", encoding="ascii")

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(_r30_manifest("RESTORE"))},
        source_replacements=_remote_root_candidates((("HOMEASSISTANT_CONFIG", root),)),
    )

    assert result["root_profile"] == "HOMEASSISTANT_CONFIG"
    assert result["manifest_match"] is False


@pytest.mark.parametrize(
    ("state", "cache_relative"),
    (
        (access.SourceState.RESTORE, None),
        (access.SourceState.RESTORE, Path("__pycache__") / "__init__.cpython-314.pyc"),
        (
            access.SourceState.CANDIDATE,
            Path("__pycache__") / "__init__.cpython-314.pyc",
        ),
        (
            access.SourceState.CANDIDATE,
            Path(".phase_a_tools")
            / "__pycache__"
            / "phase_a_status_probe_lib.cpython-314.pyc",
        ),
    ),
)
def test_r57_exact_source_inventory_ignores_runtime_bytecode_cache(
    tmp_path: Path,
    state: access.SourceState,
    cache_relative: Path | None,
) -> None:
    root = tmp_path / "homeassistant"
    label = "RESTORE" if state is access.SourceState.RESTORE else "CANDIDATE"
    bundle = access.build_source_bundle(
        state,
        _r30_files(label),
        _r30_manifest(label),
    )
    _write_remote_source(root, bundle)
    if cache_relative is not None:
        cache = root / "custom_components" / "tuya_ble" / cache_relative
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(b"\xa7\r\r\n\x00synthetic-runtime-bytecode\x00")

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(bundle.manifest)},
        source_replacements=_remote_root_candidates((("HOMEASSISTANT_CONFIG", root),)),
    )

    assert result["root_profile"] == "HOMEASSISTANT_CONFIG"
    assert result["manifest_match"] is True
    assert result["runtime_cache_file_count"] == (cache_relative is not None)


def test_r57_exact_pr41_ignores_cache_nested_below_managed_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "homeassistant"
    files = {
        "integration/__init__.py": b"synthetic integration source\n",
        "integration/nested/module.py": b"synthetic nested source\n",
    }
    entries = tuple(
        access.SourceManifestEntry(
            logical, len(content), hashlib.sha256(content).hexdigest()
        )
        for logical, content in sorted(files.items())
    )
    manifest = access.SourceManifest(access.SourceState.RESTORE, entries)
    bundle = access.SourceBundle(
        access.SourceState.RESTORE,
        tuple(
            access.SourceBundleFile(logical, content)
            for logical, content in sorted(files.items())
        ),
        manifest,
    )
    _write_remote_source(root, bundle)
    cache = (
        root
        / "custom_components"
        / "tuya_ble"
        / "nested"
        / "__pycache__"
        / "module.cpython-314.pyc"
    )
    cache.parent.mkdir()
    cache.write_bytes(b"synthetic runtime bytecode")
    default_digest = access._source_manifest_digest(_r30_manifest("RESTORE").entries)
    replacements = _remote_root_candidates((("HOMEASSISTANT_CONFIG", root),))
    replacements[default_digest] = access._source_manifest_digest(entries)

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(manifest)},
        source_replacements=replacements,
    )

    assert result["manifest_match"] is True
    assert result["runtime_cache_file_count"] == 1


@pytest.mark.parametrize(
    "extra_relative",
    (
        Path("extra.py"),
        Path("extra.pyc"),
        Path("unknown") / "extra.json",
    ),
)
def test_r57_non_cache_extras_remain_unexpected(
    tmp_path: Path, extra_relative: Path
) -> None:
    root = tmp_path / "homeassistant"
    bundle = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    _write_remote_source(root, bundle)
    extra = root / "custom_components" / "tuya_ble" / extra_relative
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_bytes(b"synthetic non-cache extra\n")

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(bundle.manifest)},
        source_replacements=_remote_root_candidates((("HOMEASSISTANT_CONFIG", root),)),
    )

    assert result["manifest_match"] is False
    assert result["unexpected_count"] > 0


def test_r57_unknown_empty_directory_remains_unexpected(tmp_path: Path) -> None:
    root = tmp_path / "homeassistant"
    bundle = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    _write_remote_source(root, bundle)
    (root / "custom_components" / "tuya_ble" / "unknown-empty").mkdir()

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(bundle.manifest)},
        source_replacements=_remote_root_candidates((("HOMEASSISTANT_CONFIG", root),)),
    )

    assert result["manifest_match"] is False
    assert result["unexpected_count"] == 1


def test_r57_unexpected_empty_helper_namespace_remains_other(tmp_path: Path) -> None:
    root = tmp_path / "homeassistant"
    bundle = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    _write_remote_source(root, bundle)
    (root / "custom_components" / "tuya_ble" / ".phase_a_tools").mkdir()

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(bundle.manifest)},
        source_replacements=_remote_root_candidates((("HOMEASSISTANT_CONFIG", root),)),
    )

    assert result["manifest_match"] is False
    assert result["unexpected_count"] == 1


def test_r57_modified_managed_source_reports_only_aggregate_mismatch(
    tmp_path: Path,
) -> None:
    root = tmp_path / "homeassistant"
    bundle = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    _write_remote_source(root, bundle)
    managed = root / "custom_components" / "tuya_ble" / "__init__.py"
    managed.write_bytes(b"synthetic modified managed source\n")

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(bundle.manifest)},
        source_replacements=_remote_root_candidates((("HOMEASSISTANT_CONFIG", root),)),
    )

    assert result["manifest_match"] is False
    assert result["content_mismatch_count"] == 1
    assert "__init__.py" not in json.dumps(result)


def test_r57_missing_managed_source_reports_only_aggregate_mismatch(
    tmp_path: Path,
) -> None:
    root = tmp_path / "homeassistant"
    bundle = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    _write_remote_source(root, bundle)
    (root / "custom_components" / "tuya_ble" / "__init__.py").unlink()

    result = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        {"manifest": access._manifest_payload(bundle.manifest)},
        source_replacements=_remote_root_candidates((("HOMEASSISTANT_CONFIG", root),)),
    )

    assert result["manifest_match"] is False
    assert result["missing_count"] == 1
    assert "__init__.py" not in json.dumps(result)


def test_r57_cache_diagnostics_are_count_only_and_identity_stable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "homeassistant"
    bundle = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    _write_remote_source(root, bundle)
    replacements = _remote_root_candidates((("HOMEASSISTANT_CONFIG", root),))
    payload = {"manifest": access._manifest_payload(bundle.manifest)}
    before = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        payload,
        source_replacements=replacements,
    )
    for relative in (
        Path("__pycache__") / "one.cpython-314.pyc",
        Path("nested") / "__pycache__" / "two.cpython-314.pyc",
        Path("nested") / "__pycache__" / "deeper" / "three.pyc",
    ):
        cache = root / "custom_components" / "tuya_ble" / relative
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(b"synthetic cache bytes")
    after = _run_synthetic_remote_program(
        tmp_path / "unused-direct-root",
        "source_inventory",
        payload,
        source_replacements=replacements,
    )

    assert after["runtime_cache_file_count"] == 3
    assert after["managed_manifest_identity"] == before["managed_manifest_identity"]
    assert after["managed_manifest_identity"] == access._source_manifest_digest(
        bundle.manifest.entries
    )
    retained = json.dumps(after, sort_keys=True)
    assert "__pycache__" not in retained
    assert ".pyc" not in retained


@pytest.mark.parametrize(
    ("installed_state", "classification", "runtime_cache_paths"),
    (
        (
            access.SourceState.RESTORE,
            access.CurrentSourceClassification.EXACT_PR41,
            (
                Path("__pycache__") / "__init__.cpython-314.pyc",
                Path("__pycache__") / "nested" / "module.cpython-314.pyc",
            ),
        ),
        (
            access.SourceState.CANDIDATE,
            access.CurrentSourceClassification.EXACT_PR45,
            (
                Path("__pycache__") / "__init__.cpython-314.pyc",
                Path(".phase_a_tools") / "__pycache__" / "helper.cpython-314.pyc",
            ),
        ),
    ),
)
def test_r57_production_pty_classifies_managed_source_with_runtime_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    installed_state: access.SourceState,
    classification: access.CurrentSourceClassification,
    runtime_cache_paths: tuple[Path, ...],
) -> None:
    result = _r53_local_pty_source_inspection(
        monkeypatch,
        tmp_path,
        root_exists=True,
        installed_state=installed_state,
        runtime_cache_paths=runtime_cache_paths,
    )

    assert result.classification is classification
    assert result.evidence is not None
    assert result.evidence.runtime_cache_file_count == 2
    assert result.evidence.managed_manifest_identity == access._source_manifest_digest(
        _r30_manifest(
            "RESTORE" if installed_state is access.SourceState.RESTORE else "CANDIDATE"
        ).entries
    )


def test_r57_backup_verification_excludes_runtime_cache(tmp_path: Path) -> None:
    restore = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    _write_remote_source(tmp_path, restore)
    cache = (
        tmp_path
        / "custom_components"
        / "tuya_ble"
        / "__pycache__"
        / "__init__.cpython-314.pyc"
    )
    cache.parent.mkdir()
    cache.write_bytes(b"synthetic runtime bytecode")

    result = _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())

    assert result["success"] is True
    assert result["file_count"] == len(restore.manifest.entries)
    package = tmp_path / ".ha_tuya_ble_r36_backup" / "integration"
    assert not (package / "__pycache__").exists()


def test_r57_retained_terminal_exact_pr41_diagnostics_remain_state_neutral() -> None:
    candidate, restore = _r47_retained_restore_failed()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    before = (journal_path.read_bytes(), anchor_path.read_bytes())
    broker = _r47_inspection_broker()
    broker.queue(
        "current_source_inventory",
        access.CurrentSourceInventoryResult(
            access.CurrentSourceClassification.EXACT_PR41,
            access.SourceInventoryResult(
                len(restore.manifest.entries),
                len(restore.manifest.entries),
                True,
                0,
                0,
                content_mismatch_count=0,
                runtime_cache_file_count=2,
                managed_manifest_identity=access._source_manifest_digest(
                    restore.manifest.entries
                ),
            ),
        ),
    )
    inspector = access.RetainedTerminalLifecycleInspector(broker)
    before_metadata = inspector.metadata

    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)

    assert result.classification is access.CurrentSourceClassification.EXACT_PR41
    assert result.evidence is not None
    assert result.evidence.runtime_cache_file_count == 2
    assert inspector.metadata == before_metadata
    assert (journal_path.read_bytes(), anchor_path.read_bytes()) == before
    inspector.close()


def test_r57_retained_terminal_other_diagnostics_cannot_authorize_retirement() -> None:
    candidate, restore = _r47_retained_restore_failed()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    before = (journal_path.read_bytes(), anchor_path.read_bytes())
    broker = _r47_inspection_broker()
    broker.queue(
        "current_source_inventory",
        access.CurrentSourceInventoryResult(
            access.CurrentSourceClassification.OTHER,
            access.SourceInventoryResult(
                len(candidate.manifest.entries),
                len(candidate.manifest.entries),
                False,
                0,
                0,
                content_mismatch_count=1,
                runtime_cache_file_count=1,
                managed_manifest_identity="f" * 64,
            ),
        ),
    )
    inspector = access.RetainedTerminalLifecycleInspector(broker)
    before_metadata = inspector.metadata

    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)
    with pytest.raises(
        access.LifecycleControllerError,
        match="LIFECYCLE_TERMINAL_RETIREMENT_NOT_AUTHORIZED",
    ):
        inspector.retire_terminal()

    assert result.classification is access.CurrentSourceClassification.OTHER
    assert result.evidence is not None
    assert result.evidence.content_mismatch_count == 1
    assert inspector.metadata == before_metadata
    assert (journal_path.read_bytes(), anchor_path.read_bytes()) == before
    inspector.close()


@pytest.mark.parametrize(
    ("installed_state", "classification"),
    (
        (
            access.SourceState.RESTORE,
            access.CurrentSourceClassification.EXACT_PR41,
        ),
        (
            access.SourceState.CANDIDATE,
            access.CurrentSourceClassification.EXACT_PR45,
        ),
        (None, access.CurrentSourceClassification.OTHER),
    ),
)
def test_r56_resolved_root_inventory_crosses_production_pty_as_typed_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    installed_state: access.SourceState | None,
    classification: access.CurrentSourceClassification,
) -> None:
    result = _r53_local_pty_source_inspection(
        monkeypatch,
        tmp_path,
        root_exists=True,
        installed_state=installed_state,
        source_replacements=_remote_root_candidates(
            (("HOMEASSISTANT_CONFIG", tmp_path),)
        ),
    )

    assert result.classification is classification
    if classification is access.CurrentSourceClassification.OTHER:
        assert result.evidence is not None
        assert result.root_profile is access.RemoteRootProfile.HOMEASSISTANT_CONFIG
    else:
        assert result.root_profile is access.RemoteRootProfile.HOMEASSISTANT_CONFIG


def test_r56_shared_mutations_use_only_the_resolved_root(tmp_path: Path) -> None:
    unused = tmp_path / "config"
    unused.mkdir()
    root = tmp_path / "homeassistant"
    integration = root / "custom_components" / "tuya_ble"
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
    replacements = _remote_root_candidates((("HOMEASSISTANT_CONFIG", root),))

    backup = _run_synthetic_remote_program(
        unused, "backup", _r36_backup_payload(), source_replacements=replacements
    )
    transfer = _run_synthetic_remote_program(
        unused,
        "transfer",
        access._bundle_payload(candidate),
        source_replacements=replacements,
    )
    install = _run_synthetic_remote_program(
        unused,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
        source_replacements=replacements,
    )
    restore_transfer = _run_synthetic_remote_program(
        unused,
        "transfer",
        access._bundle_payload(restore),
        source_replacements=replacements,
    )
    restored = _run_synthetic_remote_program(
        unused,
        "restore",
        {"manifest": access._manifest_payload(restore.manifest)},
        source_replacements=replacements,
    )

    assert all(
        result["manifest_match"] is True
        for result in (backup, transfer, install, restore_transfer, restored)
    )
    assert (root / ".ha_tuya_ble_r36_backup").is_dir()
    assert not any(path.name.startswith(".ha_tuya_ble_r") for path in unused.iterdir())


def test_r56_historical_root_root_result_stays_bounded_and_path_free() -> None:
    payload = (
        b'{"error_class":"OPERATION_FAILED","error_scope":"ROOT","error_reason":"ROOT"}'
    )

    with pytest.raises(access._RemoteOperationFailure) as raised:
        access._exact_payload(payload)

    assert raised.value.scope is access.RemoteFailureScope.ROOT
    assert raised.value.reason is access.RemoteFailureReason.ROOT
    assert "/" not in repr(raised.value)


@pytest.mark.parametrize(
    "result_emission",
    (
        (
            "print('SYNTHETIC_PREFIX', end='', flush=True)\n"
            "print(json.dumps(result, separators=(',', ':'), sort_keys=True), flush=True)"
        ),
        (
            "print(json.dumps(result, separators=(',', ':'), sort_keys=True), "
            "end='', flush=True)\nprint('SYNTHETIC_SUFFIX', flush=True)"
        ),
        (
            "print(json.dumps(result, separators=(',', ':'), sort_keys=True), flush=True)\n"
            "print(json.dumps(result, separators=(',', ':'), sort_keys=True), flush=True)"
        ),
        (
            'print(\'{"expected_count":1,"expected_count":1,\''
            '\'"manifest_match":true,"missing_count":0,\''
            '\'"observed_count":1,"unexpected_count":0}\', flush=True)'
        ),
    ),
    ids=("prefix", "suffix", "multiple", "duplicate-member"),
)
def test_r55_malformed_source_inventory_payload_remains_framing_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    result_emission: str,
) -> None:
    result = _r53_local_pty_source_inspection(
        monkeypatch,
        tmp_path,
        root_exists=True,
        result_emission=result_emission,
    )

    assert isinstance(result, access.CurrentSourceInventoryResult)
    assert result.classification is access.CurrentSourceClassification.INDETERMINATE
    assert result.failure_stage is access.DispatchFailureStage.RESPONSE_PARSE
    assert result.failure_class is access.DispatchFailureClass.FRAMING
    assert result.remote_failure_scope is None
    assert result.remote_failure_reason is None


@pytest.mark.parametrize(
    ("operation", "replacement", "scope", "reason"),
    (
        (
            access.BoundedOperation.BACKUP,
            {
                "        result = backup(value)\n": "        raise ValueError('private_state')\n"
            },
            access.RemoteFailureScope.BACKUP,
            access.RemoteFailureReason.PRIVATE_STATE,
        ),
        (
            access.BoundedOperation.TRANSFER,
            {
                "        result = transfer(value)\n": "        raise OSError(errno.EIO, 'not retained')\n"
            },
            access.RemoteFailureScope.TRANSFER,
            access.RemoteFailureReason.FILESYSTEM,
        ),
    ),
)
def test_r55_shared_operation_failure_metadata_propagates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operation: access.BoundedOperation,
    replacement: dict[str, str],
    scope: access.RemoteFailureScope,
    reason: access.RemoteFailureReason,
) -> None:
    with pytest.raises(access._DispatchFailure) as raised:
        _r53_local_pty_source_inspection(
            monkeypatch,
            tmp_path,
            root_exists=True,
            operation=operation,
            source_replacements=replacement,
        )

    assert raised.value.stage is access.DispatchFailureStage.RESPONSE_PARSE
    assert raised.value.failure_class is access.DispatchFailureClass.REMOTE_OPERATION
    assert raised.value.remote_failure_scope is scope
    assert raised.value.remote_failure_reason is reason
    assert "not retained" not in repr(raised.value)


@pytest.mark.parametrize(
    "operation",
    (access.BoundedOperation.BACKUP, access.BoundedOperation.TRANSFER),
)
def test_r53_shared_operations_classify_startup_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operation: access.BoundedOperation,
) -> None:
    with pytest.raises(access._DispatchFailure) as raised:
        _r53_local_pty_source_inspection(
            monkeypatch, tmp_path, root_exists=False, operation=operation
        )

    assert raised.value.stage is access.DispatchFailureStage.RESPONSE_PARSE
    assert raised.value.failure_class.value == "remote_operation"


def test_r47_r53_retained_exact_pr41_inspection_is_state_neutral() -> None:
    candidate, restore = _r47_retained_restore_failed()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    before_journal = journal_path.read_bytes()
    before_anchor = anchor_path.read_bytes()
    before_root_entries = set(root.iterdir())
    inspection_broker = _r47_inspection_broker()
    inspector = access.RetainedTerminalLifecycleInspector(inspection_broker)
    before_metadata = inspector.metadata

    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)

    assert result.classification is access.CurrentSourceClassification.EXACT_PR41
    assert result.failure_stage is None
    assert result.failure_class is None
    assert inspector.metadata == before_metadata
    assert inspector.metadata.state is access.LifecycleState.RESTORE_FAILED
    assert journal_path.read_bytes() == before_journal
    assert anchor_path.read_bytes() == before_anchor
    assert set(root.iterdir()) == before_root_entries
    assert [name for name, _ in inspection_broker.calls] == ["current_source_inventory"]
    inspector.close()


def test_r55_retained_remote_diagnosis_is_state_neutral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(access, "_DISABLE_DURABLE_LIFECYCLE_FOR_TESTS", False)
    candidate, restore = _r47_retained_restore_failed()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    before = (journal_path.read_bytes(), anchor_path.read_bytes())
    broker = _r47_inspection_broker()
    broker.queue(
        "current_source_inventory",
        access.CurrentSourceInventoryResult(
            access.CurrentSourceClassification.INDETERMINATE,
            failure_stage=access.DispatchFailureStage.RESPONSE_PARSE,
            failure_class=access.DispatchFailureClass.REMOTE_OPERATION,
            remote_failure_scope=access.RemoteFailureScope.SOURCE_INVENTORY,
            remote_failure_reason=access.RemoteFailureReason.DIRECTORY,
        ),
    )
    inspector = access.RetainedTerminalLifecycleInspector(broker)
    before_metadata = inspector.metadata

    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)

    assert result.remote_failure_scope is access.RemoteFailureScope.SOURCE_INVENTORY
    assert result.remote_failure_reason is access.RemoteFailureReason.DIRECTORY
    assert inspector.metadata == before_metadata
    assert inspector.metadata.state is access.LifecycleState.RESTORE_FAILED
    assert (journal_path.read_bytes(), anchor_path.read_bytes()) == before
    assert [name for name, _ in broker.calls] == ["current_source_inventory"]
    inspector.close()


def _remote_definition_namespace(
    tmp_path: Path, source_replacements: dict[str, str] | None = None
) -> dict[str, object]:
    source = access._REMOTE_CONTROL_PROGRAM.replace(
        "ROOT = Path('/config')", f"ROOT = Path({str(tmp_path)!r})"
    )
    for original, replacement in (source_replacements or {}).items():
        assert source.count(original) == 1
        source = source.replace(original, replacement)
    definitions, marker, _runtime = source.partition("operation = sys.argv[1]")
    assert marker
    namespace: dict[str, object] = {"__name__": "synthetic_r40_remote"}
    exec(  # noqa: S102 - execute the synthetic remote definitions under test.
        compile(definitions, "<synthetic-r40-definitions>", "exec"), namespace
    )
    return namespace


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

    _assert_remote_failure(result)
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

    _assert_remote_failure(result)
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
    "source_inventory": {"expected_count": 3, "observed_managed_count": 3, "manifest_match": True, "unexpected_count": 0, "missing_count": 0, "content_mismatch_count": 0, "runtime_cache_file_count": 0, "managed_manifest_identity": "__RESTORE_DIGEST__", "root_profile": "DIRECT_CONFIG"},
    "core_check": {"http_status": 200, "result": "ok"},
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
            response = {
                "dispatch_outcome": "RESPONSE_ACCEPTED",
                "http_status": 200,
                "failure_reason": None,
            }
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
            response = {"expected_count": expected_count, "observed_managed_count": expected_count, "manifest_match": True, "unexpected_count": 0, "missing_count": 0, "content_mismatch_count": 0, "runtime_cache_file_count": 0, "managed_manifest_identity": "__RESTORE_DIGEST__", "root_profile": "DIRECT_CONFIG"}
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
    synthetic_controller = access.FullPreflightLifecycleController(broker)
    synthetic_controller._restore_source_generation = "b" * 32
    broker._synthetic_test_controller = synthetic_controller

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
    ).response_accepted
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
    ).response_accepted
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
        return (
            b'{"dispatch_outcome":"DEFINITELY_NOT_DISPATCHED",'
            b'"http_status":null,"failure_reason":"CONNECT_FAILED"}'
        )

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
        assert (
            broker._restart_core(_capability=capability).dispatch_outcome
            is access.RestartDispatchOutcome.DEFINITELY_NOT_DISPATCHED
        )
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

    _assert_remote_failure(result)
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
    _assert_remote_failure(repeated)
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
    _assert_remote_failure(repeated)
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

    _assert_remote_failure(failed)
    assert not (integration / ".phase_a_tools").exists()
    marker = tmp_path / ".ha_tuya_ble_r36_backup.consumed"
    assert json.loads(marker.read_text(encoding="ascii"))["phase"] == "possibly_applied"
    _assert_remote_failure(
        _run_synthetic_remote_program(tmp_path, "restore_backup", _r36_backup_payload())
    )
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

    _assert_remote_failure(
        _run_synthetic_remote_program(tmp_path, "restore_backup", _r36_backup_payload())
    )
    marker = tmp_path / ".ha_tuya_ble_r30_restore.consumed"
    assert marker.is_file()
    _assert_remote_failure(
        _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())
    )
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
    _assert_remote_failure(
        _run_synthetic_remote_program(tmp_path, "restore_backup", _r36_backup_payload())
    )

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

    _assert_remote_failure(failed)
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
            "def restore_backup(value):\n"
            "    expected_manifest_value = validate_backup_context(value)\n"
            "    if root_relative_exists(BACKUP_CONSUMED) or root_relative_exists(\n"
            "        RESTORE_CONSUMED\n"
            "    ):\n"
            "        raise ValueError('backup_consumed')\n"
            "    package_fd = open_root_relative(BACKUP)\n"
            "    source_fd = pending_fd = installed_fd = None\n"
            "    try:\n"
            "        identity = read_backup_identity_fd(value, package_fd)\n": (
                "def restore_backup(value):\n"
                "    expected_manifest_value = validate_backup_context(value)\n"
                "    if root_relative_exists(BACKUP_CONSUMED) or "
                "root_relative_exists(\n"
                "        RESTORE_CONSUMED\n"
                "    ):\n"
                "        raise ValueError('backup_consumed')\n"
                "    package_fd = open_root_relative(BACKUP)\n"
                "    source_fd = pending_fd = installed_fd = None\n"
                "    try:\n"
                "        identity = read_backup_identity_fd(value, package_fd)\n"
                "        moved = BACKUP.with_name(BACKUP.name + '.swapped')\n"
                "        BACKUP.rename(moved)\n"
                "        shutil.copytree(moved, BACKUP)\n"
                "        (BACKUP / 'integration' / '__init__.py').write_bytes("
                "b'synthetic hostile package\\n')\n"
            )
        },
    )

    _assert_remote_failure(failed)
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

    _assert_remote_failure(failed)
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
                "def reconcile_backup_creation(value):\n"
                "    expected = validate_backup_context(value)\n"
                "    package_fd = open_root_relative(BACKUP)\n"
                "    source_fd = None\n"
                "    try:\n"
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

    _assert_remote_failure(failed)


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

    _assert_remote_failure(failed)
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

    def _release_retained_anchor_continuity_inspector(
        self,
        controller: object,
        issuer: object,
        session_generation: object,
    ) -> None:
        binding = self._controller_binding
        if (
            controller.__class__ is not access.RetainedAnchorContinuityInspector
            or binding is None
            or binding[0] is not controller
            or binding[1] is not issuer
            or binding[3] is not session_generation
            or self._session_generation is not session_generation
            or any(
                not any(capability is consumed for consumed in binding[1].consumed)
                for capability in binding[1].issued
            )
        ):
            raise access.SessionBrokerError("SYNTHETIC_CONTROLLER_RELEASE_INVALID")
        self._controller_binding = None

    def _release_retained_feature_validation_terminal_inspector(
        self,
        controller: object,
        issuer: object,
        session_generation: object,
    ) -> None:
        binding = self._controller_binding
        if (
            controller.__class__
            is not access.RetainedFeatureValidationTerminalInspector
            or binding is None
            or binding[0] is not controller
            or binding[1] is not issuer
            or binding[3] is not session_generation
            or self._session_generation is not session_generation
            or any(
                not any(capability is consumed for consumed in binding[1].consumed)
                for capability in binding[1].issued
            )
        ):
            raise access.SessionBrokerError("SYNTHETIC_CONTROLLER_RELEASE_INVALID")
        self._controller_binding = None

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

    def _consume_source_inspection_capability(self, capability: object) -> None:
        binding = self._controller_binding
        if (
            type(capability) is not access._SourceInspectionCapability
            or binding is None
            or capability.controller is not binding[0]
            or capability.issuer is not binding[1].identity
            or capability.session_generation is not binding[3]
            or self._session_generation is not binding[3]
            or not any(capability is issued for issued in binding[1].issued)
            or any(capability is consumed for consumed in binding[1].consumed)
        ):
            raise access.SessionBrokerError("SYNTHETIC_INSPECTION_CAPABILITY_INVALID")
        binding[1].consumed.append(capability)

    def _consume_retained_backup_capability(
        self, capability: object, action: access.RetainedBackupAction
    ) -> None:
        binding = self._controller_binding
        if (
            type(capability) is not access._RetainedBackupCapability
            or binding is None
            or capability.controller is not binding[0]
            or capability.issuer is not binding[1].identity
            or capability.lifecycle_generation is not binding[2]
            or capability.session_generation is not binding[3]
            or capability.action is not action
            or not any(capability is issued for issued in binding[1].issued)
            or any(capability is consumed for consumed in binding[1].consumed)
        ):
            raise access.SessionBrokerError("SYNTHETIC_BACKUP_CAPABILITY_INVALID")
        binding[1].consumed.append(capability)
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

    def _inspect_current_source(
        self,
        candidate_manifest: access.SourceManifest,
        restore_manifest: access.SourceManifest,
        *,
        _capability: object = None,
    ) -> access.CurrentSourceInventoryResult:
        assert candidate_manifest.state is access.SourceState.CANDIDATE
        assert restore_manifest.state is access.SourceState.RESTORE
        self._consume_source_inspection_capability(_capability)
        self.calls.append(("current_source_inventory", None))
        queued = self.responses.get("current_source_inventory", [])
        value = (
            queued.pop(0)
            if queued
            else access.CurrentSourceInventoryResult(
                access.CurrentSourceClassification.EXACT_PR41,
                access.SourceInventoryResult(
                    len(restore_manifest.entries),
                    len(restore_manifest.entries),
                    True,
                    0,
                    0,
                ),
            )
        )
        if isinstance(value, BaseException):
            raise value
        assert isinstance(value, access.CurrentSourceInventoryResult)
        return value

    def _retained_backup_operation(
        self,
        manifest: access.SourceManifest,
        action: access.RetainedBackupAction,
        *,
        _capability: object = None,
    ) -> access.PriorBackupContinuityResult:
        assert manifest.state is access.SourceState.RESTORE
        self._consume_retained_backup_capability(_capability, action)
        return self._next(
            "prior_backup",
            action,
            (
                access.PriorBackupContinuityResult(
                    access.PriorBackupClassification.OWNED_BY_RETAINED_LIFECYCLE
                )
                if action is access.RetainedBackupAction.INSPECT
                else access.PriorBackupContinuityResult(
                    access.PriorBackupClassification.NONE, retired=True
                )
            ),
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
        return self._next(
            "restart",
            None,
            access.RestartResult(
                access.RestartDispatchOutcome.RESPONSE_ACCEPTED, 200, None
            ),
        )

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
    broker._PrivateInteractiveSessionBroker__inspection_token = object()
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
        ("C1-M1", {"http_status": 200, "result": "ok", "check_passed": True}, False),
        ("C1-M2", {"http_status": 200, "result": "ok", "check_passed": False}, False),
        ("C1-M3", {"http_status": 200, "result": "ok"}, True),
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


def test_r58_remote_core_check_validates_current_supervisor_envelope() -> None:
    source = access._REMOTE_CONTROL_PROGRAM
    core_check = source[
        source.index("def core_check") : source.index("def restart_core")
    ]

    assert "set(body) != {'result', 'data'}" in core_check
    assert "body.get('result') != 'ok'" in core_check
    assert "body.get('data') != {}" in core_check
    assert "except urllib.error.HTTPError as error" in core_check


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

    assert result == access.CoreCheckResult(
        1,
        0,
        "error",
        False,
        "REQUEST_FAILED",
        access.CoreCheckResponseContract.ERROR,
    )


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
        "ABORTED_AT_BASELINE",
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
    "restart_dispatch_acceptable": True,
    "restart_effect_proven": True,
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
    controller._restore_source_generation = "b" * 32
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
    assert second.state is access.LifecycleState.ACTIVATION_RESTART_CONSUMED
    with pytest.raises(
        access.LifecycleControllerError, match="(?:PERMIT_CONSUMED|TRANSITION_INVALID)"
    ):
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

        def record_ambiguous(
            self, _action: access.LifecycleAction, *_diagnostic: object
        ) -> None:
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
        evidence = (
            access.RestartResult(
                access.RestartDispatchOutcome.RESPONSE_ACCEPTED, 200, None
            )
            if action
            in {
                access.LifecycleAction.ACTIVATION_RESTART,
                access.LifecycleAction.REMOVAL_RESTART,
            }
            else None
        )
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
            evidence=evidence,
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
                        else (
                            access.RestartResult(
                                access.RestartDispatchOutcome.RESPONSE_ACCEPTED,
                                200,
                                None,
                            )
                            if action
                            in {
                                access.LifecycleAction.ACTIVATION_RESTART,
                                access.LifecycleAction.REMOVAL_RESTART,
                            }
                            else None
                        )
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

    _assert_remote_failure(result)
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
            remote.index("def invoke_helper") : remote.index(
                "def research_evidence_path"
            )
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
            lambda detail: access.PhaseAResult(
                access.PhaseAOperation.PREFLIGHT,
                67,
                "schema_invalid",
                detail[1],
            ),
        )
        with pytest.raises(access.PreflightRejectedError) as raised:
            controller.run_non_probe_preflight()
        assert raised.value.reason is access.PreflightFailureReason.SCHEMA_INVALID
        with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
            controller.collect_a1()
    elif mutation == "preflight_replayed_after_ambiguity":
        controller, broker = _r32_controller()
        controller._state = access.LifecycleState.AP0_COLLECTED
        broker.queue(
            "helper",
            lambda detail: access.PhaseAResult(
                access.PhaseAOperation.PREFLIGHT,
                78,
                "transport_ambiguous",
                detail[1],
            ),
        )
        with pytest.raises(access.PreflightRejectedError) as raised:
            controller.run_non_probe_preflight()
        assert raised.value.reason is access.PreflightFailureReason.TRANSPORT_AMBIGUOUS
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

    _assert_remote_failure(result)
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

    _assert_remote_failure(repeated)
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

    _assert_remote_failure(rejected)
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

    _assert_remote_failure(result)
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

    _assert_remote_failure(result)
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

    _assert_remote_failure(result)
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
        _assert_remote_failure(
            _run_synthetic_remote_program(tmp_path, "backup", _r36_backup_payload())
        )


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
            "        synced_inodes, synced_root = sync_backup_package_fd(\n"
            "            pending_fd, staged_fd, retained_files\n"
            "        )\n": (
                "        synced_inodes, synced_root = sync_backup_package_fd(\n"
                "            pending_fd, staged_fd, retained_files\n"
                "        )\n"
                "        moved = pending.with_name(pending.name + '.swapped')\n"
                "        pending.rename(moved)\n"
                "        shutil.copytree(moved, pending)\n"
            )
        },
    )

    _assert_remote_failure(failed)
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
            "        synced_inodes, synced_root = sync_backup_package_fd(\n"
            "            pending_fd, staged_fd, retained_files\n"
            "        )\n": (
                "        synced_inodes, synced_root = sync_backup_package_fd(\n"
                "            pending_fd, staged_fd, retained_files\n"
                "        )\n"
                "        child = pending / 'integration'\n"
                "        moved = pending / 'integration.swapped'\n"
                "        child.rename(moved)\n"
                "        shutil.copytree(moved, child)\n"
            )
        },
    )

    _assert_remote_failure(failed)


def _sync_written_file_accepts_discontinuity(
    namespace: dict[str, object], tmp_path: Path, alteration: str
) -> bool:
    real_os = namespace["os"]
    content = b"synthetic retained child\n"
    path = tmp_path / f"retained-child-{alteration}"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(descriptor, content)

    class FstatMutation:
        def __init__(self) -> None:
            self.after_fsync = False

        def __getattr__(self, name: str) -> object:
            return getattr(real_os, name)

        def fsync(self, target: int) -> None:
            real_os.fsync(target)
            if target == descriptor:
                self.after_fsync = True

        def fstat(self, target: int) -> object:
            metadata = real_os.fstat(target)
            if target != descriptor or not self.after_fsync:
                return metadata
            values = {
                name: getattr(metadata, name)
                for name in (
                    "st_mode",
                    "st_nlink",
                    "st_dev",
                    "st_ino",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            }
            if alteration == "identity":
                values["st_ino"] += 1
            else:
                values["st_size"] += 1
            return type("SyntheticStat", (), values)()

    namespace["os"] = FstatMutation()
    try:
        try:
            namespace["sync_written_file"](
                descriptor, len(content), hashlib.sha256(content).hexdigest()
            )
        except ValueError:
            return False
        return True
    finally:
        namespace["os"] = real_os
        os.close(descriptor)


@pytest.mark.parametrize("alteration", ("identity", "state"))
def test_r40_original_fd_pre_post_fsync_guard_rejects_discontinuity(
    alteration: str, tmp_path: Path
) -> None:
    namespace = _remote_definition_namespace(tmp_path)

    assert not _sync_written_file_accepts_discontinuity(namespace, tmp_path, alteration)


def test_r40_red_1_backup_rejects_byte_identical_written_child_inode_swap(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")

    result = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={
            "        copy_deployment_fd(\n"
            "            live_fd, staged_fd, expected, retained_files, "
            "('integration',)\n"
            "        )\n"
            "        after = inventory_deployment_fd(staged_fd)\n": (
                "        copy_deployment_fd(\n"
                "            live_fd, staged_fd, expected, retained_files, "
                "('integration',)\n"
                "        )\n"
                "        child = pending / 'integration' / '__init__.py'\n"
                "        replacement = pending / 'synthetic-byte-identical-child'\n"
                "        replacement.write_bytes(child.read_bytes())\n"
                "        os.replace(replacement, child)\n"
                "        after = inventory_deployment_fd(staged_fd)\n"
            )
        },
    )

    _assert_remote_failure(result)
    assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()


def test_r40_red_2_backup_rejects_size_change_after_written_child_fsync(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    content = b"synthetic integration source\n"
    (integration / "__init__.py").write_bytes(content)
    mutation = (
        "    os.fsync(descriptor)\n"
        f"    if expected_size == {len(content)}:\n"
        "        if os.write(descriptor, b'x') != 1:\n"
        "            raise OSError(errno.EIO, 'short_write')\n"
        "    after = os.fstat(descriptor)\n"
    )

    result = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={
            "    os.fsync(descriptor)\n" "    after = os.fstat(descriptor)\n": mutation
        },
    )

    _assert_remote_failure(result)
    assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()


def test_r40_red_3_backup_rejects_package_root_churn_after_fsync(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")

    result = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={
            "            sync_backup_directory(descriptor, not logical)\n"
            "            after = os.fstat(descriptor)\n": (
                "            sync_backup_directory(descriptor, not logical)\n"
                "            if not logical:\n"
                "                os.rename(\n"
                "                    'integration', 'integration.transient',\n"
                "                    src_dir_fd=descriptor, dst_dir_fd=descriptor,\n"
                "                )\n"
                "                os.rename(\n"
                "                    'integration.transient', 'integration',\n"
                "                    src_dir_fd=descriptor, dst_dir_fd=descriptor,\n"
                "                )\n"
                "            after = os.fstat(descriptor)\n"
            )
        },
    )

    _assert_remote_failure(result)
    assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()


def test_r40_backup_rejects_package_root_state_change_before_publication(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")

    result = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={
            "        assert_root_relative_record(pending, pending_fd, synced_root)\n": (
                "        root_state = os.fstat(pending_fd)\n"
                "        os.utime(\n"
                "            pending_fd,\n"
                "            ns=(root_state.st_atime_ns, root_state.st_mtime_ns + 1),\n"
                "        )\n"
                "        assert_root_relative_record("
                "pending, pending_fd, synced_root)\n"
            )
        },
    )

    _assert_remote_failure(result)
    assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()


def test_r40_package_root_fsync_failure_never_publishes(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")

    result = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={
            "def sync_backup_directory(descriptor, is_package_root):\n": (
                "def sync_backup_directory(descriptor, is_package_root):\n"
                "    if is_package_root:\n"
                "        raise OSError(errno.EIO, 'synthetic package root fsync')\n"
            )
        },
    )

    _assert_remote_failure(result)
    assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()


def test_r40_red_4_backup_rejects_transient_symlink_at_child_entry_check(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")

    result = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements={
            "            synced = sync_written_file(descriptor, size, digest)\n"
            "            entry = os.stat(\n": (
                "            synced = sync_written_file(descriptor, size, digest)\n"
                "            if logical == ('integration', '__init__.py'):\n"
                "                os.rename(\n"
                "                    logical[-1], '__init__.py.displaced',\n"
                "                    src_dir_fd=parent, dst_dir_fd=parent,\n"
                "                )\n"
                "                os.symlink(\n"
                "                    '__init__.py.displaced', logical[-1], "
                "dir_fd=parent\n"
                "                )\n"
                "            entry = os.stat(\n"
            ),
            "            observed['/'.join(logical)] = synced\n": (
                "            if logical == ('integration', '__init__.py'):\n"
                "                os.unlink(logical[-1], dir_fd=parent)\n"
                "                os.rename(\n"
                "                    '__init__.py.displaced', logical[-1],\n"
                "                    src_dir_fd=parent, dst_dir_fd=parent,\n"
                "                )\n"
                "            observed['/'.join(logical)] = synced\n"
            ),
        },
    )

    _assert_remote_failure(result)
    assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()


def test_r40_backup_publishes_and_reloads_multiple_nested_regular_children(
    tmp_path: Path,
) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    nested = integration / "synthetic_nested"
    nested.mkdir(parents=True)
    files = {
        "integration/__init__.py": b"synthetic integration source\n",
        "integration/synthetic_nested/one.py": b"synthetic nested one\n",
        "integration/synthetic_nested/two.py": b"synthetic nested two\n",
    }
    for logical, content in files.items():
        relative = logical.removeprefix("integration/")
        destination = integration / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    entries = tuple(
        access.SourceManifestEntry(
            logical, len(content), hashlib.sha256(content).hexdigest()
        )
        for logical, content in sorted(files.items())
    )
    manifest = access.SourceManifest(access.SourceState.RESTORE, entries)
    payload = _r36_backup_payload()
    payload["manifest"] = access._manifest_payload(manifest)
    default_digest = access._source_manifest_digest(_r30_manifest("RESTORE").entries)
    exact_digest = access._source_manifest_digest(entries)

    created = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        payload,
        source_replacements={default_digest: exact_digest},
    )
    reloaded = _run_synthetic_remote_program(
        tmp_path,
        "reconcile_backup_creation",
        payload,
        source_replacements={default_digest: exact_digest},
    )

    assert created["success"] is True
    assert created["file_count"] == len(files)
    assert reloaded["success"] is True
    assert reloaded["file_count"] == len(files)
    package = tmp_path / ".ha_tuya_ble_r36_backup"
    assert package.is_dir()
    assert not list(tmp_path.glob(".ha_tuya_ble_r36_backup.pending-*"))
    assert {
        path.relative_to(package / "integration").as_posix(): path.read_bytes()
        for path in (package / "integration").rglob("*")
        if path.is_file()
    } == {
        logical.removeprefix("integration/"): content
        for logical, content in files.items()
    }


_R40_INODE_MUTATIONS = {
    "I-M1": "remove original-FD pre/post inode identity comparison",
    "I-M2": "fsync a pathname reopen instead of the original write FD",
    "I-M3": "substitute the original FD for the child entry lookup",
    "I-M4": "adopt a byte-identical replacement inode",
    "I-M5": "skip package-root record verification before publication",
    "I-M6": "remove the package-root directory fsync",
    "I-M7": "follow a symlink during final child-entry lookup",
    "I-M8": "ignore required post-fsync state mismatch",
}


def _r40_backup_call_swap() -> tuple[str, str]:
    needle = (
        "        copy_deployment_fd(\n"
        "            live_fd, staged_fd, expected, retained_files, "
        "('integration',)\n"
        "        )\n"
        "        after = inventory_deployment_fd(staged_fd)\n"
    )
    replacement = (
        "        copy_deployment_fd(\n"
        "            live_fd, staged_fd, expected, retained_files, "
        "('integration',)\n"
        "        )\n"
        "        child = pending / 'integration' / '__init__.py'\n"
        "        replacement = pending / 'synthetic-byte-identical-child'\n"
        "        replacement.write_bytes(child.read_bytes())\n"
        "        os.replace(replacement, child)\n"
        "        after = inventory_deployment_fd(staged_fd)\n"
    )
    return needle, replacement


def _r40_transient_entry_attack(*, symlink: bool, adopt: bool) -> dict[str, str]:
    before = (
        "            synced = sync_written_file(descriptor, size, digest)\n"
        "            entry = os.stat(\n"
    )
    injected = (
        "            synced = sync_written_file(descriptor, size, digest)\n"
        "            if logical == ('integration', '__init__.py'):\n"
        "                os.rename(\n"
        "                    logical[-1], '__init__.py.displaced',\n"
        "                    src_dir_fd=parent, dst_dir_fd=parent,\n"
        "                )\n"
    )
    if symlink:
        injected += (
            "                os.symlink(\n"
            "                    '__init__.py.displaced', logical[-1], "
            "dir_fd=parent\n"
            "                )\n"
        )
    else:
        injected += (
            "                replacement = os.open(\n"
            "                    logical[-1],\n"
            "                    os.O_RDWR | os.O_CREAT | os.O_EXCL | "
            "os.O_NOFOLLOW,\n"
            "                    0o600, dir_fd=parent,\n"
            "                )\n"
            "                payload = b'synthetic integration source\\n'\n"
            "                offset = 0\n"
            "                while offset < len(payload):\n"
            "                    written = os.write(replacement, payload[offset:])\n"
            "                    if written <= 0:\n"
            "                        raise OSError(errno.EIO, 'short_write')\n"
            "                    offset += written\n"
            "                os.close(replacement)\n"
        )
    injected += "            entry = os.stat(\n"
    after = "            observed['/'.join(logical)] = synced\n"
    if adopt:
        cleanup = (
            "            if logical == ('integration', '__init__.py'):\n"
            "                os.unlink('__init__.py.displaced', dir_fd=parent)\n"
            "            observed['/'.join(logical)] = synced\n"
        )
    else:
        cleanup = (
            "            if logical == ('integration', '__init__.py'):\n"
            "                os.unlink(logical[-1], dir_fd=parent)\n"
            "                os.rename(\n"
            "                    '__init__.py.displaced', logical[-1],\n"
            "                    src_dir_fd=parent, dst_dir_fd=parent,\n"
            "                )\n"
            "            observed['/'.join(logical)] = synced\n"
        )
    return {before: injected, after: cleanup}


@pytest.mark.parametrize("mutant", tuple(_R40_INODE_MUTATIONS))
def test_r40_i_m1_to_i_m8_source_mutations_are_detected(
    mutant: str, tmp_path: Path
) -> None:
    """Execute each weakened source object and prove its focused detector trips."""
    assert _R40_INODE_MUTATIONS[mutant]
    if mutant in {"I-M1", "I-M8"}:
        guard = {
            "I-M1": (
                "        or inode_identity(before, 'regular') "
                "!= inode_identity(after, 'regular')\n"
            ),
            "I-M8": (
                "        or inode_identity(before, 'regular') "
                "!= inode_identity(after, 'regular')\n"
                "        or inode_state(before) != inode_state(after)\n"
            ),
        }[mutant]
        replacement = (
            "        or inode_identity(before, 'regular') "
            "!= inode_identity(after, 'regular')\n"
            "        or False\n"
            if mutant == "I-M8"
            else "        or False\n"
        )
        namespace = _remote_definition_namespace(tmp_path, {guard: replacement})
        alteration = "identity" if mutant == "I-M1" else "state"
        assert _sync_written_file_accepts_discontinuity(namespace, tmp_path, alteration)
        return

    replacements: dict[str, str] = {}
    if mutant == "I-M2":
        replacements[
            "            synced = sync_written_file(descriptor, size, digest)\n"
        ] = (
            "            reopened = os.open(\n"
            "                logical[-1], os.O_RDWR | os.O_NOFOLLOW, "
            "dir_fd=parent\n"
            "            )\n"
            "            try:\n"
            "                synced = sync_written_file(reopened, size, digest)\n"
            "            finally:\n"
            "                os.close(reopened)\n"
        )
        needle, attack = _r40_backup_call_swap()
        replacements[needle] = attack
    elif mutant == "I-M3":
        replacements.update(_r40_transient_entry_attack(symlink=False, adopt=False))
        replacements[
            "            entry = os.stat(\n"
            "                logical[-1], dir_fd=parent, follow_symlinks=False\n"
            "            )\n"
        ] = "            entry = os.fstat(descriptor)\n"
    elif mutant == "I-M4":
        replacements[
            "            if (\n"
            "                not stat.S_ISREG(entry.st_mode)\n"
            "                or entry.st_nlink != 1\n"
            "                or inode_record(entry, 'regular') != synced\n"
            "            ):\n"
            "                raise ValueError('regular')\n"
        ] = (
            "            if (\n"
            "                not stat.S_ISREG(entry.st_mode)\n"
            "                or entry.st_nlink != 1\n"
            "            ):\n"
            "                raise ValueError('regular')\n"
            "            if inode_record(entry, 'regular') != synced:\n"
            "                synced = inode_record(entry, 'regular')\n"
        )
        replacements.update(_r40_transient_entry_attack(symlink=False, adopt=True))
    elif mutant == "I-M5":
        replacements[
            "        if (\n"
            "            inode_record(os.fstat(descriptor), 'directory') != expected\n"
        ] = (
            "        if False and (\n"
            "            inode_record(os.fstat(descriptor), 'directory') != expected\n"
        )
        replacements[
            "        assert_root_relative_record(pending, pending_fd, synced_root)\n"
        ] = (
            "        root_state = os.fstat(pending_fd)\n"
            "        os.utime(\n"
            "            pending_fd,\n"
            "            ns=(root_state.st_atime_ns, root_state.st_mtime_ns + 1),\n"
            "        )\n"
            "        assert_root_relative_record(pending, pending_fd, synced_root)\n"
        )
    elif mutant == "I-M6":
        replacements["            sync_backup_directory(descriptor, not logical)\n"] = (
            "            if logical:\n"
            "                sync_backup_directory(descriptor, False)\n"
        )
        replacements["def sync_backup_directory(descriptor, is_package_root):\n"] = (
            "def sync_backup_directory(descriptor, is_package_root):\n"
            "    if is_package_root:\n"
            "        raise OSError(errno.EIO, 'synthetic package root fsync')\n"
        )
    else:
        replacements[
            "            entry = os.stat(\n"
            "                logical[-1], dir_fd=parent, follow_symlinks=False\n"
            "            )\n"
        ] = (
            "            entry = os.stat(\n"
            "                logical[-1], dir_fd=parent, follow_symlinks=True\n"
            "            )\n"
        )
        replacements.update(_r40_transient_entry_attack(symlink=True, adopt=False))

    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    result = _run_synthetic_remote_program(
        tmp_path,
        "backup",
        _r36_backup_payload(),
        source_replacements=replacements,
    )

    if mutant in {"I-M3", "I-M7"}:
        _assert_remote_failure(result)
        assert not (tmp_path / ".ha_tuya_ble_r36_backup").exists()
    else:
        assert result["success"] is True
        assert (tmp_path / ".ha_tuya_ble_r36_backup").is_dir()


@pytest.mark.parametrize(
    ("source_replacements", "published"),
    (
        (
            {
                "        synced_inodes, synced_root = sync_backup_package_fd(\n"
                "            pending_fd, staged_fd, retained_files\n"
                "        )\n": ("        raise OSError(5, 'synthetic file fsync')\n")
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

    _assert_remote_failure(result)
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


def _r44_backup_ambiguity() -> tuple[object, _R32ScriptedBroker, object, object]:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
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
    return reconstructed, reconstructed_broker, candidate, restore


def test_r44_pre_source_abort_exact_pr41_skips_restore_tail() -> None:
    controller, broker, candidate, restore = _r44_backup_ambiguity()

    result = controller.resolve_pre_source_abort(candidate.manifest, restore.manifest)

    assert result.classification is access.CurrentSourceClassification.EXACT_PR41
    assert controller.state is access.LifecycleState.ABORTED_AT_BASELINE
    names = [name for name, _ in broker.calls]
    assert names == ["current_source_inventory"]
    assert names.count("transfer") == 0
    assert names.count("install_restore") == 0
    assert names.count("restart") == 0
    assert not controller._permits[access.LifecycleAction.RESTORE_TRANSFER].consumed


def test_r44_pre_source_abort_non_pr41_keeps_restore_reachable() -> None:
    controller, broker, candidate, restore = _r44_backup_ambiguity()
    broker.queue(
        "current_source_inventory",
        access.CurrentSourceInventoryResult(access.CurrentSourceClassification.OTHER),
    )

    result = controller.resolve_pre_source_abort(candidate.manifest, restore.manifest)

    assert result.classification is access.CurrentSourceClassification.OTHER
    assert controller.state is access.LifecycleState.RECOVERY_REQUIRED
    assert not controller._permits[access.LifecycleAction.RESTORE_TRANSFER].consumed
    controller.stage_restore(restore)
    assert controller.state is access.LifecycleState.RESTORE_STAGED
    assert [name for name, _ in broker.calls] == [
        "current_source_inventory",
        "transfer",
    ]
    controller.close()


def test_r44_terminal_source_inventory_is_byte_neutral() -> None:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 3, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    broker.queue(
        "transfer",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.stage_restore(restore)
    controller.close()

    terminal, terminal_broker = _r33_controller()
    assert terminal.state is access.LifecycleState.RESTORE_FAILED
    journal_path = access._LIFECYCLE_STATE_ROOT / access._LIFECYCLE_JOURNAL_NAME
    before_bytes = journal_path.read_bytes()
    before_record = json.loads(before_bytes)
    before_permits = {
        action: permit.consumed for action, permit in terminal._permits.items()
    }
    lifecycle_generation = terminal._journal.lifecycle_generation

    result = terminal.inspect_current_source(candidate.manifest, restore.manifest)

    assert isinstance(result, access.CurrentSourceInventoryResult)
    assert result.classification is access.CurrentSourceClassification.EXACT_PR41
    assert journal_path.read_bytes() == before_bytes
    assert terminal._journal._record == before_record
    assert terminal._journal.lifecycle_generation == lifecycle_generation
    assert {
        action: permit.consumed for action, permit in terminal._permits.items()
    } == before_permits
    assert [name for name, _ in terminal_broker.calls] == ["current_source_inventory"]
    terminal.close()


def _r47_retained_restore_failed() -> tuple[object, object]:
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 3, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    broker.queue(
        "transfer",
        access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED"),
    )
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.stage_restore(restore)
    controller.close()

    terminal, _ = _r33_controller()
    assert terminal.state is access.LifecycleState.RESTORE_FAILED
    terminal.close()
    return candidate, restore


def _r47_inspection_broker() -> _R32ScriptedBroker:
    broker = _R32ScriptedBroker()
    broker._durable_lifecycle_test = True
    return broker


def test_r47_production_retained_terminal_inspection_is_state_neutral() -> None:
    candidate, restore = _r47_retained_restore_failed()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    before_journal = journal_path.read_bytes()
    before_anchor = anchor_path.read_bytes()
    before_root_entries = set(root.iterdir())
    before_record = json.loads(before_journal)
    inspection_broker = _r47_inspection_broker()
    inspection_broker.queue(
        "current_source_inventory",
        access._DispatchFailure(
            access.DispatchFailureStage.RESPONSE_WAIT,
            access.DispatchFailureClass.TIMEOUT,
        ),
    )
    inspector = access.RetainedTerminalLifecycleInspector(inspection_broker)
    before_metadata = inspector.metadata

    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)

    assert result.classification is access.CurrentSourceClassification.INDETERMINATE
    assert result.failure_stage is access.DispatchFailureStage.RESPONSE_WAIT
    assert result.failure_class is access.DispatchFailureClass.TIMEOUT
    assert inspector.metadata == before_metadata
    assert inspector.metadata.state is access.LifecycleState.RESTORE_FAILED
    assert journal_path.read_bytes() == before_journal
    assert anchor_path.read_bytes() == before_anchor
    assert set(root.iterdir()) == before_root_entries
    assert inspector._journal._record == before_record
    assert inspector._journal._record["operations"] == before_record["operations"]
    assert (
        inspector._journal._record["consumed_operations"]
        == before_record["consumed_operations"]
    )
    assert not hasattr(inspector, "_permits")
    assert not any(
        hasattr(inspector, name)
        for name in (
            "create_backup",
            "stage_candidate",
            "install_candidate",
            "restart_for_candidate",
            "check_candidate_core",
            "run_non_probe_preflight",
            "collect_a0",
            "stage_restore",
        )
    )
    assert [name for name, _ in inspection_broker.calls] == ["current_source_inventory"]
    with pytest.raises(
        access.LifecycleControllerError,
        match="LIFECYCLE_TERMINAL_RETIREMENT_NOT_AUTHORIZED",
    ):
        inspector.retire_terminal()
    inspector.close()


def test_r47_terminal_retirement_after_exact_pr41_allows_fresh_lifecycle() -> None:
    candidate, restore = _r47_retained_restore_failed()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    inspector = access.RetainedTerminalLifecycleInspector(_r47_inspection_broker())
    terminal_generation = inspector.metadata.lifecycle_generation
    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)
    assert result.classification is access.CurrentSourceClassification.EXACT_PR41

    prior = inspector.inspect_prior_backup(restore.manifest)
    assert (
        prior.classification
        is access.PriorBackupClassification.OWNED_BY_RETAINED_LIFECYCLE
    )
    retired = inspector.retire_owned_prior_backup(restore.manifest)
    assert retired == access.PriorBackupContinuityResult(
        access.PriorBackupClassification.NONE, retired=True
    )

    inspector.retire_terminal()

    assert not journal_path.exists()
    assert not anchor_path.exists()
    inspector.close()

    fresh = access.FullPreflightLifecycleController(_r47_inspection_broker())
    assert fresh.state is access.LifecycleState.BASELINE
    assert fresh._journal.lifecycle_generation != terminal_generation
    assert json.loads(journal_path.read_bytes())["revision"] == 0
    assert anchor_path.is_file()
    fresh.close()


def test_r47_terminal_retirement_requires_source_proof() -> None:
    _r47_retained_restore_failed()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    before = (journal_path.read_bytes(), anchor_path.read_bytes())
    inspector = access.RetainedTerminalLifecycleInspector(_r47_inspection_broker())

    with pytest.raises(
        access.LifecycleControllerError,
        match="LIFECYCLE_TERMINAL_RETIREMENT_NOT_AUTHORIZED",
    ):
        inspector.retire_terminal()

    assert (journal_path.read_bytes(), anchor_path.read_bytes()) == before
    inspector.close()


@pytest.mark.parametrize(
    "classification",
    (
        access.CurrentSourceClassification.EXACT_PR45,
        access.CurrentSourceClassification.OTHER,
        access.CurrentSourceClassification.INDETERMINATE,
    ),
)
def test_r47_terminal_retirement_rejects_non_pr41(
    classification: access.CurrentSourceClassification,
) -> None:
    candidate, restore = _r47_retained_restore_failed()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    before = (journal_path.read_bytes(), anchor_path.read_bytes())
    broker = _r47_inspection_broker()
    broker.queue(
        "current_source_inventory",
        (
            access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")
            if classification is access.CurrentSourceClassification.INDETERMINATE
            else access.CurrentSourceInventoryResult(classification)
        ),
    )
    inspector = access.RetainedTerminalLifecycleInspector(broker)

    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)
    with pytest.raises(
        access.LifecycleControllerError,
        match="LIFECYCLE_TERMINAL_RETIREMENT_NOT_AUTHORIZED",
    ):
        inspector.retire_terminal()

    assert result.classification is classification
    assert inspector.metadata.state is access.LifecycleState.RESTORE_FAILED
    assert (journal_path.read_bytes(), anchor_path.read_bytes()) == before
    inspector.close()


def test_r47_normal_controller_still_rejects_retained_terminal() -> None:
    _r47_retained_restore_failed()

    with pytest.raises(
        access.LifecycleControllerError, match="LIFECYCLE_TERMINAL_RETAINED"
    ):
        access.FullPreflightLifecycleController(_r47_inspection_broker())


def test_r47_active_lifecycle_cannot_open_terminal_retirement() -> None:
    active, _ = _r33_controller()
    assert active.state is access.LifecycleState.BASELINE
    active.close()

    with pytest.raises(
        access.LifecycleControllerError, match="LIFECYCLE_TERMINAL_REQUIRED"
    ):
        access.RetainedTerminalLifecycleInspector(_r47_inspection_broker())


def _r61_pre_r59_restore_failed() -> tuple[object, object, Path, Path]:
    """Construct the retained R58 layout directly from its known field contract."""
    candidate, restore = _r47_retained_restore_failed()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    record = json.loads(journal_path.read_text(encoding="ascii"))
    record["schema_version"] = 1
    record.pop("restart_results")
    assert set(record) == access._DurableLifecycleJournal._V1_PRE_R59_TOP_LEVEL_KEYS
    journal_path.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")), encoding="ascii"
    )
    return candidate, restore, journal_path, anchor_path


def test_r61_j1_j2_exact_pre_r59_terminal_is_the_only_missing_member(
    tmp_path: Path,
) -> None:
    """J1/J2: the R60 failure is the absent R59-only member, not corruption."""
    _candidate, _restore, journal_path, _anchor_path = _r61_pre_r59_restore_failed()
    record = json.loads(journal_path.read_text(encoding="ascii"))

    assert record["schema_version"] == 1
    assert "restart_results" not in record
    assert access._DurableLifecycleJournal._validate_record(record) is (
        access.LifecycleJournalFormat.V1_PRE_R59
    )
    assert tmp_path / "lifecycle" == access._LIFECYCLE_STATE_ROOT


def test_r61_j3_j6_legacy_terminal_open_is_neutral_and_requires_pr41_proof() -> None:
    """J3--J6: recognized legacy terminals remain inspectable but gated."""
    candidate, restore, journal_path, anchor_path = _r61_pre_r59_restore_failed()
    before = (journal_path.read_bytes(), anchor_path.read_bytes())
    inspector = access.RetainedTerminalLifecycleInspector(_r47_inspection_broker())

    assert inspector.journal_format is access.LifecycleJournalFormat.V1_PRE_R59
    assert inspector.metadata.state is access.LifecycleState.RESTORE_FAILED
    with pytest.raises(
        access.LifecycleControllerError,
        match="LIFECYCLE_TERMINAL_RETIREMENT_NOT_AUTHORIZED",
    ):
        inspector.retire_terminal()
    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)

    assert result.classification is access.CurrentSourceClassification.EXACT_PR41
    assert (journal_path.read_bytes(), anchor_path.read_bytes()) == before
    inspector.close()


def test_r61_j7_to_j10_legacy_backup_and_terminal_retirement_keep_existing_gates() -> (
    None
):
    """J7--J10: only exact owned backup can be retired before terminal closure."""
    candidate, restore, journal_path, anchor_path = _r61_pre_r59_restore_failed()
    inspector = access.RetainedTerminalLifecycleInspector(_r47_inspection_broker())
    inspector.inspect_current_source(candidate.manifest, restore.manifest)

    assert inspector.inspect_prior_backup(restore.manifest).classification is (
        access.PriorBackupClassification.OWNED_BY_RETAINED_LIFECYCLE
    )
    assert inspector.retire_owned_prior_backup(restore.manifest) == (
        access.PriorBackupContinuityResult(access.PriorBackupClassification.NONE, True)
    )
    inspector.retire_terminal()

    assert not journal_path.exists()
    assert not anchor_path.exists()
    inspector.close()


def test_r61_j9_foreign_legacy_backup_remains_non_retirable() -> None:
    """J9: legacy recognition does not relax backup ownership."""
    candidate, restore, _journal_path, _anchor_path = _r61_pre_r59_restore_failed()
    broker = _r47_inspection_broker()
    inspector = access.RetainedTerminalLifecycleInspector(broker)
    inspector.inspect_current_source(candidate.manifest, restore.manifest)
    broker.queue(
        "prior_backup",
        access.PriorBackupContinuityResult(
            access.PriorBackupClassification.OTHER_OR_INDETERMINATE
        ),
    )

    assert inspector.inspect_prior_backup(restore.manifest).classification is (
        access.PriorBackupClassification.OTHER_OR_INDETERMINATE
    )
    with pytest.raises(
        access.LifecycleControllerError,
        match="PRIOR_BACKUP_RETIREMENT_NOT_AUTHORIZED",
    ):
        inspector.retire_owned_prior_backup(restore.manifest)
    inspector.close()


def test_r61_j11_j12_new_lifecycle_writes_and_reconstructs_v2() -> None:
    """J11/J12: new records use the current explicit format without downgrade."""
    controller, _broker = _r33_controller()
    _candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.close()
    journal_path = access._LIFECYCLE_STATE_ROOT / access._LIFECYCLE_JOURNAL_NAME

    assert json.loads(journal_path.read_text(encoding="ascii"))["schema_version"] == 2
    reconstructed, _reconstructed_broker = _r33_controller()
    assert (
        reconstructed._journal.journal_format
        is access.LifecycleJournalFormat.V2_CURRENT
    )
    assert reconstructed.state is access.LifecycleState.RECOVERY_REQUIRED
    reconstructed.close()


def test_r61_j13_j14_transitional_r59_remains_readable_and_strict() -> None:
    """J13/J14: exact R59 shape remains readable; malformed results do not."""
    controller, _broker = _r33_advance_to_candidate_core()
    controller.restart_for_candidate()
    controller.close()
    journal_path = access._LIFECYCLE_STATE_ROOT / access._LIFECYCLE_JOURNAL_NAME
    record = json.loads(journal_path.read_text(encoding="ascii"))
    record["schema_version"] = 1
    journal_path.write_text(json.dumps(record, sort_keys=True), encoding="ascii")

    journal = access._DurableLifecycleJournal()
    assert journal.journal_format is access.LifecycleJournalFormat.V1_R59_TRANSITIONAL
    journal.close()
    record["restart_results"]["activation_restart"]["http_status"] = True
    journal_path.write_text(json.dumps(record, sort_keys=True), encoding="ascii")
    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal()


def test_r61_j15_active_pre_r59_restart_history_is_recognized_but_not_resumed() -> None:
    """J15: absence never becomes an invented R59 restart outcome."""
    controller, _broker = _r33_advance_to_candidate_core()
    controller.restart_for_candidate()
    controller.close()
    journal_path = access._LIFECYCLE_STATE_ROOT / access._LIFECYCLE_JOURNAL_NAME
    record = json.loads(journal_path.read_text(encoding="ascii"))
    record["schema_version"] = 1
    record.pop("restart_results")
    journal_path.write_text(json.dumps(record, sort_keys=True), encoding="ascii")

    with pytest.raises(
        access.LifecycleControllerError, match="LIFECYCLE_LEGACY_ACTIVE_UNSUPPORTED"
    ):
        access._DurableLifecycleJournal()


@pytest.mark.parametrize(
    ("name", "mutate"),
    (
        ("J16", lambda record: record.__setitem__("unexpected", True)),
        ("J17", lambda record: record.__setitem__("schema_version", 99)),
        ("J18", lambda record: record.pop("restart_results")),
    ),
)
def test_r61_j16_to_j18_unknown_or_incomplete_format_remains_invalid(
    name: str, mutate: object
) -> None:
    """J16--J18: only the three explicitly recognized layouts are valid."""
    controller, _broker = _r33_controller()
    controller.close()
    journal_path = access._LIFECYCLE_STATE_ROOT / access._LIFECYCLE_JOURNAL_NAME
    record = json.loads(journal_path.read_text(encoding="ascii"))
    assert callable(mutate)
    mutate(record)
    journal_path.write_text(json.dumps(record, sort_keys=True), encoding="ascii")

    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal()
    assert name.startswith("J")


def test_r61_j19_j20_malformed_v2_restart_and_anchor_mismatch_are_blocking() -> None:
    """J19/J20: current restart semantics and the anchor binding remain strict."""
    controller, _broker = _r33_advance_to_candidate_core()
    controller.restart_for_candidate()
    controller.close()
    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    record = json.loads(journal_path.read_text(encoding="ascii"))
    record["restart_results"]["activation_restart"]["failure_reason"] = "invalid"
    journal_path.write_text(json.dumps(record, sort_keys=True), encoding="ascii")
    with pytest.raises(access.LifecycleControllerError, match="JOURNAL_INVALID"):
        access._DurableLifecycleJournal()

    record["restart_results"]["activation_restart"]["failure_reason"] = None
    journal_path.write_text(json.dumps(record, sort_keys=True), encoding="ascii")
    anchor = json.loads(anchor_path.read_text(encoding="ascii"))
    anchor["original_lifecycle_generation"] = "0" * 32
    anchor_path.write_text(json.dumps(anchor, sort_keys=True), encoding="ascii")
    with pytest.raises(access.LifecycleControllerError, match="ANCHOR_INVALID"):
        access._DurableLifecycleJournal()


@pytest.mark.parametrize(
    ("classification", "exact_states", "failure", "expected_calls"),
    (
        (access.CurrentSourceClassification.EXACT_PR41, (True,), None, 1),
        (access.CurrentSourceClassification.EXACT_PR45, (False, True), None, 2),
        (access.CurrentSourceClassification.OTHER, (False, False), None, 2),
        (
            access.CurrentSourceClassification.INDETERMINATE,
            (),
            access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT"),
            1,
        ),
    ),
)
def test_r44_real_current_source_inventory_has_four_bounded_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    classification: access.CurrentSourceClassification,
    exact_states: tuple[bool, ...],
    failure: BaseException | None,
    expected_calls: int,
) -> None:
    broker = _r32_unbound_real_broker()
    controller = access.FullPreflightLifecycleController(broker)
    candidate, restore = _r32_bundles()
    calls = 0

    def execute(*_args: object, **_kwargs: object) -> bytes:
        nonlocal calls
        calls += 1
        if failure is not None:
            raise failure
        manifest = restore.manifest if calls == 1 else candidate.manifest
        exact = exact_states[calls - 1]
        count = len(manifest.entries)
        return json.dumps(
            {
                "expected_count": count,
                "observed_managed_count": count if exact else count - 1,
                "manifest_match": exact,
                "unexpected_count": 0,
                "missing_count": 0 if exact else 1,
                "content_mismatch_count": 0,
                "runtime_cache_file_count": 0,
                "managed_manifest_identity": "a" * 64,
                "root_profile": "DIRECT_CONFIG",
            }
        ).encode("ascii")

    monkeypatch.setattr(
        broker,
        "_PrivateInteractiveSessionBroker__execute_bounded_operation",
        execute,
    )

    result = controller.inspect_current_source(candidate.manifest, restore.manifest)

    assert result.classification is classification
    assert calls == expected_calls
    assert (result.evidence is not None) == (
        classification
        in {
            access.CurrentSourceClassification.EXACT_PR41,
            access.CurrentSourceClassification.EXACT_PR45,
            access.CurrentSourceClassification.OTHER,
        }
    )
    if classification is access.CurrentSourceClassification.INDETERMINATE:
        assert result.failure_stage is access.DispatchFailureStage.UNKNOWN
        assert result.failure_class is access.DispatchFailureClass.TIMEOUT
    else:
        assert result.failure_stage is None
        assert result.failure_class is None
    controller.close()


@pytest.mark.parametrize(
    ("failure_location", "expected_stage", "expected_class"),
    (
        (
            "control",
            access.DispatchFailureStage.CONTROL_PROGRAM,
            access.DispatchFailureClass.CHILD_EXIT,
        ),
        (
            "wait",
            access.DispatchFailureStage.RESPONSE_WAIT,
            access.DispatchFailureClass.TIMEOUT,
        ),
        (
            "parse",
            access.DispatchFailureStage.RESPONSE_PARSE,
            access.DispatchFailureClass.FRAMING,
        ),
    ),
)
def test_r50_current_source_inventory_preserves_bounded_failure(
    monkeypatch: pytest.MonkeyPatch,
    failure_location: str,
    expected_stage: access.DispatchFailureStage,
    expected_class: access.DispatchFailureClass,
) -> None:
    broker = _r32_unbound_real_broker()
    controller = access.FullPreflightLifecycleController(broker)
    candidate, restore = _r32_bundles()
    if failure_location == "control":

        def write(_packet: object) -> None:
            raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED")

        monkeypatch.setattr(
            broker, "_PrivateInteractiveSessionBroker__write_wire", write
        )
        monkeypatch.setattr(broker, "_read_until", lambda *_args, **_kwargs: b"")
    elif failure_location == "wait":
        reads = 0

        def read(*_args: object, **_kwargs: object) -> bytes:
            nonlocal reads
            reads += 1
            if reads == 2:
                raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")
            return b""

        monkeypatch.setattr(
            broker,
            "_PrivateInteractiveSessionBroker__write_wire",
            lambda _packet: None,
        )
        monkeypatch.setattr(broker, "_read_until", read)
    else:
        monkeypatch.setattr(
            broker,
            "_PrivateInteractiveSessionBroker__execute_bounded_operation",
            lambda *_args, **_kwargs: b"synthetic malformed response",
        )

    result = controller.inspect_current_source(candidate.manifest, restore.manifest)

    assert result.classification is access.CurrentSourceClassification.INDETERMINATE
    assert result.failure_stage is expected_stage
    assert result.failure_class is expected_class
    controller.close()


def _r44_controller_at_backup(
    broker: access.PrivateInteractiveSessionBroker,
) -> access.FullPreflightLifecycleController:
    controller = access.FullPreflightLifecycleController(broker)
    journal = controller._journal
    assert journal is not None
    source_generation = journal.source_generation
    action = access.LifecycleAction.INITIAL_REPAIRS
    journal.record_intent(action, source_generation=source_generation, nonce=None)
    journal.record_dispatch_started(action)
    evidence_generation = journal.record_result(
        action,
        lifecycle_generation=journal.lifecycle_generation,
        source_generation=source_generation,
        session_generation="1" * 32,
        issuance_identity="2" * 32,
        audit_instance=None,
        nonce=None,
    )
    journal.transition(
        access.LifecycleState.INITIAL_REPAIRS_PASS,
        action=action,
        source_generation=source_generation,
        evidence_generation=evidence_generation,
    )
    return controller


@pytest.mark.parametrize(
    ("failure_location", "expected_stage"),
    (
        ("control", access.DispatchFailureStage.CONTROL_PROGRAM),
        ("payload", access.DispatchFailureStage.PAYLOAD),
    ),
)
def test_r44_transfer_write_failure_records_bounded_stage(
    monkeypatch: pytest.MonkeyPatch,
    failure_location: str,
    expected_stage: access.DispatchFailureStage,
) -> None:
    broker = _r32_unbound_real_broker()
    controller = _r44_controller_at_backup(broker)
    _candidate, restore = _r32_bundles()
    program_chunks = (
        len(base64.b64encode(access._REMOTE_CONTROL_PROGRAM.encode("utf-8")))
        + access._TRANSFER_CHUNK_SIZE
        - 1
    ) // access._TRANSFER_CHUNK_SIZE
    failure_write = 1 if failure_location == "control" else program_chunks + 3
    writes = 0

    def write(_packet: object) -> None:
        nonlocal writes
        writes += 1
        if writes == failure_write:
            raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_CHILD_EXITED")

    monkeypatch.setattr(broker, "_PrivateInteractiveSessionBroker__write_wire", write)
    monkeypatch.setattr(broker, "_read_until", lambda *_args, **_kwargs: b"")

    with pytest.raises(access.LifecycleControllerError, match="BACKUP_VERIFICATION"):
        controller.create_backup(restore.manifest)

    operation = controller._journal._record["operations"][-1]
    assert operation["phase"] == "ambiguous"
    assert operation["failure_stage"] == expected_stage.value
    assert operation["failure_class"] == access.DispatchFailureClass.CHILD_EXIT.value
    controller.close()


@pytest.mark.parametrize(
    ("failure_location", "expected_stage", "expected_class"),
    (
        (
            "wait",
            access.DispatchFailureStage.RESPONSE_WAIT,
            access.DispatchFailureClass.TIMEOUT,
        ),
        (
            "parse",
            access.DispatchFailureStage.RESPONSE_PARSE,
            access.DispatchFailureClass.FRAMING,
        ),
    ),
)
def test_r44_response_failure_records_bounded_stage_and_class(
    monkeypatch: pytest.MonkeyPatch,
    failure_location: str,
    expected_stage: access.DispatchFailureStage,
    expected_class: access.DispatchFailureClass,
) -> None:
    broker = _r32_unbound_real_broker()
    controller = _r44_controller_at_backup(broker)
    _candidate, restore = _r32_bundles()
    if failure_location == "wait":
        reads = 0

        def read(*_args: object, **_kwargs: object) -> bytes:
            nonlocal reads
            reads += 1
            if reads == 2:
                raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")
            return b""

        monkeypatch.setattr(
            broker,
            "_PrivateInteractiveSessionBroker__write_wire",
            lambda _packet: None,
        )
        monkeypatch.setattr(broker, "_read_until", read)
    else:
        monkeypatch.setattr(
            broker,
            "_PrivateInteractiveSessionBroker__execute_bounded_operation",
            lambda *_args, **_kwargs: b"synthetic malformed response",
        )

    with pytest.raises(access.LifecycleControllerError, match="BACKUP_VERIFICATION"):
        controller.create_backup(restore.manifest)

    operation = controller._journal._record["operations"][-1]
    assert operation["failure_stage"] == expected_stage.value
    assert operation["failure_class"] == expected_class.value
    controller.close()


def test_r55_backup_remote_failure_is_durable_and_reconstructable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(access, "_DISABLE_DURABLE_LIFECYCLE_FOR_TESTS", False)
    broker = _r32_unbound_real_broker()
    controller = _r44_controller_at_backup(broker)
    _candidate, restore = _r32_bundles()
    monkeypatch.setattr(
        broker,
        "_PrivateInteractiveSessionBroker__execute_bounded_operation",
        lambda *_args, **_kwargs: json.dumps(
            {
                "error_class": "OPERATION_FAILED",
                "error_scope": "BACKUP",
                "error_reason": "FILESYSTEM",
            }
        ).encode("ascii"),
    )

    with pytest.raises(access.LifecycleControllerError, match="BACKUP_VERIFICATION"):
        controller.create_backup(restore.manifest)

    operation = controller._journal._record["operations"][-1]
    assert operation["failure_stage"] == "RESPONSE_PARSE"
    assert operation["failure_class"] == "remote_operation"
    assert operation["remote_failure_scope"] == "BACKUP"
    assert operation["remote_failure_reason"] == "FILESYSTEM"
    controller.close()

    reconstructed = access._DurableLifecycleJournal()
    assert reconstructed._record["operations"][-1] == operation
    reconstructed.close()


def test_r55_transfer_remote_failure_is_durable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(access, "_DISABLE_DURABLE_LIFECYCLE_FOR_TESTS", False)
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    broker.queue(
        "transfer",
        access._DispatchFailure(
            access.DispatchFailureStage.RESPONSE_PARSE,
            access.DispatchFailureClass.REMOTE_OPERATION,
            access.RemoteFailureScope.TRANSFER,
            access.RemoteFailureReason.FILESYSTEM,
        ),
    )

    with pytest.raises(access.LifecycleControllerError, match="CANDIDATE_TRANSFER"):
        controller.stage_candidate(candidate)

    operation = controller._journal._record["operations"][-1]
    assert operation["failure_stage"] == "RESPONSE_PARSE"
    assert operation["failure_class"] == "remote_operation"
    assert operation["remote_failure_scope"] == "TRANSFER"
    assert operation["remote_failure_reason"] == "FILESYSTEM"
    controller.close()


def test_r55_historical_remote_failure_without_optional_metadata_loads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(access, "_DISABLE_DURABLE_LIFECYCLE_FOR_TESTS", False)
    broker = _r32_unbound_real_broker()
    controller = _r44_controller_at_backup(broker)
    journal = controller._journal
    action = access.LifecycleAction.BACKUP
    journal.record_intent(
        action,
        source_generation=journal._record["pr41_restore"]["generation"],
        nonce=None,
    )
    journal.record_dispatch_started(action)
    journal.record_ambiguous(
        action,
        access.DispatchFailureStage.RESPONSE_PARSE,
        access.DispatchFailureClass.REMOTE_OPERATION,
    )
    controller.close()

    reconstructed = access._DurableLifecycleJournal()
    operation = reconstructed._record["operations"][-1]
    assert operation["failure_class"] == "remote_operation"
    assert "remote_failure_scope" not in operation
    assert "remote_failure_reason" not in operation
    reconstructed.close()


def test_r44_raw_callback_exception_text_is_not_persisted() -> None:
    controller, broker = _r33_controller()
    _candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    raw_text = "synthetic private callback path /not/persisted"
    broker.queue("backup", RuntimeError(raw_text))

    with pytest.raises(RuntimeError, match="not/persisted"):
        controller.create_backup(restore.manifest)

    journal_path = access._LIFECYCLE_STATE_ROOT / access._LIFECYCLE_JOURNAL_NAME
    persisted = journal_path.read_text(encoding="ascii")
    operation = controller._journal._record["operations"][-1]
    assert raw_text not in persisted
    assert operation["failure_stage"] == access.DispatchFailureStage.CALLBACK.value
    assert operation["failure_class"] == access.DispatchFailureClass.CALLBACK.value
    controller.close()


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


def test_r58_parent_rejects_current_supervisor_success_for_candidate() -> None:
    controller, broker = _r32_controller()
    controller._state = access.LifecycleState.CANDIDATE_INVENTORY_VERIFIED
    broker.queue(
        "core_check",
        access._parse_core_check_result(
            {"http_status": 200, "result": "ok"}, attempt_ordinal=1
        ),
    )

    result = controller.check_candidate_core()

    assert result.check_passed is True
    assert controller.state is access.LifecycleState.CANDIDATE_CORE_CHECKED
    assert [detail for name, detail in broker.calls if name == "core_check"] == [1]


def test_r58_parent_reproduces_candidate_and_restore_double_failure() -> None:
    current_success = access._parse_core_check_result(
        {"http_status": 200, "result": "ok"}, attempt_ordinal=1
    )
    candidate, candidate_broker = _r32_controller()
    candidate._state = access.LifecycleState.CANDIDATE_INVENTORY_VERIFIED
    candidate_broker.queue("core_check", current_success)

    candidate.check_candidate_core()

    restored, restore_broker = _r32_controller()
    restored._state = access.LifecycleState.RESTORE_INVENTORY_VERIFIED
    restore_broker.queue(
        "core_check",
        access._parse_core_check_result(
            {"http_status": 200, "result": "ok"}, attempt_ordinal=1
        ),
    )

    restore_result = restored.check_restore_core()

    assert candidate.state is access.LifecycleState.CANDIDATE_CORE_CHECKED
    assert restore_result.check_passed is True
    assert restored.state is access.LifecycleState.RESTORE_CORE_CHECKED
    assert [
        detail for name, detail in candidate_broker.calls if name == "core_check"
    ] == [1]
    assert [
        detail for name, detail in restore_broker.calls if name == "core_check"
    ] == [1]


def _r58_create_remote_backup(tmp_path: Path) -> dict[str, object]:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    context = _r36_backup_payload()
    created = _run_synthetic_remote_program(tmp_path, "backup", context)
    assert created["success"] is True
    return {
        **context,
        "backup_generation": created["backup_generation"],
        "manifest_identity": created["manifest_identity"],
        "backup_digest": created["backup_digest"],
        "restore_marker_owned": False,
    }


def test_r58_owned_retained_backup_is_retired_and_fresh_backup_can_be_created(
    tmp_path: Path,
) -> None:
    retained_context = _r58_create_remote_backup(tmp_path)

    inspected = _run_synthetic_remote_program(
        tmp_path, "inspect_retained_backup", retained_context
    )
    retired = _run_synthetic_remote_program(
        tmp_path, "retire_retained_backup", retained_context
    )
    fresh_context = _r36_backup_payload(
        lifecycle_generation="c" * 32, source_generation="d" * 32
    )
    fresh = _run_synthetic_remote_program(tmp_path, "backup", fresh_context)

    assert inspected == {
        "classification": "OWNED_BY_RETAINED_LIFECYCLE",
        "retired": False,
    }
    assert retired == {"classification": "NONE", "retired": True}
    assert fresh["success"] is True
    assert fresh["lifecycle_generation"] == "c" * 32
    assert fresh["backup_generation"] != retained_context["backup_generation"]


def test_r58_foreign_or_indeterminate_backup_cannot_be_retired(tmp_path: Path) -> None:
    retained_context = _r58_create_remote_backup(tmp_path)
    foreign_context = dict(retained_context)
    foreign_context["lifecycle_generation"] = "e" * 32

    inspected = _run_synthetic_remote_program(
        tmp_path, "inspect_retained_backup", foreign_context
    )
    retired = _run_synthetic_remote_program(
        tmp_path, "retire_retained_backup", foreign_context
    )

    assert inspected == {
        "classification": "OTHER_OR_INDETERMINATE",
        "retired": False,
    }
    assert retired == inspected
    assert (tmp_path / ".ha_tuya_ble_r36_backup").is_dir()


def test_r58_absent_retained_backup_is_classified_none(tmp_path: Path) -> None:
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    context = {
        **_r36_backup_payload(),
        "backup_generation": "c" * 32,
        "manifest_identity": access._source_manifest_digest(
            _r30_manifest("RESTORE").entries
        ),
        "backup_digest": "d" * 64,
        "restore_marker_owned": False,
    }

    result = _run_synthetic_remote_program(tmp_path, "inspect_retained_backup", context)

    assert result == {"classification": "NONE", "retired": False}


def test_r58_committed_restore_marker_is_retired_with_owned_backup(
    tmp_path: Path,
) -> None:
    retained_context = _r58_create_remote_backup(tmp_path)
    retained_context["restore_marker_owned"] = True
    marker = tmp_path / ".ha_tuya_ble_r30_restore.consumed"
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    marker.chmod(0o600)

    inspected = _run_synthetic_remote_program(
        tmp_path, "inspect_retained_backup", retained_context
    )
    retired = _run_synthetic_remote_program(
        tmp_path, "retire_retained_backup", retained_context
    )

    assert inspected == {
        "classification": "OWNED_BY_RETAINED_LIFECYCLE",
        "retired": False,
    }
    assert retired == {"classification": "NONE", "retired": True}
    assert not marker.exists()


def test_r58_owned_restore_marker_surviving_partial_retirement_is_retired(
    tmp_path: Path,
) -> None:
    retained_context = _r58_create_remote_backup(tmp_path)
    retained_context["restore_marker_owned"] = True
    marker = tmp_path / ".ha_tuya_ble_r30_restore.consumed"
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    marker.chmod(0o600)
    shutil.rmtree(tmp_path / ".ha_tuya_ble_r36_backup")

    inspected = _run_synthetic_remote_program(
        tmp_path, "inspect_retained_backup", retained_context
    )
    retired = _run_synthetic_remote_program(
        tmp_path, "retire_retained_backup", retained_context
    )

    assert inspected == {
        "classification": "OWNED_BY_RETAINED_LIFECYCLE",
        "retired": False,
    }
    assert retired == {"classification": "NONE", "retired": True}
    assert not marker.exists()


def test_r62_valid_preflight_commits_result_and_transition_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R61 must not stop between durable PREFLIGHT evidence and its transition."""
    controller, broker = _r33_advance_to_ap0()
    journal = controller._journal
    original_transition = journal.transition

    def reject_split_preflight_transition(
        state: access.LifecycleState,
        *,
        action: access.LifecycleAction | None,
        source_generation: str,
        evidence_generation: int | None,
        recovery: bool = False,
        terminal: bool = False,
    ) -> None:
        if action is access.LifecycleAction.PREFLIGHT:
            raise access.LifecycleControllerError("LIFECYCLE_JOURNAL_INVALID")
        original_transition(
            state,
            action=action,
            source_generation=source_generation,
            evidence_generation=evidence_generation,
            recovery=recovery,
            terminal=terminal,
        )

    monkeypatch.setattr(journal, "transition", reject_split_preflight_transition)

    result = controller.run_non_probe_preflight()

    assert result.operation is access.PhaseAOperation.PREFLIGHT
    assert result.http_status is None
    assert controller.state is access.LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED
    assert journal.action_transition_committed(access.LifecycleAction.PREFLIGHT)
    assert journal._record["consumed_operations"].count("preflight") == 1
    assert (
        len(
            [
                identity
                for identity in journal._record["evidence_identities"]
                if identity["action"] == "preflight"
            ]
        )
        == 1
    )
    assert [name for name, _detail in broker.calls].count("helper") == 3
    controller.collect_a1()
    controller.validate_research_final()
    controller.collect_a2()
    proof = _r32_complete_restore_tail(controller, _r32_bundles()[1])

    assert proof.complete is True
    assert controller.state is access.LifecycleState.COMPLETE_NORMAL
    assert [name for name, _detail in broker.calls].count("helper") == 5
    assert journal._record["consumed_operations"].count("preflight") == 1
    assert "PROBE" not in access.LifecycleAction.__members__
    assert "RECEIPT" not in access.LifecycleAction.__members__
    assert journal._record["restart_tombstones"] == [
        access.LifecycleAction.ACTIVATION_RESTART.value,
        access.LifecycleAction.REMOVAL_RESTART.value,
    ]
    controller.close()


def _r63s_complete_result() -> access.RemotePhaseAInventoryResult:
    slots = tuple(
        access.RemotePhaseASlotSummary(
            f"R{index:02d}",
            "cold_then_retained" if index <= 5 else "cold",
            2 if index <= 5 else 1,
            "ack_success",
            "ack_success" if index <= 5 else None,
            index <= 5,
            True,
            False,
            False,
            False,
        )
        for index in range(1, 11)
    )
    rows = tuple(
        access.RemotePhaseADPInventory(
            dp_id,
            10,
            10,
            5,
            5,
            ("DT_VALUE",),
            (4,),
            ("DT_BOOL",),
            (1,),
            "ALWAYS_REPORTED",
        )
        for dp_id in (8, 21, 33, 34, 36, 40, 47)
    )
    return access.RemotePhaseAInventoryResult(
        "complete",
        1,
        True,
        True,
        10,
        10,
        5,
        15,
        10,
        5,
        0,
        0,
        0,
        0,
        10,
        5,
        0,
        0,
        0,
        0,
        slots,
        rows,
        None,
        None,
        None,
        None,
        False,
    )


def _r63t_ready_result() -> access.RemotePhaseAReadinessResult:
    return access.RemotePhaseAReadinessResult(
        True,
        1,
        True,
        True,
        True,
        True,
        True,
        None,
        None,
    )


def _r63s_controller_at_a2() -> tuple[object, _R32ScriptedBroker]:
    controller, broker = _r33_advance_to_ap0()
    controller.run_non_probe_preflight()
    controller.collect_a1()
    controller.validate_research_final()
    controller.collect_a2()
    return controller, broker


def test_r63s_fixed_research_session_is_state_neutral_and_one_shot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller, broker = _r63s_controller_at_a2()
    before = copy.deepcopy(controller._journal._record)
    expected = _r63s_complete_result()
    seen: list[object] = []

    def run(
        baseline: access.AuditSnapshot, *, _capability: object = None
    ) -> access.RemotePhaseAInventoryResult:
        assert isinstance(baseline, access.AuditSnapshot)
        assert type(_capability) is access._RemotePhaseAResearchCapability
        assert _capability.controller is controller
        broker._controller_binding[1].consumed.append(_capability)
        seen.append(_capability)
        if _capability.operation is access.ResearchOperation.CHECK_READINESS:
            return _r63t_ready_result()
        assert _capability.operation is access.ResearchOperation.RUN_FIXED_INVENTORY
        return expected

    monkeypatch.setattr(broker, "_invoke_remote_phase_a_research", run, raising=False)
    session = controller.open_remote_phase_a_inventory_session()

    assert repr(session) == "RemotePhaseAInventorySession(ran=False, closed=False)"
    assert controller.state is access.LifecycleState.A2_COLLECTED
    with pytest.raises(
        access.LifecycleControllerError, match="RESEARCH_SESSION_ACTIVE"
    ):
        controller.stage_restore(_r32_bundles()[1])

    readiness = session.check_readiness()
    result = session.run_remote_phase_a_inventory()

    assert readiness.ready is True
    assert result == expected
    assert len(seen) == 2
    assert controller.state is access.LifecycleState.A2_COLLECTED
    assert controller._journal._record == before
    with pytest.raises(
        access.LifecycleControllerError, match="RESEARCH_SESSION_CONSUMED"
    ):
        session.run_remote_phase_a_inventory()

    session.close()
    assert controller._journal._record == before
    with pytest.raises(
        access.LifecycleControllerError, match="RESEARCH_SESSION_INVALID"
    ):
        controller.open_remote_phase_a_inventory_session()
    proof = _r32_complete_restore_tail(controller, _r32_bundles()[1])
    assert proof.complete is True
    assert controller.state is access.LifecycleState.COMPLETE_NORMAL
    controller.close()


def test_r63s_research_session_cannot_open_before_a2_or_be_constructed() -> None:
    controller, broker = _r33_advance_to_ap0()
    with pytest.raises(access.LifecycleControllerError, match="TRANSITION_INVALID"):
        controller.open_remote_phase_a_inventory_session()
    with pytest.raises(
        access.LifecycleControllerError, match="RESEARCH_SESSION_INVALID"
    ):
        access.RemotePhaseAInventorySession(controller, broker, object(), object())
    assert not any(name == "research" for name, _detail in broker.calls)
    controller.close()


def test_r63s_public_surface_and_normal_lifecycle_remain_narrow() -> None:
    assert "PROBE" not in access.LifecycleAction.__members__
    assert "PROBE" not in access.PhaseAOperation.__members__
    assert tuple(access.ResearchOperation) == (
        access.ResearchOperation.CHECK_READINESS,
        access.ResearchOperation.RUN_FIXED_INVENTORY,
    )
    signature = inspect.signature(
        access.RemotePhaseAInventorySession.run_remote_phase_a_inventory
    )
    assert tuple(signature.parameters) == ("self",)
    public = {
        name
        for name, value in vars(access.RemotePhaseAInventorySession).items()
        if callable(value) and not name.startswith("_")
    }
    assert public == {"check_readiness", "run_remote_phase_a_inventory", "close"}
    source = inspect.getsource(access.RemotePhaseAInventorySession)
    for forbidden in (
        "config_entry_id",
        "nonce:",
        "command",
        "argv",
        "endpoint",
        "evidence_path",
        "send_shell",
    ):
        assert forbidden not in source


def test_r63s_remote_program_contains_only_fixed_research_plan() -> None:
    source = access._REMOTE_CONTROL_PROGRAM
    assert "remote_phase_a_inventory" in source
    assert "('R01', 'cold_then_retained')" in source
    assert "('R05', 'cold_then_retained')" in source
    assert "('R06', 'cold')" in source
    assert "('R10', 'cold')" in source
    assert "PHASE_A_STATUS_PROBE_CONFIG_ENTRY_ID" in source
    assert "jtmspro" in source and "xqeob8h6" in source
    assert "elif operation == 'probe'" not in source
    assert "LifecycleAction.PROBE" not in source


def test_r63s_result_parser_enforces_budgets_and_rejects_private_extras() -> None:
    expected = _r63s_complete_result()
    payload = asdict(expected)
    payload["slots"] = [dict(item) for item in payload["slots"]]
    payload["dp_inventory"] = [
        {
            **dict(item),
            "cold_type_set": list(item["cold_type_set"]),
            "cold_encoded_length_set": list(item["cold_encoded_length_set"]),
            "retained_type_set": list(item["retained_type_set"]),
            "retained_encoded_length_set": list(item["retained_encoded_length_set"]),
        }
        for item in payload["dp_inventory"]
    ]
    framed = json.dumps(payload, separators=(",", ":")).encode()
    assert access._parse_remote_phase_a_inventory_result(framed) == expected

    over_budget = copy.deepcopy(payload)
    over_budget["cold_request_count"] = 11
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_remote_phase_a_inventory_result(json.dumps(over_budget).encode())

    private = copy.deepcopy(payload)
    private["config_entry_id"] = "synthetic_private_identifier"
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_remote_phase_a_inventory_result(json.dumps(private).encode())


def _r63s_embedded_function_source(name: str) -> str:
    source = access._REMOTE_CONTROL_PROGRAM
    tree = ast.parse(source)
    node = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    return ast.get_source_segment(source, node) or ""


def test_r63s_target_resolver_is_exact_deterministic_and_rejects_zero_or_duplicates() -> (
    None
):
    entries = [
        {"domain": "tuya_ble", "state": "loaded", "entry_id": "b" * 32},
        {"domain": "tuya_ble", "state": "loaded", "entry_id": "a" * 32},
    ]

    def request_json(url: str) -> tuple[int, object]:
        if "diagnostics" in url:
            entry_id = url.rsplit("/", 1)[-1]
            return 200, {
                "data": {
                    "entry": {"entry_id": entry_id},
                    "options": {"category": "jtmspro", "product_id": "xqeob8h6"},
                }
            }
        return 200, copy.deepcopy(entries)

    namespace = {"re": __import__("re"), "request_json": request_json}
    exec(  # noqa: S102 - execute only the reviewed embedded function definition
        _r63s_embedded_function_source("loaded_tuya_entries"), namespace
    )
    exec(  # noqa: S102 - execute only the reviewed embedded function definition
        _r63s_embedded_function_source("resolve_research_target"), namespace
    )

    assert namespace["resolve_research_target"]() == (2, "a" * 32)
    entries[:] = [{"domain": "tuya_ble", "state": "loaded", "entry_id": "c" * 32}]
    assert namespace["resolve_research_target"]() == (1, "c" * 32)
    entries[0]["state"] = "not_loaded"
    assert namespace["resolve_research_target"]() == (0, None)
    entries[:] = [
        {"domain": "tuya_ble", "state": "loaded", "entry_id": "d" * 32},
        {"domain": "tuya_ble", "state": "loaded", "entry_id": "d" * 32},
    ]
    with pytest.raises(ValueError, match="research_target"):
        namespace["loaded_tuya_entries"]()


def _r63s_remote_baseline() -> dict[str, object]:
    return {
        "result": "audit_snapshot",
        "protocol_version": 1,
        "audit_instance_token": "a" * 32,
        "event_ordinal": 0,
        "history_overflow": False,
        "runtime_ms": 1,
        "counters": {name: 0 for name in access.AUDIT_COUNTER_NAMES},
        "events": [],
    }


def _r63s_remote_replacements(scenario: str) -> dict[str, str]:
    source = access._REMOTE_CONTROL_PROGRAM
    invoke_start = source.index("def invoke_research_helper")
    invoke_end = source.index("def loaded_tuya_entries")
    original_invoke = source[invoke_start:invoke_end]
    original_target = _r63s_embedded_function_source("resolve_research_target")
    synthetic_invoke = f"""SYN_SCENARIO = {scenario!r}
SYN_PROBES = 0
SYN_RECEIPTS = 0
SYN_STATUS = 0
SYN_WRITES = 0
SYN_PACKETS = 0
SYN_PROBE_NONCE = None
SYN_TARGET = None

def invoke_research_helper(operation, label, nonce, mode=None, target=None):
    global SYN_PROBES, SYN_RECEIPTS, SYN_STATUS, SYN_WRITES, SYN_PACKETS
    global SYN_PROBE_NONCE, SYN_TARGET
    if operation == 'probe':
        SYN_PROBES += 1
        if SYN_TARGET is None:
            SYN_TARGET = target
        if target != SYN_TARGET:
            raise ValueError('research_target')
        SYN_PROBE_NONCE = nonce
        if SYN_SCENARIO in {{'ambiguous', 'ambiguous_pending'}} and SYN_PROBES == 1:
            SYN_STATUS += 1
            return 78, 'transport_ambiguous', None, None
        precondition = SYN_SCENARIO == 'precondition' and SYN_PROBES == 1
        count = 0 if precondition else (2 if mode == 'cold_then_retained' else 1)
        SYN_STATUS += count
        if SYN_SCENARIO == 'write' and SYN_PROBES == 1:
            SYN_WRITES += 1
        if SYN_SCENARIO == 'packet' and SYN_PROBES == 1:
            SYN_PACKETS += 1
        requests = [
            {{'trial': trial, 'result': 'ack_success', 'duration_ms': trial}}
            for trial in range(1, count + 1)
        ]
        events = [
            {{
                'trial': trial, 'observation_ordinal': trial,
                'origin': 'explicit', 'kind': 'DP_BATCH',
                'event_ordinal': trial, 'batch_ordinal': 1,
                'dp_ids': [8, 21],
                'dp_types': (
                    ['DT_VALUE', 'DT_BOOL']
                    if trial == 1 else ['DT_ENUM', 'DT_RAW']
                ),
                'encoded_value_lengths': [4, 1] if trial == 1 else [1, 8],
                'exact_session': True,
                'ack_result': None, 'ack_phase': 'after_ack',
                'monotonic_ms': trial,
            }}
            for trial in range(1, count + 1)
        ]
        result = {{
            'mode': mode,
            'result': 'precondition_failed' if precondition else 'completed',
            'cold_request_attempted': count >= 1,
            'retained_request_attempted': count >= 2,
            'request_count': count,
            'same_session_retained': count == 2,
            'normal_release_observed': count > 0,
            'automatic_reconnect_observed': False,
            'observation_overflow': False,
            'duration_ms': 1,
            'requests': requests,
            'events': events,
            'invocation_nonce': nonce,
        }}
        if SYN_SCENARIO == 'probe_invalid' and SYN_PROBES == 1:
            result['unexpected'] = True
        return (66 if precondition else 0), result['result'], result, None
    if operation == 'receipt':
        if nonce != SYN_PROBE_NONCE:
            raise ValueError('research_nonce')
        SYN_RECEIPTS += 1
        pending = SYN_SCENARIO == 'ambiguous_pending'
        receipt = {{
            'nonce': nonce, 'known': not pending, 'service_entered': not pending,
            'request_handed_to_transport': True,
            'terminal_class': None if pending else 'completed',
            'response_available': False,
        }}
        return (66 if pending else 0), 'receipt', receipt, None
    if operation == 'audit':
        if SYN_SCENARIO == 'audit_failure' and SYN_PROBES == 1:
            raise ValueError('research_audit')
        counters = {{name: 0 for name in COUNTERS}}
        counters['device_status_requests'] = SYN_STATUS
        counters['datapoint_write_operations'] = SYN_WRITES
        counters['datapoint_protocol_packets'] = SYN_PACKETS
        audit = {{
            'result': 'audit_snapshot', 'protocol_version': 1,
            'audit_instance_token': 'a' * 32, 'event_ordinal': SYN_STATUS,
            'history_overflow': False, 'runtime_ms': SYN_PROBES,
            'counters': counters, 'events': [], 'nonce': nonce,
        }}
        return 0, 'audit_snapshot', audit, None
    raise ValueError('research_operation')

"""
    return {
        original_invoke: synthetic_invoke,
        original_target: "def resolve_research_target():\n    return 2, 'a' * 32",
    }


@pytest.mark.parametrize(
    ("scenario", "outcome", "slot_count", "cold", "retained", "receipts"),
    (
        ("complete", "complete", 10, 10, 5, 0),
        ("precondition", "sample_incomplete", 1, 0, 0, 0),
        ("ambiguous", "probe_ambiguous", 1, 1, 0, 1),
        ("ambiguous_pending", "probe_ambiguous", 1, 1, 0, 3),
        ("write", "protocol_write_gate_failed", 1, 1, 1, 0),
        ("packet", "protocol_write_gate_failed", 1, 1, 1, 0),
    ),
)
def test_r63s_remote_fixed_plan_budgets_stops_and_no_replay(
    tmp_path: Path,
    scenario: str,
    outcome: str,
    slot_count: int,
    cold: int,
    retained: int,
    receipts: int,
) -> None:
    (tmp_path / "custom_components" / "tuya_ble").mkdir(parents=True)
    result = _run_synthetic_remote_program(
        tmp_path,
        "remote_phase_a_inventory",
        {"baseline": _r63s_remote_baseline()},
        source_replacements=_r63s_remote_replacements(scenario),
    )

    assert result["outcome"] == outcome
    assert len(result["slots"]) == slot_count
    assert result["cold_request_count"] == cold
    assert result["retained_request_count"] == retained
    assert result["total_device_status_requests"] == cold + retained
    assert result["receipt_lookup_count"] == receipts
    assert result["same_private_target"] is True
    if scenario == "complete":
        assert [slot["mode"] for slot in result["slots"]] == [
            *("cold_then_retained" for _ in range(5)),
            *("cold" for _ in range(5)),
        ]
        assert result["completed_probe_slots"] == 10
        assert result["cold_ack_success_count"] == 10
        assert result["retained_ack_success_count"] == 5
        dp8 = next(item for item in result["dp_inventory"] if item["dp_id"] == 8)
        assert dp8["cold_type_set"] == ["DT_VALUE"]
        assert dp8["cold_encoded_length_set"] == [4]
        assert dp8["retained_type_set"] == ["DT_ENUM"]
        assert dp8["retained_encoded_length_set"] == [1]
    else:
        assert result["completed_probe_slots"] <= 1


def test_r63s_authority_and_privacy_boundaries_remain_fail_closed() -> None:
    controller, _broker = _r63s_controller_at_a2()
    controller._candidate_manifest = None
    with pytest.raises(
        access.LifecycleControllerError, match="RESEARCH_SESSION_INVALID"
    ):
        controller.open_remote_phase_a_inventory_session()
    controller.close()

    result = _r63s_complete_result()
    rendered = repr(result)
    for private_value in (
        "config_entry_id",
        "SUPERVISOR_TOKEN",
        "invocation_nonce",
        "evidence_path",
        "raw_payload",
        "packet_bytes",
        "motor_moved",
    ):
        assert private_value not in rendered


def test_r63s_closed_session_allows_same_durable_a2_restore_reconstruction() -> None:
    controller, broker = _r63s_controller_at_a2()
    broker._invoke_remote_phase_a_research = lambda *_args, **kwargs: (
        _r63t_ready_result()
        if kwargs["_capability"].operation is access.ResearchOperation.CHECK_READINESS
        else _r63s_complete_result()
    )
    session = controller.open_remote_phase_a_inventory_session()
    session.check_readiness()
    session.run_remote_phase_a_inventory()
    session.close()
    controller.close()

    reconstructed_broker = _R32ScriptedBroker()
    reconstructed_broker._durable_lifecycle_test = True
    reconstructed = access.FullPreflightLifecycleController(reconstructed_broker)
    assert reconstructed.state is access.LifecycleState.A2_COLLECTED
    with pytest.raises(
        access.LifecycleControllerError, match="RESEARCH_SESSION_INVALID"
    ):
        reconstructed.open_remote_phase_a_inventory_session()
    proof = _r32_complete_restore_tail(reconstructed, _r32_bundles()[1])
    assert proof.complete is True
    assert reconstructed.state is access.LifecycleState.COMPLETE_NORMAL
    reconstructed.close()


def test_r63t_research_dispatch_failure_preserves_bounded_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller, broker = _r63s_controller_at_a2()
    session = controller.open_remote_phase_a_inventory_session()
    monkeypatch.setattr(
        broker,
        "_invoke_remote_phase_a_research",
        lambda *_args, **_kwargs: _r63t_ready_result(),
        raising=False,
    )
    session.check_readiness()
    failure = access._DispatchFailure(
        access.DispatchFailureStage.RESPONSE_PARSE,
        access.DispatchFailureClass.REMOTE_OPERATION,
        access.RemoteFailureScope.PHASE_A,
        access.RemoteFailureReason.RESEARCH_TARGET,
    )

    def fail(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr(
        broker,
        "_invoke_remote_phase_a_research",
        fail,
        raising=False,
    )

    with pytest.raises(access.RemotePhaseAResearchError) as raised:
        session.run_remote_phase_a_inventory()

    assert str(raised.value) == "REMOTE_PHASE_A_RESEARCH_DISPATCH_FAILED"
    assert raised.value.dispatch_stage is access.DispatchFailureStage.RESPONSE_PARSE
    assert raised.value.dispatch_class is access.DispatchFailureClass.REMOTE_OPERATION
    assert raised.value.remote_scope is access.RemoteFailureScope.PHASE_A
    assert raised.value.remote_reason is access.RemoteFailureReason.RESEARCH_TARGET
    session.close()
    controller.close()


def test_r63t_remote_readiness_fallback_retains_phase_a_scope(tmp_path: Path) -> None:
    (tmp_path / "custom_components" / "tuya_ble").mkdir(parents=True)
    original_readiness = _r63s_embedded_function_source("remote_phase_a_readiness")
    result = _run_synthetic_remote_program(
        tmp_path,
        "remote_phase_a_readiness",
        {"baseline": _r63s_remote_baseline()},
        source_replacements={
            original_readiness: (
                "def remote_phase_a_readiness(value):\n"
                "    raise RuntimeError('synthetic-private-error')"
            )
        },
    )

    assert result == {
        "error_class": "OPERATION_FAILED",
        "error_scope": "PHASE_A",
        "error_reason": "UNKNOWN",
    }
    assert "synthetic-private-error" not in repr(result)


def test_r63t_session_requires_device_free_readiness_before_inventory() -> None:
    controller, broker = _r63s_controller_at_a2()
    session = controller.open_remote_phase_a_inventory_session()

    with pytest.raises(
        access.LifecycleControllerError,
        match="RESEARCH_READINESS_REQUIRED",
    ):
        session.run_remote_phase_a_inventory()

    assert not any(name == "research" for name, _detail in broker.calls)
    session.close()
    controller.close()


def test_r63t_readiness_failure_closes_and_restores_same_a2_lifecycle() -> None:
    controller, broker = _r63s_controller_at_a2()
    seen: list[access.ResearchOperation] = []
    failed_readiness = replace(
        _r63t_ready_result(),
        ready=False,
        selected=False,
        same_target_binding_ready=False,
        audit_ready=False,
        audit_instance_continuity=False,
        failure_stage=access.ResearchFailureStage.TARGET_RESOLUTION,
        failure_reason=access.ResearchFailureReason.TARGET_METADATA_UNAVAILABLE,
    )

    def fail_readiness(*_args: object, **kwargs: object) -> object:
        seen.append(kwargs["_capability"].operation)
        return failed_readiness

    broker._invoke_remote_phase_a_research = fail_readiness
    session = controller.open_remote_phase_a_inventory_session()

    assert session.check_readiness() is failed_readiness
    with pytest.raises(
        access.LifecycleControllerError,
        match="RESEARCH_READINESS_REQUIRED",
    ):
        session.run_remote_phase_a_inventory()
    assert seen == [access.ResearchOperation.CHECK_READINESS]
    session.close()
    controller.close()

    reconstructed_broker = _R32ScriptedBroker()
    reconstructed_broker._durable_lifecycle_test = True
    reconstructed = access.FullPreflightLifecycleController(reconstructed_broker)
    assert reconstructed.state is access.LifecycleState.A2_COLLECTED
    proof = _r32_complete_restore_tail(reconstructed, _r32_bundles()[1])
    assert proof.complete is True
    assert reconstructed.state is access.LifecycleState.COMPLETE_NORMAL
    reconstructed.close()


def test_r63t_mid_run_failure_closes_and_restores_same_a2_lifecycle() -> None:
    controller, broker = _r63s_controller_at_a2()
    failed_inventory = replace(
        _r63s_complete_result(),
        outcome="research_failed",
        completed_probe_slots=1,
        cold_request_count=1,
        retained_request_count=0,
        total_device_status_requests=1,
        cold_ack_success_count=0,
        retained_ack_success_count=0,
        failure_count=1,
        failure_category=(
            access.ResearchFailureCategory.POST_OR_POSSIBLY_SUBMITTED_PROBE_FAILURE
        ),
        failure_stage=access.ResearchFailureStage.PROBE_EVIDENCE,
        failure_reason=access.ResearchFailureReason.INVALID_SHAPE,
        failed_slot=1,
        probe_submission_possible=True,
    )
    broker._invoke_remote_phase_a_research = lambda *_args, **kwargs: (
        _r63t_ready_result()
        if kwargs["_capability"].operation is access.ResearchOperation.CHECK_READINESS
        else failed_inventory
    )
    session = controller.open_remote_phase_a_inventory_session()

    assert session.check_readiness().ready is True
    assert session.run_remote_phase_a_inventory() is failed_inventory
    session.close()
    controller.close()

    reconstructed_broker = _R32ScriptedBroker()
    reconstructed_broker._durable_lifecycle_test = True
    reconstructed = access.FullPreflightLifecycleController(reconstructed_broker)
    assert reconstructed.state is access.LifecycleState.A2_COLLECTED
    proof = _r32_complete_restore_tail(reconstructed, _r32_bundles()[1])
    assert proof.complete is True
    assert reconstructed.state is access.LifecycleState.COMPLETE_NORMAL
    reconstructed.close()


def _r63t_readiness_replacements(scenario: str) -> dict[str, str]:
    source = access._REMOTE_CONTROL_PROGRAM
    invoke_start = source.index("def invoke_research_helper")
    invoke_end = source.index("def loaded_tuya_entries")
    original_invoke = source[invoke_start:invoke_end]
    original_target = _r63s_embedded_function_source("resolve_research_target")
    target = (
        "def resolve_research_target():\n    return 0, None"
        if scenario == "zero_target"
        else (
            "def resolve_research_target():\n" "    raise ValueError('research_target')"
            if scenario == "target_failure"
            else "def resolve_research_target():\n    return 1, 'a' * 32"
        )
    )
    synthetic_invoke = f"""def invoke_research_helper(operation, label, nonce, mode=None, target=None):
    if operation != 'audit' or mode is not None or target is not None:
        raise ValueError('research_operation')
    counters = {{name: 0 for name in COUNTERS}}
    audit = {{
        'result': 'audit_snapshot', 'protocol_version': 1,
        'audit_instance_token': {'b' * 32!r} if {scenario!r} == 'instance' else {'a' * 32!r},
        'event_ordinal': 0, 'history_overflow': False, 'runtime_ms': 1,
        'counters': counters, 'events': [], 'nonce': nonce,
    }}
    if {scenario!r} == 'audit_failure':
        return 67, 'schema_invalid', None, None
    if {scenario!r} == 'counter_regression':
        audit['counters']['connect_attempts'] = -1
    if {scenario!r} == 'device_request':
        audit['counters']['device_status_requests'] = 1
    return 0, 'audit_snapshot', audit, None

"""
    return {original_invoke: synthetic_invoke, original_target: target}


@pytest.mark.parametrize(
    ("scenario", "ready", "stage", "reason"),
    (
        ("ready", True, None, None),
        ("zero_target", False, "TARGET_RESOLUTION", "NO_ELIGIBLE_TARGET"),
        (
            "target_failure",
            False,
            "TARGET_RESOLUTION",
            "TARGET_METADATA_UNAVAILABLE",
        ),
        ("audit_failure", False, "AUDIT", "HELPER_TERMINAL"),
        ("instance", False, "AUDIT", "AUDIT_INSTANCE_CHANGED"),
        ("counter_regression", False, "AUDIT", "INVALID_SHAPE"),
        ("device_request", False, "AUDIT", "PROTOCOL_WRITE_DETECTED"),
    ),
)
def test_r63t_remote_readiness_is_device_free_and_bounded(
    tmp_path: Path,
    scenario: str,
    ready: bool,
    stage: str | None,
    reason: str | None,
) -> None:
    (tmp_path / "custom_components" / "tuya_ble").mkdir(parents=True)
    result = _run_synthetic_remote_program(
        tmp_path,
        "remote_phase_a_readiness",
        {"baseline": _r63s_remote_baseline()},
        source_replacements=_r63t_readiness_replacements(scenario),
    )

    assert result["ready"] is ready
    assert result["failure_stage"] == stage
    assert result["failure_reason"] == reason
    assert "probe" not in _r63s_embedded_function_source("remote_phase_a_readiness")


@pytest.mark.parametrize(
    ("scenario", "stage", "reason", "failed_slot", "possible"),
    (
        ("probe_invalid", "PROBE_EVIDENCE", "INVALID_SHAPE", 1, True),
        ("audit_failure", "AUDIT", "INVALID_SHAPE", 1, True),
    ),
)
def test_r63t_remote_inventory_preserves_terminal_failure_progress(
    tmp_path: Path,
    scenario: str,
    stage: str,
    reason: str,
    failed_slot: int,
    possible: bool,
) -> None:
    (tmp_path / "custom_components" / "tuya_ble").mkdir(parents=True)
    result = _run_synthetic_remote_program(
        tmp_path,
        "remote_phase_a_inventory",
        {"baseline": _r63s_remote_baseline()},
        source_replacements=_r63s_remote_replacements(scenario),
    )

    assert result["outcome"] == "research_failed"
    assert result["failure_stage"] == stage
    assert result["failure_reason"] == reason
    assert result["failed_slot"] == failed_slot
    assert result["probe_submission_possible"] is possible
    assert result["cold_request_count"] <= 1
    assert result["retained_request_count"] <= 1


def test_r63t_remote_target_failure_proves_pre_probe_zero_requests(
    tmp_path: Path,
) -> None:
    (tmp_path / "custom_components" / "tuya_ble").mkdir(parents=True)
    replacements = _r63s_remote_replacements("complete")
    original = _r63s_embedded_function_source("resolve_research_target")
    replacements[original] = (
        "def resolve_research_target():\n" "    raise ValueError('research_target')"
    )
    result = _run_synthetic_remote_program(
        tmp_path,
        "remote_phase_a_inventory",
        {"baseline": _r63s_remote_baseline()},
        source_replacements=replacements,
    )

    assert result["outcome"] == "research_failed"
    assert result["failure_category"] == "PRE_PROBE_FAILURE"
    assert result["failure_stage"] == "TARGET_RESOLUTION"
    assert result["failed_slot"] == 0
    assert result["probe_submission_possible"] is False
    assert result["total_device_status_requests"] == 0


def test_r63t_target_resolver_accepts_supported_ulid_config_entry_ids() -> None:
    ulid = "01K2E8Z9N7Q4D6M1B3C5F7G8HJ"
    entries = [
        {
            "domain": "tuya_ble",
            "state": "loaded",
            "entry_id": ulid,
        }
    ]

    def request_json(url: str) -> tuple[int, object]:
        if "diagnostics" in url:
            entry_id = url.rsplit("/", 1)[-1]
            return 200, {
                "data": {
                    "entry": {"entry_id": entry_id},
                    "options": {
                        "category": "jtmspro",
                        "product_id": "xqeob8h6",
                    },
                },
                "issues": [],
            }
        return 200, copy.deepcopy(entries)

    namespace = {"re": __import__("re"), "request_json": request_json}
    exec(  # noqa: S102 - execute only reviewed embedded function definitions
        _r63s_embedded_function_source("loaded_tuya_entries"), namespace
    )
    exec(  # noqa: S102 - execute only reviewed embedded function definitions
        _r63s_embedded_function_source("resolve_research_target"), namespace
    )

    assert namespace["resolve_research_target"]() == (1, ulid)
    entries.append(
        {
            "domain": "tuya_ble",
            "state": "loaded",
            "entry_id": "a" * 32,
        }
    )
    assert namespace["resolve_research_target"]() == (2, ulid)


@pytest.mark.parametrize(
    "entry_id",
    (
        "01K2E8Z9N7Q4D6M1B3C5F7G8H/",
        "01K2E8Z9N7Q4D6M1B3C5F7G8HI",
        "01K2E8Z9N7Q4D6M1B3C5F7G8H",
        "../synthetic-entry",
    ),
)
def test_r63t_target_resolver_rejects_noncanonical_or_unsafe_ids(
    entry_id: str,
) -> None:
    def request_json(_url: str) -> tuple[int, object]:
        return 200, [
            {
                "domain": "tuya_ble",
                "state": "loaded",
                "entry_id": entry_id,
            }
        ]

    namespace = {"re": __import__("re"), "request_json": request_json}
    exec(  # noqa: S102 - execute only the reviewed embedded function definition
        _r63s_embedded_function_source("loaded_tuya_entries"), namespace
    )

    with pytest.raises(ValueError, match="research_target"):
        namespace["loaded_tuya_entries"]()


def _r62c_retained_restored_after_abort_v1(
    *, device_drift: bool = True
) -> tuple[access.SourceBundle, access.SourceBundle, Path, Path]:
    """Build the exact retained R61 terminal shape with an explicit V1 anchor."""
    controller, broker = _r33_controller()
    candidate, restore = _r32_bundles()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_candidate(candidate)
    broker.queue("install_candidate", access.InstallResult(False, 3, 0, False))
    with pytest.raises(access.LifecycleControllerError, match="ROLLBACK_REQUIRED"):
        controller.install_candidate(candidate.manifest)
    proof = _r32_complete_restore_tail(controller, restore)
    assert proof.complete is True
    assert controller.state is access.LifecycleState.RESTORED_AFTER_ABORT
    controller.close()

    root = access._LIFECYCLE_STATE_ROOT
    journal_path = root / access._LIFECYCLE_JOURNAL_NAME
    anchor_path = access._lifecycle_anchor_path(root)
    anchor = json.loads(anchor_path.read_text(encoding="ascii"))
    assert anchor["schema_version"] == 2
    anchor["schema_version"] = 1
    current_device = root.stat().st_dev
    anchor["state_root_device"] = current_device + 1 if device_drift else current_device
    anchor_path.write_text(
        json.dumps(anchor, sort_keys=True, separators=(",", ":")), encoding="ascii"
    )
    anchor_path.chmod(0o600)
    return candidate, restore, journal_path, anchor_path


def _r62c_exact_pr41_inventory(
    restore: access.SourceBundle,
) -> access.CurrentSourceInventoryResult:
    count = len(restore.manifest.entries)
    return access.CurrentSourceInventoryResult(
        access.CurrentSourceClassification.EXACT_PR41,
        access.SourceInventoryResult(
            count,
            count,
            True,
            0,
            0,
            access.RemoteRootProfile.HOMEASSISTANT_CONFIG,
            0,
            0,
            access._source_manifest_digest(restore.manifest.entries),
        ),
    )


def test_r62c_a1_parent_contract_normal_path_rejects_device_only_drift() -> None:
    _candidate, _restore, journal_path, anchor_path = (
        _r62c_retained_restored_after_abort_v1()
    )
    before = (journal_path.read_bytes(), anchor_path.read_bytes())

    with pytest.raises(access.LifecycleControllerError, match="ANCHOR_INVALID"):
        access.RetainedTerminalLifecycleInspector(_r47_inspection_broker())

    assert (journal_path.read_bytes(), anchor_path.read_bytes()) == before


def test_r62c_a2_a3_drift_classification_and_exact_v1_compatibility() -> None:
    _candidate, _restore, journal_path, anchor_path = (
        _r62c_retained_restored_after_abort_v1()
    )
    before = (journal_path.read_bytes(), anchor_path.read_bytes())
    drift = access.RetainedAnchorContinuityInspector(_r47_inspection_broker())

    assert drift.metadata.anchor_format is access.LifecycleAnchorFormat.V1_DEVICE_BOUND
    assert drift.metadata.classification is (
        access.LifecycleAnchorClassification.DEVICE_DRIFT_ONLY
    )
    drift.close()
    assert (journal_path.read_bytes(), anchor_path.read_bytes()) == before

    exact_anchor = json.loads(anchor_path.read_text(encoding="ascii"))
    exact_anchor["state_root_device"] = access._LIFECYCLE_STATE_ROOT.stat().st_dev
    anchor_path.write_text(json.dumps(exact_anchor, sort_keys=True), encoding="ascii")
    exact_before = anchor_path.read_bytes()
    exact = access.RetainedTerminalLifecycleInspector(_r47_inspection_broker())
    assert exact.anchor_format is access.LifecycleAnchorFormat.V1_DEVICE_BOUND
    exact.close()
    assert anchor_path.read_bytes() == exact_before


@pytest.mark.parametrize(
    "mutate",
    (
        lambda anchor, record: anchor.__setitem__(
            "state_root_inode", anchor["state_root_inode"] + 1
        ),
        lambda anchor, record: anchor.__setitem__(
            "original_lifecycle_generation", "0" * 32
        ),
        lambda anchor, record: anchor.__setitem__("pr41_commit", "0" * 40),
        lambda anchor, record: anchor.__setitem__(
            "root_revision", anchor["root_revision"] + 2
        ),
        lambda anchor, record: anchor["baseline_backup_identity"].__setitem__(
            "backup_digest", "e" * 64
        ),
    ),
    ids=("inode", "lifecycle", "pr41", "revision", "backup"),
)
def test_r62c_a4_to_a8_second_mismatch_is_invalid(mutate: object) -> None:
    _candidate, _restore, _journal_path, anchor_path = (
        _r62c_retained_restored_after_abort_v1()
    )
    anchor = json.loads(anchor_path.read_text(encoding="ascii"))
    record = json.loads(
        (access._LIFECYCLE_STATE_ROOT / access._LIFECYCLE_JOURNAL_NAME).read_text(
            encoding="ascii"
        )
    )
    assert callable(mutate)
    mutate(anchor, record)
    anchor_path.write_text(json.dumps(anchor, sort_keys=True), encoding="ascii")

    with pytest.raises(access.LifecycleControllerError, match="ANCHOR_INVALID"):
        access.RetainedAnchorContinuityInspector(_r47_inspection_broker())


def test_r62c_a9_active_device_drift_is_not_adopted() -> None:
    controller, _broker = _r33_controller()
    controller.close()
    root = access._LIFECYCLE_STATE_ROOT
    anchor_path = access._lifecycle_anchor_path(root)
    anchor = json.loads(anchor_path.read_text(encoding="ascii"))
    anchor["schema_version"] = 1
    anchor["state_root_device"] = root.stat().st_dev + 1
    anchor_path.write_text(json.dumps(anchor, sort_keys=True), encoding="ascii")
    broker = _r47_inspection_broker()

    with pytest.raises(
        access.LifecycleControllerError, match="DEVICE_DRIFT_ACTIVE_UNSUPPORTED"
    ):
        access.RetainedAnchorContinuityInspector(broker)

    assert broker.calls == []


@pytest.mark.parametrize(
    "classification",
    (
        access.CurrentSourceClassification.EXACT_PR45,
        access.CurrentSourceClassification.OTHER,
        access.CurrentSourceClassification.INDETERMINATE,
    ),
)
def test_r62c_a10_to_a13_migration_requires_one_exact_pr41_proof(
    classification: access.CurrentSourceClassification,
) -> None:
    candidate, restore, journal_path, anchor_path = (
        _r62c_retained_restored_after_abort_v1()
    )
    before = (journal_path.read_bytes(), anchor_path.read_bytes())
    broker = _r47_inspection_broker()
    inspector = access.RetainedAnchorContinuityInspector(broker)
    with pytest.raises(
        access.LifecycleControllerError, match="MIGRATION_NOT_AUTHORIZED"
    ):
        inspector.migrate_anchor()
    broker.queue(
        "current_source_inventory",
        access.CurrentSourceInventoryResult(classification),
    )
    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)

    with pytest.raises(
        access.LifecycleControllerError, match="MIGRATION_NOT_AUTHORIZED"
    ):
        inspector.migrate_anchor()

    assert result.classification is classification
    assert [name for name, _ in broker.calls] == ["current_source_inventory"]
    assert (journal_path.read_bytes(), anchor_path.read_bytes()) == before
    inspector.close()


def test_r62c_a14_to_a24_exact_one_shot_atomic_migration_and_normal_reopen() -> None:
    candidate, restore, journal_path, anchor_path = (
        _r62c_retained_restored_after_abort_v1()
    )
    before_journal = journal_path.read_bytes()
    before_anchor = json.loads(anchor_path.read_text(encoding="ascii"))
    broker = _r47_inspection_broker()
    broker.queue("current_source_inventory", _r62c_exact_pr41_inventory(restore))
    inspector = access.RetainedAnchorContinuityInspector(broker)
    result = inspector.inspect_current_source(candidate.manifest, restore.manifest)
    migration = inspector.migrate_anchor()
    migrated = json.loads(anchor_path.read_text(encoding="ascii"))

    assert result.classification is access.CurrentSourceClassification.EXACT_PR41
    assert migration == access.LifecycleAnchorMigrationResult(
        True,
        access.LifecycleAnchorFormat.V2_STABLE_ROOT,
        False,
        False,
        False,
        False,
        False,
        False,
        True,
    )
    assert set(migrated) == access._DurableLifecycleJournal._V2_ANCHOR_FIELDS
    assert migrated["schema_version"] == 2
    assert "state_root_device" not in migrated
    for key in access._DurableLifecycleJournal._V2_ANCHOR_FIELDS - {"schema_version"}:
        assert migrated[key] == before_anchor[key]
    assert journal_path.read_bytes() == before_journal
    assert stat.S_IMODE(anchor_path.stat().st_mode) == 0o600
    assert not any(
        path.name.startswith(".anchor-") for path in anchor_path.parent.iterdir()
    )
    with pytest.raises(
        access.LifecycleControllerError, match="MIGRATION_NOT_AUTHORIZED"
    ):
        inspector.migrate_anchor()
    inspector.close()

    normal = access.RetainedTerminalLifecycleInspector(broker)
    assert normal.anchor_format is access.LifecycleAnchorFormat.V2_STABLE_ROOT
    assert normal.journal_format is access.LifecycleJournalFormat.V2_CURRENT
    assert normal.metadata.state is access.LifecycleState.RESTORED_AFTER_ABORT
    normal.close()


@pytest.mark.parametrize(
    "mutate",
    (
        lambda anchor: anchor.__setitem__(
            "state_root_inode", anchor["state_root_inode"] + 1
        ),
        lambda anchor: anchor.__setitem__("unexpected", True),
        lambda anchor: anchor.__setitem__("schema_version", 99),
    ),
    ids=("inode", "extra", "unknown-schema"),
)
def test_r62c_a21_to_a23_v2_remains_strict(mutate: object) -> None:
    _candidate, _restore, _journal_path, anchor_path = (
        _r62c_retained_restored_after_abort_v1(device_drift=False)
    )
    anchor = json.loads(anchor_path.read_text(encoding="ascii"))
    anchor["schema_version"] = 2
    anchor.pop("state_root_device")
    assert callable(mutate)
    mutate(anchor)
    anchor_path.write_text(json.dumps(anchor, sort_keys=True), encoding="ascii")

    with pytest.raises(access.LifecycleControllerError, match="ANCHOR_INVALID"):
        access.RetainedTerminalLifecycleInspector(_r47_inspection_broker())


def test_r62c_a25_to_a28_migrated_retirement_and_fresh_v2_anchor() -> None:
    candidate, restore, _journal_path, anchor_path = (
        _r62c_retained_restored_after_abort_v1()
    )
    broker = _r47_inspection_broker()
    broker.queue("current_source_inventory", _r62c_exact_pr41_inventory(restore))
    continuity = access.RetainedAnchorContinuityInspector(broker)
    continuity.inspect_current_source(candidate.manifest, restore.manifest)
    continuity.migrate_anchor()
    continuity.close()

    retained = access.RetainedTerminalLifecycleInspector(broker)
    with pytest.raises(
        access.LifecycleControllerError,
        match="LIFECYCLE_TERMINAL_RETIREMENT_NOT_AUTHORIZED",
    ):
        retained.retire_terminal()
    retained.inspect_current_source(candidate.manifest, restore.manifest)
    assert retained.inspect_prior_backup(restore.manifest).classification is (
        access.PriorBackupClassification.OWNED_BY_RETAINED_LIFECYCLE
    )
    assert retained.retire_owned_prior_backup(restore.manifest) == (
        access.PriorBackupContinuityResult(
            access.PriorBackupClassification.NONE, retired=True
        )
    )
    retained.retire_terminal()
    retained.close()

    fresh = access.FullPreflightLifecycleController(_r47_inspection_broker())
    fresh_anchor = json.loads(anchor_path.read_text(encoding="ascii"))
    assert fresh._journal.anchor_format is access.LifecycleAnchorFormat.V2_STABLE_ROOT
    assert set(fresh_anchor) == access._DurableLifecycleJournal._V2_ANCHOR_FIELDS
    assert "state_root_device" not in fresh_anchor
    fresh.close()


def test_r62c_a30_full_migrated_terminal_to_complete_normal_path() -> None:
    candidate, restore, _journal_path, _anchor_path = (
        _r62c_retained_restored_after_abort_v1()
    )
    retained_broker = _r47_inspection_broker()
    retained_broker.queue(
        "current_source_inventory", _r62c_exact_pr41_inventory(restore)
    )
    continuity = access.RetainedAnchorContinuityInspector(retained_broker)
    continuity.inspect_current_source(candidate.manifest, restore.manifest)
    continuity.migrate_anchor()
    continuity.close()
    retained = access.RetainedTerminalLifecycleInspector(retained_broker)
    retained.inspect_current_source(candidate.manifest, restore.manifest)
    retained.inspect_prior_backup(restore.manifest)
    retained.retire_owned_prior_backup(restore.manifest)
    retained.retire_terminal()
    retained.close()

    controller, broker = _r33_controller()
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
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

    assert proof.complete is True
    assert controller.state is access.LifecycleState.COMPLETE_NORMAL
    assert (
        controller._journal.anchor_format is access.LifecycleAnchorFormat.V2_STABLE_ROOT
    )
    assert controller._journal._record["consumed_operations"].count("preflight") == 1
    assert [name for name, _ in broker.calls].count("restart") == 2
    assert [name for name, _ in broker.calls].count("helper") == 5
    assert "PROBE" not in access.LifecycleAction.__members__
    assert "RECEIPT" not in access.LifecycleAction.__members__
    assert controller._journal._record["restart_tombstones"] == [
        access.LifecycleAction.ACTIVATION_RESTART.value,
        access.LifecycleAction.REMOVAL_RESTART.value,
    ]
    controller.close()


def test_r62_e_t3_not_submitted_remains_typed_with_expected_nonce() -> None:
    """A definitely-not-submitted helper result has no nonce to correlate."""
    result = access._parse_phase_a_result(
        access.PhaseAOperation.PREFLIGHT,
        b'{"exit_code":65,"outcome":"not_submitted"}',
        expected_nonce="a" * 16,
    )

    assert result == access.PhaseAResult(
        access.PhaseAOperation.PREFLIGHT, 65, "not_submitted"
    )


@pytest.mark.parametrize(
    ("exit_code", "outcome", "reason"),
    (
        (65, "not_submitted", "NOT_SUBMITTED"),
        (67, "schema_invalid", "SCHEMA_INVALID"),
        (67, "nonce_mismatch", "NONCE_MISMATCH"),
        (67, "evidence_write_failed", "EVIDENCE_WRITE_FAILED"),
        (78, "transport_ambiguous", "TRANSPORT_AMBIGUOUS"),
    ),
)
def test_r62_e_t3_to_t10_typed_preflight_failure_is_bounded_and_not_replayed(
    exit_code: int,
    outcome: str,
    reason: str,
) -> None:
    """A typed helper terminal remains reportable after durable rollback."""
    controller, broker = _r33_advance_to_ap0()
    broker.queue(
        "helper",
        lambda detail: access.PhaseAResult(
            access.PhaseAOperation.PREFLIGHT,
            exit_code,
            outcome,
            None if exit_code == 65 else detail[1],
        ),
    )

    with pytest.raises(access.PreflightRejectedError) as raised:
        controller.run_non_probe_preflight()

    assert raised.value.reason is getattr(access.PreflightFailureReason, reason)
    assert str(raised.value) == "LIFECYCLE_ROLLBACK_REQUIRED"
    assert controller.state is access.LifecycleState.ROLLBACK_REQUIRED
    assert controller._permits[access.LifecycleAction.PREFLIGHT].consumed
    operation = next(
        item
        for item in controller._journal._record["operations"]
        if item["action"] == access.LifecycleAction.PREFLIGHT.value
    )
    assert operation["phase"] == "result_durable"
    assert (
        controller._journal.action_transition_committed(
            access.LifecycleAction.PREFLIGHT
        )
        is False
    )
    assert all(
        transition["stage"] != access.LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED.value
        for transition in controller._journal.transitions
    )
    with pytest.raises((AttributeError, access.LifecycleControllerError)):
        controller.run_non_probe_preflight()
    preflight_calls = [
        detail
        for name, detail in broker.calls
        if name == "helper" and detail[0] is access.PhaseAOperation.PREFLIGHT
    ]
    assert len(preflight_calls) == 1
    assert not any(name in {"receipt", "probe"} for name, _detail in broker.calls)
    controller.close()


@pytest.mark.parametrize("http_status", (400, 404, 500))
def test_r62f_c1_to_c3_http_rejection_parses_with_bounded_status(
    http_status: int,
) -> None:
    """Exit 66 is a received HTTP rejection, not transport ambiguity."""
    nonce = "d" * 16
    result = access._parse_phase_a_result(
        access.PhaseAOperation.PREFLIGHT,
        json.dumps(
            {
                "exit_code": 66,
                "outcome": "http_rejected",
                "nonce": nonce,
                "http_status": http_status,
            }
        ).encode(),
        expected_nonce=nonce,
    )

    assert result == access.PhaseAResult(
        operation=access.PhaseAOperation.PREFLIGHT,
        exit_code=66,
        outcome="http_rejected",
        nonce=nonce,
        http_status=http_status,
    )
    assert result.preflight is None
    assert result.receipt is None
    assert result.audit is None


@pytest.mark.parametrize("http_status", (None, True, "404", 399, 600))
def test_r62f_c2_c3_http_rejection_rejects_nonce_or_status_mismatch(
    http_status: object,
) -> None:
    """The rejection projection requires matching nonce and exact status bounds."""
    payload = {
        "exit_code": 66,
        "outcome": "http_rejected",
        "nonce": "d" * 16,
        "http_status": http_status,
    }

    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            access.PhaseAOperation.PREFLIGHT,
            json.dumps(payload).encode(),
            expected_nonce="d" * 16,
        )


def test_r62f_c2_http_rejection_requires_submitted_nonce_match() -> None:
    payload = {
        "exit_code": 66,
        "outcome": "http_rejected",
        "nonce": "d" * 16,
        "http_status": 404,
    }

    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            access.PhaseAOperation.PREFLIGHT,
            json.dumps(payload).encode(),
            expected_nonce="e" * 16,
        )


@pytest.mark.parametrize("private_key", ("body", "headers", "reason", "url"))
def test_r62f_c3_http_rejection_rejects_private_schema_extras(
    private_key: str,
) -> None:
    """No response material can cross the exact four-field parser boundary."""
    payload = {
        "exit_code": 66,
        "outcome": "http_rejected",
        "nonce": "d" * 16,
        "http_status": 404,
        private_key: "synthetic-private-value",
    }

    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_phase_a_result(
            access.PhaseAOperation.PREFLIGHT,
            json.dumps(payload).encode(),
            expected_nonce="d" * 16,
        )


def test_r62f_c1_remote_helper_projects_only_http_rejection_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The embedded remote adapter admits only outcome, nonce, and status."""
    tree = ast.parse(access._REMOTE_CONTROL_PROGRAM)
    invoke_helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "invoke_helper"
    )
    namespace = {
        "sys": sys,
        "HELPER": Path("/synthetic/helper"),
        "EVIDENCE": Path("/synthetic/evidence"),
        "decode_json": lambda value: json.loads(value),
    }
    exec(  # noqa: S102 - execute only the isolated, repository-owned AST fixture.
        compile(
            ast.Module(body=[invoke_helper], type_ignores=[]), "<invoke_helper>", "exec"
        ),
        namespace,
    )

    class Completed:
        stderr = b""
        returncode = 66
        stdout = (
            b'{"outcome":"http_rejected","nonce":"dddddddddddddddd","http_status":404}'
        )

    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: Completed())
    result = namespace["invoke_helper"](
        {"helper_operation": "preflight", "nonce": "d" * 16}
    )

    assert result == {
        "exit_code": 66,
        "outcome": "http_rejected",
        "nonce": "d" * 16,
        "http_status": 404,
    }
    Completed.stdout = b'{"outcome":"http_rejected","nonce":"dddddddddddddddd","http_status":404,"body":"private"}'
    with pytest.raises(ValueError, match="helper_output"):
        namespace["invoke_helper"]({"helper_operation": "preflight", "nonce": "d" * 16})


def test_r62f_c4_to_c11_http_rejection_is_bounded_durable_and_not_replayed() -> None:
    """A definitive rejection remains one-shot and cannot commit success."""
    controller, broker = _r33_advance_to_ap0()
    broker.queue(
        "helper",
        lambda detail: access.PhaseAResult(
            operation=access.PhaseAOperation.PREFLIGHT,
            exit_code=66,
            outcome="http_rejected",
            nonce=detail[1],
            http_status=404,
        ),
    )

    with pytest.raises(access.PreflightRejectedError) as raised:
        controller.run_non_probe_preflight()

    assert raised.value.reason is access.PreflightFailureReason.HTTP_REJECTED
    assert raised.value.http_status == 404
    assert str(raised.value) == "LIFECYCLE_ROLLBACK_REQUIRED"
    assert controller.state is access.LifecycleState.ROLLBACK_REQUIRED
    assert controller._permits[access.LifecycleAction.PREFLIGHT].consumed
    operation = next(
        item
        for item in controller._journal._record["operations"]
        if item["action"] == access.LifecycleAction.PREFLIGHT.value
    )
    assert operation["phase"] == "result_durable"
    assert not controller._journal.action_transition_committed(
        access.LifecycleAction.PREFLIGHT
    )
    assert all(
        item["stage"] != access.LifecycleState.NON_PROBE_PREFLIGHT_COMPLETED.value
        for item in controller._journal.transitions
    )
    with pytest.raises((AttributeError, access.LifecycleControllerError)):
        controller.run_non_probe_preflight()
    assert (
        len(
            [
                detail
                for name, detail in broker.calls
                if name == "helper" and detail[0] is access.PhaseAOperation.PREFLIGHT
            ]
        )
        == 1
    )
    assert not any(name in {"receipt", "probe"} for name, _detail in broker.calls)
    controller.close()


def test_r62f_c11_transport_ambiguity_has_no_http_status() -> None:
    """Exit 78 remains a distinct status-free transport terminal."""
    controller, broker = _r33_advance_to_ap0()
    broker.queue(
        "helper",
        lambda detail: access.PhaseAResult(
            access.PhaseAOperation.PREFLIGHT,
            78,
            "transport_ambiguous",
            detail[1],
        ),
    )

    with pytest.raises(access.PreflightRejectedError) as raised:
        controller.run_non_probe_preflight()

    assert raised.value.reason is access.PreflightFailureReason.TRANSPORT_AMBIGUOUS
    assert raised.value.http_status is None
    controller.close()


def _r65_exact_r64_manifest() -> access.SourceManifest:
    """Return the metadata-only immutable R64 authority; no Git object is needed."""
    raw = (
        (
            "integration/__init__.py",
            37986,
            "0af97bd07f5831b2d78b72fcaf8d3b80f208b96db5d5eaecef4a7c8c46f1a056",
        ),
        (
            "integration/base.py",
            3198,
            "fe8328c56c96afd8fdabe03cdc8af04b19367e984c122428c30ce8e50296ffd6",
        ),
        (
            "integration/binary_sensor.py",
            21836,
            "28c719fa01b4668d2d60a255e803b3ad458118e90c28b0e5b0932f71c69cf171",
        ),
        (
            "integration/button.py",
            11682,
            "8a28f2dc0e7965b59facb1074ae569547d98f17981d6a37b06cd8072d29c056a",
        ),
        (
            "integration/climate.py",
            16446,
            "ef63c5451be5524611bd9a08d679f9427c4a0597091c3a3f518b8f32d718c08f",
        ),
        (
            "integration/cloud.py",
            13260,
            "10523fe9427bcb2e4a2f6ca99ea249ce4e1259573290aedad927cd6eeeabb915",
        ),
        (
            "integration/config_flow.py",
            18117,
            "463c920cb6a838113d09f597002f119b4c585c1635bfbe925777e66fe8946ca4",
        ),
        (
            "integration/const.py",
            33178,
            "d95b348e92a3b4c48988f37bf0504bf406c56eed1a9a99a36d3fd766f3eef48f",
        ),
        (
            "integration/cover.py",
            13944,
            "bde8e9b28dfe19993d69a2e18605da749d96e0d176a6f262b23f41eadfcc1550",
        ),
        (
            "integration/devices.py",
            29766,
            "6625c5aa4e7d5907c5cf1e4bf97bab77727a9d6bf7ef9e03d399001534f62e38",
        ),
        (
            "integration/diagnostics.py",
            1000,
            "e01dd4f13e78ef30c879b5b53859393272196b36c4b1bffe06d9c3fdf0627d0c",
        ),
        (
            "integration/event.py",
            5322,
            "7fa28029ac69a6cbafb6d20de30cd464b0e2e51144cc81a7700453109a92e862",
        ),
        (
            "integration/last_confirmed.py",
            3273,
            "8d82d5e80e7da34a3dc155788bf64697e18159be5d044524b87f2a2aa7d24e60",
        ),
        (
            "integration/light.py",
            32978,
            "f20f77a97b6c52433cc4ffa73c14770c2b36e600a81c9f9d18c35c4b9eba1f10",
        ),
        (
            "integration/lock.py",
            25958,
            "a8e8c6d616319c8aa09fafd84056726edb28c96b3279c1919c2d6c8442809e46",
        ),
        (
            "integration/manifest.json",
            751,
            "5f572bf9ccb6c9e35a3cf2483c18789b062f321e1eba9dbf34e630e79d0299c1",
        ),
        (
            "integration/number.py",
            45692,
            "650bcf5c9161f3e4735d2d1ea5e9523ade52846fb9a35f64137db479b754b281",
        ),
        (
            "integration/select.py",
            35099,
            "cd62fbabeea1d73f9f827fd16410b9bcc698b2484ebf993c360e2489e5bcd731",
        ),
        (
            "integration/sensor.py",
            95498,
            "0de06c14b55a1254a95a86912663d0297e11ab85951d96a1366630dfad554288",
        ),
        (
            "integration/strings.json",
            20455,
            "9d9a4d1525a18f9f30da868fae958934971332c67d3b6310f2dabc7e345e29b2",
        ),
        (
            "integration/switch.py",
            40865,
            "ae5cfbffa3501f643c57b422a6a79a6f47f4820ec86b826e337f537d98a1f8ac",
        ),
        (
            "integration/text.py",
            9272,
            "5440b13b5abf176e70e069efa482422747a9e8fbcbbbb776498a5ca09c17043f",
        ),
        (
            "integration/translations/de.json",
            16959,
            "2c1e0f7793826a5096dcb7b9894b679db380d309d19368afc84c72a944f80a47",
        ),
        (
            "integration/translations/en.json",
            20913,
            "e5b8925729c601b2f6d925ed46bd6bd5f6bbe4953bab436004bdfb200fb2d7c2",
        ),
        (
            "integration/translations/es.json",
            16610,
            "becdcd23e115588e09e982ced8c70ceb926faf1c811db4a0430d7e9eeba84293",
        ),
        (
            "integration/translations/fr.json",
            16698,
            "b1797e5c0ba989df5394927a5e079a8dcb5a7a204ad575a807391c6a53ddfada",
        ),
        (
            "integration/translations/it.json",
            16603,
            "954b36366a62891ce369ed1e68b39959d45dd43f832c1c3cabaa27331c1a6635",
        ),
        (
            "integration/translations/pt-BR.json",
            16627,
            "4aa3042b9bfb39bb44230b3afca1a577da06682a76c34c882715e7147ae53597",
        ),
        (
            "integration/translations/zh-Hans.json",
            15357,
            "d7d048dea414ecfddad07faedb77c6deacf828a045efe14e01f62cfcccab8fd8",
        ),
        (
            "integration/tuya_ble/__init__.py",
            515,
            "76ccce79bcae72ec606f1409da968361913a4cd7c460e35b83ab76d6ff63b7a7",
        ),
        (
            "integration/tuya_ble/const.py",
            2177,
            "d262f9bbde4787ecc7b3d10d713652d30471a1eb7b0d90add4ad4f313fa347c7",
        ),
        (
            "integration/tuya_ble/exceptions.py",
            3330,
            "c1cd47d9ece846cf70e4f1abc079df9e17e7a3863a6aa49c16e61d026a05d678",
        ),
        (
            "integration/tuya_ble/manager.py",
            2686,
            "f668097f7647fe20302a96c5252fcb0a1128f7990f7b76f672c8a07cb4e47e0b",
        ),
        (
            "integration/tuya_ble/security.py",
            2408,
            "1dd3655e035945f39f0f4079fc6f6646ddad5adb8f65a675ee23852b3b18b55e",
        ),
        (
            "integration/tuya_ble/tuya_ble.py",
            178784,
            "bc573c61e134fde333b299cff26617ae1a99a4aad29f22b6bd06a457199f1ccc",
        ),
        (
            "integration/util.py",
            499,
            "c829772d9b5ce3ddbe9a41e3ab38e57f39911bf48213f7782372a2e23a784ee8",
        ),
        (
            "integration/vacuum.py",
            13068,
            "4be1fe04e030e255d07010ae0ba385dcd74007aacc270657c4e83ab76ead1dbb",
        ),
    )
    return access.SourceManifest(
        access.SourceState.R64_RUNTIME,
        tuple(access.SourceManifestEntry(*item) for item in raw),
    )


@pytest.fixture
def r65_bundles(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[access.SourceBundle, access.SourceBundle]:
    """Use small visible-synthetic bundles for lifecycle behavior tests."""
    bundles = []
    for state, content in (
        (access.SourceState.R64_RUNTIME, b"synthetic r64 runtime\n"),
        (access.SourceState.RESTORE, b"synthetic pr41 restore\n"),
    ):
        file = access.SourceBundleFile("integration/__init__.py", content)
        manifest = access.SourceManifest(
            state,
            (
                access.SourceManifestEntry(
                    file.relative_path,
                    len(content),
                    hashlib.sha256(content).hexdigest(),
                ),
            ),
        )
        monkeypatch.setitem(
            access._AUTHORITY_MANIFEST_DIGESTS,
            state.value,
            access._source_manifest_digest(manifest.entries),
        )
        bundles.append(access.build_source_bundle(state, (file,), manifest))
    return bundles[0], bundles[1]


def _r65_packet_parser() -> object:
    tree = ast.parse(access._REMOTE_REFRESH_STATUS_PROGRAM)
    selected = [ast.Import(names=[ast.alias("re")])]
    wanted_assignments = {"EMPTY_COUNTS", "LOG_RE", "SEND_RE"}
    for node in tree.body:
        if (
            (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id in wanted_assignments
                    for target in node.targets
                )
            )
            or isinstance(node, ast.FunctionDef)
            and node.name == "parse_lines"
        ):
            selected.append(node)
    namespace: dict[str, object] = {}
    module = ast.fix_missing_locations(ast.Module(selected, type_ignores=[]))
    exec(  # noqa: S102 - execute only the isolated repository-owned parser AST.
        compile(module, "<r65-parser>", "exec"),
        namespace,
    )
    return namespace


def _r65_log_boundary() -> dict[str, object]:
    """Load only the private embedded marker protocol for synthetic tests."""
    tree = ast.parse(access._REMOTE_REFRESH_STATUS_PROGRAM)
    names = {
        "BOUNDARY_LOGGER",
        "LOG_RE",
        "REFRESH_TERMINAL_RE",
        "LogStream",
        "LogBoundaryNotEstablished",
        "LogWindow",
        "marker_line",
        "emit_validation_log_marker",
    }
    selected = []
    for node in tree.body:
        if (
            isinstance(node, (ast.Import, ast.ImportFrom))
            or isinstance(node, (ast.ClassDef, ast.FunctionDef))
            and node.name in names
            or isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id in names
                for target in node.targets
            )
        ):
            selected.append(node)
    namespace: dict[str, object] = {}
    exec(  # noqa: S102 - execute only isolated repository-owned marker code.
        compile(
            ast.fix_missing_locations(ast.Module(selected, type_ignores=[])),
            "<r65b-boundary>",
            "exec",
        ),
        namespace,
    )
    return namespace


def _r65b_stream(boundary: dict[str, object]) -> object:
    stream = boundary["LogStream"].__new__(boundary["LogStream"])
    stream.lines = __import__("queue").Queue(maxsize=512)
    stream.overflow = False
    return stream


class _R65BMarkerWebSocket:
    def __init__(self, stream: object, *, start: bool = True, end: bool = True) -> None:
        self.stream = stream
        self.start = start
        self.end = end
        self.calls: list[dict[str, object]] = []

    def command(self, kind: str, **fields: object) -> None:
        self.calls.append({"kind": kind, **fields})
        marker = fields["service_data"]["message"]
        permitted = self.start if "_START_" in marker else self.end
        if permitted:
            self.stream.lines.put(
                "2026-01-01 [ha_tuya_ble.r65_validation_boundary] " + marker + "\n"
            )


class _R65ScriptedBroker(_R32ScriptedBroker):
    source_classification = access.CurrentSourceClassification.EXACT_PR41

    def __init__(self) -> None:
        super().__init__()
        self.feature_backup_classification = (
            access.FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
        )

    def _consume_feature_capability(
        self, capability: object, action: access.FeatureValidationAction
    ) -> None:
        binding = self._controller_binding
        if (
            type(capability) is not access._FeatureValidationCapability
            or binding is None
            or capability.controller is not binding[0]
            or capability.issuer is not binding[1].identity
            or capability.lifecycle_generation is not binding[2]
            or capability.session_generation is not binding[3]
            or capability.action is not action
            or not any(capability is issued for issued in binding[1].issued)
            or any(capability is consumed for consumed in binding[1].consumed)
        ):
            raise access.SessionBrokerError("SYNTHETIC_FEATURE_CAPABILITY_INVALID")
        binding[1].consumed.append(capability)

    def _consume_feature_backup_capability(
        self, capability: object, action: access.FeatureBackupAction
    ) -> None:
        binding = self._controller_binding
        if (
            type(capability) is not access._FeatureBackupContinuityCapability
            or binding is None
            or capability.controller is not binding[0]
            or capability.issuer is not binding[1].identity
            or capability.lifecycle_generation is not binding[2]
            or capability.session_generation is not binding[3]
            or capability.action is not action
            or action is access.FeatureBackupAction.RETIRE
            and type(capability.backup_identity) is not dict
            or not any(capability is issued for issued in binding[1].issued)
            or any(capability is consumed for consumed in binding[1].consumed)
        ):
            raise access.SessionBrokerError("SYNTHETIC_BACKUP_CAPABILITY_INVALID")
        binding[1].consumed.append(capability)
        self._pending_capability = capability

    def _create_private_backup(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.BackupResult:
        self._consume_capability(_capability, access.LifecycleAction.BACKUP)
        assert isinstance(_capability, access._LifecycleCapability)
        self.calls.append(("backup", None))
        return access.BackupResult(
            True,
            len(manifest.entries),
            True,
            True,
            str(_capability.lifecycle_generation),
            str(_capability.source_generation),
            "c" * 32,
            access._source_manifest_digest(manifest.entries),
            "d" * 64,
        )

    def _inspect_current_source(
        self,
        candidate_manifest: access.SourceManifest,
        restore_manifest: access.SourceManifest,
        *,
        _capability: object = None,
    ) -> access.CurrentSourceInventoryResult:
        assert candidate_manifest.state is access.SourceState.R64_RUNTIME
        assert restore_manifest.state is access.SourceState.RESTORE
        self._consume_source_inspection_capability(_capability)
        self.calls.append(("current_source_inventory", None))
        return access.CurrentSourceInventoryResult(
            self.source_classification,
            access.SourceInventoryResult(
                len(
                    restore_manifest.entries
                    if self.source_classification
                    is access.CurrentSourceClassification.EXACT_PR41
                    else candidate_manifest.entries
                ),
                len(
                    restore_manifest.entries
                    if self.source_classification
                    is access.CurrentSourceClassification.EXACT_PR41
                    else candidate_manifest.entries
                ),
                True,
                0,
                0,
                access.RemoteRootProfile.HOMEASSISTANT_CONFIG,
                0,
                0,
                access._source_manifest_digest(
                    restore_manifest.entries
                    if self.source_classification
                    is access.CurrentSourceClassification.EXACT_PR41
                    else candidate_manifest.entries
                ),
            ),
        )

    def _feature_backup_continuity_operation(
        self,
        manifest: access.SourceManifest,
        action: access.FeatureBackupAction,
        *,
        _capability: object = None,
    ) -> access.FeatureBackupContinuityResult:
        assert manifest.state is access.SourceState.RESTORE
        self._consume_feature_backup_capability(_capability, action)
        if action is access.FeatureBackupAction.RETIRE:
            self.feature_backup_classification = access.FeatureBackupClassification.NONE
        return self._next(
            "feature_backup_" + action.value,
            None,
            access.FeatureBackupContinuityResult(
                self.feature_backup_classification,
                action is access.FeatureBackupAction.RETIRE,
            ),
        )

    def _restore_private_backup(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.InstallResult:
        self._consume_capability(_capability, access.LifecycleAction.BACKUP_FALLBACK)
        self.calls.append(("backup_fallback", None))
        count = len(manifest.entries)
        return access.InstallResult(True, count, count, True)

    def _reconcile_private_backup(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.FallbackReconciliationResult:
        self._consume_capability(
            _capability, access.LifecycleAction.BACKUP_FALLBACK_RECONCILE
        )
        self.calls.append(("backup_fallback_reconcile", None))
        return access.FallbackReconciliationResult(
            "reconciled", True, True, len(manifest.entries)
        )

    def _transfer_source_bundle(
        self, bundle: access.SourceBundle, *, _capability: object = None
    ) -> access.TransferResult:
        self._consume_capability(
            _capability,
            (
                access.LifecycleAction.CANDIDATE_TRANSFER
                if bundle.state is access.SourceState.R64_RUNTIME
                else access.LifecycleAction.RESTORE_TRANSFER
            ),
        )
        return self._next(
            "transfer",
            bundle.state,
            access.TransferResult(True, len(bundle.files), True, True),
        )

    def _verify_source_inventory(
        self, manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.SourceInventoryResult:
        self._consume_capability(
            _capability,
            (
                access.LifecycleAction.CANDIDATE_INVENTORY
                if manifest.state is access.SourceState.R64_RUNTIME
                else access.LifecycleAction.RESTORE_INVENTORY
            ),
        )
        count = len(manifest.entries)
        return self._next(
            "inventory",
            manifest.state,
            access.SourceInventoryResult(count, count, True, 0, 0),
        )

    def _run_s1_refresh_status_live_validation(
        self, *, _capability: object = None
    ) -> access.RefreshStatusLiveValidationResult:
        self._consume_feature_capability(
            _capability, access.FeatureValidationAction.LIVE_VALIDATION
        )
        self.calls.append(("live_validation", None))
        cold = access.RefreshPressResult(
            True,
            access.RefreshPacketCounts(1, 1, 1, 0, 0),
            access.RefreshSessionProvenance.NEW_SESSION,
            True,
            (8, 33),
        )
        warm = access.RefreshPressResult(
            True,
            access.RefreshPacketCounts(0, 0, 1, 0, 0),
            access.RefreshSessionProvenance.REUSED_SESSION,
            True,
            (8,),
        )
        return access.RefreshStatusLiveValidationResult(
            4,
            True,
            True,
            True,
            True,
            True,
            cold,
            warm,
            True,
            access.RefreshHoldResult(True, True, False),
            False,
            None,
            False,
        )

    def _observe_owner_refresh_status_trial(
        self,
        trial_kind: access.OwnerRefreshTrialKind,
        *,
        _capability: object = None,
    ) -> access.OwnerRefreshTrialResult:
        self._consume_feature_capability(
            _capability, access.FeatureValidationAction.HARDWARE_OBSERVATION
        )
        self.calls.append(("owner_refresh_trial", trial_kind))
        cold = trial_kind is access.OwnerRefreshTrialKind.COLD
        failure = getattr(self, "owner_trial_failure", None)
        return access.OwnerRefreshTrialResult(
            trial_kind,
            True,
            True,
            (
                access.RefreshSessionProvenance.NEW_SESSION
                if cold and failure is None
                else access.RefreshSessionProvenance.REUSED_SESSION
            ),
            access.RefreshPacketCounts(1 if cold else 0, 1 if cold else 0, 1, 0, 0),
            (8, 33),
            (
                access.OwnerRefreshDpMetadata(8, ("DT_VALUE",), (4,)),
                access.OwnerRefreshDpMetadata(33, ("DT_BOOL",), (1,)),
            ),
            True,
            True,
            True,
            False,
            failure,
        )

    def _observe_owner_refresh_release(
        self, *, _capability: object = None
    ) -> access.OwnerRefreshReleaseResult:
        self._consume_feature_capability(
            _capability, access.FeatureValidationAction.HARDWARE_OBSERVATION
        )
        self.calls.append(("owner_refresh_release", None))
        return access.OwnerRefreshReleaseResult(True, False, False, None)

    def _verify_refresh_feature_absent(
        self, *, _capability: object = None
    ) -> access.FeatureAbsenceResult:
        self._consume_feature_capability(
            _capability, access.FeatureValidationAction.FEATURE_ABSENCE
        )
        self.calls.append(("feature_absence", None))
        return access.FeatureAbsenceResult(False)


def _r65_advance_to_live(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> tuple[
    access.RefreshStatusLiveValidationController,
    _R65ScriptedBroker,
    access.SourceBundle,
    access.SourceBundle,
]:
    r64, restore = r65_bundles
    broker = _R65ScriptedBroker()
    broker._durable_lifecycle_test = True
    controller = access.RefreshStatusLiveValidationController(broker)
    controller.inspect_initial_source(r64.manifest, restore.manifest)
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_r64(r64)
    controller.install_r64(r64.manifest)
    controller.verify_r64_inventory(r64.manifest)
    controller.check_r64_core()
    controller.restart_for_r64()
    controller.await_r64_readiness()
    controller.verify_r64_inventory(r64.manifest)
    return controller, broker, r64, restore


def _r65e_historical_pr41_controller(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
    *,
    backup_classification: access.FeatureBackupClassification = (
        access.FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
    ),
    prove_source: bool = True,
) -> tuple[
    access.RefreshStatusLiveValidationController,
    _R65ScriptedBroker,
    access.SourceBundle,
    access.SourceBundle,
]:
    """Reconstruct the retained schema-1 R65D journal without rewriting it."""
    r64, restore = r65_bundles
    original_broker = _R65ScriptedBroker()
    original_broker._durable_lifecycle_test = True
    original = access.RefreshStatusLiveValidationController(original_broker)
    original.inspect_initial_source(r64.manifest, restore.manifest)
    original.admit_initial_repairs()

    def lose_backup_response(
        _manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.BackupResult:
        original_broker._consume_capability(_capability, access.LifecycleAction.BACKUP)
        original_broker.calls.append(("backup", None))
        raise access.SessionBrokerError("SYNTHETIC_BACKUP_RESPONSE_LOST")

    original_broker._create_private_backup = lose_backup_response
    with pytest.raises(access.LifecycleControllerError, match="BACKUP_VERIFICATION"):
        original.create_backup(restore.manifest)
    original.close()

    retained = json.loads(
        (
            access._LIFECYCLE_STATE_ROOT / access._FEATURE_VALIDATION_JOURNAL_NAME
        ).read_text(encoding="ascii")
    )
    assert retained["schema_version"] == 1
    assert retained["state"] == access.FeatureValidationState.RESTORE_REQUIRED.value
    assert retained["operations"][access.FeatureValidationAction.BACKUP.value] == (
        "ambiguous"
    )
    assert retained["backup_identity"] is None

    broker = _R65ScriptedBroker()
    broker._durable_lifecycle_test = True
    broker.feature_backup_classification = backup_classification
    controller = access.RefreshStatusLiveValidationController(broker)
    if prove_source:
        result = controller.reconcile_interrupted_source(r64.manifest, restore.manifest)
        assert result.classification is access.CurrentSourceClassification.EXACT_PR41
        assert controller.state is access.FeatureValidationState.PR41_RESTORED
    return controller, broker, r64, restore


def test_r65_c1_to_c6_exact_authorities_are_distinct_and_closed() -> None:
    candidate = _r30_manifest()
    r64 = _r65_exact_r64_manifest()

    assert candidate.authority_commit == access.PR45_CANDIDATE_COMMIT
    assert candidate.authority_tree == access.PR45_CANDIDATE_TREE
    assert access.PR41_RESTORE_COMMIT == "4f73a9b008dcb89134bc41001c486f06d6056867"
    assert access.PR41_RESTORE_TREE == "463ed8553da01eae591de611e76e45392ad9e7bf"
    access.validate_source_manifest(r64)
    assert len(r64.entries) == 37
    assert sum(item.size for item in r64.entries) == 838810
    assert r64.authority_commit == access.R64_RUNTIME_COMMIT
    assert r64.authority_tree == access.R64_RUNTIME_TREE
    assert r64.state is access.SourceState.R64_RUNTIME
    assert (
        access._source_manifest_digest(r64.entries)
        == "4eaed95e3a0dea264e11fffde6a42facdedf775552a3ea85026e85ecffd4b1d7"
    )
    assert set(access.SourceState) == {
        access.SourceState.CANDIDATE,
        access.SourceState.RESTORE,
        access.SourceState.R64_RUNTIME,
    }
    wrong = access.SourceManifest(
        access.SourceState.R64_RUNTIME,
        (replace(r64.entries[0], sha256="0" * 64),) + r64.entries[1:],
    )
    with pytest.raises(access.SourceBundleError, match="AUTHORITY"):
        access.validate_source_manifest(wrong)


def test_r65_c7_to_c9_api_and_result_boundary_are_private_and_fixed() -> None:
    method = (
        access.RefreshStatusLiveValidationController.run_s1_refresh_status_live_validation
    )
    assert tuple(inspect.signature(method).parameters) == ("self",)
    assert not any(
        name.startswith(("call_service", "get_logs"))
        for name in dir(access.RefreshStatusLiveValidationController)
    )
    sentinel = SYNTHETIC_FORBIDDEN_TRANSCRIPT_SENTINELS[2]
    payload = {
        "eligible_s1_count": 1,
        "selected": True,
        "refresh_button_present": True,
        "policy_on_demand": True,
        "ble_control_enabled": True,
        "hold_time_valid": True,
        "cold": {
            "service_success": True,
            "counts": {
                "device_info": 1,
                "pair": 1,
                "device_status": 1,
                "datapoint": 0,
                "other": 0,
            },
            "session_provenance": "NEW_SESSION",
            "last_status_update_advanced": True,
            "retained_confirmation_changed_dp_ids": [],
        },
        "warm": {
            "service_success": True,
            "counts": {
                "device_info": 0,
                "pair": 0,
                "device_status": 1,
                "datapoint": 0,
                "other": 0,
            },
            "session_provenance": "REUSED_SESSION",
            "last_status_update_advanced": True,
            "retained_confirmation_changed_dp_ids": [],
        },
        "same_authenticated_session": True,
        "hold": {
            "warm_immediately_after_press": True,
            "normal_release_observed": True,
            "automatic_reconnect_observed": False,
        },
        "ambiguous": False,
        "failure_class": None,
        "conditional_omission_observed": False,
        "raw_logs": sentinel,
    }
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL") as raised:
        access._parse_refresh_status_live_validation_result(
            json.dumps(payload).encode()
        )
    assert sentinel not in repr(raised.value)


def test_r65_c10_to_c13_packet_parser_is_exact_and_ambiguity_closed() -> None:
    parser = _r65_packet_parser()
    parse_lines = parser["parse_lines"]
    first = "tuya-ble-session-" + "g" * 16
    prefix = "2026-01-01 [custom_components.tuya_ble.tuya_ble.tuya_ble] " + first + ": "
    identity, counts, _events = parse_lines(
        [
            prefix + "Sending packet: #1 FUN_SENDER_DEVICE_INFO\n",
            prefix + "Sending packet: #2 FUN_SENDER_PAIR\n",
            prefix + "Sending packet: #3 FUN_SENDER_DEVICE_STATUS in response to #2\n",
            prefix + "Sending packet: #4 FUN_SENDER_DPS\n",
            prefix + "Sending packet: #5 FUN_SENDER_DPS_V4\n",
            prefix + "Sending packet: #6 FUN_SENDER_LOCK\n",
        ],
        first,
    )
    assert identity == first
    assert counts == {
        "device_info": 1,
        "pair": 1,
        "device_status": 1,
        "datapoint": 2,
        "other": 1,
    }
    second = "tuya-ble-session-" + "h" * 16
    selected, selected_counts, _ = parse_lines(
        [
            prefix + "Sending packet: #1 FUN_SENDER_DEVICE_STATUS\n",
            "2026 [custom_components.tuya_ble.tuya_ble.tuya_ble] "
            + second
            + ": Connecting; synthetic\n",
        ],
        first,
    )
    assert selected == first
    assert selected_counts["device_status"] == 1
    with pytest.raises(ValueError, match="identity"):
        parse_lines([prefix + "Sending packet: #1 FUN_SENDER_DEVICE_INFO\n"])
    assert "stream.establish_boundary()" not in access._REMOTE_REFRESH_STATUS_PROGRAM
    assert "state(connection_id).get('state') != 'off'" in (
        access._REMOTE_REFRESH_STATUS_PROGRAM
    )
    cold = access.RefreshPressResult(
        True,
        access.RefreshPacketCounts(1, 1, 1, 0, 0),
        access.RefreshSessionProvenance.NEW_SESSION,
        True,
    )
    warm = access.RefreshPressResult(
        True,
        access.RefreshPacketCounts(0, 0, 1, 0, 0),
        access.RefreshSessionProvenance.REUSED_SESSION,
        True,
        (8,),
    )
    result = access.RefreshStatusLiveValidationResult(
        1,
        True,
        True,
        True,
        True,
        True,
        cold,
        warm,
        True,
        access.RefreshHoldResult(True, True, False),
        False,
        None,
        False,
    )
    assert result.passed


@pytest.mark.parametrize("historical_count", (2, 5))
def test_r65_m1_to_m4_r65b_marker_discards_arbitrary_history(
    historical_count: int,
) -> None:
    boundary = _r65_log_boundary()
    stream = _r65b_stream(boundary)
    history = [
        "2026 [custom_components.tuya_ble.tuya_ble.tuya_ble] "
        "tuya-ble-session-"
        + "g" * 16
        + ": Sending packet: #1 FUN_SENDER_DEVICE_STATUS\n"
    ] + [f"historical {index}\n" for index in range(1, historical_count)]
    for line in history:
        stream.lines.put(line)
    ws = _R65BMarkerWebSocket(stream)
    window = boundary["LogWindow"](stream, ws)

    assert not window.established
    window.start()
    assert window.established
    stream.lines.put("active only after observed start\n")
    lines = window.finish()

    assert lines == ["active only after observed start\n"]
    assert len(ws.calls) == 2
    assert all(call["kind"] == "call_service" for call in ws.calls)


def test_r65_m5_r65b_missing_start_is_zero_press_boundary_failure() -> None:
    boundary = _r65_log_boundary()
    stream = _r65b_stream(boundary)
    ws = _R65BMarkerWebSocket(stream, start=False)
    press_count = 0
    values = [0.0, 0.0, 11.0]
    boundary["time"] = type(
        "SyntheticTime",
        (),
        {"monotonic": staticmethod(lambda: values.pop(0) if values else 11.0)},
    )

    with pytest.raises(boundary["LogBoundaryNotEstablished"]):
        boundary["LogWindow"](stream, ws).start()

    assert press_count == 0
    assert "LOG_BOUNDARY_NOT_ESTABLISHED" in access._REMOTE_REFRESH_STATUS_PROGRAM


def test_r65_m6_to_m8_r65b_end_is_required_and_exclusive() -> None:
    boundary = _r65_log_boundary()
    stream = _r65b_stream(boundary)
    ws = _R65BMarkerWebSocket(stream, end=False)
    window = boundary["LogWindow"](stream, ws)
    window.start()
    press_count = 1
    original_time = boundary["time"]
    values = [0.0, 0.0, 11.0]
    boundary["time"] = type(
        "SyntheticTime",
        (),
        {"monotonic": staticmethod(lambda: values.pop(0) if values else 11.0)},
    )

    with pytest.raises(ValueError, match="log_marker"):
        window.finish()

    assert press_count == 1
    assert window.finish_attempted
    with pytest.raises(ValueError, match="log_window"):
        window.finish()
    boundary["time"] = original_time

    complete_stream = _r65b_stream(boundary)
    complete_ws = _R65BMarkerWebSocket(complete_stream)
    complete = boundary["LogWindow"](complete_stream, complete_ws)
    complete.start()
    complete_stream.lines.put("inside\n")
    complete.finish()
    complete_stream.lines.put("after end\n")
    assert complete_stream.take_available() == ["after end\n"]


def test_r65_m9_m10_r65b_identity_binding_is_selected_and_fail_closed() -> None:
    parser = _r65_packet_parser()["parse_lines"]
    first = "tuya-ble-session-" + "g" * 16
    second = "tuya-ble-session-" + "h" * 16

    def record(identity: str, message: str) -> str:
        return (
            "2026 [custom_components.tuya_ble.tuya_ble.tuya_ble] "
            + identity
            + ": "
            + message
            + "\n"
        )

    cold = [
        record(first, "Connecting; synthetic"),
        record(first, "Connected; synthetic"),
        record(first, "Successfully connected synthetic"),
        record(first, "Sending packet: #1 FUN_SENDER_DEVICE_INFO"),
        record(first, "Sending packet: #2 FUN_SENDER_PAIR"),
        record(first, "Sending packet: #3 FUN_SENDER_DEVICE_STATUS"),
    ]
    foreign = record(second, "Sending packet: #4 FUN_SENDER_DPS")
    identity, counts, _ = parser(cold + [foreign], first)
    assert identity == first
    assert counts["datapoint"] == 0
    with pytest.raises(ValueError, match="identity"):
        parser(cold + [foreign])


def test_r65_m11_m12_r65b_marker_is_private_and_service_is_fixed() -> None:
    boundary = _r65_log_boundary()
    stream = _r65b_stream(boundary)
    ws = _R65BMarkerWebSocket(stream)
    window = boundary["LogWindow"](stream, ws)
    token = window.start_marker
    window.start()
    window.finish()
    rendered = json.dumps({"failure_class": "LOG_BOUNDARY_NOT_ESTABLISHED"})

    assert token not in repr(window)
    assert token not in rendered
    assert tuple(
        inspect.signature(
            access.RefreshStatusLiveValidationController.run_s1_refresh_status_live_validation
        ).parameters
    ) == ("self",)
    assert all(
        call
        == {
            "kind": "call_service",
            "domain": "system_log",
            "service": "write",
            "service_data": {
                "message": call["service_data"]["message"],
                "level": "critical",
                "logger": "ha_tuya_ble.r65_validation_boundary",
            },
            "return_response": False,
        }
        for call in ws.calls
    )


def test_r65_g1_to_g6_r65b_exact_cold_gate_has_no_availability_substitute() -> None:
    program = access._REMOTE_REFRESH_STATUS_PROGRAM
    boundary = _r65_log_boundary()
    cold_precondition = program.split("stream = LogStream()", 1)[1].split(
        "before_last = state(last_id).get('state')", 1
    )[0]

    assert "'binary_sensor', 'bluetooth_connection'" in program
    assert "state(connection_id).get('state') != 'off'" in program
    assert "state(button_id).get('state') == 'unavailable'" in program
    assert "window.start()" in cold_precondition
    assert "time.sleep" not in cold_precondition
    assert "take_available" not in cold_precondition
    assert "cold_gate_admissible" not in program
    assert "relevant_session_activity" not in program
    assert boundary["marker_line"](
        "2026 [ha_tuya_ble.r65_validation_boundary] R65_WINDOW_START_"
        + "a" * 64
        + "\n",
        "R65_WINDOW_START_" + "a" * 64,
    )
    assert not boundary["marker_line"](
        "2026 [wrong.logger] R65_WINDOW_START_" + "a" * 64 + "\n",
        "R65_WINDOW_START_" + "a" * 64,
    )


def test_r65_r65b_supervisor_minimum_history_regression_is_marker_bounded() -> None:
    """A two-record minimum defeats one-pop logic but not an exact START marker."""
    boundary = _r65_log_boundary()
    historical = ["history one\n", "history two\n"]
    old_remaining = historical[1:]
    stream = _r65b_stream(boundary)
    for line in historical:
        stream.lines.put(line)
    ws = _R65BMarkerWebSocket(stream)
    window = boundary["LogWindow"](stream, ws)
    window.start()

    assert old_remaining == ["history two\n"]
    assert stream.take_available() == []


def _r65c_refresh_lifecycle_parser() -> object:
    """Load only the fixed identifier-free lifecycle parser from remote source."""
    tree = ast.parse(access._REMOTE_REFRESH_STATUS_PROGRAM)
    selected = [ast.Import(names=[ast.alias("re")])]
    wanted_assignments = {
        "EMPTY_COUNTS",
        "LOG_RE",
        "SEND_RE",
        "REFRESH_BOUND_RE",
        "REFRESH_TERMINAL_RE",
    }
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id in wanted_assignments
                for target in node.targets
            )
        ) or (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "parse_refresh_lifecycle"
        ):
            selected.append(node)
    namespace: dict[str, object] = {}
    exec(  # noqa: S102 - execute only the reviewed embedded parser definitions
        compile(
            ast.fix_missing_locations(ast.Module(selected, type_ignores=[])),
            "<r65c-refresh-lifecycle-parser>",
            "exec",
        ),
        namespace,
    )
    return namespace


def _r65c_record(identity: str, message: str) -> str:
    return (
        "2026 [custom_components.tuya_ble.tuya_ble.tuya_ble] "
        + identity
        + ": "
        + message
        + "\n"
    )


def test_r65c_runtime_lifecycle_excludes_pre_accept_selected_traffic() -> None:
    parser = _r65c_refresh_lifecycle_parser()["parse_refresh_lifecycle"]
    identity = "tuya-ble-session-" + "g" * 16
    lines = [
        _r65c_record(identity, "Sending packet: #7 FUN_SENDER_DEVICE_STATUS"),
        _r65c_record(identity, "S1_REFRESH_ACCEPTED"),
        _r65c_record(identity, "Sending packet: #8 FUN_SENDER_DEVICE_INFO"),
        _r65c_record(identity, "Sending packet: #9 FUN_SENDER_PAIR"),
        _r65c_record(identity, "S1_REFRESH_SESSION_BOUND_NEW session_ordinal=4"),
        _r65c_record(identity, "Sending packet: #10 FUN_SENDER_DEVICE_STATUS"),
        _r65c_record(identity, "S1_REFRESH_COMPLETED session_ordinal=4"),
        _r65c_record(identity, "Sending packet: #11 FUN_SENDER_DEVICE_STATUS"),
    ]

    parsed = parser(lines)

    assert parsed[0] == identity
    assert parsed[1] == {
        "device_info": 1,
        "pair": 1,
        "device_status": 1,
        "datapoint": 0,
        "other": 0,
    }
    assert parsed[3:] == ("NEW_SESSION", 4, True)


def test_r65c_new_and_reused_cannot_be_synthesized_from_packet_counts() -> None:
    parser = _r65c_refresh_lifecycle_parser()["parse_refresh_lifecycle"]
    identity = "tuya-ble-session-" + "h" * 16
    cold_counts_only = [
        _r65c_record(identity, "S1_REFRESH_ACCEPTED"),
        _r65c_record(identity, "Sending packet: #1 FUN_SENDER_DEVICE_INFO"),
        _r65c_record(identity, "Sending packet: #2 FUN_SENDER_PAIR"),
        _r65c_record(identity, "Sending packet: #3 FUN_SENDER_DEVICE_STATUS"),
        _r65c_record(identity, "S1_REFRESH_COMPLETED session_ordinal=8"),
    ]
    reused_zero_info = [
        _r65c_record(identity, "S1_REFRESH_ACCEPTED"),
        _r65c_record(identity, "S1_REFRESH_SESSION_BOUND_REUSED session_ordinal=8"),
        _r65c_record(identity, "Sending packet: #4 FUN_SENDER_DEVICE_STATUS"),
        _r65c_record(identity, "S1_REFRESH_COMPLETED session_ordinal=8"),
    ]

    with pytest.raises(ValueError, match="refresh_lifecycle"):
        parser(cold_counts_only)
    parsed = parser(reused_zero_info)
    assert parsed[1]["device_info"] == 0
    assert parsed[3] == "REUSED_SESSION"


def test_r65c_foreign_claim_classification_cannot_satisfy_cold() -> None:
    parser = _r65c_refresh_lifecycle_parser()["parse_refresh_lifecycle"]
    identity = "tuya-ble-session-" + "j" * 16
    lines = [
        _r65c_record(identity, "S1_REFRESH_ACCEPTED"),
        _r65c_record(identity, "Sending packet: #1 FUN_SENDER_DEVICE_INFO"),
        _r65c_record(identity, "Sending packet: #2 FUN_SENDER_PAIR"),
        _r65c_record(identity, "S1_REFRESH_SESSION_BOUND_REUSED session_ordinal=12"),
        _r65c_record(identity, "Sending packet: #3 FUN_SENDER_DEVICE_STATUS"),
        _r65c_record(identity, "S1_REFRESH_COMPLETED session_ordinal=12"),
    ]

    parsed = parser(lines)
    cold = access.RefreshPressResult(
        True,
        access.RefreshPacketCounts(1, 1, 1, 0, 0),
        access.RefreshSessionProvenance(parsed[3]),
        True,
    )
    warm = access.RefreshPressResult(
        True,
        access.RefreshPacketCounts(0, 0, 1, 0, 0),
        access.RefreshSessionProvenance.REUSED_SESSION,
        True,
    )
    result = access.RefreshStatusLiveValidationResult(
        1,
        True,
        True,
        True,
        True,
        True,
        cold,
        warm,
        True,
        access.RefreshHoldResult(True, True, False),
        False,
        None,
        False,
    )

    assert parsed[3] == "REUSED_SESSION"
    assert not result.passed


def test_r65c_cold_and_warm_require_exact_matching_runtime_session() -> None:
    parser = _r65c_refresh_lifecycle_parser()["parse_refresh_lifecycle"]
    cold_identity = "tuya-ble-session-" + "k" * 16
    warm_identity = "tuya-ble-session-" + "m" * 16
    cold = parser(
        [
            _r65c_record(cold_identity, "S1_REFRESH_ACCEPTED"),
            _r65c_record(
                cold_identity, "S1_REFRESH_SESSION_BOUND_NEW session_ordinal=2"
            ),
            _r65c_record(cold_identity, "Sending packet: #1 FUN_SENDER_DEVICE_INFO"),
            _r65c_record(cold_identity, "Sending packet: #2 FUN_SENDER_PAIR"),
            _r65c_record(cold_identity, "Sending packet: #3 FUN_SENDER_DEVICE_STATUS"),
            _r65c_record(cold_identity, "S1_REFRESH_COMPLETED session_ordinal=2"),
        ]
    )
    warm_lines = [
        _r65c_record(warm_identity, "S1_REFRESH_ACCEPTED"),
        _r65c_record(
            warm_identity, "S1_REFRESH_SESSION_BOUND_REUSED session_ordinal=2"
        ),
        _r65c_record(warm_identity, "Sending packet: #1 FUN_SENDER_DEVICE_STATUS"),
        _r65c_record(warm_identity, "S1_REFRESH_COMPLETED session_ordinal=2"),
    ]

    with pytest.raises(ValueError, match="refresh_lifecycle"):
        parser(warm_lines, cold_identity)
    assert cold[4] == 2


def test_r65c_program_uses_runtime_provenance_not_external_cold_inference() -> None:
    program = access._REMOTE_REFRESH_STATUS_PROGRAM

    assert "parse_refresh_lifecycle" in program
    assert "S1_REFRESH_SESSION_BOUND_(NEW|REUSED)" in program
    assert "NEW_SESSION" in program
    assert "REUSED_SESSION" in program
    assert "cold_gate_admissible" not in program
    assert "relevant_session_activity" not in program
    assert "stream.take_available()" not in program
    assert program.count("press(ws, button_id)") == 2
    assert "same_authenticated_session" in program
    assert "same_authenticated_session_reused" not in program
    assert "if cold_provenance != 'NEW_SESSION'" in program
    assert "COLD_SESSION_PROVENANCE_FAILED" in program


def test_r65c_public_result_retains_classification_but_not_session_ordinal() -> None:
    payload = {
        "eligible_s1_count": 1,
        "selected": True,
        "refresh_button_present": True,
        "policy_on_demand": True,
        "ble_control_enabled": True,
        "hold_time_valid": True,
        "cold": {
            "service_success": True,
            "counts": {
                "device_info": 1,
                "pair": 1,
                "device_status": 1,
                "datapoint": 0,
                "other": 0,
            },
            "session_provenance": "NEW_SESSION",
            "last_status_update_advanced": False,
            "retained_confirmation_changed_dp_ids": [],
        },
        "warm": {
            "service_success": True,
            "counts": {
                "device_info": 0,
                "pair": 0,
                "device_status": 1,
                "datapoint": 0,
                "other": 0,
            },
            "session_provenance": "REUSED_SESSION",
            "last_status_update_advanced": False,
            "retained_confirmation_changed_dp_ids": [8],
        },
        "same_authenticated_session": True,
        "hold": {
            "warm_immediately_after_press": True,
            "normal_release_observed": True,
            "automatic_reconnect_observed": False,
        },
        "ambiguous": False,
        "failure_class": None,
        "conditional_omission_observed": True,
    }

    result = access._parse_refresh_status_live_validation_result(
        json.dumps(payload).encode()
    )

    assert result.passed
    assert result.same_authenticated_session is True
    assert result.cold.session_provenance is access.RefreshSessionProvenance.NEW_SESSION
    assert (
        result.warm.session_provenance is access.RefreshSessionProvenance.REUSED_SESSION
    )
    assert "session_ordinal" not in repr(result)


def test_r65c_exact_runtime_authority_manifest_is_git_derived() -> None:
    manifest = _r65_exact_r64_manifest()
    runtime = next(
        entry
        for entry in manifest.entries
        if entry.relative_path == "integration/tuya_ble/tuya_ble.py"
    )

    commit = "7cfcf9598941de253a24b7c30b06170a98b4ba86"  # gitleaks:allow
    tree = "f289523beedb1abe38b28221b1880fa4dec2a7b9"  # gitleaks:allow
    assert access.R64_RUNTIME_COMMIT == commit
    assert access.R64_RUNTIME_TREE == tree
    assert len(manifest.entries) == 37
    assert sum(item.size for item in manifest.entries) == 838810
    assert runtime.size == 178784
    assert (
        runtime.sha256
        == "bc573c61e134fde333b299cff26617ae1a99a4aad29f22b6bd06a457199f1ccc"
    )
    assert (
        access._source_manifest_digest(manifest.entries)
        == "4eaed95e3a0dea264e11fffde6a42facdedf775552a3ea85026e85ecffd4b1d7"
    )


def test_r65_c14_to_c19_two_press_operation_and_exact_restore(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, _r64, restore = _r65_advance_to_live(r65_bundles)
    result = controller.run_s1_refresh_status_live_validation()
    with pytest.raises(access.LifecycleControllerError, match="TRANSITION"):
        controller.run_s1_refresh_status_live_validation()
    controller.stage_restore(restore)
    controller.restore_pr41(restore.manifest)
    controller.reconcile_interrupted_source(_r64.manifest, restore.manifest)
    controller.inspect_feature_backup(restore.manifest)
    controller.retire_owned_feature_backup(restore.manifest)
    controller.inspect_feature_backup(restore.manifest)
    controller.verify_restore_inventory(restore.manifest)
    controller.check_restore_core()
    controller.restart_for_restore()
    controller.await_restore_readiness()
    controller.verify_refresh_feature_absent()
    controller.admit_post_restore_repairs()
    proof = controller.complete()

    assert result.passed
    assert proof.complete
    assert [name for name, _detail in broker.calls].count("live_validation") == 1
    assert "disconnect" not in {name for name, _detail in broker.calls}
    assert [detail for name, detail in broker.calls if name == "transfer"] == [
        access.SourceState.R64_RUNTIME,
        access.SourceState.RESTORE,
    ]


def test_r65_c15_c16_c20_ambiguous_live_operation_cannot_be_replayed(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, _r64, restore = _r65_advance_to_live(r65_bundles)

    def fail_once(*, _capability: object = None) -> object:
        broker._consume_feature_capability(
            _capability, access.FeatureValidationAction.LIVE_VALIDATION
        )
        broker.calls.append(("live_validation", None))
        raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")

    broker._run_s1_refresh_status_live_validation = fail_once
    result = controller.run_s1_refresh_status_live_validation()
    controller.close()
    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    replacement.source_classification = access.CurrentSourceClassification.EXACT_R64
    reconstructed = access.RefreshStatusLiveValidationController(replacement)

    assert result.ambiguous
    assert result.failure_class is access.RefreshStatusFailureClass.AMBIGUOUS
    with pytest.raises(access.LifecycleControllerError, match="TRANSITION"):
        reconstructed.run_s1_refresh_status_live_validation()
    reconstructed.reconcile_interrupted_source(_r64.manifest, restore.manifest)
    reconstructed.stage_restore(restore)
    assert [name for name, _detail in broker.calls].count("live_validation") == 1
    assert not any(name == "live_validation" for name, _detail in replacement.calls)
    reconstructed.close()


def test_r65_c20_interrupted_activation_restart_is_restore_only(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    r64, restore = r65_bundles
    broker = _R65ScriptedBroker()
    broker._durable_lifecycle_test = True
    controller = access.RefreshStatusLiveValidationController(broker)
    controller.inspect_initial_source(r64.manifest, restore.manifest)
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    controller.stage_r64(r64)
    controller.install_r64(r64.manifest)
    controller.verify_r64_inventory(r64.manifest)
    controller.check_r64_core()
    broker.queue(
        "restart", access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")
    )
    with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
        controller.restart_for_r64()
    controller.close()

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    replacement.source_classification = access.CurrentSourceClassification.EXACT_R64
    reconstructed = access.RefreshStatusLiveValidationController(replacement)
    with pytest.raises(access.LifecycleControllerError, match="TRANSITION"):
        reconstructed.restart_for_r64()
    reconstructed.reconcile_interrupted_source(r64.manifest, restore.manifest)
    reconstructed.stage_restore(restore)

    assert [name for name, _detail in broker.calls].count("restart") == 1
    assert not any(name == "restart" for name, _detail in replacement.calls)
    reconstructed.close()


@pytest.mark.parametrize(
    "action",
    (
        access.FeatureValidationAction.R64_TRANSFER,
        access.FeatureValidationAction.R64_INSTALL,
        access.FeatureValidationAction.RESTORE_TRANSFER,
        access.FeatureValidationAction.RESTORE_INSTALL,
    ),
)
def test_r65_c20_source_mutation_interruption_reconciles_without_replay(
    action: access.FeatureValidationAction,
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    r64, restore = r65_bundles
    broker = _R65ScriptedBroker()
    broker._durable_lifecycle_test = True
    controller = access.RefreshStatusLiveValidationController(broker)
    controller.inspect_initial_source(r64.manifest, restore.manifest)
    controller.admit_initial_repairs()
    controller.create_backup(restore.manifest)
    if action is not access.FeatureValidationAction.R64_TRANSFER:
        controller.stage_r64(r64)
    if action not in {
        access.FeatureValidationAction.R64_TRANSFER,
        access.FeatureValidationAction.R64_INSTALL,
    }:
        controller.install_r64(r64.manifest)
        controller.verify_r64_inventory(r64.manifest)
        controller.check_r64_core()
        controller.restart_for_r64()
        controller.await_r64_readiness()
        controller.verify_r64_inventory(r64.manifest)
        controller.run_s1_refresh_status_live_validation()
    if action is access.FeatureValidationAction.RESTORE_INSTALL:
        controller.stage_restore(restore)
    controller._begin(action)
    controller._mark(action, "dispatch_started")
    controller.close()

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    replacement.source_classification = access.CurrentSourceClassification.EXACT_R64
    reconstructed = access.RefreshStatusLiveValidationController(replacement)
    assert reconstructed.state is access.FeatureValidationState.RESTORE_REQUIRED
    classification = reconstructed.reconcile_interrupted_source(
        r64.manifest, restore.manifest
    )
    assert classification.classification is access.CurrentSourceClassification.EXACT_R64
    with pytest.raises(access.LifecycleControllerError, match="TRANSITION"):
        getattr(
            reconstructed,
            {
                access.FeatureValidationAction.R64_TRANSFER: "stage_r64",
                access.FeatureValidationAction.R64_INSTALL: "install_r64",
                access.FeatureValidationAction.RESTORE_TRANSFER: "stage_restore",
                access.FeatureValidationAction.RESTORE_INSTALL: "restore_pr41",
            }[action],
        )(
            {
                access.FeatureValidationAction.R64_TRANSFER: r64,
                access.FeatureValidationAction.R64_INSTALL: r64.manifest,
                access.FeatureValidationAction.RESTORE_TRANSFER: restore,
                access.FeatureValidationAction.RESTORE_INSTALL: restore.manifest,
            }[action]
        )
    if action in {
        access.FeatureValidationAction.RESTORE_TRANSFER,
        access.FeatureValidationAction.RESTORE_INSTALL,
    }:
        reconstructed.restore_private_backup_fallback(restore.manifest)
        assert [name for name, _detail in replacement.calls].count(
            "backup_fallback"
        ) == 1
    else:
        reconstructed.stage_restore(restore)
        reconstructed.restore_pr41(restore.manifest)
    assert reconstructed.state is access.FeatureValidationState.PR41_RESTORED
    reconstructed.close()


def test_r65_c20_interrupted_backup_fallback_uses_reconciliation_only(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    r64, restore = r65_bundles
    controller, _broker, _r64, _restore = _r65_advance_to_live(r65_bundles)
    controller.run_s1_refresh_status_live_validation()
    controller.close()

    broker = _R65ScriptedBroker()
    broker._durable_lifecycle_test = True
    broker.source_classification = access.CurrentSourceClassification.EXACT_R64
    reconstructed = access.RefreshStatusLiveValidationController(broker)
    reconstructed.reconcile_interrupted_source(r64.manifest, restore.manifest)
    reconstructed._begin(access.FeatureValidationAction.BACKUP_FALLBACK)
    reconstructed._mark(
        access.FeatureValidationAction.BACKUP_FALLBACK, "dispatch_started"
    )
    reconstructed.close()

    final_broker = _R65ScriptedBroker()
    final_broker._durable_lifecycle_test = True
    final = access.RefreshStatusLiveValidationController(final_broker)
    final.reconcile_private_backup_fallback(restore.manifest)

    assert final.state is access.FeatureValidationState.PR41_RESTORED
    assert not any(name == "backup_fallback" for name, _ in final_broker.calls)
    assert [name for name, _ in final_broker.calls].count(
        "backup_fallback_reconcile"
    ) == 1
    final.close()


def test_r65_c20_restoration_and_final_proof_survive_reconstruction(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, _broker, r64, restore = _r65_advance_to_live(r65_bundles)
    controller.run_s1_refresh_status_live_validation()
    controller.stage_restore(restore)
    controller.restore_pr41(restore.manifest)
    controller.close()

    second_broker = _R65ScriptedBroker()
    second_broker._durable_lifecycle_test = True
    second = access.RefreshStatusLiveValidationController(second_broker)
    second.verify_restore_inventory(restore.manifest)
    second.check_restore_core()
    second.restart_for_restore()
    second.await_restore_readiness()
    second.verify_refresh_feature_absent()
    second.admit_post_restore_repairs()
    second.close()

    final_broker = _R65ScriptedBroker()
    final_broker._durable_lifecycle_test = True
    final_broker.feature_backup_classification = access.FeatureBackupClassification.NONE
    final = access.RefreshStatusLiveValidationController(final_broker)
    final.reconcile_interrupted_source(r64.manifest, restore.manifest)
    final.inspect_feature_backup(restore.manifest)
    proof = final.complete()

    assert proof.complete
    assert final.state is access.FeatureValidationState.COMPLETE_NORMAL


@pytest.mark.parametrize(
    ("scenario", "classification"),
    (
        (
            "owned",
            access.FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE,
        ),
        ("none", access.FeatureBackupClassification.NONE),
        (
            "foreign",
            access.FeatureBackupClassification.OTHER_OR_INDETERMINATE,
        ),
        (
            "malformed",
            access.FeatureBackupClassification.OTHER_OR_INDETERMINATE,
        ),
    ),
)
def test_r65e_b1_to_b4_historical_ambiguous_backup_is_boundedly_classified(
    scenario: str,
    classification: access.FeatureBackupClassification,
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, _r64, restore = _r65e_historical_pr41_controller(
        r65_bundles, backup_classification=classification
    )

    result = controller.inspect_feature_backup(restore.manifest)

    assert scenario in {"owned", "none", "foreign", "malformed"}
    assert result == access.FeatureBackupContinuityResult(classification)
    assert set(asdict(result)) == {"classification", "retired"}
    assert not any(
        name in {"backup", "transfer", "install", "feature_backup_retire"}
        for name, _detail in broker.calls
    )
    assert controller._journal is not None
    assert controller._journal.consumed_actions == frozenset(
        {
            access.FeatureValidationAction.INITIAL_SOURCE,
            access.FeatureValidationAction.INITIAL_REPAIRS,
            access.FeatureValidationAction.BACKUP,
        }
    )
    controller.close()


def test_r65e_b4_real_malformed_package_is_preserved_as_indeterminate(
    tmp_path: Path,
) -> None:
    context = _r58_create_remote_backup(tmp_path)
    package = tmp_path / ".ha_tuya_ble_r36_backup"
    metadata = package / "metadata.json"
    metadata.write_bytes(b"{}")
    before = {
        path.relative_to(package).as_posix(): path.read_bytes()
        for path in package.rglob("*")
        if path.is_file()
    }

    inspected = _run_synthetic_remote_program(
        tmp_path, "inspect_retained_backup", context
    )
    retired = _run_synthetic_remote_program(tmp_path, "retire_retained_backup", context)
    after = {
        path.relative_to(package).as_posix(): path.read_bytes()
        for path in package.rglob("*")
        if path.is_file()
    }

    assert inspected == {
        "classification": "OTHER_OR_INDETERMINATE",
        "retired": False,
    }
    assert retired == inspected
    assert package.is_dir()
    assert after == before


def test_r65e_feature_pr41_source_generation_is_accepted_by_remote_backup(
    tmp_path: Path,
) -> None:
    """The Feature controller's exact commit authority is a valid generation."""
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    context = _r36_backup_payload(source_generation=access.PR41_RESTORE_COMMIT)

    created = _run_synthetic_remote_program(tmp_path, "backup", context)
    inspected = _run_synthetic_remote_program(
        tmp_path,
        "inspect_retained_backup",
        {
            **context,
            "restore_marker_owned": False,
        },
    )

    assert created["success"] is True
    assert created["source_generation"] == access.PR41_RESTORE_COMMIT
    assert inspected == {
        "classification": "OWNED_BY_RETAINED_LIFECYCLE",
        "retired": False,
    }


def test_r65h_feature_backup_reconciliation_accepts_exact_pr41_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The remote result crosses the parser before Feature reconciliation."""
    r64_manifest = access.SourceManifest(
        access.SourceState.R64_RUNTIME, _r30_manifest("RESTORE").entries
    )
    monkeypatch.setitem(
        access._AUTHORITY_MANIFEST_DIGESTS,
        access.SourceState.R64_RUNTIME.value,
        access._source_manifest_digest(r64_manifest.entries),
    )
    monkeypatch.setitem(
        access._AUTHORITY_MANIFEST_DIGESTS,
        access.SourceState.RESTORE.value,
        access._source_manifest_digest(_r30_manifest("RESTORE").entries),
    )
    r64 = access.build_source_bundle(
        access.SourceState.R64_RUNTIME, _r30_files("RESTORE"), r64_manifest
    )
    restore = access.build_source_bundle(
        access.SourceState.RESTORE,
        _r30_files("RESTORE"),
        _r30_manifest("RESTORE"),
    )
    controller, broker, _r64, restore = _r65e_historical_pr41_controller((r64, restore))
    _write_remote_source(tmp_path, restore)
    context = {
        "lifecycle_generation": str(controller._lifecycle_generation),
        "source_generation": access.PR41_RESTORE_COMMIT,
        "source_state": "PR41_BASELINE",
        "manifest": access._manifest_payload(restore.manifest),
    }
    created = _run_synthetic_remote_program(tmp_path, "backup", context)
    remote_result = _run_synthetic_remote_program(
        tmp_path, "reconcile_backup_creation", context
    )
    private_output = json.dumps(remote_result, separators=(",", ":")).encode("ascii")
    parsed = access._parse_backup_result(
        private_output,
        expected_source_generation=access.PR41_RESTORE_COMMIT,
    )

    def parse_reconciliation(
        manifest: access.SourceManifest, *, _capability: object = None
    ) -> access.BackupResult:
        assert manifest == restore.manifest
        broker._consume_capability(_capability, access.LifecycleAction.BACKUP_RECONCILE)
        assert parsed.source_generation == str(_capability.source_generation)
        return access._bind_evidence_origin(parsed, _capability)

    monkeypatch.setattr(
        broker, "_reconcile_private_backup_creation", parse_reconciliation
    )
    controller.inspect_feature_backup(restore.manifest)

    reconciled = controller.reconcile_feature_backup_creation(restore.manifest)

    assert created["source_generation"] == access.PR41_RESTORE_COMMIT
    assert remote_result["source_generation"] == access.PR41_RESTORE_COMMIT
    assert reconciled.classification is (
        access.FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
    )
    controller.close()


def _r65h_backup_result_output(**overrides: object) -> bytes:
    payload: dict[str, object] = {
        "success": True,
        "file_count": 1,
        "manifest_match": True,
        "regular_files_only": True,
        "lifecycle_generation": "a" * 32,
        "source_generation": access.PR41_RESTORE_COMMIT,
        "backup_generation": "b" * 32,
        "manifest_identity": "c" * 64,
        "backup_digest": "d" * 64,
    }
    payload.update(overrides)
    return json.dumps(payload, separators=(",", ":")).encode("ascii")


def test_r65h_legacy_backup_source_generation_remains_exact() -> None:
    source_generation = "e" * 32

    result = access._parse_backup_result(
        _r65h_backup_result_output(source_generation=source_generation),
        expected_source_generation=source_generation,
    )

    assert result.source_generation == source_generation


@pytest.mark.parametrize("wrong_source", ("0" * 40, "f" * 32))
def test_r65h_backup_parser_rejects_wrong_source_authority(
    wrong_source: str,
) -> None:
    assert wrong_source != access.PR41_RESTORE_COMMIT

    with pytest.raises(
        access.SessionBrokerError, match="PRIVATE_INTERACTIVE_SESSION_PROTOCOL"
    ):
        access._parse_backup_result(
            _r65h_backup_result_output(source_generation=wrong_source),
            expected_source_generation=access.PR41_RESTORE_COMMIT,
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("lifecycle_generation", "a" * 40),
        ("backup_generation", "b" * 40),
        ("manifest_identity", "c" * 63),
        ("backup_digest", "g" * 64),
    ),
)
def test_r65h_backup_parser_keeps_other_identity_fields_strict(
    field: str, invalid: str
) -> None:
    with pytest.raises(
        access.SessionBrokerError, match="PRIVATE_INTERACTIVE_SESSION_PROTOCOL"
    ):
        access._parse_backup_result(
            _r65h_backup_result_output(**{field: invalid}),
            expected_source_generation=access.PR41_RESTORE_COMMIT,
        )


def test_r65h_backup_parser_requires_source_authority_binding() -> None:
    parameter = inspect.signature(access._parse_backup_result).parameters[
        "expected_source_generation"
    ]

    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty
    with pytest.raises(TypeError):
        access._parse_backup_result(_r65h_backup_result_output())


def test_r65e_b5_b6_to_b12_owned_backup_reconciles_and_retires_once(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, r64, restore = _r65e_historical_pr41_controller(r65_bundles)
    assert controller.inspect_feature_backup(restore.manifest).classification is (
        access.FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
    )
    reconciled = controller.reconcile_feature_backup_creation(restore.manifest)
    assert reconciled.classification is (
        access.FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
    )
    controller.close()

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    replacement.feature_backup_classification = (
        access.FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
    )
    reconstructed = access.RefreshStatusLiveValidationController(replacement)
    reconstructed.inspect_feature_backup(restore.manifest)
    with pytest.raises(
        access.LifecycleControllerError, match="RETIREMENT_NOT_AUTHORIZED"
    ):
        reconstructed.retire_owned_feature_backup(restore.manifest)

    reconstructed.reconcile_interrupted_source(r64.manifest, restore.manifest)
    retired = reconstructed.retire_owned_feature_backup(restore.manifest)
    final = reconstructed.inspect_feature_backup(restore.manifest)

    assert retired == access.FeatureBackupContinuityResult(
        access.FeatureBackupClassification.NONE, retired=True
    )
    assert final == access.FeatureBackupContinuityResult(
        access.FeatureBackupClassification.NONE
    )
    assert [name for name, _detail in broker.calls].count(
        "backup_creation_reconcile"
    ) == 1
    assert [name for name, _detail in replacement.calls].count(
        "feature_backup_retire"
    ) == 1
    assert [name for name, _detail in replacement.calls].count(
        "feature_backup_inspect"
    ) == 2
    assert not any(
        name in {"backup", "transfer", "install"} for name, _detail in replacement.calls
    )
    with pytest.raises(access.LifecycleControllerError):
        reconstructed.retire_owned_feature_backup(restore.manifest)
    assert [name for name, _detail in replacement.calls].count(
        "feature_backup_retire"
    ) == 1
    reconstructed.close()


def test_r65e_i1_inspection_interruption_is_repeatable_before_one_retirement(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, _broker, r64, restore = _r65e_historical_pr41_controller(r65_bundles)
    controller.inspect_feature_backup(restore.manifest)
    controller.close()

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    reconstructed = access.RefreshStatusLiveValidationController(replacement)
    reconstructed.reconcile_interrupted_source(r64.manifest, restore.manifest)
    reconstructed.inspect_feature_backup(restore.manifest)
    reconstructed.reconcile_feature_backup_creation(restore.manifest)
    reconstructed.retire_owned_feature_backup(restore.manifest)

    assert [name for name, _detail in replacement.calls].count(
        "feature_backup_inspect"
    ) == 1
    assert [name for name, _detail in replacement.calls].count(
        "feature_backup_retire"
    ) == 1
    assert not any(name == "backup" for name, _detail in replacement.calls)
    reconstructed.close()


def test_r65e_i2_i3_lost_retirement_response_reconciles_none_without_replay(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, r64, restore = _r65e_historical_pr41_controller(r65_bundles)
    controller.inspect_feature_backup(restore.manifest)
    controller.reconcile_feature_backup_creation(restore.manifest)
    broker.queue(
        "feature_backup_retire",
        access.SessionBrokerError("SYNTHETIC_RETIREMENT_RESPONSE_LOST"),
    )
    with pytest.raises(access.LifecycleControllerError, match="RETIREMENT_AMBIGUOUS"):
        controller.retire_owned_feature_backup(restore.manifest)
    assert controller.state is access.FeatureValidationState.PR41_RESTORED
    assert controller._journal is not None
    assert (
        controller._journal.operation_phase(
            access.FeatureValidationAction.BACKUP_RETIRE
        )
        == "ambiguous"
    )
    controller.close()

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    replacement.feature_backup_classification = access.FeatureBackupClassification.NONE
    reconstructed = access.RefreshStatusLiveValidationController(replacement)
    reconstructed.reconcile_interrupted_source(r64.manifest, restore.manifest)
    result = reconstructed.inspect_feature_backup(restore.manifest)

    assert result.classification is access.FeatureBackupClassification.NONE
    assert reconstructed._journal is not None
    assert (
        reconstructed._journal.operation_phase(
            access.FeatureValidationAction.BACKUP_RETIRE
        )
        == "transition_committed"
    )
    assert not any(
        name == "feature_backup_retire" for name, _detail in replacement.calls
    )
    with pytest.raises(access.LifecycleControllerError):
        reconstructed.retire_owned_feature_backup(restore.manifest)
    assert not any(
        name == "feature_backup_retire" for name, _detail in replacement.calls
    )
    reconstructed.close()


def test_r65e_i2_process_loss_after_retirement_dispatch_is_tombstoned_on_open(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, _broker, r64, restore = _r65e_historical_pr41_controller(r65_bundles)
    controller.inspect_feature_backup(restore.manifest)
    controller.reconcile_feature_backup_creation(restore.manifest)
    controller._begin(access.FeatureValidationAction.BACKUP_RETIRE)
    controller._mark(access.FeatureValidationAction.BACKUP_RETIRE, "dispatch_started")
    controller.close()

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    replacement.feature_backup_classification = access.FeatureBackupClassification.NONE
    reconstructed = access.RefreshStatusLiveValidationController(replacement)
    assert reconstructed._journal is not None
    assert (
        reconstructed._journal.operation_phase(
            access.FeatureValidationAction.BACKUP_RETIRE
        )
        == "ambiguous"
    )
    reconstructed.reconcile_interrupted_source(r64.manifest, restore.manifest)
    reconstructed.inspect_feature_backup(restore.manifest)

    assert (
        reconstructed._journal.operation_phase(
            access.FeatureValidationAction.BACKUP_RETIRE
        )
        == "transition_committed"
    )
    assert not any(
        name == "feature_backup_retire" for name, _detail in replacement.calls
    )
    reconstructed.close()


def test_r65e_i4_reconstruction_clears_transient_source_retirement_authority(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, _broker, r64, restore = _r65e_historical_pr41_controller(r65_bundles)
    controller.inspect_feature_backup(restore.manifest)
    controller.reconcile_feature_backup_creation(restore.manifest)
    controller.reconcile_interrupted_source(r64.manifest, restore.manifest)
    controller.close()

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    reconstructed = access.RefreshStatusLiveValidationController(replacement)
    reconstructed.inspect_feature_backup(restore.manifest)
    with pytest.raises(
        access.LifecycleControllerError, match="RETIREMENT_NOT_AUTHORIZED"
    ):
        reconstructed.retire_owned_feature_backup(restore.manifest)
    reconstructed.reconcile_interrupted_source(r64.manifest, restore.manifest)
    reconstructed.retire_owned_feature_backup(restore.manifest)

    assert [name for name, _detail in replacement.calls].count(
        "feature_backup_retire"
    ) == 1
    reconstructed.close()


def test_r65e_i5_i6_foreign_backup_blocks_all_mutations_and_completion(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, _r64, restore = _r65e_historical_pr41_controller(
        r65_bundles,
        backup_classification=(
            access.FeatureBackupClassification.OTHER_OR_INDETERMINATE
        ),
    )
    assert controller.inspect_feature_backup(restore.manifest).classification is (
        access.FeatureBackupClassification.OTHER_OR_INDETERMINATE
    )
    with pytest.raises(access.LifecycleControllerError, match="RECONCILIATION_FAILED"):
        controller.reconcile_feature_backup_creation(restore.manifest)
    with pytest.raises(
        access.LifecycleControllerError, match="RETIREMENT_NOT_AUTHORIZED"
    ):
        controller.retire_owned_feature_backup(restore.manifest)
    with pytest.raises(access.LifecycleControllerError, match="CONTINUITY_REQUIRED"):
        controller.complete()

    assert not any(
        name
        in {
            "backup",
            "backup_creation_reconcile",
            "feature_backup_retire",
            "transfer",
            "install",
        }
        for name, _detail in broker.calls
    )
    assert controller._journal is not None
    assert (
        controller._journal.operation_phase(
            access.FeatureValidationAction.FINAL_ACCEPTANCE
        )
        is None
    )
    controller.close()


def test_r65e_final_acceptance_requires_fresh_none_without_consuming_failure(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, _r64, restore = _r65e_historical_pr41_controller(
        r65_bundles, backup_classification=access.FeatureBackupClassification.NONE
    )
    controller.verify_restore_inventory(restore.manifest)
    controller.check_restore_core()
    controller.restart_for_restore()
    controller.await_restore_readiness()
    controller.verify_refresh_feature_absent()
    controller.admit_post_restore_repairs()

    with pytest.raises(access.LifecycleControllerError, match="CONTINUITY_REQUIRED"):
        controller.complete()
    assert controller._journal is not None
    assert (
        controller._journal.operation_phase(
            access.FeatureValidationAction.FINAL_ACCEPTANCE
        )
        is None
    )

    controller.inspect_feature_backup(restore.manifest)
    proof = controller.complete()

    assert proof.complete is True
    assert controller.state is access.FeatureValidationState.COMPLETE_NORMAL
    assert not any(
        name in {"backup", "feature_backup_retire", "transfer", "install"}
        for name, _detail in broker.calls
    )


def test_r65e_public_backup_continuity_api_has_no_path_or_identity_inputs() -> None:
    for name in (
        "inspect_feature_backup",
        "reconcile_feature_backup_creation",
        "retire_owned_feature_backup",
    ):
        signature = inspect.signature(
            getattr(access.RefreshStatusLiveValidationController, name)
        )
        assert tuple(signature.parameters) == ("self", "manifest")
    result = access.FeatureBackupContinuityResult(
        access.FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE
    )
    rendered = repr(result)
    assert "generation" not in rendered
    assert "digest" not in rendered
    assert "path" not in rendered


def _r65g_complete_feature_terminal(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> tuple[object, access.SourceBundle, access.SourceBundle]:
    controller, _broker, r64, restore = _r65_advance_to_live(r65_bundles)
    controller.run_s1_refresh_status_live_validation()
    controller.stage_restore(restore)
    controller.restore_pr41(restore.manifest)
    controller.reconcile_interrupted_source(r64.manifest, restore.manifest)
    controller.inspect_feature_backup(restore.manifest)
    controller.retire_owned_feature_backup(restore.manifest)
    controller.inspect_feature_backup(restore.manifest)
    controller.verify_restore_inventory(restore.manifest)
    controller.check_restore_core()
    controller.restart_for_restore()
    controller.await_restore_readiness()
    controller.verify_refresh_feature_absent()
    controller.admit_post_restore_repairs()
    assert controller._journal is not None
    generation = controller._journal.lifecycle_generation
    assert controller.complete().complete is True
    return generation, r64, restore


def _r65g_feature_inspector(
    *,
    backup: access.FeatureBackupClassification = access.FeatureBackupClassification.NONE,
) -> tuple[access.RetainedFeatureValidationTerminalInspector, _R65ScriptedBroker]:
    broker = _R65ScriptedBroker()
    broker._durable_lifecycle_test = True
    broker.feature_backup_classification = backup
    return access.RetainedFeatureValidationTerminalInspector(broker), broker


def test_r65g_t1_complete_feature_terminal_is_admitted_with_bounded_metadata(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _r65g_complete_feature_terminal(r65_bundles)

    inspector, _broker = _r65g_feature_inspector()

    assert inspector.metadata == access.RetainedFeatureValidationTerminalMetadata(
        state=access.FeatureValidationState.COMPLETE_NORMAL,
        terminal=access.FeatureValidationState.COMPLETE_NORMAL,
        active=False,
        schema_version=2,
        final_restore_complete=True,
        live_result_durability=(
            access.FeatureLiveResultDurabilityClassification.DURABLY_AVAILABLE
        ),
    )
    rendered = repr(inspector.metadata)
    for forbidden in ("generation", "revision", "digest", "path", "identity"):
        assert forbidden not in rendered
    inspector.close()


def test_r65g_t2_active_feature_lifecycle_is_rejected_without_mutation(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _r64, _restore = r65_bundles
    broker = _R65ScriptedBroker()
    broker._durable_lifecycle_test = True
    controller = access.RefreshStatusLiveValidationController(broker)
    controller.close()
    journal = access._LIFECYCLE_STATE_ROOT / access._FEATURE_VALIDATION_JOURNAL_NAME
    before = journal.read_bytes()

    with pytest.raises(access.LifecycleControllerError, match="TERMINAL_REQUIRED"):
        _r65g_feature_inspector()

    assert journal.read_bytes() == before


def test_r65g_t3_failed_feature_terminal_is_rejected_without_mutation(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _r64, _restore = r65_bundles
    broker = _R65ScriptedBroker()
    broker._durable_lifecycle_test = True
    controller = access.RefreshStatusLiveValidationController(broker)
    assert controller._journal is not None
    controller._journal.terminal(access.FeatureValidationState.RESTORE_FAILED)
    controller.close()
    journal = access._LIFECYCLE_STATE_ROOT / access._FEATURE_VALIDATION_JOURNAL_NAME
    before = journal.read_bytes()

    with pytest.raises(access.LifecycleControllerError, match="TERMINAL_NOT_COMPLETE"):
        _r65g_feature_inspector()

    assert journal.read_bytes() == before


@pytest.mark.parametrize("malformation", ("empty", "unknown_schema"))
def test_r65g_t4_malformed_feature_terminal_is_rejected_without_mutation(
    malformation: str,
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _r65g_complete_feature_terminal(r65_bundles)
    journal = access._LIFECYCLE_STATE_ROOT / access._FEATURE_VALIDATION_JOURNAL_NAME
    if malformation == "empty":
        journal.write_bytes(b"{}")
    else:
        record = json.loads(journal.read_text(encoding="ascii"))
        record["schema_version"] = 999
        journal.write_text(json.dumps(record), encoding="ascii")
    before = journal.read_bytes()

    with pytest.raises(
        access.LifecycleControllerError, match="FEATURE_JOURNAL_INVALID"
    ):
        _r65g_feature_inspector()

    assert journal.read_bytes() == before


def test_r65g_t5_legacy_lifecycle_cannot_open_as_feature_terminal() -> None:
    broker = _R32ScriptedBroker()
    broker._durable_lifecycle_test = True
    legacy = access.FullPreflightLifecycleController(broker)
    legacy.close()
    legacy_journal = access._LIFECYCLE_STATE_ROOT / access._LIFECYCLE_JOURNAL_NAME
    before = legacy_journal.read_bytes()

    with pytest.raises(access.LifecycleControllerError, match="MODE_CONFLICT"):
        _r65g_feature_inspector()

    assert legacy_journal.read_bytes() == before


@pytest.mark.parametrize(
    "classification",
    (
        access.CurrentSourceClassification.EXACT_R64,
        access.CurrentSourceClassification.OTHER,
        access.CurrentSourceClassification.INDETERMINATE,
    ),
)
def test_r65g_t7_to_t9_non_pr41_source_denies_retirement(
    classification: access.CurrentSourceClassification,
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _generation, r64, restore = _r65g_complete_feature_terminal(r65_bundles)
    inspector, broker = _r65g_feature_inspector()
    broker.source_classification = classification

    result = inspector.inspect_current_source(r64.manifest, restore.manifest)

    assert result.classification is classification
    with pytest.raises(access.LifecycleControllerError, match="NOT_AUTHORIZED"):
        inspector.retire_terminal()
    inspector.close()


def test_r65g_t6_retirement_requires_same_handle_current_source_proof(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _r65g_complete_feature_terminal(r65_bundles)
    inspector, _broker = _r65g_feature_inspector()

    with pytest.raises(access.LifecycleControllerError, match="NOT_AUTHORIZED"):
        inspector.retire_terminal()

    inspector.close()


@pytest.mark.parametrize(
    "classification",
    (
        access.FeatureBackupClassification.OWNED_BY_CURRENT_FEATURE_LIFECYCLE,
        access.FeatureBackupClassification.OTHER_OR_INDETERMINATE,
    ),
)
def test_r65g_t10_t11_non_none_backup_denies_terminal_retirement(
    classification: access.FeatureBackupClassification,
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _generation, r64, restore = _r65g_complete_feature_terminal(r65_bundles)
    inspector, _broker = _r65g_feature_inspector(backup=classification)
    assert (
        inspector.inspect_current_source(r64.manifest, restore.manifest).classification
        is access.CurrentSourceClassification.EXACT_PR41
    )
    assert inspector.inspect_feature_backup(restore.manifest).classification is (
        classification
    )

    with pytest.raises(access.LifecycleControllerError, match="NOT_AUTHORIZED"):
        inspector.retire_terminal()

    inspector.close()


def test_r65g_t12_to_t15_clean_retirement_is_single_and_allows_fresh_lifecycle(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    old_generation, r64, restore = _r65g_complete_feature_terminal(r65_bundles)
    inspector, broker = _r65g_feature_inspector()
    assert (
        inspector.inspect_current_source(r64.manifest, restore.manifest).classification
        is access.CurrentSourceClassification.EXACT_PR41
    )
    assert inspector.inspect_feature_backup(restore.manifest).classification is (
        access.FeatureBackupClassification.NONE
    )

    inspector.retire_terminal()
    with pytest.raises(access.LifecycleControllerError, match="NOT_AUTHORIZED"):
        inspector.retire_terminal()
    inspector.close()

    journal = access._LIFECYCLE_STATE_ROOT / access._FEATURE_VALIDATION_JOURNAL_NAME
    assert not journal.exists()
    with pytest.raises(access.LifecycleControllerError, match="TERMINAL_REQUIRED"):
        _r65g_feature_inspector()
    fresh = access.RefreshStatusLiveValidationController(broker)
    assert fresh.state is access.FeatureValidationState.BASELINE
    assert fresh._journal is not None
    assert fresh._journal.lifecycle_generation != old_generation
    assert fresh._journal.consumed_actions == frozenset()
    assert fresh._journal._record["operations"] == {}
    assert fresh._journal.backup_identity is None
    assert fresh._journal.source_classification is None
    fresh.close()


@pytest.mark.parametrize(
    "missing",
    (
        access.FeatureValidationAction.RESTORE_INVENTORY,
        access.FeatureValidationAction.RESTORE_CORE_CHECK,
        access.FeatureValidationAction.REMOVAL_RESTART,
        access.FeatureValidationAction.RESTORE_READINESS,
        access.FeatureValidationAction.FEATURE_ABSENCE,
        access.FeatureValidationAction.POST_RESTORE_REPAIRS,
        access.FeatureValidationAction.FINAL_ACCEPTANCE,
    ),
)
def test_r65g_final_proof_incomplete_terminal_is_rejected_without_mutation(
    missing: access.FeatureValidationAction,
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _generation, _r64, _restore = _r65g_complete_feature_terminal(r65_bundles)
    journal = access._LIFECYCLE_STATE_ROOT / access._FEATURE_VALIDATION_JOURNAL_NAME
    record = json.loads(journal.read_text(encoding="ascii"))
    record["consumed_actions"].remove(missing.value)
    del record["operations"][missing.value]
    if missing is access.FeatureValidationAction.REMOVAL_RESTART:
        record["restart_results"].pop(missing.value, None)
    journal.write_text(json.dumps(record), encoding="ascii")
    before = journal.read_bytes()

    with pytest.raises(
        access.LifecycleControllerError, match="FEATURE_JOURNAL_INVALID"
    ):
        _r65g_feature_inspector()

    assert journal.read_bytes() == before


def test_r65g_schema1_terminal_string_without_final_proof_cannot_retire(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _generation, r64, restore = _r65g_complete_feature_terminal(r65_bundles)
    journal = access._LIFECYCLE_STATE_ROOT / access._FEATURE_VALIDATION_JOURNAL_NAME
    record = json.loads(journal.read_text(encoding="ascii"))
    record["schema_version"] = 1
    del record["live_result"]
    del record["final_restore_complete"]
    record["consumed_actions"].remove(
        access.FeatureValidationAction.FINAL_ACCEPTANCE.value
    )
    del record["operations"][access.FeatureValidationAction.FINAL_ACCEPTANCE.value]
    journal.write_text(json.dumps(record), encoding="ascii")
    before = journal.read_bytes()

    inspector, _broker = _r65g_feature_inspector()
    assert inspector.metadata.final_restore_complete is False
    assert (
        inspector.inspect_current_source(r64.manifest, restore.manifest).classification
        is access.CurrentSourceClassification.EXACT_PR41
    )
    assert inspector.inspect_feature_backup(restore.manifest).classification is (
        access.FeatureBackupClassification.NONE
    )
    with pytest.raises(access.LifecycleControllerError, match="NOT_AUTHORIZED"):
        inspector.retire_terminal()
    inspector.close()
    assert journal.read_bytes() == before


def test_r65g_public_inspector_surface_has_no_paths_ids_or_mutation_bypass() -> None:
    public = {
        name
        for name, value in inspect.getmembers(
            access.RetainedFeatureValidationTerminalInspector,
            predicate=callable,
        )
        if not name.startswith("_")
    }
    assert public == {
        "inspect_current_source",
        "inspect_feature_backup",
        "retire_terminal",
        "close",
    }
    assert tuple(
        inspect.signature(
            access.RetainedFeatureValidationTerminalInspector.retire_terminal
        ).parameters
    ) == ("self",)


def test_r65g_schema1_r65e_terminal_remains_inspectable_without_live_result(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    _r65g_complete_feature_terminal(r65_bundles)
    journal = access._LIFECYCLE_STATE_ROOT / access._FEATURE_VALIDATION_JOURNAL_NAME
    record = json.loads(journal.read_text(encoding="ascii"))
    record["schema_version"] = 1
    del record["live_result"]
    del record["final_restore_complete"]
    journal.write_text(json.dumps(record), encoding="ascii")

    inspector, _broker = _r65g_feature_inspector()

    assert inspector.metadata.schema_version == 1
    assert inspector.metadata.final_restore_complete is True
    assert inspector.metadata.live_result_durability is (
        access.FeatureLiveResultDurabilityClassification.NOT_DURABLY_AVAILABLE
    )
    inspector.close()


def test_r65g_live_result_is_sanitized_durable_and_reconstructed_once(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, _broker, r64, restore = _r65_advance_to_live(r65_bundles)
    live = controller.run_s1_refresh_status_live_validation()
    expected = access._durable_refresh_status_live_result(live)
    assert controller.durable_live_result == expected
    controller.close()

    journal = access._LIFECYCLE_STATE_ROOT / access._FEATURE_VALIDATION_JOURNAL_NAME
    retained = journal.read_text(encoding="ascii")
    for forbidden in (
        "retained_confirmation_changed_dp_ids",
        "entity_id",
        "device_id",
        "entry_id",
        "session_ordinal",
    ):
        assert forbidden not in retained

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    replacement.source_classification = access.CurrentSourceClassification.EXACT_R64
    reconstructed = access.RefreshStatusLiveValidationController(replacement)

    assert reconstructed.durable_live_result == expected
    assert reconstructed.durable_live_result is not None
    assert reconstructed.durable_live_result.retained_confirmation_observed is True
    assert reconstructed.durable_live_result.zero_write_gate is True
    with pytest.raises(access.LifecycleControllerError, match="TRANSITION"):
        reconstructed.run_s1_refresh_status_live_validation()
    reconstructed.reconcile_interrupted_source(r64.manifest, restore.manifest)
    reconstructed.close()


def test_r65g_ambiguous_live_result_is_durable_before_restoration(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, _r64, _restore = _r65_advance_to_live(r65_bundles)

    def ambiguous(*, _capability: object = None) -> object:
        broker._consume_feature_capability(
            _capability, access.FeatureValidationAction.LIVE_VALIDATION
        )
        raise access.SessionBrokerError("SYNTHETIC_AMBIGUOUS_RESULT")

    broker._run_s1_refresh_status_live_validation = ambiguous
    result = controller.run_s1_refresh_status_live_validation()

    assert result.ambiguous is True
    assert controller.durable_live_result is not None
    assert controller.durable_live_result.ambiguous is True
    assert controller.durable_live_result.failure_class is (
        access.RefreshStatusFailureClass.AMBIGUOUS
    )
    controller.close()

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    reconstructed = access.RefreshStatusLiveValidationController(replacement)
    assert reconstructed.durable_live_result is not None
    assert reconstructed.durable_live_result.ambiguous is True
    reconstructed.close()


def test_r66a_red1_public_owner_refresh_observer_exists() -> None:
    """The exact R65H parent has no observer-only owner-press API."""
    method = access.RefreshStatusLiveValidationController.observe_owner_refresh_trial
    assert tuple(inspect.signature(method).parameters) == ("self", "trial_kind")


def test_r66a_red2_automated_collector_is_not_the_owner_observer() -> None:
    """The existing live collector triggers its own two Refresh presses."""
    tree = ast.parse(access._REMOTE_REFRESH_STATUS_PROGRAM)
    automated = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_validation"
    )
    press_calls = [
        node
        for node in ast.walk(automated)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "press"
    ]
    assert len(press_calls) == 2
    assert hasattr(
        access.RefreshStatusLiveValidationController, "begin_hardware_observation"
    )


def test_r66a_red3_feature_journal_can_retain_owner_trial_rows() -> None:
    """The exact parent journal has no durable R66 hardware section."""
    assert hasattr(access._DurableFeatureValidationJournal, "hardware_observation")
    assert hasattr(access._DurableFeatureValidationJournal, "record_hardware_trial")


def test_r66a_red4_partial_owner_sequence_has_reconstruction_api() -> None:
    """The exact parent cannot resume at the next unobserved owner trial."""
    assert hasattr(
        access.RefreshStatusLiveValidationController,
        "hardware_observation",
    )
    assert hasattr(
        access.RefreshStatusLiveValidationController,
        "observe_hardware_release",
    )


def _r66a_owner_parser() -> dict[str, object]:
    """Load only the value-free owner lifecycle parser from embedded source."""
    tree = ast.parse(access._REMOTE_REFRESH_STATUS_PROGRAM)
    selected = [ast.Import(names=[ast.alias("re")])]
    assignments = {
        "EMPTY_COUNTS",
        "LOG_RE",
        "SEND_RE",
        "REFRESH_BOUND_RE",
        "REFRESH_TERMINAL_RE",
        "DP_RE",
    }
    functions = {"parse_refresh_lifecycle", "parse_owner_refresh_lifecycle"}
    for node in tree.body:
        if (
            (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id in assignments
                    for target in node.targets
                )
            )
            or isinstance(node, ast.FunctionDef)
            and node.name in functions
        ):
            selected.append(node)
    namespace: dict[str, object] = {}
    exec(  # noqa: S102 - isolated repository-owned parser definitions only.
        compile(
            ast.fix_missing_locations(ast.Module(selected, type_ignores=[])),
            "<r66a-owner-parser>",
            "exec",
        ),
        namespace,
    )
    return namespace


def _r66a_embedded_function(name: str) -> object:
    """Load one dependency-free embedded observer helper."""
    tree = ast.parse(access._REMOTE_REFRESH_STATUS_PROGRAM)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    namespace: dict[str, object] = {}
    exec(  # noqa: S102 - isolated repository-owned helper definition only.
        compile(
            ast.fix_missing_locations(ast.Module([function], type_ignores=[])),
            f"<r66a-{name}>",
            "exec",
        ),
        namespace,
    )
    return namespace[name]


def test_r66a_o1_observer_source_has_no_refresh_or_generic_service_dispatch() -> None:
    tree = ast.parse(access._REMOTE_REFRESH_STATUS_PROGRAM)
    observer = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "observe_owner_trial"
    )
    called_names = {
        node.func.id
        for node in ast.walk(observer)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    literals = {
        node.value
        for node in ast.walk(observer)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }

    assert "press" not in called_names
    assert "button.press" not in literals
    service_dispatches = [
        node
        for node in ast.walk(observer)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "command"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "call_service"
    ]
    assert service_dispatches == []
    assert "owner_refresh_trial" in access._REMOTE_REFRESH_STATUS_PROGRAM
    source = ast.get_source_segment(access._REMOTE_REFRESH_STATUS_PROGRAM, observer)
    assert source is not None
    assert source.index("discard_before_owner_lifecycle(stream)") < source.index(
        "wait_for_owner_press(ws, button_id, 60)"
    )


def test_r66a_o2_to_o4_only_exact_owned_button_event_can_start_trial() -> None:
    owner_press_event = _r66a_embedded_function("owner_press_event")
    selected = "button.selected_refresh_status"

    def event(entity_id: object, *, service: str = "press") -> dict[str, object]:
        return {
            "type": "event",
            "event": {
                "event_type": "call_service",
                "data": {
                    "domain": "button",
                    "service": service,
                    "service_data": {"entity_id": entity_id},
                },
            },
        }

    assert owner_press_event(event(selected), selected) is True
    assert owner_press_event(event("button.foreign_refresh_status"), selected) is False
    assert owner_press_event(event(selected, service="turn_on"), selected) is False
    assert owner_press_event({"type": "event", "event": {}}, selected) is False


def test_r66a_o2_to_o12_exact_lifecycle_metadata_is_value_free() -> None:
    parser = _r66a_owner_parser()["parse_owner_refresh_lifecycle"]
    identity = "tuya-ble-session-" + "n" * 16
    foreign = "tuya-ble-session-" + "p" * 16
    lines = [
        _r65c_record(foreign, "Sending packet: #1 FUN_SENDER_DEVICE_STATUS"),
        _r65c_record(identity, "Sending packet: #1 FUN_SENDER_DEVICE_STATUS"),
        _r65c_record(identity, "S1_REFRESH_ACCEPTED"),
        _r65c_record(identity, "S1_REFRESH_SESSION_BOUND_NEW session_ordinal=3"),
        _r65c_record(identity, "Sending packet: #2 FUN_SENDER_DEVICE_INFO"),
        _r65c_record(identity, "Sending packet: #3 FUN_SENDER_PAIR"),
        _r65c_record(identity, "Sending packet: #4 FUN_SENDER_DEVICE_STATUS"),
        _r65c_record(identity, "Sending packet: #5 FUN_SENDER_DPS_V4"),
        _r65c_record(
            identity,
            "Received datapoint update, id: 8, type: DT_VALUE, length: 4",
        ),
        _r65c_record(
            identity,
            "Received datapoint update, id: 33, type: DT_BOOL, length: 1",
        ),
        _r65c_record(identity, "S1_REFRESH_COMPLETED session_ordinal=3"),
    ]

    parsed = parser(lines)

    assert parsed[0] == identity
    assert parsed[1] == {
        "device_info": 1,
        "pair": 1,
        "device_status": 1,
        "datapoint": 1,
        "other": 0,
    }
    assert parsed[3:5] == ("NEW_SESSION", True)
    assert parsed[5] == [
        {"dp_id": 8, "types": ["DT_VALUE"], "encoded_lengths": [4]},
        {"dp_id": 33, "types": ["DT_BOOL"], "encoded_lengths": [1]},
    ]
    rendered = repr(parsed)
    assert "payload" not in rendered.lower()


def test_r66a_o14_overlapping_refresh_lifecycles_are_rejected() -> None:
    parser = _r66a_owner_parser()["parse_owner_refresh_lifecycle"]
    identity = "tuya-ble-session-" + "q" * 16
    lines = [
        _r65c_record(identity, "S1_REFRESH_ACCEPTED"),
        _r65c_record(identity, "S1_REFRESH_SESSION_BOUND_NEW session_ordinal=1"),
        _r65c_record(identity, "S1_REFRESH_ACCEPTED"),
        _r65c_record(identity, "S1_REFRESH_COMPLETED session_ordinal=1"),
    ]
    with pytest.raises(ValueError, match="refresh_lifecycle"):
        parser(lines)


def test_r66a_o5_to_o13_trial_parser_preserves_provenance_and_timeout() -> None:
    payload = {
        "trial_kind": "COLD",
        "owner_press_observed": True,
        "request_completed": True,
        "session_provenance": "REUSED_SESSION",
        "counts": {
            "device_info": 0,
            "pair": 0,
            "device_status": 1,
            "datapoint": 0,
            "other": 0,
        },
        "reported_dp_ids": [8],
        "per_dp": [{"dp_id": 8, "types": ["DT_VALUE"], "encoded_lengths": [4]}],
        "current_session_provenance": True,
        "retained_confirmation_observed": True,
        "hold_active_after_refresh": True,
        "ambiguous": False,
        "failure_class": "PROVENANCE_MISMATCH",
    }
    result = access._parse_owner_refresh_trial_result(
        json.dumps(payload).encode("ascii")
    )
    assert result.trial_kind is access.OwnerRefreshTrialKind.COLD
    assert result.session_provenance is access.RefreshSessionProvenance.REUSED_SESSION
    assert result.failure_class is access.OwnerRefreshFailureClass.PROVENANCE_MISMATCH

    timeout = dict(payload)
    timeout.update(
        owner_press_observed=False,
        request_completed=False,
        session_provenance=None,
        counts={name: 0 for name in payload["counts"]},
        reported_dp_ids=[],
        per_dp=[],
        current_session_provenance=None,
        retained_confirmation_observed=False,
        hold_active_after_refresh=None,
        failure_class="OWNER_PRESS_NOT_OBSERVED",
    )
    parsed_timeout = access._parse_owner_refresh_trial_result(
        json.dumps(timeout).encode("ascii")
    )
    assert parsed_timeout.owner_press_observed is False
    assert parsed_timeout.counts == access.RefreshPacketCounts(0, 0, 0, 0, 0)

    retained = dict(payload)
    retained.update(
        trial_kind="RETAINED",
        session_provenance="NEW_SESSION",
    )
    parsed_retained = access._parse_owner_refresh_trial_result(
        json.dumps(retained).encode("ascii")
    )
    assert parsed_retained.session_provenance is (
        access.RefreshSessionProvenance.NEW_SESSION
    )
    assert parsed_retained.failure_class is (
        access.OwnerRefreshFailureClass.PROVENANCE_MISMATCH
    )

    with_value = dict(payload)
    with_value["per_dp"] = [
        {
            "dp_id": 8,
            "types": ["DT_VALUE"],
            "encoded_lengths": [4],
            "value": 1,
        }
    ]
    with pytest.raises(access.SessionBrokerError, match="PROTOCOL"):
        access._parse_owner_refresh_trial_result(json.dumps(with_value).encode("ascii"))


def test_r66a_o19_release_observer_has_no_device_operation() -> None:
    tree = ast.parse(access._REMOTE_REFRESH_STATUS_PROGRAM)
    observer = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "observe_release"
    )
    calls = [
        node
        for node in ast.walk(observer)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "command"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    ]
    assert all(node.args[0].value != "call_service" for node in calls)
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "press"
        for node in ast.walk(observer)
    )


def test_r66a_o15_to_o20_partial_sequence_reconstructs_without_replay(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, r64, restore = _r65_advance_to_live(r65_bundles)
    assert controller.begin_hardware_observation().trials == ()
    assert controller.observe_owner_refresh_trial(access.OwnerRefreshTrialKind.COLD)
    assert controller.observe_owner_refresh_trial(access.OwnerRefreshTrialKind.RETAINED)
    assert controller.observe_hardware_release().normal_release_observed is True
    controller.close()

    replacement = _R65ScriptedBroker()
    replacement._durable_lifecycle_test = True
    reconstructed = access.RefreshStatusLiveValidationController(replacement)
    evidence = reconstructed.hardware_observation
    assert evidence is not None
    assert len(evidence.trials) == 2
    assert len(evidence.releases) == 1
    assert evidence.zero_write_aggregate is True
    assert (
        reconstructed.state
        is access.FeatureValidationState.R64_POST_RESTART_INVENTORY_VERIFIED
    )
    third = reconstructed.observe_owner_refresh_trial(access.OwnerRefreshTrialKind.COLD)
    assert third.trial_kind is access.OwnerRefreshTrialKind.COLD
    assert len(reconstructed.hardware_observation.trials) == 3
    reconstructed.stage_restore(restore)
    reconstructed.restore_pr41(restore.manifest)
    reconstructed.reconcile_interrupted_source(r64.manifest, restore.manifest)
    reconstructed.close()
    assert [name for name, _detail in broker.calls].count("owner_refresh_trial") == 2


def test_r66a_failed_observation_stops_before_another_remote_wait(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, _r64, _restore = _r65_advance_to_live(r65_bundles)
    controller.begin_hardware_observation()
    broker.owner_trial_failure = access.OwnerRefreshFailureClass.PROVENANCE_MISMATCH
    result = controller.observe_owner_refresh_trial(access.OwnerRefreshTrialKind.COLD)
    assert result.failure_class is access.OwnerRefreshFailureClass.PROVENANCE_MISMATCH
    before = len(broker.calls)
    with pytest.raises(access.LifecycleControllerError, match="OBSERVATION_INVALID"):
        controller.observe_owner_refresh_trial(access.OwnerRefreshTrialKind.RETAINED)
    assert len(broker.calls) == before
    controller.close()


def test_r66a_o15_o16_exact_plan_caps_before_remote_wait(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, broker, _r64, _restore = _r65_advance_to_live(r65_bundles)
    controller.begin_hardware_observation()
    for index, kind in enumerate(access._R66_TRIAL_SEQUENCE, start=1):
        controller.observe_owner_refresh_trial(kind)
        if index in access._R66_RELEASE_AFTER_TRIAL_COUNTS:
            controller.observe_hardware_release()
    complete = controller.finish_hardware_observation()
    assert complete.phase is access.HardwareObservationPhase.COMPLETE
    assert len(complete.trials) == 15
    assert len(complete.releases) == 10
    before = len(broker.calls)
    with pytest.raises(access.LifecycleControllerError, match="OBSERVATION_INVALID"):
        controller.observe_owner_refresh_trial(access.OwnerRefreshTrialKind.COLD)
    assert len(broker.calls) == before
    controller.close()


def test_r66a_o18_legacy_feature_journal_has_no_synthetic_hardware_evidence(
    r65_bundles: tuple[access.SourceBundle, access.SourceBundle],
) -> None:
    controller, _broker, _r64, _restore = _r65_advance_to_live(r65_bundles)
    assert controller._journal is not None
    assert controller._journal.schema_version == 1
    assert controller.hardware_observation is None
    controller.close()


def test_r66a_o21_o22_automated_collector_and_restore_predecessors_unchanged() -> None:
    tree = ast.parse(access._REMOTE_REFRESH_STATUS_PROGRAM)
    automated = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_validation"
    )
    assert (
        sum(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "press"
            for node in ast.walk(automated)
        )
        == 2
    )
    assert access._FEATURE_ACTION_PREDECESSORS[
        access.FeatureValidationAction.RESTORE_TRANSFER
    ] >= {
        access.FeatureValidationState.R64_POST_RESTART_INVENTORY_VERIFIED,
        access.FeatureValidationState.LIVE_VALIDATION_CONSUMED,
    }


def test_r65g_warm_retained_confirmation_is_required_for_live_pass() -> None:
    zero = access.RefreshPacketCounts(0, 0, 1, 0, 0)
    result = access.RefreshStatusLiveValidationResult(
        1,
        True,
        True,
        True,
        True,
        True,
        access.RefreshPressResult(
            True,
            access.RefreshPacketCounts(1, 1, 1, 0, 0),
            access.RefreshSessionProvenance.NEW_SESSION,
            True,
            (8,),
        ),
        access.RefreshPressResult(
            True,
            zero,
            access.RefreshSessionProvenance.REUSED_SESSION,
            True,
            (),
        ),
        True,
        access.RefreshHoldResult(True, True, False),
        False,
        access.RefreshStatusFailureClass.RETAINED_CONFIRMATION_NOT_OBSERVED,
        False,
    )

    assert result.passed is False
    durable = access._durable_refresh_status_live_result(result)
    assert durable.warm_passed is False
    assert durable.retained_confirmation_observed is False


@pytest.mark.parametrize("window", ("cold", "warm"))
def test_r65g_unexpected_sender_fails_zero_write_gate(window: str) -> None:
    cold_counts = access.RefreshPacketCounts(1, 1, 1, 0, int(window == "cold"))
    warm_counts = access.RefreshPacketCounts(0, 0, 1, 0, int(window == "warm"))
    result = access.RefreshStatusLiveValidationResult(
        1,
        True,
        True,
        True,
        True,
        True,
        access.RefreshPressResult(
            True,
            cold_counts,
            access.RefreshSessionProvenance.NEW_SESSION,
            True,
            (8,),
        ),
        access.RefreshPressResult(
            True,
            warm_counts,
            access.RefreshSessionProvenance.REUSED_SESSION,
            True,
            (8,),
        ),
        True,
        access.RefreshHoldResult(True, True, False),
        False,
        access.RefreshStatusFailureClass.ZERO_WRITE_GATE_FAILED,
        False,
    )

    assert result.passed is False
    assert access._durable_refresh_status_live_result(result).zero_write_gate is False
    assert "cold_counts['datapoint'] or cold_counts['other']" in (
        access._REMOTE_REFRESH_STATUS_PROGRAM
    )
    assert "warm_counts['datapoint'] or warm_counts['other']" in (
        access._REMOTE_REFRESH_STATUS_PROGRAM
    )
