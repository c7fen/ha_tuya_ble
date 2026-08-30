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
import subprocess
import sys
import traceback
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
        evidence = broker.collect_resolution_info(
            access.RepairsGate.INITIAL, _relevant, _critical
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
    evidence = broker.collect_resolution_info(
        access.RepairsGate.INITIAL, _relevant, _critical
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
    assert broker.collect_resolution_info(
        access.RepairsGate.INITIAL, _relevant, _critical
    ) == access.RepairsEvidence(shape_valid=True, relevant_count=0, critical_count=0)
    assert broker.collect_resolution_info(
        access.RepairsGate.POST_ACTIVATION, _relevant, _critical
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
    evidence = broker.collect_resolution_info(
        access.RepairsGate.INITIAL, _relevant, _critical
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
    assert hasattr(access.PrivateInteractiveSessionBroker, "collect_resolution_info")


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
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    """Keep synthetic source acceptance explicit and separate from Git authorities."""
    if not request.node.name.startswith("test_r30_"):
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
    }
    public_callables = {
        name
        for name, value in vars(access.PrivateInteractiveSessionBroker).items()
        if not name.startswith("_") and callable(value)
    }
    assert public_callables == {
        "open",
        "close",
        "collect_resolution_info",
        "create_private_backup",
        "transfer_source_bundle",
        "install_staged_source",
        "verify_source_inventory",
        "check_core",
        "restart_core",
        "wait_for_core_readiness",
        "inventory_temporary_services",
        "invoke_phase_a",
        "run_invalid_nonce_preflight",
        "restore_source",
        "restore_private_backup",
    }
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
    monkeypatch.setattr(broker, "_write_private", writes.append)

    with pytest.raises(access.SessionBrokerError, match="OPERATION_INVALID"):
        broker._execute_bounded_operation("arbitrary", {})

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
    writes: list[str] = []
    monkeypatch.setattr(broker, "_write_private", writes.append)

    with pytest.raises(access.SessionBrokerError, match="HELPER_OPERATION_INVALID"):
        broker.invoke_phase_a("probe")

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
        and node.name == "restart_core"
    )

    assert not any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(restart))


def test_r30_restart_replay_rejected_before_second_remote_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One activated source state can submit at most one restart."""
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    broker._active_source_state = access.SourceState.CANDIDATE
    broker._restarted_states = set()
    calls: list[object] = []

    def execute(operation: object, _value: object) -> bytes:
        calls.append(operation)
        return b'{"submitted":true,"accepted":true}'

    monkeypatch.setattr(broker, "_execute_bounded_operation", execute)

    assert broker.restart_core().accepted is True
    with pytest.raises(access.SessionBrokerError, match="ALREADY_SUBMITTED"):
        broker.restart_core()
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
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    calls: list[object] = []

    def execute(operation: object, _value: object, *, detail: str) -> bytes:
        calls.append((operation, detail))
        return b'{"exit_code":78,"outcome":"transport_ambiguous","nonce":"aaaaaaaaaaaaaaaa"}'

    monkeypatch.setattr(broker, "_execute_bounded_operation", execute)
    result = broker.invoke_phase_a(access.PhaseAOperation.PREFLIGHT, nonce="a" * 16)

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
        b'{"exit_code":65,"outcome":"not_submitted","http_handoff":false}',
    )

    assert result.exit_code == 65
    assert result.outcome == "not_submitted"
    assert result.http_handoff is False


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
        broker.restore_source(candidate)


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
    assert "operation not in {'preflight', 'audit', 'receipt'}" in helper_source
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
        access.PrivateInteractiveSessionBroker.restore_private_backup
    )

    assert tuple(signature.parameters) == ("self",)
    assert access.BoundedOperation.RESTORE_BACKUP.value == "restore_backup"


def _run_synthetic_remote_program(
    tmp_path: Path,
    operation: str,
    value: dict[str, object],
    *,
    source_replacements: dict[str, str] | None = None,
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

    backup = _run_synthetic_remote_program(tmp_path, "backup", {})
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
    "backup": {"success": True, "file_count": 3, "manifest_match": True, "regular_files_only": True},
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
                response = {"exit_code": 65, "outcome": "not_submitted", "http_handoff": False}
            elif "audit" in line:
                response = {
                    "exit_code": 0,
                    "outcome": "audit_snapshot",
                    "nonce": "b" * 16,
                    "audit": {
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
            elif "receipt" in line:
                response = {"exit_code": 0, "outcome": "receipt", "nonce": "b" * 16}
            else:
                response = {"exit_code": 0, "outcome": "preflight_ok", "nonce": "b" * 16}
        elif operation == "restore":
            response = {"installation_success": True, "expected_file_count": 3, "installed_file_count": 3, "manifest_match": True}
        else:
            response = responses[operation]
        print(json.dumps(response, separators=(",", ":")), flush=True)
        emit(values[1])
    elif line.strip() == "exit":
        assert restart_count == 2
        break
""".replace(
    "__COUNTERS__", repr(access.AUDIT_COUNTER_NAMES)
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
    assert broker.collect_resolution_info(
        access.RepairsGate.INITIAL, _relevant, _critical
    ).shape_valid
    assert broker.create_private_backup().success
    assert broker.transfer_source_bundle(candidate).manifest_match
    assert broker.install_staged_source(candidate.manifest).manifest_match
    assert broker.verify_source_inventory(candidate.manifest).manifest_match
    assert broker.check_core(1).check_passed
    assert broker.restart_core().accepted
    assert broker.wait_for_core_readiness().integration_loaded
    assert broker.inventory_temporary_services(
        access.ServiceExpectation.PRESENT
    ).all_expected_present
    a0 = broker.invoke_phase_a(
        access.PhaseAOperation.AUDIT,
        nonce="b" * 16,
        evidence_label=access.AuditLabel.A0,
    )
    assert a0.audit is not None
    assert broker.run_invalid_nonce_preflight().http_handoff is False
    ap0 = broker.invoke_phase_a(
        access.PhaseAOperation.AUDIT,
        nonce="b" * 16,
        evidence_label=access.AuditLabel.AP0,
    )
    assert access.compare_audit_snapshots(a0.audit, ap0.audit).zero_io_unchanged
    assert (
        broker.invoke_phase_a(
            access.PhaseAOperation.PREFLIGHT, nonce="b" * 16
        ).exit_code
        == 0
    )
    assert broker.invoke_phase_a(
        access.PhaseAOperation.RECEIPT, nonce="b" * 16
    ).exit_code in {0, 66}
    a1 = broker.invoke_phase_a(
        access.PhaseAOperation.AUDIT,
        nonce="b" * 16,
        evidence_label=access.AuditLabel.A1,
    )
    assert a1.audit is not None
    a2 = broker.invoke_phase_a(
        access.PhaseAOperation.AUDIT,
        nonce="b" * 16,
        evidence_label=access.AuditLabel.A2,
    )
    assert a2.audit is not None
    assert broker.restore_source(restore).manifest_match
    assert broker.check_core(1).check_passed
    assert broker.restart_core().accepted
    assert broker.wait_for_core_readiness().integration_loaded
    assert broker.verify_source_inventory(restore.manifest).manifest_match
    assert broker.inventory_temporary_services(
        access.ServiceExpectation.ABSENT
    ).all_expected_absent
    assert broker.collect_resolution_info(
        access.RepairsGate.POST_ROLLBACK, _relevant, _critical
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
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    broker._active_source_state = access.SourceState.CANDIDATE
    broker._restarted_states = set()
    calls = 0

    def execute(_operation: object, _value: object) -> bytes:
        nonlocal calls
        calls += 1
        if failure_mode == "exception":
            raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")
        return b'{"submitted":false,"accepted":false}'

    monkeypatch.setattr(broker, "_execute_bounded_operation", execute)

    if failure_mode == "exception":
        with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
            broker.restart_core()
    else:
        assert broker.restart_core().submitted is False
    with pytest.raises(access.SessionBrokerError, match="ALREADY_SUBMITTED"):
        broker.restart_core()
    assert calls == 1


def test_r30_echo_suppression_must_succeed_before_operation_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed stty transition cannot release program or bundle bytes."""
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    broker._echo_disabled = False
    writes: list[str] = []
    monkeypatch.setattr(broker, "_write_private", writes.append)

    def fail_read(_frame: bytes, **_kwargs: object) -> bytes:
        raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")

    monkeypatch.setattr(broker, "_read_until", fail_read)

    with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
        broker._ensure_echo_disabled()
    assert len(writes) == 1
    assert writes[0].startswith("stty -echo && ")
    assert "python3" not in writes[0]
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
    assert "os.replace(staged, INTEGRATION)" in activate


def test_r30_private_backup_fallback_is_consumed_once(tmp_path: Path) -> None:
    """Fallback restoration deletes the displaced candidate and cannot toggle back."""
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    original = b"synthetic integration source\n"
    (integration / "__init__.py").write_bytes(original)
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )

    assert _run_synthetic_remote_program(tmp_path, "backup", {})["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]

    restored = _run_synthetic_remote_program(tmp_path, "restore_backup", {})
    repeated = _run_synthetic_remote_program(tmp_path, "restore_backup", {})

    assert restored["manifest_match"] is True
    assert repeated == {"error_class": "OPERATION_FAILED"}
    assert (integration / "__init__.py").read_bytes() == original
    assert not (integration / ".phase_a_tools").exists()
    assert not (tmp_path / ".ha_tuya_ble_r30_backup").exists()


def test_r30_backup_cleanup_failure_remains_consumed(tmp_path: Path) -> None:
    """A cleanup error cannot make a successful fallback reusable."""
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    original = b"synthetic integration source\n"
    (integration / "__init__.py").write_bytes(original)
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    assert _run_synthetic_remote_program(tmp_path, "backup", {})["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path, "transfer", access._bundle_payload(candidate)
    )["manifest_match"]
    assert _run_synthetic_remote_program(
        tmp_path,
        "install",
        {"manifest": access._manifest_payload(candidate.manifest)},
    )["manifest_match"]

    cleanup = """    try:
        remove(BACKUP)
    except OSError:
        pass
"""
    failed_cleanup = """    try:
        raise OSError('synthetic_cleanup')
    except OSError:
        pass
"""
    restored = _run_synthetic_remote_program(
        tmp_path,
        "restore_backup",
        {},
        source_replacements={cleanup: failed_cleanup},
    )
    repeated = _run_synthetic_remote_program(tmp_path, "restore_backup", {})

    assert restored["manifest_match"] is True
    assert repeated == {"error_class": "OPERATION_FAILED"}
    assert (integration / "__init__.py").read_bytes() == original
    assert (tmp_path / ".ha_tuya_ble_r30_backup.consumed").is_file()


def test_r30_backup_post_exchange_failure_rolls_back_and_clears_marker(
    tmp_path: Path,
) -> None:
    """A failed fallback restores candidate state and permits one safe retry."""
    integration = tmp_path / "custom_components" / "tuya_ble"
    integration.mkdir(parents=True)
    (integration / "__init__.py").write_bytes(b"synthetic integration source\n")
    candidate = access.build_source_bundle(
        access.SourceState.CANDIDATE, _r30_files(), _r30_manifest()
    )
    assert _run_synthetic_remote_program(tmp_path, "backup", {})["manifest_match"]
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
        {},
        source_replacements={
            "        installed = inventory_targets()\n": (
                "        raise ValueError('synthetic_after_exchange')\n"
            )
        },
    )

    assert failed == {"error_class": "OPERATION_FAILED"}
    assert (integration / ".phase_a_tools").is_dir()
    assert not (tmp_path / ".ha_tuya_ble_r30_backup.consumed").exists()
    assert _run_synthetic_remote_program(tmp_path, "restore_backup", {})[
        "manifest_match"
    ]


def test_r30_authoritative_restore_invalidates_backup_and_new_backup_resets_marker(
    tmp_path: Path,
) -> None:
    """PR #41 consumes fallback authority; a later verified backup starts fresh."""
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
    assert _run_synthetic_remote_program(tmp_path, "backup", {})["manifest_match"]
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

    assert _run_synthetic_remote_program(tmp_path, "restore_backup", {}) == {
        "error_class": "OPERATION_FAILED"
    }
    marker = tmp_path / ".ha_tuya_ble_r30_backup.consumed"
    assert marker.is_file()
    assert _run_synthetic_remote_program(tmp_path, "backup", {})["manifest_match"]
    assert not marker.exists()


def test_r30_broker_backup_fence_consumed_before_failed_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost fallback result cannot authorize a second remote exchange."""
    broker = object.__new__(access.PrivateInteractiveSessionBroker)
    broker._active_source_state = access.SourceState.CANDIDATE
    broker._backup_restore_attempted = False
    calls = 0

    def execute(_operation: object, _value: object) -> bytes:
        nonlocal calls
        calls += 1
        raise access.SessionBrokerError("PRIVATE_INTERACTIVE_SESSION_TIMEOUT")

    monkeypatch.setattr(broker, "_execute_bounded_operation", execute)

    with pytest.raises(access.SessionBrokerError, match="TIMEOUT"):
        broker.restore_private_backup()
    with pytest.raises(access.SourceBundleError, match="ALREADY_CONSUMED"):
        broker.restore_private_backup()
    assert calls == 1
