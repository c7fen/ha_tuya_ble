"""Regression coverage for the HTTP-upgrade/WebSocket byte boundary.

Only a socketpair is used. The real embedded WebSocket constructor, framing,
and command code run; no Home Assistant connection or device call is made.
"""

from __future__ import annotations

import ast
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import struct
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "tools/home_assistant_live_access.py"
HEADER = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
)


def transport_namespace():
    outer = ast.parse(SOURCE.read_text(encoding="utf-8"))
    program = next(
        ast.literal_eval(node.value)
        for node in outer.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "_REMOTE_REFRESH_STATUS_PROGRAM"
            for target in node.targets
        )
    )
    tree = ast.parse(program)
    selected = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        and node.name in {"strict_json", "WebSocket", "OwnerWebSocket"}
    ]
    namespace = dict(
        base64=base64, json=json, os=os, socket=socket, struct=struct, time=time
    )
    exec(
        compile(
            ast.Module(body=selected, type_ignores=[]), "<embedded-transport>", "exec"
        ),
        namespace,
    )
    return namespace


def frame(value, opcode=1):
    payload = (
        json.dumps(value, separators=(",", ":")).encode() if opcode == 1 else value
    )
    size = len(payload)
    if size < 126:
        return bytes([0x80 | opcode, size]) + payload
    return bytes([0x80 | opcode, 126]) + struct.pack(">H", size) + payload


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def read_client_frame(sock):
    first, second = read_exact(sock, 2)
    size = second & 0x7F
    if size == 126:
        size = struct.unpack(">H", read_exact(sock, 2))[0]
    elif size == 127:
        size = struct.unpack(">Q", read_exact(sock, 8))[0]
    assert second & 0x80, "Client frames must remain masked"
    mask = read_exact(sock, 4)
    payload = read_exact(sock, size)
    decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return first & 0x0F, decoded


class WatchedSocket:
    """Real socket with a signal marking the first transport read."""

    def __init__(self, sock):
        self.sock = sock
        self.first_read_done = threading.Event()
        self.first_read_length = None

    def recv(self, size):
        data = self.sock.recv(size)
        if not self.first_read_done.is_set():
            self.first_read_length = len(data)
            self.first_read_done.set()
        return data

    def __getattr__(self, name):
        return getattr(self.sock, name)


@contextmanager
def upgrade_server(
    prefix_bytes, *, prefix_control=b"", fragmented_header=False, reject_auth=False
):
    """Choose legal TCP boundaries deterministically; do not mock recv()."""
    client, server = socket.socketpair()
    watched = WatchedSocket(client)
    server.settimeout(0.4)
    auth_frame = prefix_control + frame({"type": "auth_required"})
    cut = len(auth_frame) if prefix_bytes == "all" else prefix_bytes
    first = (HEADER[:11] if fragmented_header else HEADER) + (
        b"" if fragmented_header else auth_frame[:cut]
    )
    server.sendall(first)
    calls, errors = [], []
    completed = threading.Event()

    def serve():
        try:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                request.extend(read_exact(server, 1))
            assert watched.first_read_done.wait(1)
            if fragmented_header:
                server.sendall(HEADER[11:] + auth_frame)
            elif cut < len(auth_frame):
                server.sendall(auth_frame[cut:])
            opcode, payload = read_client_frame(server)
            if opcode == 10:
                calls.append("pong")
                opcode, payload = read_client_frame(server)
            auth = json.loads(payload)
            assert opcode == 1 and auth["type"] == "auth"
            calls.append("auth")
            if reject_auth:
                server.sendall(frame({"type": "auth_invalid"}))
                return
            # Coalesce auth_ok with a later unrelated event as a second boundary.
            server.sendall(
                frame({"type": "auth_ok"}) + frame({"type": "event", "event": {}})
            )
            opcode, payload = read_client_frame(server)
            command = json.loads(payload)
            assert opcode == 1 and command["type"] == "config/device_registry/list"
            calls.append(command["type"])
            server.sendall(
                frame(
                    {
                        "id": command["id"],
                        "type": "result",
                        "success": True,
                        "result": [],
                    }
                )
            )
            completed.wait(1)
        except (OSError, EOFError) as error:
            errors.append(type(error).__name__)
        except BaseException as error:
            errors.append(type(error).__name__)
        finally:
            server.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    with (
        patch.dict(os.environ, {"SUPERVISOR_TOKEN": "SYNTHETIC_TEST_ONLY"}),
        patch.object(socket, "create_connection", return_value=watched) as connect,
    ):
        try:
            yield SimpleNamespace(
                client=watched, calls=calls, errors=errors, connect=connect
            )
        finally:
            completed.set()
            client.close()
            worker.join(timeout=2)
            assert not worker.is_alive()


@pytest.mark.parametrize("cut", [0, 1, 2, 3, 8, 15, "all"])
def test_upgrade_preserves_full_and_partial_first_frame(cut):
    ns = transport_namespace()
    with upgrade_server(cut) as server:
        ws = ns["WebSocket"]()
        assert ws.command("config/device_registry/list") == []
        ws.close()
        assert server.connect.call_count == 1
        assert server.calls == ["auth", "config/device_registry/list"]
        assert not server.errors


def test_fragmented_http_header_with_coalesced_authentication():
    ns = transport_namespace()
    with upgrade_server("all", fragmented_header=True) as server:
        ws = ns["WebSocket"]()
        assert ws.command("config/device_registry/list") == []
        ws.close()
        assert server.connect.call_count == 1
        assert not server.errors


def test_ping_and_authentication_coalesced_with_upgrade():
    ns = transport_namespace()
    with upgrade_server("all", prefix_control=frame(b"check", opcode=9)) as server:
        ws = ns["WebSocket"]()
        assert ws.ping_count == 1
        assert ws.command("config/device_registry/list") == []
        ws.close()
        assert server.calls == ["pong", "auth", "config/device_registry/list"]
        assert not server.errors


def test_failed_authentication_closes_socket_without_reconnection():
    ns = transport_namespace()
    with upgrade_server(0, reject_auth=True) as server:
        with pytest.raises(ValueError, match="websocket_auth"):
            ns["WebSocket"]()
        assert server.client.fileno() == -1
        assert server.connect.call_count == 1


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 403 Forbidden\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nX: " + b"x" * 16384,
        b"HTTP/1.1 101 Switching Protocols\r\n",
    ],
)
def test_invalid_or_truncated_upgrade_closes_socket(response):
    ns = transport_namespace()
    client, server = socket.socketpair()
    server.sendall(response)
    server.shutdown(socket.SHUT_WR)
    try:
        with (
            patch.dict(os.environ, {"SUPERVISOR_TOKEN": "SYNTHETIC_TEST_ONLY"}),
            patch.object(socket, "create_connection", return_value=client) as connect,
        ):
            errors = []

            def construct():
                try:
                    ns["WebSocket"]()
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=construct, daemon=True)
            worker.start()
            worker.join(timeout=0.25)
            returned = not worker.is_alive()
            if not returned:
                client.close()
                worker.join(timeout=1)
            assert returned, "EOF/invalid upgrade must not loop indefinitely"
            assert len(errors) == 1 and isinstance(errors[0], ValueError)
            assert str(errors[0]).startswith("websocket")
            assert client.fileno() == -1
            assert connect.call_count == 1
    finally:
        client.close()
        server.close()


def test_buffered_data_cannot_extend_absolute_deadline():
    ns = transport_namespace()
    client, server = socket.socketpair()
    ws = ns["WebSocket"].__new__(ns["WebSocket"])
    ws.sock = client
    ws._receive_buffer = bytearray(frame({"type": "event"}))
    before = bytes(ws._receive_buffer)
    try:
        with pytest.raises(socket.timeout):
            ws.recv(time.monotonic() - 1)
        assert bytes(ws._receive_buffer) == before
    finally:
        client.close()
        server.close()


def test_ping_does_not_extend_absolute_deadline():
    ns = transport_namespace()
    client, server = socket.socketpair()
    ws = ns["WebSocket"].__new__(ns["WebSocket"])
    ws.sock = client
    ws._receive_buffer = bytearray(frame(b"check", opcode=9))
    started = time.monotonic()
    try:
        with pytest.raises(socket.timeout):
            ws.recv(started + 0.05)
        assert time.monotonic() - started < 0.5
        assert ws.ping_count == 1
        assert read_client_frame(server) == (10, b"check")
    finally:
        client.close()
        server.close()


def test_partial_buffered_frame_timeout_still_closes_connection():
    ns = transport_namespace()
    client, server = socket.socketpair()
    ws = ns["WebSocket"].__new__(ns["WebSocket"])
    ws.sock = client
    ws._receive_buffer = bytearray(b"\x81")
    try:
        with pytest.raises(ValueError, match="websocket_partial_frame"):
            ws.recv(time.monotonic() + 0.05)
        assert client.fileno() == -1
    finally:
        client.close()
        server.close()


def preflight_namespace():
    ns = transport_namespace()
    outer = ast.parse(SOURCE.read_text(encoding="utf-8"))
    program = next(
        ast.literal_eval(node.value)
        for node in outer.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "_REMOTE_REFRESH_STATUS_PROGRAM"
            for t in node.targets
        )
    )
    nodes = [
        node
        for node in ast.parse(program).body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"empty_owner_preflight", "preflight_owner_trial"}
    ]
    import urllib.error

    ns["urllib"] = urllib
    ns["R66_CONTEXT"] = {"bound": None, "approved": []}
    candidates = [
        dict(
            valid=True,
            fingerprint=f"SYNTHETIC-{i}",
            hold=15,
            options={"connection_mode": "on_demand", "ble_control_enabled": True},
            button=f"button.synthetic_{i}",
            connection=f"binary_sensor.synthetic_{i}",
        )
        for i in range(4)
    ]

    def resolve(ws):
        assert ws.command("config/device_registry/list") == []
        return candidates

    ns["resolve_owner_refresh_target"] = resolve
    ns["state"] = lambda entity: {
        "state": "off" if entity.startswith("binary_sensor.") else "unknown"
    }
    exec(
        compile(
            ast.Module(body=nodes, type_ignores=[]), "<embedded-preflight>", "exec"
        ),
        ns,
    )
    return ns


def test_preflight_reaches_all_candidates_after_coalesced_upgrade():
    ns = preflight_namespace()
    with upgrade_server("all") as server:
        result = ns["preflight_owner_trial"]("COLD")
        assert result["ready"] is True
        assert result["failure_class"] is None
        assert result["diagnostics"]["boundary"] == "COMPLETE"
        assert result["diagnostics"]["candidates_checked"] == 4
        assert result["diagnostics"]["candidates_ready"] == 4
        assert server.connect.call_count == 1
        assert server.calls == ["auth", "config/device_registry/list"]
