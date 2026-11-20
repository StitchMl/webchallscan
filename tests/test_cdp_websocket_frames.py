"""CDP WebSocket read limits and strict frame handling, with no network."""
import json
import struct

import pytest

from webchallscan.session import SessionCaptureError, _WebSocket


class FakeSocket:
    def __init__(self, data):
        self.data = bytearray(data)
        self.requested = []
        self.sent = []
    def recv(self, n):
        self.requested.append(n)
        result = bytes(self.data[:n])
        del self.data[:n]
        return result
    def sendall(self, data):
        self.sent.append(data)


def frame(payload, opcode=1, *, fin=True):
    marker = (0x80 if fin else 0) | opcode
    if len(payload) < 126:
        return bytes([marker, len(payload)]) + payload
    if len(payload) < 65536:
        return bytes([marker, 126]) + struct.pack("!H", len(payload)) + payload
    return bytes([marker, 127]) + struct.pack("!Q", len(payload)) + payload


def ws(content):
    instance = _WebSocket.__new__(_WebSocket)
    instance.sock = FakeSocket(content)
    return instance


def test_single_text_frame_and_ping_pong_then_json():
    value = {"id": 1, "result": {"ok": True}}
    payload = frame(b"abc", 9) + frame(json.dumps(value).encode())
    client = ws(payload)
    assert client.recv_json() == value
    assert len(client.sock.sent) == 1
    assert client.sock.sent[0][0] == 0x8A


def test_large_announced_frame_rejected_before_body_read():
    announced = bytes([0x81, 127]) + struct.pack("!Q", 2_000_001)
    client = ws(announced)
    with pytest.raises(SessionCaptureError, match="2 MB"):
        client.recv_json()
    # No request for payload bytes of an attacker-selected size.
    assert max(client.sock.requested) <= 8


@pytest.mark.parametrize("raw, reason", [
    (bytes([0x81, 0x81]), "unmasked"),
    (bytes([0x41, 0]), "unsupported frame extensions"),
    (frame(b"{}", fin=False), "unsupported CDP"),
    (frame(b"binary", opcode=2), "unsupported CDP"),
    (frame(b"x" * 126, opcode=9), "control frame"),
    (frame(b"{}", opcode=8, fin=False), "control frame"),
    (frame(b"close", opcode=8), "closed unexpectedly"),
    (frame(b"not-json"), "invalid CDP"),
    (frame(b"[]"), "must be an object"),
])
def test_invalid_frames_are_rejected_safely(raw, reason):
    socket = ws(raw)
    with pytest.raises(SessionCaptureError, match=reason):
        socket.recv_json()


def test_control_pong_frame_is_ignored():
    client = ws(frame(b"ignored", opcode=10) + frame(b'{"id": 3}'))
    assert client.recv_json() == {"id": 3}
    assert client.sock.sent == []
