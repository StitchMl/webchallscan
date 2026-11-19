"""RFC 6455 CDP upgrade must validate specific headers and preserve frames."""
import base64
import hashlib
import json

import pytest

from webchallscan.session import SessionCaptureError, _WebSocket


class FakeSocket:
    def __init__(self, response):
        self.buffer = bytearray(response)
        self.sent = []
        self.closed = False
        self.requested = []
    def recv(self, count):
        self.requested.append(count)
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        return data
    def sendall(self, data):
        self.sent.append(data)
    def settimeout(self, *_):
        pass
    def close(self):
        self.closed = True


def accept_header():
    key = base64.b64encode(bytes(16)).decode()
    return base64.b64encode(hashlib.sha1(
        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
    ).digest())


def valid_headers(accept=None):
    value = accept if accept is not None else accept_header()
    return (b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + value + b"\r\n\r\n")


def make_client(monkeypatch, response, url="ws://127.0.0.1:9222/devtools/page/1"):
    socket = FakeSocket(response)
    monkeypatch.setattr("webchallscan.session.os.urandom", lambda n: bytes(n))
    monkeypatch.setattr("webchallscan.session.socket.create_connection", lambda *_a, **_kw: socket)
    return socket, _WebSocket(url, 1.0)


def test_valid_handshake_preserves_immediately_following_cdp_frame(monkeypatch):
    result = {"id": 2, "result": {"ok": True}}
    data = json.dumps(result).encode()
    frame = bytes([0x81, len(data)]) + data
    sock, client = make_client(monkeypatch, valid_headers() + frame)
    assert client.recv_json() == result
    assert sock.sent[0].startswith(b"GET /devtools/page/1 HTTP/1.1\r\n")
    assert not sock.buffer
    assert sock.requested.count(1) > 10


@pytest.mark.parametrize("headers", [
    b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
    b"X-Misleading: " + accept_header() + b"\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\nSec-WebSocket-Accept: " + accept_header() + b"\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept_header() + b"\r\n\r\n",
    valid_headers(b"wrong-accept"),
    valid_headers()[:-2] + b"Sec-WebSocket-Accept: " + accept_header() + b"\r\n\r\n",
])
def test_invalid_handshake_is_rejected_and_connection_closed(monkeypatch, headers):
    sock = FakeSocket(headers)
    monkeypatch.setattr("webchallscan.session.os.urandom", lambda n: bytes(n))
    monkeypatch.setattr("webchallscan.session.socket.create_connection", lambda *_a, **_kw: sock)
    with pytest.raises(SessionCaptureError):
        _WebSocket("ws://127.0.0.1:9222/devtools/page/1", 1.0)
    assert sock.closed


def test_truncated_or_oversize_http_upgrade_refused(monkeypatch):
    for response in (b"HTTP/1.1 101 Switching Protocols\r\n", b"A" * 65536):
        sock = FakeSocket(response)
        monkeypatch.setattr("webchallscan.session.os.urandom", lambda n: bytes(n))
        monkeypatch.setattr("webchallscan.session.socket.create_connection", lambda *_a, **_kw: sock)
        with pytest.raises(SessionCaptureError):
            _WebSocket("ws://127.0.0.1:9222/devtools", 1.0)
        assert sock.closed
