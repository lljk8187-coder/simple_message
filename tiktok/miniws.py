"""Minimal blocking WebSocket client (stdlib only) with HTTP-CONNECT proxy.

Implemented because curl_cffi's WS API segfaults on dead handles and the
`websockets` package cannot ride a pre-opened CONNECT tunnel cleanly.
Client frames are masked per RFC 6455; server frames are parsed unmasked.
"""
import base64
import os
import random
import socket
import ssl
import struct
import time


class WsFrame:
    def __init__(self, opcode, payload):
        self.opcode = opcode      # 1 text, 2 binary, 8 close, 9 ping, 10 pong
        self.payload = payload


class MiniWs:
    def __init__(self, host, path, headers, proxy=None, timeout=15):
        self.host = host
        self.path = path
        self.timeout = timeout
        if proxy:
            phost, pport = proxy.replace('http://', '').split(':')
            self.sock = socket.create_connection((phost, int(pport)), timeout=timeout)
            self.sock.sendall(('CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n'
                               % (host, host)).encode())
            resp = b''
            while b'\r\n\r\n' not in resp:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ConnectionError('proxy closed during CONNECT')
                resp += chunk
            status = resp.split(b'\r\n')[0].decode()
            if ' 200' not in status:
                raise ConnectionError('proxy CONNECT failed: ' + status)
        else:
            self.sock = socket.create_connection((host, 443), timeout=timeout)
        self.tls = ssl.create_default_context()
        self.s = self.tls.wrap_socket(self.sock, server_hostname=host)

        key = base64.b64encode(os.urandom(16)).decode()
        req = ('GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n'
               'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
               'Sec-WebSocket-Version: 13\r\n' % (path, host, key))
        for k, v in (headers or {}).items():
            req += '%s: %s\r\n' % (k, v)
        req += '\r\n'
        self.s.sendall(req.encode())
        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise ConnectionError('closed during upgrade')
            buf += chunk
        head, _, rest = buf.partition(b'\r\n\r\n')
        status = head.split(b'\r\n')[0].decode()
        if ' 101' not in status:
            raise ConnectionError('upgrade failed: ' + status)
        self._buf = rest

    # ---- frame io ----
    def _recv_exact(self, n):
        while len(self._buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError('socket closed (have %d/%d)'
                                      % (len(self._buf), n))
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv_frame(self):
        b = self._recv_exact(2)
        fin_op = b[0]
        opcode = fin_op & 0x0F
        masked = b[1] & 0x80
        ln = b[1] & 0x7F
        if ln == 126:
            ln = struct.unpack('>H', self._recv_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack('>Q', self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(ln) if ln else b''
        if mask:
            payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        return WsFrame(opcode, payload)

    def send_frame(self, opcode, payload):
        mask = os.urandom(4)
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack('>H', n)
        else:
            header += bytes([0x80 | 127]) + struct.pack('>Q', n)
        masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        self.s.sendall(header + mask + masked)

    def send_binary(self, data):
        self.send_frame(2, data)

    def send_text(self, s):
        self.send_frame(1, s.encode())

    def close(self):
        try:
            self.send_frame(8, struct.pack('>H', 1000))
        except Exception:
            pass
        try:
            self.s.close()
        except Exception:
            pass
