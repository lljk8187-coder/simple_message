"""TikTok WebSocket 发送通道（纯标准库）—— 冷建联的唯一有效传输。

为什么需要它（实测，2026-10-20/21）：
  - 网页端私信走 `wss://im-ws.tiktok.com/ws/v2`（二进制 protobuf，双向 "hi" 心跳），
    不是 HTTP。HTTP `/v1/message/send` 对**陌生人 / message-request 会话**一律静默
    丢弃（返回 biz_code=0 但不落地）；对已接受会话才正常。
  - 所以冷建联必须走这条通道；已接受会话仍可走 HTTP（见 adapter.send）。

鉴权（与线上抓包逐字节一致）：
    access_key = md5('9' + appKey + device_id + 'f8a69f1719916z')

帧结构（三层，均已用官方帧 3480B 校准，6 处差异见下）：
  外层  { f1 seq, f2 ts_ms, f3 5, f4 1, f5 KV(X-Bogus 在前 + 环境), f7 'pb',
          f8 内层信封, f15 ticket-guard KV, f18 1 }
  内层  { f1 100, f2 seq 回显, f3 '1.8.2', f4 '', f5 3, f6 0, f7 build,
          f8 {100 载荷}, f9 device_id, f11 'web', f15 环境 KV, f18 1 }
  载荷  { f1 conv_id, f2 1, f3 short_id, f4 正文 JSON,
          f5 ext(仅 s:mentioned_users + s:client_message_id), f6 7,
          f7 'deprecated', f8 client_message_id }

与直觉做法（把 HTTP 帧塞进 WS）的 6 处差异，逐条都是构帧失败的原因：
  1. 内层 f2 是 seq 回显，不是 HTTP 子命令
  2. ext 只带两个 KV（没有 HTTP 版其它字段）
  3. f7 是 'deprecated' 字面量，不是真实 ticket
  4. 外层没有 f9
  5. guard KV 在外层 f15，不在 f5
  6. 内层 f4 是空串，不是 feature tag

回执（2026-10-21 解码）：
  ACK  f8.f1=100，f2=seq 回显，f3=biz_code（0=接受），f4=biz_msg，
       f6.100.f1=服务端 msg_id，f6.100.f4=我方 client_message_id
  PUSH f8.f1=500，f6.500.f2=conv_id，.f5=消息（f7 发送者，f8 正文，
       f9 含 s:client_message_id / s:is_stranger）
注意 ACK 成功 ≠ 落地：对方未回复时的第 2 条仍回 biz_code=0 但被丢弃。
"""
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import time
import uuid

from . import proto as pb
from . import client as cl

WS_HOST = 'im-ws.tiktok.com'
WS_PATH = '/ws/v2'
APP_KEY = 'e1bd35ec9db7b8d846de66ed140b1ad9'
SECRET = 'f8a69f1719916z'
FPID = 9
SEQ_START = 10001          # SDK 全局计数器起点；实测被服务端接受
CONNECT_TIMEOUT = 15
ACK_TIMEOUT = 12


def access_key(device_id):
    return hashlib.md5((str(FPID) + APP_KEY + str(device_id) + SECRET).encode()).hexdigest()


def _cookie_val(cookie, name):
    for part in (cookie or '').split('; '):
        if part.startswith(name + '='):
            return part[len(name) + 1:]
    return ''


def _kv(k, v):
    return pb.s(1, k) + pb.s(2, v)


def _env_kv(sess):
    """环境 KV 列表（外层 f5 与内层 f15 共用）。"""
    ua = cl.UA_DEFAULT
    return [
        ('aid', '1988'), ('app_name', 'tiktok_web'), ('channel', 'web'),
        ('device_platform', 'web_pc'), ('device_id', sess.device_id),
        ('region', 'US'), ('priority_region', 'US'), ('os', 'windows'),
        ('referer', cl.WEB + '/business-suite/messages'),
        ('root_referer', 'https://www.google.com/'),
        ('cookie_enabled', 'true'), ('screen_width', '1920'),
        ('screen_height', '1080'), ('browser_language', 'zh-CN'),
        ('browser_platform', 'Win32'), ('browser_name', 'Mozilla'),
        ('browser_version', ua.split('Mozilla/')[1]),
        ('browser_online', 'true'), ('verifyFp', ''),
        ('app_language', 'zh-Hans'), ('webcast_language', 'zh-Hans'),
        ('tz_name', 'Asia/Shanghai'), ('is_page_visible', 'true'),
        ('focus_state', 'true'), ('is_fullscreen', 'false'),
        ('history_len', '17'), ('user_is_login', 'true'),
        ('data_collection_enabled', 'true'), ('from_appID', '1988'),
        ('locale', 'zh-Hans'), ('user_agent', ua),
        ('Web-Sdk-Ms-Token', sess.ms_token),
    ]


# ------------------------------------------------------------------ 构帧

def build_payload(conv_id, short_id, text, cid):
    ext = _kv('s:mentioned_users', '') + _kv('s:client_message_id', cid)
    return (pb.s(1, conv_id) + pb.vint(2, 1) + pb.vint(3, int(short_id))
            + pb.s(4, json.dumps({'aweType': 0, 'text': text}, separators=(',', ':')))
            + pb.ld(5, ext) + pb.vint(6, 7) + pb.s(7, 'deprecated') + pb.s(8, cid))


def build_inner_envelope(sess, payload, seq):
    return (pb.vint(1, 100) + pb.vint(2, seq) + pb.s(3, cl.ENVELOPE_VER) + pb.s(4, '')
            + pb.vint(5, 3) + pb.vint(6, 0) + pb.s(7, cl.ENVELOPE_BUILD)
            + pb.sub(8, pb.sub(100, payload))
            + pb.s(9, sess.device_id) + pb.s(11, 'web'))


def build_frame(sess, conv_id, short_id, text, cid=None, seq=SEQ_START, xbogus='1'):
    """返回 (frame_bytes, cid, tier)。"""
    cid = cid or str(uuid.uuid4())
    payload = build_payload(conv_id, short_id, text, cid)
    inner = build_inner_envelope(sess, payload, seq)

    guard_h, tier = cl.ticket_guard_headers(sess, '/v1/message/send')
    guard_kv = b''.join(pb.ld(15, _kv(k, v)) for k, v in guard_h.items())

    for k, v in _env_kv(sess):
        inner += pb.ld(15, _kv(k, v))
    inner += guard_kv
    inner += pb.vint(18, 1)

    outer = pb.vint(1, seq) + pb.vint(2, int(time.time() * 1000))
    outer += pb.vint(3, 5) + pb.vint(4, 1)
    for k, v in [('X-Bogus', xbogus)] + _env_kv(sess):
        outer += pb.ld(5, _kv(k, v))
    outer += pb.s(7, 'pb')
    outer += pb.sub(8, inner)
    outer += guard_kv
    outer += pb.vint(18, 1)
    return outer, cid, tier


# ------------------------------------------------------------------ 回执

def _kv_pairs(items, field=5):
    out = {}
    for _f, _w, _v, b in pb.all_of(items, field, 2):
        kv = pb.parse(b)
        if not kv:
            continue
        k = pb.text(pb.blob(kv, 1))
        if k:
            out.setdefault(k, pb.text(pb.blob(kv, 2)))
    return out


def parse_down_frame(data):
    """把服务端帧分类成 ack / push / other，并解出关键字段。"""
    items = pb.parse(data)
    if items is None:
        return {'kind': 'binary', 'len': len(data)}
    meta = _kv_pairs(items, 5)
    inner_raw = pb.blob(items, 8)
    inner = pb.parse(inner_raw) if inner_raw else None
    if not inner:
        return {'kind': 'other', 'kv': meta, 'len': len(data)}
    cmd = pb.one(inner, 1)
    info = {'kind': 'other', 'cmd': cmd, 'seq': pb.one(inner, 2),
            'biz_code': pb.one(inner, 3), 'biz_msg': pb.text(pb.blob(inner, 4)),
            'is_ack': meta.get('is_ack') == '1'}
    body = pb.blob(inner, 6)
    sub = pb.parse(body) if body else None
    if cmd == 100:
        info['kind'] = 'ack'
        got = pb.parse(pb.blob(sub, 100) or b'') if sub else None
        if got:
            info['msg_id'] = pb.one(got, 1)
            info['cid'] = pb.text(pb.blob(got, 4))
    elif cmd == 500:
        info['kind'] = 'push'
        conv = pb.parse(pb.blob(sub, 500) or b'') if sub else None
        if conv:
            info['conv_id'] = pb.text(pb.blob(conv, 2))
            msg = pb.parse(pb.blob(conv, 5) or b'')
            if msg:
                info['msg_id'] = pb.one(msg, 3)
                info['sender'] = pb.one(msg, 7)
                kv9 = _kv_pairs(msg, 9)
                info['cid'] = kv9.get('s:client_message_id')
                info['is_stranger'] = kv9.get('s:is_stranger')
    return info


# ------------------------------------------------------------------ 传输

class WsFrame:
    def __init__(self, opcode, payload):
        self.opcode = opcode
        self.payload = payload


class MiniWs:
    """最小 WebSocket 客户端：CONNECT 隧道 + RFC6455 帧编解码（客户端掩码）。"""

    def __init__(self, host, path, headers, proxy=None, timeout=CONNECT_TIMEOUT):
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
        self.s = ssl.create_default_context().wrap_socket(self.sock, server_hostname=host)

        key = base64.b64encode(os.urandom(16)).decode()
        req = ('GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n'
               'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
               'Sec-WebSocket-Version: 13\r\n' % (path, host, key))
        for k, v in (headers or {}).items():
            req += '%s: %s\r\n' % (k, v)
        self.s.sendall((req + '\r\n').encode())
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

    def _recv_exact(self, n):
        while len(self._buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError('socket closed (have %d/%d)' % (len(self._buf), n))
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv_frame(self):
        b = self._recv_exact(2)
        opcode = b[0] & 0x0F
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
        self.s.sendall(header + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload)))

    def send_binary(self, data):
        self.send_frame(2, data)

    def close(self):
        try:
            self.send_frame(8, struct.pack('>H', 1000))
        except Exception:
            pass
        try:
            self.s.close()
        except Exception:
            pass


def ws_url(sess):
    from urllib.parse import quote
    return (WS_PATH + '?aid=1459&fpid=%d&access_key=%s&device_platform=web&ttwid=%s'
            '&Web-Sdk-Ms-Token=%s'
            % (FPID, access_key(sess.device_id),
               quote(_cookie_val(sess.cookie, 'ttwid').replace('%7C', '|'), safe=''),
               quote(sess.ms_token, safe='')))


def open_ws(sess, proxy=None, retries=2):
    headers = {'Cookie': sess.cookie,
               'Origin': 'https://www.tiktok.com',
               'User-Agent': cl.UA_DEFAULT}
    last = None
    for attempt in range(retries + 1):
        try:
            ws = MiniWs(WS_HOST, ws_url(sess), headers, proxy=proxy)
            ws.send_binary(b'hi')
            time.sleep(0.4)
            return ws
        except Exception as e:
            last = e
            time.sleep(2 + attempt * 2)
    raise ConnectionError('ws connect failed: %s' % str(last)[:120])


def wait_ack(ws, seq=None, cid=None, timeout=ACK_TIMEOUT):
    """等匹配的 ACK。返回 (info, 其他帧列表)；info['kind'] 可能为 timeout/error。"""
    deadline = time.time() + timeout
    others = []
    while time.time() < deadline:
        try:
            f = ws.recv_frame()
        except Exception as e:
            if 'timed out' in str(e):
                continue
            return {'kind': 'error', 'error': str(e)[:120]}, others
        if f.payload == b'hi':
            ws.send_binary(b'hi')
            continue
        info = parse_down_frame(f.payload)
        if info.get('kind') != 'ack':
            others.append(info)
            continue
        if cid is not None and info.get('cid') != cid:
            others.append(info)
            continue
        if seq is not None and info.get('seq') != seq:
            others.append(info)
            continue
        return info, others
    return {'kind': 'timeout'}, others


def send_message(sess, conv_id, short_id, text, proxy=None, seq=SEQ_START,
                 cid=None, retries=1):
    """高层：连接 → hi → 发帧 → 等 ACK → 关闭。返回发送结果 dict。"""
    last = {'ok': False, 'stage': 'ws-connect'}
    for attempt in range(retries + 1):
        ws = None
        try:
            ws = open_ws(sess, proxy=proxy)
            frame, cid, tier = build_frame(sess, conv_id, short_id, text,
                                           cid=cid, seq=seq)
            ws.send_binary(frame)
            ack, _others = wait_ack(ws, seq=seq, cid=cid)
        except Exception as e:
            last = {'ok': False, 'stage': 'ws-error', 'cid': cid,
                    'error': '%s: %s' % (type(e).__name__, str(e)[:120]),
                    'tier': tier if 'tier' in dir() else None}
            time.sleep(1.5 + attempt)
            continue
        finally:
            if ws is not None:
                try:
                    ws.close()
                except Exception:
                    pass
        out = {'ok': ack.get('kind') == 'ack' and ack.get('biz_code') == 0,
               'stage': 'ack', 'cid': cid, 'tier': tier,
               'ack_kind': ack.get('kind'), 'biz_code': ack.get('biz_code'),
               'biz_msg': ack.get('biz_msg'), 'msg_id': ack.get('msg_id')}
        if not out['ok']:
            out['error'] = (ack.get('error')
                            or 'biz_code=%s %s' % (ack.get('biz_code'), ack.get('biz_msg'))
                            if ack.get('kind') == 'ack' else 'no ACK (%s)' % ack.get('kind'))
        return out
    return last
