"""TikTok web IM WebSocket client — cold-send transport.

Established empirically against live traffic (2026-10-20):
  - Official web client sends messages over wss://im-ws.tiktok.com/ws/v2
    (binary protobuf). HTTP /v1/message/send is silently dropped for
    stranger/message-request conversations while still returning biz_code=0,
    so the WS transport is mandatory for cold outreach.
  - WS URL auth: access_key = md5(fpid + appKey + device_id + SECRET),
    fpid=9, appKey=e1bd35ec9db7b8d846de66ed140b1ad9, SECRET=f8a69f1719916z
    (verified against a live capture: dc9de301194da7892e15118fa36834eb).
  - Handshake/heartbeat: 2-byte binary "hi" both directions.
  - Send frame (top level): {1:10017, 2:ts_ms, 3:5, 4:1, 5:repeated KV env
    (X-Bogus first, then _create_env_pairs-like list), 7:'pb',
    8:{HTTP-style send envelope incl f15 env block, f18=1},
    then tt-ticket-guard-* KV pairs, 18:1}.  f9=2193 was observed between
    'pb' and the envelope in the capture; its role is unconfirmed, so it is
    toggleable (INCLUDE_F9).
"""
import base64
import hashlib
import json
import os
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import proto as pb
from app import client as cl
from curl_cffi.requests import Session
from curl_cffi.const import CurlWsFlag

_DEAD_WS = []   # keep references so GC never touches dead curl handles
_DEAD_S = []

WS_URL = 'wss://im-ws.tiktok.com/ws/v2'
APP_KEY = 'e1bd35ec9db7b8d846de66ed140b1ad9'
SECRET = 'f8a69f1719916z'
FPID = 9
CMD_SEND = 10017          # observed on a real UI cold send
INCLUDE_F9 = True         # captured frame carried f9=2193; toggle for A/B
XBOGUS = '1'              # captured value was a real 16-char X-Bogus; '1' accepted on im-api


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
    """Env KV list as seen in the WS frame (f5 block and envelope f15 block)."""
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


def build_payload(conv_id, short_id, text, cid, sess):
    """Message payload per byte-exact official capture (wsid=41 frame 52).

    ext carries ONLY s:mentioned_users (empty) + s:client_message_id.
    f6=7, f7 is the literal string 'deprecated' (ticket slot retired on WS).
    """
    ext = _kv('s:mentioned_users', '') + _kv('s:client_message_id', cid)
    return (pb.s(1, conv_id) + pb.vint(2, 1) + pb.vint(3, int(short_id))
            + pb.s(4, json.dumps({'aweType': 0, 'text': text}, separators=(',', ':')))
            + pb.ld(5, ext) + pb.vint(6, 7) + pb.s(7, 'deprecated') + pb.s(8, cid))


def build_inner_envelope(sess, payload, seq):
    """HTTP-style cmd-100 envelope as embedded in the WS frame.

    Captured shape: f2=seq echo (not the HTTP sub-command!), f4='',
    f5=3, f6=0, f15 env block (+ guard KVs appended by caller), f18=1.
    """
    body = (pb.vint(1, 100) + pb.vint(2, seq) + pb.s(3, cl.ENVELOPE_VER) + pb.s(4, '')
            + pb.vint(5, 3) + pb.vint(6, 0) + pb.s(7, cl.ENVELOPE_BUILD)
            + pb.sub(8, pb.sub(100, payload))
            + pb.s(9, sess.device_id) + pb.s(11, 'web'))
    return body


def build_frame(sess, conv_id, short_id, text, cid=None, xbogus=XBOGUS,
                seq=10001, guard='both'):
    """Outer frame: {1:seq, 2:ts_ms, 3:5, 4:1, 5:KV(X-Bogus+env), 7:'pb',
    8:inner(+f15 env+guard, f18=1), 15:guard KVs, 18:1}.

    guard: 'both' (official shape), 'inner'/'outer'/'none' for A/B.
    """
    cid = cid or str(uuid.uuid4())
    payload = build_payload(conv_id, short_id, text, cid, sess)
    inner = build_inner_envelope(sess, payload, seq)

    guard_h, tier = cl.ticket_guard_headers(sess, '/v1/message/send')
    guard_kv = b''.join(pb.ld(15, _kv(k, v)) for k, v in guard_h.items())

    for k, v in _env_kv(sess):
        inner += pb.ld(15, _kv(k, v))
    if guard in ('both', 'inner'):
        inner += guard_kv
    inner += pb.vint(18, 1)

    outer = pb.vint(1, seq) + pb.vint(2, int(time.time() * 1000))
    outer += pb.vint(3, 5) + pb.vint(4, 1)
    for k, v in [('X-Bogus', xbogus)] + _env_kv(sess):
        outer += pb.ld(5, _kv(k, v))
    outer += pb.s(7, 'pb')
    outer += pb.sub(8, inner)
    if guard in ('both', 'outer'):
        outer += guard_kv
    outer += pb.vint(18, 1)
    return outer, cid, tier


# ---------------------------------------------------------- down-frame parsing

def _kv_pairs(items, field=5):
    """Decode repeated {f1:key, f2:value} into a dict (first wins)."""
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
    """Classify/decode one server frame.

    Verified against live captures (2026-10-21):
      ACK   — outer f5 KV is_ack=1, f8.f1=100, f8.f2=seq echo,
              f8.f3=biz_code (0 = accepted), f8.f4=biz_msg ('OK'),
              f8.f6.100.f1=server msg id, f8.f6.100.f4=our client_message_id
      PUSH  — f8.f1=500, f8.f6.500.f2=conv_id, .f5=message
              (message f7=sender uid, f8=content JSON, f9 has
               s:client_message_id and s:is_stranger)
    """
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
            'is_ack': meta.get('is_ack') == '1', 'kv': meta}
    body = pb.blob(inner, 6)
    sub = pb.parse(body) if body else None
    if cmd == 100:
        info['kind'] = 'ack'
        got = pb.parse(pb.blob(sub, 100) or b'') if sub else None
        if got:
            info['msg_id'] = pb.one(got, 1)
            info['cid'] = pb.text(pb.blob(got, 4))
            info['msg_status'] = pb.one(got, 3)
    elif cmd == 500:
        info['kind'] = 'push'
        conv = pb.parse(pb.blob(sub, 500) or b'') if sub else None
        if conv:
            info['conv_id'] = pb.text(pb.blob(conv, 2))
            msg = pb.parse(pb.blob(conv, 5) or b'')
            if msg:
                info['msg_id'] = pb.one(msg, 3)
                info['sender'] = pb.one(msg, 7)
                info['text'] = pb.text(pb.blob(msg, 8))
                kv9 = _kv_pairs(msg, 9)
                info['cid'] = kv9.get('s:client_message_id')
                info['is_stranger'] = kv9.get('s:is_stranger')
    return info


def wait_ack(ws, seq=None, cid=None, timeout=10):
    """Pump the socket until the ACK matching (seq, cid) arrives.

    Returns (ack_info, other_frames). ack_info['kind'] is 'ack' on success,
    'timeout' if nothing matched, 'error' if the socket died.
    """
    deadline = time.time() + timeout
    frames = []
    while time.time() < deadline:
        try:
            f = ws.recv_frame()
        except Exception as e:
            if 'timed out' in str(e):
                continue
            return {'kind': 'error', 'error': str(e)[:100]}, frames
        if f.payload == b'hi':
            ws.send_binary(b'hi')
            continue
        info = parse_down_frame(f.payload)
        frames.append(info)
        if info.get('kind') != 'ack':
            continue
        if cid is not None and info.get('cid') != cid:
            continue
        if seq is not None and info.get('seq') != seq:
            continue
        return info, frames
    return {'kind': 'timeout'}, frames


class WsIm:
    """Minimal blocking WS IM connection. Not thread-safe."""

    def __init__(self, sess, verbose=True):
        # Probe working egress; candidates are tried until the 'hi' heartbeat
        # is answered (HTTP probe alone can pick the SOCKS twin port).
        self.verbose = verbose
        for k in ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy',
                  'ALL_PROXY', 'all_proxy'):
            os.environ.pop(k, None)
        try:
            import certifi, shutil
            src = certifi.where()
            base = os.environ.get('PROGRAMDATA') or r'C:\ProgramData'
            dst = os.path.join(base, 'tk-message-demo', 'cacert.pem')
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(src):
                shutil.copyfile(src, dst)
            os.environ['CURL_CA_BUNDLE'] = dst
        except Exception:
            pass
        ttwid = _cookie_val(sess.cookie, 'ttwid')
        url = (WS_URL + '?aid=1459&fpid=%d&version_code=fws_1.0.0'
               '&access_key=%s&device_platform=web&ttwid=%s&Web-Sdk-Ms-Token=%s'
               % (FPID, access_key(sess.device_id), ttwid, sess.ms_token))
        headers = {
            'Cookie': sess.cookie,
            'Origin': 'https://www.tiktok.com',
            'User-Agent': cl.UA_DEFAULT,
        }
        cands = [p for p in cl.PROXY_CANDIDATES if p in
                 ('http://127.0.0.1:10809', 'http://127.0.0.1:10808', 'http://127.0.0.1:7897')]
        last_err = None
        self.ws = None
        for proxy in cands:
            for attempt in range(3):
                s = Session(impersonate='chrome')
                try:
                    ws = s.ws_connect(url, headers=headers,
                                      **({'proxy': proxy} if proxy else {}))
                    ws.send(b'hi', CurlWsFlag.BINARY)
                    data, _ = ws.recv()
                    if bytes(data) == b'hi':
                        self.ws = ws
                        self.proxy = proxy
                        if verbose:
                            print('[ws] proxy OK: %s (attempt %d)' % (proxy, attempt), flush=True)
                        break
                    ws.close()
                    last_err = 'no hi reply via %s' % proxy
                    if verbose:
                        print('[ws] %s' % last_err, flush=True)
                except Exception as e:
                    last_err = '%s: %s' % (proxy, str(e)[:80])
                    if verbose:
                        print('[ws] fail %s (attempt %d)' % (last_err, attempt), flush=True)
                    time.sleep(1)
                    # NOTE: never touch/GC the ws handle after an error —
                    # curl_cffi segfaults on close()/recv()/gc of a dead socket.
                    if 'ws' in dir():
                        _DEAD_WS.append(ws)
                    _DEAD_S.append(s)
                if self.ws is not None:
                    break
            if self.ws is not None:
                break
        if self.ws is None:
            raise ConnectionError('no working WS egress (%s)' % last_err)
        self.sess = sess
        self._alive = True
        self.log = []          # (dir, bytes)
        self.down = []         # parsed down protobuf frames

    def _send(self, data, flag=CurlWsFlag.BINARY):
        self.ws.send(data, flag)
        self.log.append(('up', bytes(data)))

    def handshake(self, timeout=8):
        self._send(b'hi')
        deadline = time.time() + timeout
        while time.time() < deadline:
            data, flags = self.ws.recv()
            self.log.append(('down', bytes(data)))
            if bytes(data) == b'hi':
                return True
        return False

    def send_message(self, conv_id, short_id, text, seq=10001, collect=4, **kw):
        frame, cid, tier = build_frame(self.sess, conv_id, short_id, text,
                                       cid=cid, seq=seq, **kw)
        self._send(frame)
        down = self.pump(collect)
        return cid, tier, down

    def heartbeat(self):
        self._send(b'hi')

    def pump(self, seconds, on_frame=None):
        """Recv loop for `seconds`; returns collected down frames."""
        deadline = time.time() + seconds
        out = []
        while time.time() < deadline:
            try:
                data, flags = self.ws.recv()
            except Exception as e:
                self.log.append(('err', str(e).encode()))
                break
            if isinstance(data, str):
                data = data.encode()
            data = bytes(data)
            self.log.append(('down', data))
            if data == b'hi':
                self.heartbeat()
                continue
            out.append(data)
            if on_frame:
                on_frame(data)
        self.down.extend(out)
        return out

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass
