"""Douyin (抖音) IM protocol client — desktop-client clone.

Everything here was established empirically against live traffic (MITM of the
official desktop client 8.5.1, 2026-10-08/09; evidence samples in
D:/wbtools/workspace/dy-recon/). Pure HTTPS request/response: no WebSocket,
no native signing — the official desktop client does it exactly this way.

Transport   POST https://imapi.douyin.com/v1|v2/... (application/x-protobuf)
Auth        cookie jar (sessionid 等，从已登录客户端/浏览器收割)；
            发送类请求另带 bd-ticket-guard-* 头族（与 TikTok 同机制）
Envelope    {1:cmd, 2:sub, 3:'0.1.8', 7:'0d50935:feat/pc-im-group',
             8:{<业务体号>:inner}, 9:'0', 11:'douyin_pc', 14:'360000',
             15:repeated KV params}
            业务体号因接口而异（实物核对）：send=100 / get_user_message=2048 /
            stranger_list=1000 / get_info_list=610
Ticket      服务端随 get_info_list 响应下发（conversation.ticket），客户端
            纯透传、每次发送取最新；两次 send 不同是服务端轮换（实测）。
"""
import json
import os
import time
import uuid

import shutil as _shutil

from . import proto as pb
try:
    import certifi as _certifi
    from curl_cffi import requests as curl_requests
    from curl_cffi.const import CurlHttpVersion
except ImportError:
    curl_requests = None
    CurlHttpVersion = None


def _ascii_ca():
    """curl on Windows can't open CA bundles under non-ASCII paths (error 77);
    copy the bundle to an ASCII location once (same workaround as igconnect)."""
    src = _certifi.where()
    if src.isascii():
        return src
    base = os.environ.get('PROGRAMDATA') or r'C:\ProgramData'
    if not base.isascii():
        base = r'C:\ProgramData'
    dst = os.path.join(base, 'tk-message-demo', 'cacert.pem')
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(src):
        _shutil.copyfile(src, dst)
    return dst

IM_API = 'https://imapi.douyin.com'

BUILD = '0d50935:feat/pc-im-group'
VERSION = '0.1.8'
APP_NAME = 'douyin_pc'
VERSION_CODE = '360000'

CMD_SEND = 100
CMD_GET_MSG = 2048
CMD_STRANGER = 1001
CMD_INFO = 610
CMD_INIT = 2043            # 会话建立：启动后第一个请求，响应=全量初始化数据


def body_init():
    """get_message_by_init 的业务体（实物仅 {2:0}）。"""
    return pb.vint(2, 0)

# 桌面客户端实物的完整 UA（保真：客户端版本串是风控画像的一部分）
UA_DESKTOP = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) douyin/8.5.1 Chrome/136.0.7103.59 '
              'Electron/36.4.0-rs.31.release.pgo.7 '
              'TTElectron/36.4.0-rs.31.release.pgo.7 Safari/537.36 '
              'awemePcClient/8.5.1 buildId/469669512 osName/Windows')

# 信封 #15 的 KV 参数（桌面客户端实物逐项；browser_version 为 UA 版本段）
ENVELOPE_PARAMS = [
    ('session_aid', '6383'),
    ('session_did', '0'),
    ('app_name', 'douyin_pc'),
    ('priority_region', 'cn'),
    ('user_agent', UA_DESKTOP),
    ('cookie_enabled', 'true'),
    ('browser_language', 'zh-CN'),
    ('browser_platform', 'Win32'),
    ('browser_name', 'Mozilla'),
    ('browser_version', '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                        '(KHTML, like Gecko) Chrome/136.0.7103.59 Safari/537.36'),
    ('browser_online', 'true'),
    ('screen_width', '1920'),
    ('screen_height', '1080'),
    ('referer', 'https://www.douyin.com/jingxuan'),
    ('timezone_name', 'Asia/Shanghai'),
    ('deviceId', '0'),
    ('is-retry', '0'),
]


class SubSeq:
    """field2 的请求序列号——实测每次调用都不同（10021→10221），非接口固定值。"""

    def __init__(self, start=10000):
        self.n = start

    def next(self):
        self.n += 1
        return self.n


def _kv(field, key, value):
    """repeated KV entry: {1:key, 2:value}"""
    return pb.ld(field, pb.s(1, key) + pb.s(2, value))


_SUBSEQ = SubSeq()


def envelope(cmd, sub=None, body_field=None, inner=None, flag6=1):
    """按桌面客户端实物结构构造请求信封。

    body_field/inner：field8 里嵌的业务体（号因接口而异，见模块注释）；
    inner=None 时 field8 缺省（部分请求不带业务体）。
    """
    sub = sub or _SUBSEQ.next()
    out = bytearray()
    out += pb.vint(1, cmd)
    out += pb.vint(2, sub)
    out += pb.s(3, VERSION)
    out += pb.ld(4, b'')
    out += pb.vint(5, 3)
    if flag6 is not None:
        out += pb.vint(6, flag6)
    out += pb.s(7, BUILD)
    if inner is not None:
        out += pb.ld(8, pb.ld(body_field, inner))
    out += pb.s(9, '0')
    out += pb.s(11, APP_NAME)
    out += pb.s(14, VERSION_CODE)
    # 注意字段顺序：官方实物中 field18/21/22 在 field15 KV 列表之后（信封最末尾），
    # 字节序与服务端校验相关——不可提前。
    for k, v in ENVELOPE_PARAMS:
        out += _kv(15, k, v)
    out += pb.vint(18, 1)
    out += pb.s(21, 'douyin_web')
    out += pb.s(22, 'web_sdk')
    return bytes(out)


# ------------------------------------------------------- 业务体构造器

def body_stranger_list():
    """stranger/get_conversation_list 的业务体（实物：{1:0, 2:1, 3:1}）。"""
    return pb.vint(1, 0) + pb.vint(2, 1) + pb.vint(3, 1)


def body_info_list(conv_pairs):
    """get_info_list 的业务体：repeated entry{1: conv_id, 2: short_id, 3: 1}（实物结构）。

    conv_pairs: [(conv_id, conv_short_id), ...]
    """
    out = bytearray()
    for cid, sid in conv_pairs:
        entry = pb.s(1, cid) + pb.vint(2, sid) + pb.vint(3, 1)
        out += pb.ld(1, entry)
    return bytes(out)


def build_send_inner(conv_id, conv_short_id, ticket, text, cmid=None, stime_ms=None):
    """SendMessageRequestBody（field100 的载荷）。

    字段号与 jadx 反编译的 WireField 注解 + 抓包实物双重核对：
      1=conversation_id  2=conversation_type  3=conversation_short_id
      4=content(JSON)    5=repeated ext KV    6=message_type
      7=ticket           8=client_message_id
    """
    cmid = cmid or str(uuid.uuid4())
    stime_ms = stime_ms or '%d' % int(time.time() * 1000)
    content = json.dumps({'aweType': 700, 'type': 0, 'richTextInfos': [],
                          'text': text}, ensure_ascii=False, separators=(',', ':'))
    inner = bytearray()
    inner += pb.s(1, conv_id)
    inner += pb.vint(2, 1)                      # conversation_type = 1 (P2P)
    inner += pb.vint(3, conv_short_id)
    inner += pb.s(4, content)
    inner += _kv(5, 's:mentioned_users', '')
    inner += _kv(5, 's:client_message_id', cmid)
    inner += _kv(5, 's:stime', stime_ms)
    inner += pb.vint(6, 7)                      # message_type = 7 (text)
    inner += pb.s(7, ticket)
    inner += pb.s(8, cmid)
    return bytes(inner), cmid


def parse_conversation_info(body):
    """解析 get_info_list 响应 → [conversation dict]。

    实测结构（info-regular.bin）：
    top[6] > field610 > field1 (MGet 结果条目) = {
        1: conv_id, 2: 0, 3: 0,
        4: ticket (121B base64)   ← 发送就用它,
        6: 摘要, 50: 会话全量详情, 51: ...
    }
    注意：仅覆盖「常规会话」——陌生人会话 MGet 返回 request.MGet empty。
    """
    out = []
    top = pb.parse(body)
    if not top:
        return out
    f6 = pb.blob(top, 6)
    if not f6:
        return out
    b610 = pb.blob(pb.parse(f6), 610)
    if not b610:
        return out
    for _f, _w, _v, b1 in pb.all_of(pb.parse(b610), 1):
        m = pb.parse(b1)
        if not m:
            continue
        conv_id = pb.text(pb.blob(m, 1))
        if not conv_id or ':1:' not in conv_id:
            continue
        short_id = pb.one(m, 2, 0)
        detail = pb.blob(m, 50)
        if detail and not short_id:
            short_id = pb.one(pb.parse(detail), 2, 0)
        out.append({
            'conv_id': conv_id,
            'conv_short_id': short_id,
            'ticket': pb.text(pb.blob(m, 4)) or '',
        })
    return out


def parse_stranger_list(body):
    """解析 stranger/get_conversation_list 响应。

    实测结构（stranger-resp2.bin）：
    top[6] > field1000 > field4(页) > { field3: 会话核心, field4: conv_id }
    会话核心: 1=conv_id, 3=conv_short_id, 7=对端uid, 8=最后一条消息JSON,
              10=时间戳, 14=对端sec_uid。
    """
    out = []
    top = pb.parse(body)
    if not top:
        return out
    f6 = pb.blob(top, 6)
    if not f6:
        return out
    b1000 = pb.blob(pb.parse(f6), 1000)
    if not b1000:
        return out
    for _f, _w, _v, page_blob in pb.all_of(pb.parse(b1000), 4):
        page = pb.parse(page_blob)
        for _f3, _w3, _v3, core_b in pb.all_of(page, 3):
            core = pb.parse(core_b)
            if not core:
                continue
            conv_id = pb.text(pb.blob(core, 1))
            if not conv_id or ':1:' not in conv_id:
                continue
            out.append({
                'conv_id': conv_id,
                'conv_short_id': pb.one(core, 3, 0),
                'peer_uid': pb.one(core, 7, 0),
                'sec_uid': pb.text(pb.blob(core, 14)) or '',
                'last_message': pb.text(pb.blob(core, 8)) or '',
                'ticket': '',
            })
    return out


class DySession:
    """一个已登录的抖音桌面协议会话。"""

    def __init__(self, cookie, proxy=None, uid='', auth_headers=None):
        self.cookie = cookie.strip()
        self.uid = uid
        # bd-ticket-guard 等认证头族（收割自登录客户端；发送类请求必须）
        self.auth_headers = auth_headers or {}
        # TLS 指纹对齐官方客户端（Chrome 指纹 + ASCII 路径 CA，同 igconnect 方案）
        self.curl = None
        if curl_requests is not None:
            self.curl = curl_requests.Session(impersonate='chrome', proxy=proxy,
                                              verify=_ascii_ca())
        self._tickets = {}       # conv_id(str) -> {'short_id': int, 'ticket': str}
        self._inited = False

    # ------------------------------------------------------------- transport

    def _post(self, path, body):
        headers = {
            'Content-Type': 'application/x-protobuf',
            'Accept': 'application/x-protobuf',
            'Origin': 'https://www.douyin.com',
            'Referer': 'https://www.douyin.com/',
        }
        if self.cookie:
            headers['Cookie'] = self.cookie
        headers.update(self.auth_headers)
        if self.curl is not None:
            r = self.curl.post(IM_API + path, headers=headers, data=body, timeout=30,
                               http_version=CurlHttpVersion.V2_0)
            if r.status_code != 200:
                raise RuntimeError('douyin HTTP %s on %s' % (r.status_code, path))
            return r.content
        status, resp, _hdr = self.http.post(
            IM_API + path, headers={**headers, 'Cookie': self.cookie}, body=body)
        if status != 200:
            raise RuntimeError('douyin HTTP %s on %s' % (status, path))
        return resp

    def init(self):
        """会话建立：启动后第一个请求（服务端要求，缺失报
        'unexpected session length'）。返回响应字节数。"""
        body = self._post('/v1/message/get_message_by_init',
                          envelope(CMD_INIT, body_field=2043, inner=body_init()))
        return len(body)

    # ------------------------------------------------------------ 会话与票据

    def refresh_stranger_conversations(self):
        """陌生人会话列表（cmd=1001，业务体模板完全已知）。"""
        body = self._post('/v1/stranger/get_conversation_list',
                          envelope(CMD_STRANGER, 1000, body_stranger_list()))
        convs = parse_stranger_list(body)
        for c in convs:
            if c.get('conv_short_id'):
                self._tickets.setdefault(c['conv_id'], c)
        return convs

    def refresh_conversation_info(self, conv_pairs):
        """get_info_list：按会话列表查详情（**ticket 的来源**）。

        conv_pairs: [(conv_id, conv_short_id), ...]
        """
        body = self._post('/v2/conversation/get_info_list',
                          envelope(CMD_INFO, body_field=610,
                                   inner=body_info_list(conv_pairs)))
        convs = parse_conversation_info(body)
        for c in convs:
            if c.get('ticket') and c.get('conv_short_id'):
                self._tickets[c['conv_id']] = c
        return convs

    def refresh_conversations(self):
        """v1 全量刷新：init 建会话 → stranger 列表 → get_info_list 补 ticket。"""
        if not self._inited:
            self.init()
            self._inited = True
        convs = self.refresh_stranger_conversations()
        pairs = [(c['conv_id'], c['conv_short_id']) for c in convs]
        if pairs:
            self.refresh_conversation_info(pairs)
        return [self._tickets[k] for k in self._tickets]

    def ticket_for(self, conv_id):
        t = self._tickets.get(conv_id)
        return (t or {}).get('ticket') or ''

    # ------------------------------------------------------------------- 发送

    def send(self, conv_id, text):
        """发一条文本。conv_id 形如 '0:1:<uid>:<peer>'；ticket 必须已刷新。"""
        info = self._tickets.get(conv_id)
        if not info or not info.get('ticket'):
            self.refresh_conversation_info([conv_id])
            info = self._tickets.get(conv_id)
        if not info:
            raise RuntimeError('unknown conversation: %s (refresh failed)' % conv_id)
        short_id = int(info['conv_short_id'])
        inner, cmid = build_send_inner(conv_id, short_id, info['ticket'], text)
        resp = self._post('/v1/message/send',
                          envelope(CMD_SEND, 100, inner))
        top = pb.parse(resp)
        ok = pb.text(pb.blob(top, 4)) == 'OK' if top else False
        return {'ok': bool(ok), 'client_message_id': cmid,
                'status_code': pb.one(top, 5, -1) if top else -1}
