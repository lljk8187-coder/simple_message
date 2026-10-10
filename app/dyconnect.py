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
import threading

import shutil as _shutil
import zlib as _zlib

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
path_SEND = '/v1/message/send'

# ticket-guard 的静态服务端证书（CN=ecies-server，2022-2069，内置在页面 SDK 中）
import os as _os
_SERVER_CERT_PATH = _os.path.join(_os.path.dirname(__file__), 'dy-server-cert.pem')
SERVER_CERT_PEM = open(_SERVER_CERT_PATH, encoding='utf-8').read()

BUILD = '0d50935:feat/pc-im-group'
VERSION = '0.1.8'
APP_NAME = 'douyin_pc'
VERSION_CODE = '360000'

CMD_SEND = 100
CMD_GET_MSG = 2048
CMD_STRANGER = 1001
CMD_INFO = 610
CMD_INIT = 2043            # 会话建立：启动后第一个请求，响应=全量初始化数据
CMD_HISTORY = 301          # get_by_conversation：历史消息分页（10-10 逆向）
CMD_GUM = 2048             # get_user_message：gum 心跳，实时增量收信（10-10 逆向）
path_GUM = '/v1/message/get_user_message'

# 用户资料端点（A2；web 端点，2026-10-10 抓包实物。webid/uifid 为设备级指纹，
# 与登录会话无关，可复用）
_USER_INFO_URL = 'https://www-hj.douyin.com/aweme/v1/web/im/user/info/?'
USER_INFO_QS = {
    'version_code': '170400', 'device_platform': 'webapp', 'aid': '6383',
    'channel': 'channel_pc_web', 'pc_client_type': '1',
    'pc_libra_divert': 'Windows', 'update_version_code': '170400',
    'support_h265': '1', 'support_dash': '1', 'version_name': '17.4.0',
    'cookie_enabled': 'true', 'screen_width': '1920', 'screen_height': '1080',
    'browser_language': 'zh-CN', 'browser_platform': 'Win32',
    'browser_name': 'Chrome', 'browser_version': '154.0.0.0',
    'browser_online': 'true', 'engine_name': 'Blink',
    'engine_version': '154.0.0.0', 'os_name': 'Windows', 'os_version': '10',
    'cpu_core_num': '16', 'device_memory': '32', 'platform': 'PC',
    'downlink': '1.4', 'effective_type': '3g', 'round_trip_time': '250',
    'webid': '7694196726711174656',
    'uifid': 'c8e4e9571f734f80bfe570d2d6f4308b6d7e878c8513cc69011763d4f6766844e6f70928fb2a3cb0',
}


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


def build_send_inner(conv_id, conv_short_id, ticket, text, cmid=None, stime_ms=None,
                     msg_type=7, content=None):
    """SendMessageRequestBody（field100 的载荷）。

    字段号与 jadx 反编译的 WireField 注解 + 抓包实物双重核对：
      1=conversation_id  2=conversation_type  3=conversation_short_id
      4=content(JSON)    5=repeated ext KV    6=message_type
      7=ticket           8=client_message_id
    msg_type/content：默认 7=文本（aweType 700）。卡片消息传
    msg_type=8（aweType 800 视频卡等，2026-10-10 发送抓包实物同构）。
    """
    cmid = cmid or str(uuid.uuid4())
    stime_ms = stime_ms or '%d' % int(time.time() * 1000)
    if content is None:
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
    inner += pb.vint(6, msg_type)
    inner += pb.s(7, ticket)
    inner += pb.s(8, cmid)
    return bytes(inner), cmid


def video_card_content(item_id, title, cover_url='', author_uid=0,
                       cover_w=1080, cover_h=1920):
    """转发视频的卡片 content JSON（aweType 800；2026-10-10 发送抓包实物）。

    keys 与实物逐项对照：aweType/content_title/cover_height/cover_width/
    itemId/cover_url/content_thumb/uid。
    """
    cover_url = cover_url or ''
    return {
        'aweType': 800,
        'content_title': title or '',
        'cover_height': cover_h,
        'cover_width': cover_w,
        'itemId': str(item_id),
        'cover_url': {'url_list': [cover_url]} if cover_url else {'url_list': []},
        'content_thumb': {'url_list': [cover_url] if cover_url else []},
        'uid': str(author_uid or 0),
    }


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


def parse_init_conversations(body):
    """解析 get_message_by_init 响应 → 全量会话面（每会话一容器）。

    实测结构（init-resp-1010.bin）：
    top[6] > field2043 > field1(容器，重复，每会话一个) = {
        1: 会话核心 { 1: conv_id, 2: conv_short_id, 4: ticket(121B) },
        2: 消息记录（重复，最近最多 20 条）,
        4/5/...: 参与者等扩展段
    }
    init 响应即全量会话列表源（含常规会话的 ticket）——**无需 MGet 端点**。
    注意 conv_id 有两类形态：'0:1:<uid>:<peer>'（单聊）与纯数字（其他会话
    类型），core.f1 原样保留。
    """
    out = []
    top = pb.parse(body)
    if not top:
        return out
    f6 = pb.blob(top, 6)
    if not f6:
        return out
    b2043 = pb.blob(pb.parse(f6), 2043)
    if not b2043:
        return out
    for _f, _w, _v, ct_b in pb.all_of(pb.parse(b2043), 1):
        ct = pb.parse(ct_b)
        if not ct:
            continue
        core_b = pb.blob(ct, 1)
        if not core_b:
            continue
        core = pb.parse(core_b)
        if not core:
            continue
        conv_id = pb.text(pb.blob(core, 1))
        if not conv_id:
            continue
        out.append({
            'conv_id': conv_id,
            'conv_short_id': pb.one(core, 2, 0),
            'ticket': pb.text(pb.blob(core, 4)) or '',
            'msg_count': sum(1 for _ in pb.all_of(ct, 2)),
        })
    return out


# init 消息 f6 类型 → Message.kind（init-resp-1010.bin 167 条实测归纳；
# 未收录类型一律 'unknown'，媒体类 text 带描述便于前端渲染）
_MSG_KIND = {7: 'text', 1: 'tip', 5: 'media', 8: 'media', 15: 'media',
             17: 'media', 21: 'media', 60: 'media', 77: 'media',
             105: 'media', 110: 'media', 168: 'media'}


def _describe_media(content):
    for k in ('content_name', 'display_name', 'desc', 'hint_text', 'aweme_title'):
        v = content.get(k)
        if isinstance(v, str) and v:
            return '[媒体] %s' % v
    return '[媒体消息]'


def _dy_attachments(f6, content):
    """从消息内容 JSON 提取平台无关载荷（A1，尽力而为：缺失字段即跳过）。

    类型实测依据 init-resp-1010.bin 的 f6 分布：
      17 语音 → resource_url.url_list + audio_duration
      5/15 贴纸/大表情 → joker_stickers[].static_url
      8/77/168 名片/视频卡 → content_name + content_thumb
      105/110 视频分享 → aweme_title/comment + aweme_info.cover_url
      60  外链卡片 → desc + icon
    """
    out = []

    def _first_url(obj):
        if not isinstance(obj, dict):
            return ''
        urls = obj.get('url_list') or []
        return urls[0] if urls else (obj.get('uri') or '')

    try:
        if f6 == 17:                                   # 语音
            u = _first_url(content.get('resource_url'))
            if u:
                out.append({'type': 'voice', 'url': u,
                            'duration': int(content.get('audio_duration') or 0)})
        elif f6 in (5, 15):                            # 贴纸 / 大表情
            st = (content.get('joker_stickers') or [{}])[0]
            u = _first_url(st.get('static_url'))
            if u:
                out.append({'type': 'sticker', 'url': u,
                            'title': st.get('display_name') or ''})
        elif f6 in (8, 77, 168):                       # 用户/视频名片卡
            out.append({'type': 'card',
                        'url': _first_url(content.get('content_thumb')),
                        'title': content.get('content_name') or ''})
        elif f6 in (105, 110):                         # 视频分享
            info = content.get('aweme_info') or {}
            u = _first_url(info.get('cover_url')) or _first_url(content.get('cover_url'))
            out.append({'type': 'video_card', 'url': u,
                        'title': content.get('aweme_title') or content.get('description')
                        or content.get('comment') or '',
                        # 原始 content 与视频 id 留存：send_media 转发时重放
                        'item_id': str(content.get('item_id')
                                       or content.get('itemId')
                                       or info.get('item_id') or ''),
                        'author_uid': str(content.get('aweme_author_id')
                                          or info.get('author_uid') or ''),
                        'content': content})
        elif f6 == 60:                                 # 外链卡片
            out.append({'type': 'link',
                        'url': _first_url(content.get('icon')),
                        'title': content.get('desc') or ''})
    except Exception:
        pass                                           # 载荷提取失败不影响消息本体
    return out


def _msg_record(m_b):
    """单条消息记录 → dict。init f2 与 get_by_conversation f1 同构（10-10 实测）。

    字段：1=conv_id 3=msg_id 4=服务端混淆微秒（**历史翻页游标原料**）
          5=conv_short_id 6=消息类型 7=sender uid 8=内容 JSON
          10=服务器毫秒真时间（f4/f13 是混淆时基，勿作展示）
          14=sender sec_uid
    """
    m = pb.parse(m_b) or ()
    conv_id = sec_uid = ''
    msg_id = us = short_id = msg_type = sender = ms = 0
    content = {}
    for x in m:
        fid, wt, ival, bval = x
        if wt == 2:
            if fid == 1:
                conv_id = pb.text(bval) or ''
            elif fid == 8:
                try:
                    content = json.loads(pb.text(bval) or '{}') or {}
                except ValueError:
                    content = {}
            elif fid == 14:
                sec_uid = pb.text(bval) or ''
        else:
            if fid == 3:
                msg_id = ival
            elif fid == 4:
                us = ival
            elif fid == 5:
                short_id = ival
            elif fid == 6:
                msg_type = ival
            elif fid == 7:
                sender = ival
            elif fid == 10:
                ms = ival
    kind = _MSG_KIND.get(msg_type, 'unknown')
    text = content.get('text') or ''
    if kind != 'text' and not text and content:
        text = _describe_media(content)
    return {
        'conv_id': conv_id,
        'msg_id': str(msg_id),
        'conv_short_id': short_id,
        'kind': kind,
        'sender_uid': str(sender),
        'text': text,
        'ms': ms,
        'us': us,
        'sender_sec_uid': sec_uid,
        'attachments': _dy_attachments(msg_type, content),
    }


def parse_init_messages(body):
    """解析 init 响应中的消息记录（每会话容器 field2，重复，最近 ≤20 条）。"""
    out = []
    top = pb.parse(body)
    if not top:
        return out
    f6 = next((x[3] for x in top if x[0] == 6 and x[1] == 2), None)
    if not f6:
        return out
    b2043 = next((x[3] for x in pb.parse(f6) if x[0] == 2043 and x[1] == 2), None)
    if not b2043:
        return out
    for _f, _w, _v, ct_b in pb.all_of(pb.parse(b2043), 1):
        for _f2, _w2, _v2, m_b in pb.all_of(pb.parse(ct_b), 2):
            rec = _msg_record(m_b)
            if rec['conv_id']:
                out.append(rec)
    return out


def body_history(conv_id, conv_short_id, anchor_us, limit=50, direction=1):
    """get_by_conversation 业务体（两页实物对比 2026-10-10）：
    f1=conv_id, f2=1(向旧), f3=short_id, f4=1, f5=游标(混淆微秒),
    f6=每页条数（实测 50）。"""
    return (pb.s(1, conv_id) + pb.vint(2, direction)
            + pb.vint(3, int(conv_short_id)) + pb.vint(4, 1)
            + pb.vint(5, int(anchor_us)) + pb.vint(6, limit))


def _dump_ws(frame):
    """WS 推送帧原文落盘（dy-recon/ws-push/），供格式迭代。"""
    try:
        import os as _os
        d = r'D:\wbtools\workspace\dy-recon\ws-push'
        _os.makedirs(d, exist_ok=True)
        with open(_os.path.join(d, 'ws-%d.bin' % int(time.time() * 1000)),
                  'wb') as f:
            f.write(frame)
    except Exception:
        pass


def parse_ws_push(frame, sess=None):
    """frontier-im 推送帧 → 消息列表。

    实测帧结构（ws-push/ws-*.bin，2026-10-10 回环实物）：
      top f8(载荷) > f6 > f500 > { 2: conv_id, 5: 消息记录, 6/7/10/11: 时间戳(us) }
    消息记录（f5 层，与 init/gum 记录同语义）：
      f1: 会话子结构（内嵌 conv_id）、f3: msg_id、f5: short_id、
      f6: 类型、f7: sender uid、f8: 内容 JSON、f10/f4: 时间
    解析策略：递归下钻，凡某层同时具备"f8=内容 JSON + f3=msg_id"即视为
    一条消息记录；conv_id 从本层 f1 子结构或父层 500.f2 继承。
    解析失败返回 []，帧原文由 _dump_ws 留档供迭代。
    """
    out = []
    seen_ids = set()

    def conv_id_of(fields, fallback):
        for x in fields:
            if x[1] == 2 and x[3] and x[3].startswith(b'0:1:'):
                return pb.text(x[3])
            if x[1] == 2 and x[3] and len(x[3]) < 80 and b'0:1:' in x[3]:
                m = re.search(rb'0:1:\d{10,}:\d{10,}', x[3])
                if m:
                    return m.group().decode()
        return fallback

    def from_fields(fields, conv_id):
        d = {}
        for x in fields:
            if x[0] not in d:
                d[x[0]] = x
        content_b = d[8][3] if 8 in d and d[8][1] == 2 else b''
        if not content_b:
            return None
        try:
            content = json.loads(pb.text(content_b) or '{}') or {}
        except ValueError:
            return None
        if 3 not in d or d[3][1] != 0:
            return None
        mid = str(d[3][2])
        if mid in ('', '0'):
            return None
        msg_type = d[6][2] if 6 in d and d[6][1] == 0 else 0
        kind = _MSG_KIND.get(msg_type, 'unknown')
        text = content.get('text') or ''
        if kind != 'text' and not text and content:
            text = _describe_media(content)
        us = 0
        for fid in (10, 4):
            if fid in d and d[fid][1] == 0:
                v = d[fid][2]
                if v > 1e15:
                    us = v
                elif v > 1e12:
                    us = v * 1000
                break
        sid = d[5][2] if 5 in d and d[5][1] == 0 else 0
        sender = str(d[7][2]) if 7 in d and d[7][1] == 0 else ''
        cid = conv_id
        if not cid and 1 in d and d[1][1] == 2 and d[1][3].startswith(b'0:1:'):
            cid = pb.text(d[1][3])             # 记录自带的会话 ID（WS 推送路径）
        return {
            'conv_id': cid or '',
            'msg_id': mid,
            'conv_short_id': sid,
            'kind': kind,
            'sender_uid': sender,
            'text': text,
            'ms': us // 1000 if us else int(time.time() * 1000),
            'us': us,
            'sender_sec_uid': pb.text(d[14][3]) if 14 in d and d[14][1] == 2 else '',
            'attachments': _dy_attachments(msg_type, content),
        }

    # 规范路径（回环实物 ws-*.bin 验证）：top f8 > f6 > f500 > f5(重复) = 消息记录
    try:
        _top = pb.parse(frame) or ()
        _f8 = next(x[3] for x in _top if x[0] == 8 and x[1] == 2)
        _f6 = next(x[3] for x in (pb.parse(_f8) or ()) if x[0] == 6 and x[1] == 2)
        _f500 = next(x[3] for x in (pb.parse(_f6) or ()) if x[0] == 500 and x[1] == 2)
        for _rec in (x[3] for x in (pb.parse(_f500) or ())
                     if x[0] == 5 and x[1] == 2):
            rec = from_fields(pb.parse(_rec) or (), None)
            if rec and rec['msg_id'] not in seen_ids:
                seen_ids.add(rec['msg_id'])
                out.append(rec)
    except (StopIteration, Exception):
        pass
    if out:
        return out

    def walk(data, conv_id, depth=0):
        if depth > 12:
            return
        try:
            fields = pb.parse(data) or ()
        except Exception:
            return
        d = {}
        for x in fields:
            if x[0] not in d:
                d[x[0]] = x
        # 本层是否为消息记录：f8=内容 JSON 且 f3=msg_id
        if (8 in d and d[8][1] == 2
                and (b'aweType' in d[8][3] or b'"text":"' in d[8][3])
                and 3 in d and d[3][1] == 0):
            rec = from_fields(list(d.values()), conv_id)
            if rec and rec['msg_id'] not in seen_ids:
                seen_ids.add(rec['msg_id'])
                out.append(rec)
            return                       # 记录内部不再下钻
        nid = conv_id_of(fields, conv_id)
        for x in fields:
            if x[1] == 2 and x[3]:
                walk(x[3], nid, depth + 1)

    walk(frame, None)
    return out


def body_gum(cursor_us, seq, now_us):
    """gum（get_user_message, cmd 2048）业务体——10-10 实物（gum-req.bin）：
    wrapper f2048 > { 1: 上次游标（微秒）, 2: 消息批计数器, 4: 当前时间（微秒）,
    5: 空串 }。响应带回 f2={3: seq, 4: 游标} 供下一拍回填。"""
    inner = (pb.vint(1, int(cursor_us)) + pb.vint(2, int(seq))
             + pb.vint(4, int(now_us)) + pb.s(5, ''))
    return pb.ld(2048, inner)


def parse_gum(body):
    """gum 响应 → {'messages': [...], 'cursor_us': int, 'seq': int}。

    实物（gum-resp.bin，10-08 桌面抓包）布局：
      top[6] > f2048 > {
        1: 会话容器 { 1: 时间戳(us), 2: 每会话一批（重复） },
        2: 游标 { 3: 批计数器 seq, 4: 游标（微秒） } }
    每批: { 1: short_id, 5: conv_id, 2: 消息包装（重复） }
    消息包装: { 3: msg_id, 4: 服务器时间(us), 6: 类型, 7: sender uid,
                8: 内容 JSON }——与 init 记录同语义（f4 代替 f10，单位 us）。
    解析失败的包装跳过并计数（格式以后如有漂移由 canary 的 protocol 类兜底）。
    """
    out, cursor_us, seq, bad = [], 0, 0, 0
    try:
        top = pb.parse(body)
        biz = next(x[3] for x in top if x[0] == 6 and x[1] == 2)
        g2048 = next(x[3] for x in pb.parse(biz) if x[0] == 2048 and x[1] == 2)
        inner = pb.parse(g2048)
    except Exception:
        return {'messages': out, 'cursor_us': cursor_us, 'seq': seq, 'bad': bad}
    f2seg = next((x[3] for x in inner if x[0] == 2 and x[1] == 2), None)
    if f2seg:
        for y in pb.parse(f2seg):
            if y[0] == 3 and y[1] == 0:
                seq = y[2]
            elif y[0] == 4 and y[1] == 0:
                cursor_us = y[2]
    for cont in (x[3] for x in inner if x[0] == 1 and x[1] == 2):
        for b in (x[3] for x in pb.parse(cont) if x[0] == 2 and x[1] == 2):
            conv_id = short_id = None
            wraps = []
            for x in pb.parse(b):
                if x[0] == 5 and x[1] == 2:
                    conv_id = pb.text(x[3])
                elif x[0] == 1 and x[1] == 0:
                    short_id = x[2]
                elif x[0] == 2 and x[1] == 2:
                    wraps.append(x[3])
            if not conv_id:
                bad += len(wraps)
                continue
            for w in wraps:
                try:
                    m = pb.parse(w)
                    d = {x[0]: x for x in m}
                    msg_type = d[6][2] if 6 in d and d[6][1] == 0 else 0
                    content_b = d[8][3] if 8 in d and d[8][1] == 2 else b''
                    content = {}
                    if content_b:
                        try:
                            content = json.loads(pb.text(content_b) or '{}') or {}
                        except ValueError:
                            content = {}
                    kind = _MSG_KIND.get(msg_type, 'unknown')
                    text = content.get('text') or ''
                    if kind != 'text' and not text and content:
                        text = _describe_media(content)
                    us = d[4][2] if 4 in d and d[4][1] == 0 else 0
                    out.append({
                        'conv_id': conv_id,
                        'msg_id': str(d[3][2] if 3 in d and d[3][1] == 0 else 0),
                        'conv_short_id': short_id or (d[5][2] if 5 in d and d[5][1] == 0 else 0),
                        'kind': kind,
                        'sender_uid': str(d[7][2] if 7 in d and d[7][1] == 0 else 0),
                        'text': text,
                        'ms': us // 1000 if us else 0,
                        'us': us,
                        'sender_sec_uid': '',
                        'attachments': _dy_attachments(msg_type, content),
                    })
                except Exception:
                    bad += 1
    return {'messages': out, 'cursor_us': cursor_us, 'seq': seq, 'bad': bad}


def parse_history_page(body):
    """get_by_conversation 响应 → {'messages', 'cursor', 'has_more'}。

    top[6] > field301 = { 1: 消息记录（重复，与 init f2 同构，≤50 条/页）,
                          2: 下一页游标（= 本页最旧记录的混淆微秒）,
                          3: 是否还有更早的消息,
                          5: read-index 相关段 }
    """
    top = pb.parse(body) or ()
    f6 = next((x[3] for x in top if x[0] == 6 and x[1] == 2), None)
    if not f6:
        return {'messages': [], 'cursor': 0, 'has_more': False}
    b301 = next((x[3] for x in pb.parse(f6) if x[0] == 301 and x[1] == 2), None)
    if not b301:
        return {'messages': [], 'cursor': 0, 'has_more': False}
    msgs, cursor, has_more = [], 0, False
    for x in pb.parse(b301):
        if x[0] == 1 and x[1] == 2:
            rec = _msg_record(x[3])
            if rec['conv_id']:
                msgs.append(rec)
        elif x[0] == 2 and x[1] == 0:
            cursor = x[2]
        elif x[0] == 3 and x[1] == 0:
            has_more = bool(x[2])
    return {'messages': msgs, 'cursor': cursor, 'has_more': has_more}


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
        self._msgs = {}          # conv_id(str) -> [msg dict, ...]（ms 升序，init 填充）
        self._inited = False
        self._gum_cursor = 0     # gum 游标（微秒，响应 f2.f4 回填）
        self._gum_seq = 0        # gum 批计数器（响应 f2.f3 回填）
        self._gum_seen = set()   # 已入库 msg_id（去重）
        self._gum_stop = threading.Event()
        self._gum_thread = None

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
        'unexpected session length'）。返回响应字节数。

        注意：init 后服务端有约 5-8 分钟的会话就绪窗口，期间 send 被拒
        （实测数据点：+8s/+15s/+74s/+3min 全败，+8min 起 OK）。

        响应同时携带全量会话面（每会话一容器：core{conv_id,short_id,
        ticket} + 最近消息）——解析入库 _tickets，常规会话无需 MGet。
        """
        body = self._post('/v1/message/get_message_by_init',
                          envelope(CMD_INIT, body_field=2043, inner=body_init()))
        self._init_at = time.time()
        convs = parse_init_conversations(body)
        for c in convs:
            if c.get('ticket') and c.get('conv_short_id'):
                self._tickets[c['conv_id']] = c
        self._init_convs = convs
        # 消息记录同源：每会话容器 field2（≤20 条），按会话分组、ms 升序
        by_conv = {}
        for m in parse_init_messages(body):
            by_conv.setdefault(m['conv_id'], []).append(m)
        for lst in by_conv.values():
            lst.sort(key=lambda x: x['ms'])
        self._msgs = by_conv
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

    def messages(self, conv_id, before_ms=None, limit=30):
        """会话消息（init 响应缓存，旧→新升序；before_ms 向前翻页）。

        缓存来自最近一次 init；增量新鲜度由上层控制（低频重新 init）。
        """
        rows = self._msgs.get(conv_id) or []
        if before_ms:
            rows = [m for m in rows if m['ms'] < int(before_ms)]
        return rows[-limit:] if limit else rows

    def oldest_cached_us(self, conv_id):
        """缓存中最旧消息的混淆微秒（历史翻页初始锚点；无消息返回 0）。"""
        rows = self._msgs.get(conv_id) or []
        return min((m['us'] for m in rows if m.get('us')), default=0)

    def gum(self):
        """一次 gum 心跳（cmd 2048）：拉增量消息并并入缓存。

        返回本拍新消息列表（已按 _gum_seen 去重；拍内无新消息返回 []）。
        游标/计数器从响应 f2 回填；响应原文带消息时存
        dy-recon/gum-poll/ 供格式迭代。
        """
        if self.curl is None:
            raise RuntimeError('gum requires the curl_cffi transport')
        body = body_gum(self._gum_cursor or int(time.time() * 1e6),
                        self._gum_seq, int(time.time() * 1e6))
        # 2026-10-10 web 实物（gum-web-5941.json）：f2=10406 固定子号、
        # 裸 URL（无 query/无 a_bogus）、基础头（无 ticket-guard）
        env = envelope(CMD_GUM, sub=10406, body_field=2048, inner=body)
        headers = {
            'Accept': 'application/x-protobuf',
            'Content-Type': 'application/x-protobuf',
            'Origin': 'https://www.douyin.com',
            'Referer': 'https://www.douyin.com/',
            'Cookie': self.cookie,
            'User-Agent': (self._send_cred or {}).get('ua')
                          or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                             ' (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        r = self.curl.post(IM_API + path_GUM, headers=headers, data=env, timeout=15)
        raw = r.content
        parsed = parse_gum(raw)
        if parsed['cursor_us']:
            self._gum_cursor = parsed['cursor_us']
        if parsed['seq']:
            self._gum_seq = parsed['seq']
        fresh = []
        for m in parsed['messages']:
            if m['msg_id'] in self._gum_seen:
                continue
            self._gum_seen.add(m['msg_id'])
            fresh.append(m)
            cid = m['conv_id']
            info = self._tickets.get(cid)
            if info is None:
                self._tickets[cid] = {'conv_id': cid,
                                      'conv_short_id': m['conv_short_id'],
                                      'ticket': ''}
            lst = self._msgs.setdefault(cid, [])
            lst.append(m)
            lst.sort(key=lambda x: x['ms'])
        if fresh:
            try:
                import os as _os
                d = r'D:\wbtools\workspace\dy-recon\gum-poll'
                _os.makedirs(d, exist_ok=True)
                with open(_os.path.join(d, 'gum-%d.bin' % int(time.time())),
                          'wb') as f:
                    f.write(raw)
            except Exception:
                pass
        return fresh

    def _ws_push_url(self):
        """frontier-im 推送长连接 URL（2026-10-10 逆向，公式字节级验证）：
        access_key = md5(fpid + appKey + device_id + 'f8a69f1719916z')。
        appKey=e1bd35ec9db7b8d846de66ed140b1ad9（ImEntryVmok 配置），fpid=9。"""
        import hashlib as _h
        fpid, appkey = '9', 'e1bd35ec9db7b8d846de66ed140b1ad9'
        ak = _h.md5((fpid + appkey + str(self.uid or '') + 'f8a69f1719916z')
                    .encode()).hexdigest()
        return ('wss://frontier-im.douyin.com/ws/v2?device_platform=web'
                '&version_code=fws_1.0.0&access_key=%s&fpid=%s&aid=6383'
                '&device_id=%s&xsack=0&xaack=0&xsqos=0&qos_sdk_version=2'
                % (ak, fpid, self.uid or ''))

    def start_realtime(self, on_messages, interval=6.0):
        """启动 frontier-im WebSocket 推送（实时收信正路）。

        2026-10-10 实测定性：gum（cmd 2048）只是周期校验点——官方 web 客户端
        自己的 gum 在消息到达后也返回空拍，消息实际由 frontier-im 长连接推送。
        心跳协议：每 ~10s 发 2 字节文本帧 "hi"。推送帧格式首拍落盘
        dy-recon/ws-push/ 后迭代解析；解析成功才回调 on_messages。
        重复调用幂等；断线自动重连（5s 退避）。
        """
        if self._gum_thread and self._gum_thread.is_alive():
            return
        sess = self

        def loop():
            import select as _select
            while not sess._gum_stop.wait(1):
                ws = None
                try:
                    from curl_cffi.const import CurlInfo
                    ws = sess.curl.ws_connect(
                        sess._ws_push_url(),
                        headers={'Origin': 'https://www.douyin.com',
                                 'Cookie': sess.cookie,
                                 'User-Agent': (sess._send_cred or {}).get('ua')
                                 or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                        impersonate='chrome',
                        verify=_ascii_ca(), timeout=30)
                    fd = ws.curl.getinfo(CurlInfo.ACTIVESOCKET)
                    if fd in (None, -1):
                        raise RuntimeError('ws no active socket')
                    last_hi = time.time()
                    while not sess._gum_stop.is_set():
                        r, _, _ = _select.select([fd], [], [], 1.0)
                        if r:
                            data, op = ws.recv()
                            if op == 8:            # close
                                break
                            if not data:
                                continue
                            fresh = parse_ws_push(data, sess)
                            if fresh:
                                _dump_ws(data)
                                # 并入缓存（gum() 同款）：/messages 读这里
                                for m in fresh:
                                    cid = m['conv_id']
                                    if cid and sess._tickets.get(cid) is None:
                                        sess._tickets[cid] = {
                                            'conv_id': cid,
                                            'conv_short_id': m['conv_short_id'],
                                            'ticket': ''}
                                    lst = sess._msgs.setdefault(cid, [])
                                    if not any(x['msg_id'] == m['msg_id']
                                               for x in lst):
                                        lst.append(m)
                                    lst.sort(key=lambda x: x['ms'])
                                try:
                                    on_messages(fresh)
                                except Exception:
                                    pass
                        now = time.time()
                        if now - last_hi >= 10:
                            ws.send_str('hi')
                            last_hi = now
                except Exception as e:
                    print('[dy-ws] 断线重连: %s' % e)
                finally:
                    try:
                        if ws is not None:
                            ws.close()
                    except Exception:
                        pass
                if not sess._gum_stop.is_set():
                    sess._gum_stop.wait(5)         # 重连退避

        self._gum_thread = threading.Thread(target=loop, name='dy-ws-push',
                                            daemon=True)
        self._gum_thread.start()

    def stop_realtime(self):
        self._gum_stop.set()

    def get_history(self, conv_id, anchor_us, limit=50):
        """拉一页历史消息（cmd 301，10-10 逆向）。

        anchor_us：上一页返回的游标（混淆微秒）；首页用 oldest_cached_us()。
        返回 {'messages', 'cursor', 'has_more'}，并把消息并入 _msgs 缓存。
        """
        info = self._tickets.get(conv_id) or {}
        short_id = int(info.get('conv_short_id') or 0)
        if not short_id:
            raise RuntimeError('no short_id for %s — cannot page history' % conv_id)
        inner = body_history(conv_id, short_id, anchor_us, limit=limit)
        body = self._post('/v1/message/get_by_conversation',
                          envelope(CMD_HISTORY, body_field=301, inner=inner))
        page = parse_history_page(body)
        for m in page['messages']:
            lst = self._msgs.setdefault(conv_id, [])
            if not any(x['msg_id'] == m['msg_id'] for x in lst):
                lst.append(m)
        lst = self._msgs.get(conv_id) or []
        lst.sort(key=lambda x: x['ms'])
        return page

    # ------------------------------------------------- 用户资料（A2，web 端点）

    def get_user_infos(self, sec_uids):
        """批量拉用户资料 → {sec_uid: {'nickname', 'avatar', 'uid'}}。

        端点：POST /aweme/v1/web/im/user/info/（www-hj.douyin.com，web 端点，
        2026-10-10 抓包实物）。body=form sec_user_ids=[...]；query 带标准
        web 参数 + msToken + a_bogus（同一 ABogus 算法，UA 绑定收割值）。
        依赖 setup_send_credentials（a_bogus/msToken）。
        """
        from urllib.parse import quote as _quote, urlencode as _urlencode
        if not getattr(self, '_send_cred', None):
            raise RuntimeError('user info needs send credentials (a_bogus/msToken)')
        ids = [s for s in sec_uids if s][:30]
        if not ids:
            return {}
        c = self._send_cred
        form = 'sec_user_ids=' + _quote(json.dumps(ids, separators=(',', ':')),
                                        safe='')
        qs = dict(USER_INFO_QS)
        qs['msToken'] = c['ms_token']
        iquery = _urlencode(qs)
        iurl = (_USER_INFO_URL + iquery
                + '&a_bogus=' + _quote(self._abogus.get_value(iquery, body=form.encode()),
                                       safe=''))
        r = self.curl.post(iurl, data=form, headers={
            'Accept': 'application/json, text/plain, */*', 'User-Agent': c['ua'],
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://www.douyin.com/', 'Cookie': self.cookie}, timeout=30)
        j = r.json()
        if j.get('status_code') != 0:
            raise RuntimeError('im/user/info failed: status_code=%s' % j.get('status_code'))
        out = {}
        for u in j.get('data') or []:
            sec = u.get('sec_uid') or ''
            if not sec:
                continue
            av = (u.get('avatar_thumb') or {}).get('url_list') or []
            out[sec] = {'nickname': u.get('nickname') or '',
                        'avatar': av[0] if av else '',
                        'uid': str(u.get('uid') or '')}
        return out

    # ------------------------------------------------- 发送凭据（登录时收割）

    def setup_send_credentials(self, verify_fp, ms_token,
                               tg_private_pem, tg_ticket, tg_ts_sign, tg_ree_pub,
                               user_agent=None, session_dtrait=''):
        """装配 send 所需的全套凭据（登录/cookie 收割时一次性传入）。

        - verify_fp: cookie s_v_web_id（URL verifyFp/fp 参数）
        - ms_token:  msToken（SDK 内存态；收割时从浏览器 localStorage xmst 取）
        - tg_private_pem: bd-ticket-guard EC P-256 私钥（浏览器 IndexedDB
          secure-store/cryptvalues 的 ec_privateKey）
        - tg_ticket / tg_ts_sign: localStorage web_protect 的 ticket/ts_sign
        - tg_ree_pub: bd-ticket-guard-ree-public-key 头的值
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        from .abogus_imapi import ABogus

        self._send_cred = {
            'verify_fp': verify_fp,
            'ms_token': ms_token,
            'tg_ticket': tg_ticket,
            'tg_ts_sign': tg_ts_sign,
            'ree_pub': tg_ree_pub,
            'dtrait': session_dtrait,
            'ua': user_agent or UA_DESKTOP,
        }
        priv = serialization.load_pem_private_key(tg_private_pem.encode(), password=None)
        cert = x509.load_pem_x509_certificate(SERVER_CERT_PEM.encode())
        self._send_cred['ecdh_key'] = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b'', info=b'').derive(
            priv.exchange(ec.ECDH(), cert.public_key()))
        self._abogus = ABogus(user_agent=self._send_cred['ua'])

    def _tg_client_data(self, path):
        """bd-ticket-guard-client-data 头（timestamp 必须是数字——字符串会被拒）。"""
        import base64 as _b64
        import hashlib as _hashlib
        import hmac as _hmac
        c = self._send_cred
        ts_int = int(time.time())
        payload = 'ticket=%s&path=%s&timestamp=%d' % (c['tg_ticket'], path, ts_int)
        req_sign = _b64.b64encode(_hmac.new(
            c['ecdh_key'], payload.encode(), _hashlib.sha256).digest()).decode()
        cd = {'ts_sign': c['tg_ts_sign'], 'req_content': 'ticket,path,timestamp',
              'req_sign': req_sign, 'timestamp': ts_int, 't_trust': 1}
        return _b64.b64encode(json.dumps(cd, separators=(',', ':')).encode()).decode()

    def get_identity_token(self):
        """取 identity_security_token（send 前现取，passport 端点不占座位）。"""
        import uuid as _uuid
        from urllib.parse import quote as _quote
        c = self._send_cred
        iparams = [
            ('passport_jssdk_version', '4.2.3'), ('passport_jssdk_type', 'lite'),
            ('is_from_ttaccountsdk', '1'), ('aid', '6383'), ('language', 'zh'),
            ('scene', 'web_im'), ('auto_retry_req', '0'), ('skip_verify', 'false'),
            ('identity_token_force_get_tag', '0'),
            ('biz_trace_id', _uuid.uuid4().hex[:16]),
            ('id_token_version', '1.2.10'), ('msToken', c['ms_token']),
        ]
        iquery = '&'.join('%s=%s' % (k, v) for k, v in iparams)
        iurl = ('https://www.douyin.com/passport/safe/get_identity_security_token/?'
                + iquery + '&a_bogus=' + _quote(self._abogus.get_value(iquery), safe=''))
        r = self.curl.get(iurl, headers={
            'Accept': 'application/json, text/plain, */*', 'User-Agent': c['ua'],
            'Referer': 'https://www.douyin.com/', 'Cookie': self.cookie}, timeout=30)
        j = r.json()
        d = j.get('data') or {}
        if j.get('message') != 'success' or not d.get('identity_security_token'):
            raise RuntimeError('get_identity_security_token failed: %s' % j.get('message'))
        return d['identity_security_token'], d.get('device_id', '')

    # ------------------------------------------------------------------- 发送

    INIT_SETTLE_SECONDS = 480   # init 后服务端会话就绪窗口（实测 5-8 分钟）

    def send(self, conv_id, text):
        """发一条文本（全签名链）。

        前置：setup_send_credentials() 已装配凭据；会话 ticket 已刷新
        （refresh_conversation_info([(conv_id, short_id)])）；init 已过就绪窗口。
        """
        if not getattr(self, '_send_cred', None):
            raise RuntimeError('send credentials missing — call setup_send_credentials() '
                               'after cookie harvest')
        since_init = time.time() - getattr(self, '_init_at', 0)
        if since_init < self.INIT_SETTLE_SECONDS:
            raise RuntimeError('session warming up: %.0fs since init, send allowed '
                               'after %ds' % (since_init, self.INIT_SETTLE_SECONDS))
        info = self._tickets.get(conv_id)
        if not info or not info.get('ticket'):
            raise RuntimeError('no ticket for %s — call refresh_conversation_info '
                               '([(conv_id, short_id)]) first' % conv_id)
        if self.curl is None:
            raise RuntimeError('send requires the curl_cffi transport')

        inner, cmid = build_send_inner(conv_id, int(info['conv_short_id']),
                                       info['ticket'], text)
        return self._dispatch_inner(conv_id, inner, cmid)

    def send_media(self, conv_id, attachments, text=''):
        """发一条带载荷的消息（CAP_SEND_MEDIA；10-10 契约扩展）。

        支持 type：
          video_card — 站内视频转发（msg_type=8 / aweType 800）：attachment
            提供 'content'（接收消息里的卡片 JSON dict，原样重放）
            或 item_id/title/cover/author_uid（由 video_card_content 组装）。
          image — 自产图片（msg_type=27 / aweType 2702）：attachment 提供
            'data_b64'（图片二进制的 base64）→ upload_image 五步链
            （config/Apply/TOS/Commit，B2 10-10 逆向）后引用加密 oid/skey。
        """
        if not getattr(self, '_send_cred', None):
            raise RuntimeError('send credentials missing — call setup_send_credentials() '
                               'after cookie harvest')
        since_init = time.time() - getattr(self, '_init_at', 0)
        if since_init < self.INIT_SETTLE_SECONDS:
            raise RuntimeError('session warming up: %.0fs since init, send allowed '
                               'after %ds' % (since_init, self.INIT_SETTLE_SECONDS))
        info = self._tickets.get(conv_id)
        if not info or not info.get('ticket'):
            raise RuntimeError('no ticket for %s — call refresh_conversation_info '
                               '([(conv_id, short_id)]) first' % conv_id)
        if self.curl is None:
            raise RuntimeError('send requires the curl_cffi transport')

        for att in attachments or ():
            if att.get('type') == 'video_card':
                content = att.get('content') if isinstance(att.get('content'), dict) else None
                if content is None:
                    content = video_card_content(
                        att.get('item_id') or '', att.get('title') or '',
                        att.get('cover') or att.get('thumb') or '',
                        att.get('author_uid') or 0)
                inner, cmid = build_send_inner(
                    conv_id, int(info['conv_short_id']), info['ticket'], '',
                    msg_type=8,
                    content=json.dumps(content, ensure_ascii=False,
                                       separators=(',', ':')))
                return self._dispatch_inner(conv_id, inner, cmid)
            if att.get('type') == 'image' and att.get('data_b64'):
                import base64 as _b64
                image = _b64.b64decode(att['data_b64'])
                content = self.upload_image(image)
                inner, cmid = build_send_inner(
                    conv_id, int(info['conv_short_id']), info['ticket'], '',
                    msg_type=27,
                    content=json.dumps(content, ensure_ascii=False,
                                       separators=(',', ':')))
                return self._dispatch_inner(conv_id, inner, cmid)
        raise ValueError("no sendable attachment — supported: video_card / image")

    # ------------------------------------------------- 图片上传（B2，VOD 五步链）

    _img_cfg = None      # 类级 STS 缓存 {'cfg': dict, 'expire': epoch 秒}

    def _image_config(self):
        """im/upload/config/v2 → public_image_config 块（STS 缓存至过期前 5min）。

        ⚠ 必须用 public_image_config（非 _v2）——同一响应里 v2 块的
        session_token 与其余三块分属不同 STS 序列，实测用 v2 的 token
        报 'session token sequence is broken'（100029）；浏览器实物用
        public_image_config 的（SpaceName=zhenzhen，绑定 uid）。
        STS PolicyString 授权 vod:ApplyUploadInner/CommitUploadInner，
        绑定 AppId=6383 与本账号 uid。
        """
        from urllib.parse import quote as _quote
        cached = DySession._img_cfg
        if cached and cached['expire'] - time.time() > 300:
            return cached['cfg']
        c = self._send_cred
        qs = dict(USER_INFO_QS)
        qs['msToken'] = c['ms_token']
        iquery = '&'.join('%s=%s' % (k, _quote(str(v), safe='')) for k, v in qs.items())
        iurl = ('https://www.douyin.com/aweme/v1/web/im/upload/config/v2?'
                + iquery + '&a_bogus=' + _quote(self._abogus.get_value(iquery), safe=''))
        r = self.curl.get(iurl, headers={
            'Accept': 'application/json, text/plain, */*', 'User-Agent': c['ua'],
            'Referer': 'https://www.douyin.com/', 'Cookie': self.cookie}, timeout=30)
        cfg = (r.json() or {}).get('public_image_config') or {}
        if not cfg.get('session_token'):
            raise RuntimeError('upload config v2 failed: no session_token')
        DySession._img_cfg = {'cfg': cfg, 'expire': int(cfg.get('expire_at') or 0)}
        return cfg

    def _vod_request(self, action, extra_params, payload=b''):
        """VOD API（vod.bytedanceapi.com，AWS SigV4 兼容鉴权，SDK=45444.js）。

        对照 SDK 的三处关键差异（逐项核对 vod-sdk-45444.js）：
        ① canonical headers 块尾显式 "\n"（与 join 的分隔符形成空行）；
        ② POST/Commit 自动加 X-Amz-Content-Sha256 头（= sha256(body 字节)，
          x-amz- 前缀自动进签名头集合）；③ payload hash 在 canonical 末行
        （GET=空串 sha256）。
        """
        import hashlib as _h
        import hmac as _hm
        from urllib.parse import quote as _quote
        cfg = self._image_config()
        params = {'Action': action, 'Version': '2020-11-19',
                  'SpaceName': cfg.get('space_name') or 'zhenzhen', **extra_params}
        qs = '&'.join('%s=%s' % (k, _quote(str(v), safe=''))
                      for k, v in sorted(params.items()))
        amzdate = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        datestamp = amzdate[:8]
        payload_hash = _h.sha256(payload).hexdigest()
        # SDK addHeaders：有 body 时自动加 X-Amz-Content-Sha256（x-amz- 前缀
        # 自动参与签名）；canonical headers 按名排序
        sig_headers = {'x-amz-date': amzdate,
                       'x-amz-security-token': cfg['session_token']}
        if payload:
            sig_headers['x-amz-content-sha256'] = payload_hash
        names = sorted(sig_headers)
        canonical_headers = '\n'.join('%s:%s' % (n, sig_headers[n]) for n in names)
        signed_headers = ';'.join(names)
        canonical = '\n'.join([
            'POST' if payload else 'GET', '/', qs,
            canonical_headers + '\n',       # SDK: headers 块尾显式 \n → 与 join 分隔符形成空行
            signed_headers, payload_hash])
        scope = '%s/cn-north-1/vod/aws4_request' % datestamp
        sts = 'AWS4-HMAC-SHA256\n%s\n%s\n%s' % (
            amzdate, scope, _h.sha256(canonical.encode()).hexdigest())
        key = ('AWS4' + cfg['secret_access_key']).encode()
        for part in (datestamp, 'cn-north-1', 'vod', 'aws4_request'):
            key = _hm.new(key, part.encode(), _h.sha256).digest()
        sig = _hm.new(key, sts.encode(), _h.sha256).hexdigest()
        auth = ('AWS4-HMAC-SHA256 Credential=%s/%s, '
                'SignedHeaders=%s, Signature=%s'
                % (cfg['access_key_id'], scope, signed_headers, sig))
        headers = {'Authorization': auth,
                   'x-amz-date': amzdate,
                   'x-amz-security-token': cfg['session_token'],
                   'Origin': 'https://www.douyin.com',
                   'Referer': 'https://www.douyin.com/'}
        if payload:
            headers['x-amz-content-sha256'] = payload_hash
            headers['Content-Type'] = 'text/plain;charset=UTF-8'
            r = self.curl.post('https://vod.bytedanceapi.com/?' + qs,
                               headers=headers, data=payload, timeout=30)
        else:
            # 实物为 GET（浏览器 Apply 无 body）；签名 canonical 也是 GET
            r = self.curl.get('https://vod.bytedanceapi.com/?' + qs,
                              headers=headers, timeout=30)
        return r.json()

    def upload_image(self, image_bytes):
        """上传图片 → 图片消息 content dict（B2 五步链，2026-10-10 逆向）。

        步骤：config v2(STS) → ApplyUploadInner(SigV4，下发 StoreUri+SpaceKey
        JWT) → TOS 直传原始字节 → CommitUploadInner（服务端 AES-256-GCM
        加密，返回加密 Uri/SecretKey）→ 组装 resource_url{oid,skey,md5}。
        前置：send 凭据已装配（config 的 a_bogus/msToken/UA）。
        """
        import hashlib as _h
        import random as _rd
        md5 = _h.md5(image_bytes).hexdigest()
        s = ''.join(_rd.choice('abcdefghijklmnopqrstuvwxyz0123456789')
                    for _ in range(12))
        apply_j = self._vod_request('ApplyUploadInner',
                                    {'FileType': 'image', 'IsInner': '1',
                                     'NeedFallback': 'true',
                                     'FileSize': len(image_bytes), 's': s})
        ua = (apply_j.get('Result') or {}).get('UploadAddress') or {}
        si = (ua.get('StoreInfos') or [{}])[0]
        store_uri, auth = si.get('StoreUri'), si.get('Auth')
        session_key = ua.get('SessionKey') or ''
        host = (ua.get('UploadHosts') or ['tos-nc2-slb2.douyin.com'])[0]
        if not store_uri or not auth:
            raise RuntimeError('ApplyUploadInner failed: %s' % str(apply_j)[:200])
        if not host.startswith('http'):
            host = 'https://' + host
        up = self.curl.post('%s/upload/v1/%s' % (host.rstrip('/'), store_uri),
                            headers={'Authorization': auth,
                                     'Content-Type': 'application/octet-stream',
                                     'content-crc32': '%08x' % (_zlib.crc32(image_bytes) & 0xffffffff),
                                     'content-disposition': 'attachment; filename="undefined"',
                                     'x-storage-u': str(self.uid or ''),
                                     'Origin': 'https://www.douyin.com',
                                     'Referer': 'https://www.douyin.com/'},
                            data=image_bytes, timeout=60)
        if up.status_code not in (200, 201):
            raise RuntimeError('TOS upload failed: %s %s'
                               % (up.status_code, up.text[:120]))
        # Functions=Encryption：触发服务端 AES-256-GCM 加密（缺失则无 Encryption）
        commit_body = json.dumps({
            'SessionKey': session_key,
            'Functions': [{'name': 'Encryption',
                           'input': {'Config': {'copies': 'cipher_v2'},
                                     'PolicyParams': {'policy-set': 'check,thumb,medium,large'}}}],
        }).encode()
        commit = self._vod_request('CommitUploadInner', {}, payload=commit_body)
        results = ((commit.get('Result') or {}).get('Results') or [{}])
        enc = results[0].get('Encryption') or {}
        oid, skey = enc.get('Uri'), enc.get('SecretKey')
        if not oid or not skey:
            raise RuntimeError('CommitUploadInner failed: %s' % str(commit)[:200])
        extra = enc.get('Extra') or {}
        return {'resource_url': {'oid': oid, 'skey': skey,
                                 'data_size': int(extra.get('encryption_size')
                                                  or len(image_bytes)),
                                 'md5': enc.get('SourceMd5') or md5},
                'cover_height': int(extra.get('img_height') or 0),
                'cover_width': int(extra.get('img_width') or 0),
                'check_pics': [],
                'md5': md5,
                'from_gallery': 1,
                'aweType': 2702}

    def send_image(self, conv_id, image_bytes):
        """发一张图片（upload_image 五步链 + msg_type=27 消息体）。"""
        content = self.upload_image(image_bytes)
        info = self._tickets.get(conv_id)
        if not info or not info.get('ticket'):
            raise RuntimeError('no ticket for %s' % conv_id)
        inner, cmid = build_send_inner(
            conv_id, int(info['conv_short_id']), info['ticket'], '',
            msg_type=27,
            content=json.dumps(content, ensure_ascii=False,
                               separators=(',', ':')))
        return self._dispatch_inner(conv_id, inner, cmid)

    def _dispatch_inner(self, conv_id, inner, cmid):
        """发送公共传输：identity token → 信封 → a_bogus → POST → 响应解析。
        send()/send_media()/send_image() 共用（守卫已在调用方完成）。"""
        c = self._send_cred
        id_token, id_device = self.get_identity_token()

        global ENVELOPE_PARAMS
        saved = ENVELOPE_PARAMS
        ENVELOPE_PARAMS = [
            ('identity_security_token', json.dumps({'token': id_token}, separators=(',', ':'))),
            ('identity_security_device_id', id_device),
            ('identity_security_aid', ''),
        ] + saved
        try:
            env = envelope(CMD_SEND, body_field=100, inner=inner, flag6=0)
        finally:
            ENVELOPE_PARAMS = saved

        query = 'verifyFp=%s&fp=%s&msToken=%s' % (c['verify_fp'], c['verify_fp'], c['ms_token'])
        a_bogus = self._abogus.get_value(query, body=inner)
        from urllib.parse import quote as _quote
        url = IM_API + path_SEND + '?' + query + '&a_bogus=' + _quote(a_bogus, safe='')
        headers = {
            'Accept': 'application/x-protobuf',
            'Content-Type': 'application/x-protobuf',
            'Origin': 'https://www.douyin.com',
            'Referer': 'https://www.douyin.com/',
            'Cookie': self.cookie,
            # UA 必须与 a_bogus 签名所绑定的 UA 完全一致（a_bogus 校验 UA）
            'User-Agent': c['ua'],
            'sec-ch-ua': '"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'bd-ticket-guard-client-data': self._tg_client_data(path_SEND),
            'bd-ticket-guard-ree-public-key': c['ree_pub'],
            'bd-ticket-guard-version': '2',
            'bd-ticket-guard-web-sign-type': '1',
            'bd-ticket-guard-web-version': '2',
        }
        if c.get('dtrait'):
            headers['x-tt-session-dtrait'] = c['dtrait']
        r = self.curl.post(url, headers=headers, data=env, timeout=30)
        top = pb.parse(r.content)
        ok = pb.text(pb.blob(top, 4)) == 'OK' if top else False
        return {'ok': bool(ok), 'client_message_id': cmid,
                'status_code': pb.one(top, 5, -1) if top else -1,
                'error': pb.text(pb.blob(top, 4)) if top and not ok else ''}
