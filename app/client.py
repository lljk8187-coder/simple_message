"""Client for the recovered IM protocol.

Everything here was established empirically against a live session; see the
project README for the field map. No signature is implemented because the read
path needs none and the write path can reuse captured guard headers.
"""
import base64
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from . import proto as pb
from . import signing

IM_API = 'https://im-api.tiktok.com'
WEB = 'https://www.tiktok.com'
UA_DEFAULT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36')

ENVELOPE_VER = '1.8.2'
ENVELOPE_BUILD = '1132b10:master'
FEATURE_TAG = '$75bcb7b:feat/im-core-sdk-ooo-push-v2'

# sub-command per command id (diffed from live captures, not guessed)
SUB = {
    100: 10000,
    203: 10001,
    204: 10040,
    301: 10007,
    609: 10007,   # v2/conversation/create (cold contact) shares 301's sub value
}

PROXY_CANDIDATES = [
    'http://127.0.0.1:7897', 'http://127.0.0.1:7890',
    'http://127.0.0.1:10809', 'http://127.0.0.1:10808',
    'http://127.0.0.1:1080', 'http://127.0.0.1:8889',
]


class ApiError(RuntimeError):
    def __init__(self, message, status=None, biz_code=None, payload=None):
        super().__init__(message)
        self.status = status
        self.biz_code = biz_code
        self.payload = payload


# --------------------------------------------------------------- transport

def _probe(url, timeout=3):
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({'http': url, 'https': url}))
        req = urllib.request.Request('https://www.tiktok.com/',
                                     method='HEAD', headers={'User-Agent': UA_DEFAULT})
        with opener.open(req, timeout=timeout) as r:
            return r.status < 500
    except Exception:
        return False


def detect_proxy(explicit=None, timeout=3):
    """Return a working proxy URL, or None for direct.

    The proxy in HTTPS_PROXY is often the host application's internal channel and
    cannot reach the internet, so candidates are probed rather than trusted.
    """
    cands = []
    if explicit:
        cands.append(explicit)
    env = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
    if env:
        cands.append(env)
    cands.extend(PROXY_CANDIDATES)
    seen = set()
    for c in cands:
        if not c or c in seen:
            continue
        seen.add(c)
        if _probe(c, timeout):
            return c
    return None


class HttpClient:
    def __init__(self, proxy=None, timeout=30, ua=None, detect=True):
        self.timeout = timeout
        self.ua = ua or UA_DEFAULT
        if proxy is None and detect:
            proxy = detect_proxy()
        self.proxy = proxy
        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
        self._opener = urllib.request.build_opener(*handlers)

    def request(self, method, url, *, headers=None, body=None):
        h = {'User-Agent': self.ua, 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            raw = e.read()
            raise ApiError('HTTP %s' % e.code, status=e.code, payload=raw) from None

    def get(self, url, **kw):
        return self.request('GET', url, **kw)

    def post(self, url, **kw):
        return self.request('POST', url, **kw)


# ----------------------------------------------------------------- session

class Session:
    """One account's credentials plus the derived request headers.

    Two ways to authenticate a write, in order of preference:

      tier B — sign locally from `ticket` + `ts_sign` + `private_key`
      tier A — replay the captured `guard` headers verbatim

    Tier B survives longer and is not tied to one captured request; tier A needs
    no key material at all. Reads need neither.
    """

    def __init__(self, cookie, device_id, uid, username='', region='',
                 guard=None, ticket='', nickname='', avatar='',
                 private_key=None, ts_sign=''):
        self.cookie = cookie
        self.device_id = str(device_id)
        self.uid = str(uid)
        self.username = username
        self.nickname = nickname
        self.avatar = avatar
        self.region = region
        self.guard = dict(guard or {})
        self.ticket = ticket
        self.private_key = private_key          # int scalar, or None
        self.ts_sign = ts_sign or ''

    @classmethod
    def from_dict(cls, d):
        guard = d.get('guard') or {}
        if isinstance(guard, str):              # guard is stored as JSON text in SQLite
            try:
                guard = json.loads(guard) or {}
            except Exception:
                guard = {}
        key = d.get('private_key') or ''
        if isinstance(key, str) and key:
            try:
                key = signing.parse_private_key(key)
            except Exception:
                key = None
        return cls(cookie=d.get('cookie') or '', device_id=d.get('device_id') or '',
                   uid=d.get('uid') or '', username=d.get('username') or '',
                   region=d.get('region') or '', guard=guard,
                   ticket=d.get('ticket') or '', nickname=d.get('nickname') or '',
                   avatar=d.get('avatar') or '', private_key=key or None,
                   ts_sign=d.get('ts_sign') or '')

    def to_dict(self):
        return {'cookie': self.cookie, 'device_id': self.device_id, 'uid': self.uid,
                'username': self.username, 'nickname': self.nickname,
                'avatar': self.avatar, 'region': self.region, 'guard': self.guard,
                'ticket': self.ticket,
                'private_key': ('%064x' % self.private_key) if self.private_key else '',
                'ts_sign': self.ts_sign}

    @property
    def ms_token(self):
        for part in (self.cookie or '').split('; '):
            if part.startswith('msToken='):
                return part[len('msToken='):]
        return ''


def _proto_headers(sess):
    return {
        'Content-Type': 'application/x-protobuf',
        'Accept': 'application/x-protobuf',
        'Origin': WEB,
        'Referer': WEB + '/',
        'Cookie': sess.cookie,
    }


def envelope(cmd, payload, sess, with_sub=True, feature=False, env_block=False):
    """Build the request envelope.

    Reads accept a minimal envelope; the write path must OMIT f2 (including it
    flips the response to a parameter error).
    """
    body = pb.vint(1, cmd)
    if with_sub:
        body += pb.vint(2, SUB.get(cmd, 0))
    body += pb.s(3, ENVELOPE_VER)
    if feature:
        body += pb.s(4, FEATURE_TAG)
    body += pb.vint(5, 3) + pb.vint(6, 0) + pb.s(7, ENVELOPE_BUILD)
    body += pb.sub(8, pb.sub(cmd, payload))
    body += pb.s(9, sess.device_id) + pb.s(11, 'web')
    if env_block:
        for k, v in _env_pairs(sess):
            body += pb.ld(15, pb.s(1, k) + pb.s(2, v))
    return body


def create_envelope(cmd, payload, sess):
    """Envelope shape used by cmd 609 (conversation/create).

    Diffed against a live UI capture (2026-10-20): f4 present but EMPTY
    (not the feature tag), an f15 env block with a fuller key set, and a
    trailing f18=1. Sends to a conversation created without these exact
    extras were accepted (biz_code=0) but silently dropped, so this shape
    is reproduced field-for-field.
    """
    body = (pb.vint(1, cmd) + pb.vint(2, SUB.get(cmd, 0)) + pb.s(3, ENVELOPE_VER)
            + pb.s(4, '') + pb.vint(5, 3) + pb.vint(6, 0) + pb.s(7, ENVELOPE_BUILD)
            + pb.sub(8, pb.sub(cmd, payload))
            + pb.s(9, sess.device_id) + pb.s(11, 'web') + pb.vint(18, 1))
    for k, v in _create_env_pairs(sess):
        body += pb.ld(15, pb.s(1, k) + pb.s(2, v))
    return body


def _create_env_pairs(sess):
    ua = UA_DEFAULT
    return [('aid', '1988'), ('app_name', 'tiktok_web'), ('channel', 'web'),
            ('device_platform', 'web_pc'), ('device_id', sess.device_id),
            ('region', 'US'), ('priority_region', 'US'), ('os', 'windows'),
            ('referer', WEB + '/'), ('root_referer', WEB + '/'),
            ('cookie_enabled', 'true'), ('screen_width', '1920'),
            ('screen_height', '1080'), ('browser_language', 'zh-CN'),
            ('browser_platform', 'Win32'), ('browser_name', 'Mozilla'),
            ('browser_version', ua.split('Mozilla/')[1]),
            ('browser_online', 'true'), ('verifyFp', ''),
            ('app_language', 'zh-Hans'), ('webcast_language', 'zh-Hans'),
            ('tz_name', 'Asia/Shanghai'), ('is_page_visible', 'true'),
            ('focus_state', 'true'), ('is_fullscreen', 'false'),
            ('history_len', '13'), ('user_is_login', 'true'),
            ('data_collection_enabled', 'true'), ('from_appID', '1988'),
            ('locale', 'zh-Hans'), ('user_agent', ua),
            ('Web-Sdk-Ms-Token', sess.ms_token)]


def _env_pairs(sess):
    return [('aid', '1988'), ('app_name', 'tiktok_web'), ('channel', 'web'),
            ('device_platform', 'web_pc'), ('device_id', sess.device_id),
            ('region', 'US'), ('priority_region', 'US'), ('os', 'windows'),
            ('referer', WEB + '/'), ('cookie_enabled', 'true'),
            ('screen_width', '1920'), ('screen_height', '1080'),
            ('browser_language', 'zh-CN'), ('browser_platform', 'Win32'),
            ('browser_name', 'Mozilla'), ('browser_online', 'true'),
            ('tz_name', 'Asia/Shanghai'), ('is_page_visible', 'true'),
            ('focus_state', 'true'), ('user_is_login', 'true'),
            ('from_appID', '1988'), ('locale', 'zh-Hans'),
            ('Web-Sdk-Ms-Token', sess.ms_token)]


def unwrap(raw, cmd):
    """Strip the response envelope -> (payload fields | None, meta)."""
    top = pb.parse(raw)
    if top is None:
        raise ApiError('response is not valid protobuf')
    meta = {
        'cmd': pb.one(top, 1),
        'sub': pb.one(top, 2),
        'biz_code': pb.one(top, 3),
        'biz_msg': pb.text(pb.blob(top, 4)),
        'server_ms': pb.one(top, 10),
        'region': pb.text(pb.blob(top, 14)),
        'uid': pb.one(top, 15),
    }
    holder = pb.blob(top, 6)
    if holder is None:
        return None, meta
    payload = pb.blob(pb.parse(holder), cmd)
    return (pb.parse(payload) if payload else []), meta


# -------------------------------------------------------------------- reads

# f8 里出现这些键名时按"非文本消息"归类（贴纸 / 图片 / 视频 / 附件）。
# 各家客户端版本键名不一，所以按名字匹配而不是穷举结构。
_MEDIA_KEYS = ('sticker', 'image', 'video', 'attachment', 'media', 'aweurl')


def parse_message(entry, my_uid):
    it = pb.parse(entry)
    if it is None:
        return None
    raw_text = pb.text(pb.blob(it, 8)) or ''
    body, awe, j = raw_text, 0, {}
    if raw_text:
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                j = parsed
                body = j.get('text', '') or ''
                awe = j.get('aweType', 0) or 0
        except Exception:
            j = {}
    sender = pb.one(it, 7) or 0
    micros = pb.one(it, 4) or 0
    millis = pb.one(it, 10) or (micros // 1000 if micros else 0)
    ext = pb.pairs(pb.all_of(it, 9))
    # f8 also carries non-chat payloads. Tag them so the UI can say *what* it is
    # instead of drawing an unexplained empty bubble:
    #   command  session-control event ({"command_type":1,...}) — dropped by store
    #   tip      server notice mixed into the stream; measured live:
    #            {"tips":"Message request accepted. You can start chatting."}
    #            -> shown verbatim (it is genuine user-visible text)
    #   reaction non-zero aweType (emoji/sticker reaction on a message)
    #   media    sticker/image/video payload (keys vary, matched by name)
    #   unknown  empty and unrecognised — better an explicit label than a blank
    if 'command_type' in j:
        kind = 'command'
    elif body.strip():
        kind = 'text'
    elif j.get('tips'):
        kind, body = 'tip', str(j['tips'])
    elif raw_text.strip() == '{"hack":"1"}':
        # 10-12 实测：手机发的图片/语音，服务端对 web 通道下发的是剥离后的
        # 占位 {"hack":"1"}（媒体数据不下发，官方网页同样只显示"请下载 App"）
        kind, body = 'tip', '[图片/语音消息：TikTok 网页端不显示，请在手机 App 查看]'
    elif awe:
        kind = 'reaction'
    elif any(k in raw_text.lower() for k in _MEDIA_KEYS):
        kind = 'media'
    else:
        kind = 'unknown'

    # f24 private media（10-12 借鉴 matrix-tiktok 逆向）：手机发的图片/语音，
    # 服务端对 web 通道把 f8 content 换成占位 {"hack":"1"}，但媒体附件在
    # f24：{decrypt_key=3, variants=20[{label=1, url=2 重复}]}。
    # private_image 的 full 档 CDN 密文用 decrypt_key AES-256-GCM 解密
    # （nonce=前12B，与抖音图片同构）；private_video 的 URL 直接可播。
    atts = []
    subtype = pb.text(pb.blob(it, 21)) or ''
    f24 = pb.blob(it, 24)
    if f24:
        att = pb.parse(f24)
        dkey = pb.text(pb.blob(att, 3)) or ''
        full = thumb = ''
        for _, _, _, vbl in pb.all_of(att, 20):
            v = pb.parse(vbl)
            label = pb.text(pb.blob(v, 1)) or ''
            for x in v:
                if x[0] == 2 and x[1] == 2:
                    u = pb.text(x[3]) or ''
                    if label == 'full' and not full:
                        full = u
                    if label == 'preview' and not thumb:
                        thumb = u
        if subtype == 'private_image' and full and dkey:
            import base64 as _b64
            uenc = _b64.urlsafe_b64encode(full.encode()).decode().rstrip('=')
            atts.append({'type': 'image',
                         'url': '/api/img?u=%s&k=%s' % (uenc, dkey),
                         'thumb': thumb})
            kind = 'media'
    return {
        'msg_id': str(pb.one(it, 3) or ''),
        'conv_id': pb.text(pb.blob(it, 1)) or '',
        'sender': str(sender),
        'outgoing': str(sender) == str(my_uid),
        'text': body,
        'kind': kind,
        'awe_type': awe,
        'ms': int(millis),
        'us': int(micros),
        'ext': ext,
        'attachments': tuple(atts),
        # the id we generated when sending; lets a client match its own optimistic
        # bubble against the message that eventually comes back from the server
        'cid': ext.get('s:client_message_id') or '',
    }


def list_conversations(client, sess, max_pages=1):
    """cmd 203 / sub 10001 -> conversations + their latest messages.

    分页机制（10-28 实测）：官方网页连发 N 次相同请求、服务端按会话有状态地
    逐页返回（每页 ~10 会话，页间零交集，无 cursor 参数）——max_pages>1 时
    顺序调用直到整页重复（已见过的 conv_id 集合），合并去重返回全部。
    注意：分页状态在服务端会话上，必须串行调用；页 1 调用即重置游标。"""
    all_convs = {}
    seen_ids = set()
    for page in range(max(1, max_pages)):
        body = envelope(203, pb.vint(1, 0), sess)
        _, raw, _ = client.post(IM_API + '/v2/message/get_by_user_init',
                                headers=_proto_headers(sess), body=body)
        payload, meta = unwrap(raw, 203)
        if payload is None:
            if page == 0:
                raise ApiError('conversation list: %s' % (meta.get('biz_msg') or 'no payload'),
                               biz_code=meta.get('biz_code'))
            break

        newest = {}
        for entry in pb.all_of(payload, 1):
            m = parse_message(entry[3], sess.uid)
            if not m or not m['conv_id']:
                continue
            cur = newest.get(m['conv_id'])
            if cur is None or m['ms'] > cur['ms']:
                newest[m['conv_id']] = m

        page_convs = []
        for entry in pb.all_of(payload, 2):
            it = pb.parse(entry[3])
            conv_id = pb.text(pb.blob(it, 1)) or ''
            short_id = pb.one(it, 2)
            parts = []
            holder = pb.blob(it, 6)
            if holder:
                for p in pb.all_of(pb.parse(holder), 1):
                    u = pb.one(pb.parse(p[3]), 1)
                    if u:
                        parts.append(str(u))
            page_convs.append({
                'conv_id': conv_id,
                'short_id': str(short_id) if short_id else '',
                'peer_uid': peer_of(conv_id, sess.uid),
                'participants': parts,
                'updated_ms': int(pb.one(it, 13) or 0),
                # server-side unread count (badge). Confirmed by diffing two snapshots
                # around a single incoming message: 40 -> 41, exactly +1, on this and
                # on v1/conversation/list (2006) which reports the identical value.
                'unread': int(pb.one(it, 11) or 0),
                'last': newest.get(conv_id),
            })
        # 整页都是已见会话 → 服务端游标已到底，停止翻页
        page_ids = {c['conv_id'] for c in page_convs}
        if page_convs and page_ids <= seen_ids:
            break
        seen_ids |= page_ids
        for c in page_convs:
            prev = all_convs.get(c['conv_id'])
            if prev is None or c['updated_ms'] > prev['updated_ms']:
                all_convs[c['conv_id']] = c
        if not page_convs:
            break

    convs = sorted(all_convs.values(), key=lambda c: c['updated_ms'], reverse=True)
    return convs, {'next_cursor': '', 'meta': meta,
                   'pages': page + 1 if page_convs else page}


def combo_poll(client, sess, cursor):
    """cmd 204: the site's own incremental sync — and it is a real one.

    Send the last cursor; the reply carries everything newer **plus per-
    conversation unread counts** (measured: an hour-old cursor returned four
    full message entries and a status blob; a current cursor returns a 117-byte
    empty tick). Envelope: f8 → f204 → f1{f1:0, f2:cursor, f3:50, f4:8}.

    Reply payload (inside f8 → f204):
      f1      the incremental container: f2 = repeated message entries
              (same shape as 301's), f5 = next cursor, f6 = poll interval,
              f9 = repeated {f1 short_id, f4 conv_id, f5 unread, f6 total, f7 ts}
      f5      next cursor (echo)

    Returns (ok, new_cursor, interval, messages, unread_list).
    """
    inner = pb.vint(1, 0) + pb.vint(2, int(cursor)) + pb.vint(3, 50) + pb.vint(4, 8)
    payload = pb.sub(1, inner)
    body = envelope(204, payload, sess)
    try:
        _, raw, _ = client.post(IM_API + '/v1/message/get_by_user_combo',
                                headers=_proto_headers(sess), body=body)
    except Exception:
        return False, cursor, None, [], []
    fields, meta = unwrap(raw, 204)
    if fields is None or meta.get('biz_code') != 0:
        return False, cursor, None, [], []

    messages, unread, interval = [], [], None
    inc = pb.blob(fields, 1)
    if inc:
        it = pb.parse(inc)
        for _, _, _, bl in pb.all_of(it, 2):
            m = parse_message(bl, sess.uid)
            if m and (m['conv_id'] or m['text'] or m['msg_id']):
                messages.append(m)
        v = pb.one(it, 6)
        interval = int(v) if v else None
        for _, _, _, bl in pb.all_of(it, 9):
            u = pb.parse(bl)
            if not u:
                continue
            unread.append({
                'short_id': str(pb.one(u, 1) or ''),
                'conv_id': pb.text(pb.blob(u, 4)) or '',
                'unread': int(pb.one(u, 5) or 0),
                'total': int(pb.one(u, 6) or 0),
                'ts': int(pb.one(u, 7) or 0),
            })
    new_cursor = pb.one(fields, 5) or (messages[-1]['us'] if messages else cursor)
    return True, int(new_cursor), interval, messages, unread


def peer_of(conv_id, my_uid):
    """Conversation ids look like 0:1:<uidA>:<uidB>; the peer is the other one.

    Deriving it from the id is reliable; reading it from payload fields is not
    (some fields carry your own uid, which makes every row look like a self-chat).
    """
    parts = (conv_id or '').split(':')
    if len(parts) >= 4:
        return parts[3] if parts[2] == str(my_uid) else parts[2]
    return ''


def list_messages(client, sess, conv_id, short_id, anchor_us=None, limit=20):
    """cmd 301 -> messages older than `anchor_us` (microseconds)."""
    if anchor_us is None:
        anchor_us = int(time.time() * 1_000_000)
    payload = (pb.s(1, conv_id) + pb.vint(2, 1) + pb.vint(3, int(short_id))
               + pb.vint(4, 1) + pb.vint(5, int(anchor_us)) + pb.vint(6, int(limit)))
    body = envelope(301, payload, sess)
    _, raw, _ = client.post(IM_API + '/v1/message/get_by_conversation',
                            headers=_proto_headers(sess), body=body)
    fields, meta = unwrap(raw, 301)
    if fields is None:
        raise ApiError('history: %s' % (meta.get('biz_msg') or 'no payload'),
                       biz_code=meta.get('biz_code'))
    msgs = [parse_message(e[3], sess.uid) for e in pb.all_of(fields, 1)]
    msgs = [m for m in msgs if m and (m['conv_id'] or m['text'])]
    msgs.sort(key=lambda m: m['us'])
    return msgs, {'next_cursor': str(pb.one(fields, 2) or ''), 'meta': meta}


def user_profiles(client, sess, uids):
    """Batched profile lookup (GET, JSON, no signature).

    Returns {uid: {'nickname','unique_id','avatar'}}.
    """
    uids = [str(u) for u in uids if u]
    if not uids:
        return {}
    q = urllib.parse.urlencode({'aid': '1988', 'user_ids': json.dumps(uids)})
    url = WEB + '/tiktok/v1/im/user/profile/?' + q
    _, raw, _ = client.get(url, headers={'Accept': 'application/json',
                                         'Cookie': sess.cookie,
                                         'Referer': WEB + '/'})
    try:
        data = json.loads(raw.decode('utf-8'))
    except Exception:
        raise ApiError('profile response was not JSON')
    out = {}
    for u in data.get('users') or []:
        p = u.get('im_user_profile') or {}
        uid = str(p.get('user_id_str') or p.get('user_id') or '')
        if not uid:
            continue
        avatar = ''
        avatars = p.get('avatars') or {}
        for key in ('avatar_small', 'avatar_medium', 'avatar_thumb'):
            slot = avatars.get(key) or {}
            urls = slot.get('url_list') or []
            if urls:
                avatar = urls[0]
                break
        out[uid] = {
            'nickname': p.get('nick_name') or '',
            'unique_id': p.get('unique_id') or '',
            'avatar': avatar,
        }
    return out


# --------------------------------------------------------------------- write

def profile_by_username(client, sess, username):
    """@username -> {uid, nickname, unique_id} via the profile page's SSR blob.

    The JSON API (`/api/user/detail/`) is signed and returns an empty body,
    but the profile page ships the same user object as
    `__UNIVERSAL_DATA_FOR_REHYDRATION__` → `webapp.user-detail.userInfo.user`,
    so no signature is needed. The uid field there is `id` (not `id_str`).

    Raises ApiError when the page has no SSR block (bot wall / unknown user).
    """
    name = str(username or '').lstrip('@').strip()
    if not name:
        raise ApiError('username is empty')
    url = WEB + '/@' + urllib.parse.quote(name)
    _, raw, _ = client.get(url, headers={'Cookie': sess.cookie})
    html = raw.decode('utf-8', 'ignore')
    m = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>',
                  html, re.S)
    if not m:
        raise ApiError('profile page has no SSR block for @%s' % name)
    try:
        data = json.loads(m.group(1))
        ui = data['__DEFAULT_SCOPE__']['webapp.user-detail']['userInfo']['user']
    except (ValueError, KeyError, TypeError):
        raise ApiError('profile page structure changed for @%s' % name)
    uid = ui.get('id') or ui.get('id_str')
    if not uid:
        raise ApiError('no uid on profile @%s' % name)
    return {'uid': str(uid), 'nickname': ui.get('nickname') or '',
            'unique_id': ui.get('uniqueId') or name}


def ts_sign_from_guard(sess):
    """The companion token rides inside the captured client-data as base64 JSON.

    Recovering it here means an account imported with only tier A material can be
    upgraded to tier B just by adding a private key.
    """
    blob = (sess.guard or {}).get('tt-ticket-guard-client-data')
    if not blob:
        return ''
    try:
        return (json.loads(base64.b64decode(blob).decode('utf-8')) or {}).get('ts_sign') or ''
    except Exception:
        return ''


def signable(sess):
    return bool(sess.ticket and sess.private_key and (sess.ts_sign or ts_sign_from_guard(sess)))


def _throwaway_guard_headers():
    """Tier Z — a fresh throwaway key, no client-data, no ticket.

    matrix-tiktok (production bridge, Aug 2026) sends exactly this way; measured
    here as biz_code=0 with guard_result=1104. The guard pipeline scores the
    request lower than a verified signature but still accepts it. This makes
    sending possible with NOTHING but the cookie — no harvesting, no
    cross-account material sharing, no browser, ever.
    """
    d = secrets.randbelow(signing.N - 1) + 1
    return {
        'tt-ticket-guard-public-key':
            base64.b64encode(signing.public_key_raw(d)).decode('ascii'),
        'tt-ticket-guard-version': '2',
        'tt-ticket-guard-iteration-version': '0',
        'tt-ticket-guard-web-version': '1',
    }, 'Z'


def ticket_guard_headers(sess, path, timestamp=None):
    """Build `tt-ticket-guard-*` headers for `path`.

    Returns (headers, tier). Preference order:
      B — sign locally from `ticket` + `ts_sign` + `private_key`   (result 0)
      A — replay the captured `guard` headers verbatim             (0 / 1003)
      Z — throwaway key, no ticket, no client-data                 (1104)
    Tier A is bound to the path it was captured for, so a mismatch is a real
    risk there — tier B has no such constraint. Tier Z has neither constraint
    nor harvested material: every account sends independently.
    """
    ts_sign = sess.ts_sign or ts_sign_from_guard(sess)
    if sess.private_key and sess.ticket and ts_sign:
        ts = int(timestamp if timestamp is not None else time.time())
        payload = ('ticket=%s&path=%s&timestamp=%d' % (sess.ticket, path, ts)).encode('utf-8')
        der = signing.sign(payload, sess.private_key)
        client_data = {
            'ts_sign': ts_sign,
            'req_content': 'ticket,path,timestamp',
            'req_sign': base64.b64encode(der).decode('ascii'),
            'timestamp': ts,
        }
        return {
            'tt-ticket-guard-public-key':
                base64.b64encode(signing.public_key_raw(sess.private_key)).decode('ascii'),
            'tt-ticket-guard-client-data':
                base64.b64encode(json.dumps(client_data, separators=(',', ':')).encode('utf-8')).decode('ascii'),
            'tt-ticket-guard-version': '2',
            'tt-ticket-guard-iteration-version': '0',
            'tt-ticket-guard-web-version': '1',
        }, 'B'
    if sess.guard:
        return dict(sess.guard), 'A'
    return _throwaway_guard_headers()


def send_message(client, sess, conv_id, short_id, text):
    """cmd 100. Tier B signs locally, A replays captured headers, Z sends bare."""
    cid = str(uuid.uuid4())
    ext = b''
    for k, v in (('s:client_message_id', cid), ('deprecated', cid),
                 ('source_aid', '1180'), ('s:mode', '0')):
        ext += pb.s(1, k) + pb.s(2, v)
    payload = (pb.s(1, conv_id) + pb.vint(2, 1) + pb.vint(3, int(short_id))
               + pb.s(4, json.dumps({'aweType': 0, 'text': text}, separators=(',', ':')))
               + pb.ld(5, ext) + pb.vint(6, 7)
               + (pb.s(7, sess.ticket) if sess.ticket else b'')   # tier Z omits the ticket
               + pb.s(8, cid))
    body = envelope(100, payload, sess, with_sub=False, feature=True)
    headers = _proto_headers(sess)
    guard, tier = ticket_guard_headers(sess, '/v1/message/send')
    if guard:
        headers.update(guard)
    query = ('?aid=1988&version_code=1.0.0&app_name=tiktok_web&device_platform=web_pc'
             '&msToken=' + urllib.parse.quote(sess.ms_token, safe=''))
    status, raw, resp_headers = client.post(IM_API + '/v1/message/send' + query,
                                            headers=headers, body=body)
    _, meta = unwrap(raw, 100)
    guard_result = None
    for k, v in resp_headers.items():
        if k.lower() == 'tt-ticket-guard-result':
            guard_result = v
    ok = meta.get('biz_code') == 0 and (meta.get('biz_msg') or '').upper() == 'OK'
    return {
        'ok': ok,
        'http': status,
        'biz_code': meta.get('biz_code'),
        'biz_msg': meta.get('biz_msg'),
        'guard_result': guard_result,
        'tier': tier,
        'client_message_id': cid,
    }


ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'


def create_conversation(client, sess, peer_uid):
    """cmd 609 /v2/conversation/create — the cold-contact prelude.

    Measured live (2026-10-20 UI capture): opening a chat with a stranger
    sends NOTHING; the conversation row is created server-side only when the
    composer is used, via this call. Payload is f609{f1:1, repeated f2: uid}
    (both participants); the reply's f1 carries the canonical conv_id and f2
    the real short_id that cmd 100 requires. Without this prelude a send to a
    self-constructed conv_id returns biz_code=0 but the message silently
    never lands.

    No ticket-guard headers are attached (the official client sends none).
    Idempotent: an existing conversation returns its current (conv_id,
    short_id).
    """
    a, b = sorted([str(sess.uid), str(peer_uid)], key=int)
    payload = pb.vint(1, 1) + pb.vint(2, int(a)) + pb.vint(2, int(b))
    body = create_envelope(609, payload, sess)
    query = ('?aid=1988&version_code=1.0.0&app_name=tiktok_web&device_platform=web_pc'
             '&msToken=' + urllib.parse.quote(sess.ms_token, safe=''))
    _, raw, _ = client.post(IM_API + '/v2/conversation/create' + query,
                            headers=_proto_headers(sess), body=body)
    fields, meta = unwrap(raw, 609)
    if fields is None or meta.get('biz_code') != 0:
        raise ApiError('conversation/create: %s' % (meta.get('biz_msg') or 'no payload'),
                       biz_code=meta.get('biz_code'))
    conv = pb.parse(pb.blob(fields, 1) or b'')
    conv_id = pb.text(pb.blob(conv, 1)) or ''
    short_id = pb.one(conv, 2)
    if not conv_id or not short_id:
        raise ApiError('conversation/create: missing conv_id/short_id in reply')
    return {'conv_id': conv_id, 'short_id': str(short_id),
            'created': bool(pb.one(conv, 8)), 'meta': meta}


def cold_send(client, sess, peer_uid, text):
    """Full cold-contact chain: ensure conversation exists, then send."""
    conv = create_conversation(client, sess, peer_uid)
    result = send_message(client, sess, conv['conv_id'], conv['short_id'], text)
    result['conv_id'] = conv['conv_id']
    result['short_id'] = conv['short_id']
    return result


def mark_read(client, sess, conv_id, short_id, read_index, unread=0):
    """cmd 2002 (mark read) -> inner field 604, sub=1.

    Recipe diffed against matrix-tiktok and validated live (biz_code=0):
    f4 is the read index in epoch-microseconds (the newest message's f4),
    f5/f6 carry the local unread counters. Known quirk: the server-side
    conversation counters (f11/f9 of cmd 203) do not move from this call —
    the receipt lands on the peer's side, which is exactly the "seen" mark
    the official clients show.
    """
    payload = (pb.s(1, conv_id) + pb.vint(2, int(short_id)) + pb.vint(3, 1)
               + pb.vint(4, int(read_index))
               + pb.vint(5, int(unread)) + pb.vint(6, int(unread)))
    body = (pb.vint(1, 2002) + pb.vint(2, 1) + pb.s(3, ENVELOPE_VER)
            + pb.vint(5, 3) + pb.vint(6, 0) + pb.s(7, ENVELOPE_BUILD)
            + pb.sub(8, pb.sub(604, payload))
            + pb.s(9, sess.device_id) + pb.s(11, 'web'))
    headers = _proto_headers(sess)
    guard, tier = ticket_guard_headers(sess, '/v3/conversation/mark_read')
    if guard:
        headers.update(guard)
    bogus = ''.join(secrets.choice(ALNUM) for _ in range(24))   # X-Bogus: random, like the web client
    query = ('?aid=1988&version_code=1.0.0&app_name=tiktok_web&device_platform=web_pc'
             '&msToken=' + urllib.parse.quote(sess.ms_token or '', safe='')
             + '&X-Bogus=' + bogus)
    status, raw, rh = client.post(IM_API + '/v3/conversation/mark_read' + query,
                                  headers=headers, body=body)
    _, meta = unwrap(raw, 2002)
    guard_result = None
    for k, v in rh.items():
        if k.lower() == 'tt-ticket-guard-result':
            guard_result = v
    return {'ok': meta.get('biz_code') == 0, 'http': status,
            'biz_code': meta.get('biz_code'), 'biz_msg': meta.get('biz_msg'),
            'guard_result': guard_result, 'tier': tier}


# --------------------------------------------------------------------- login

def verify_cookie(client, cookie):
    """Ask passport who this cookie belongs to. Raises ApiError when unauthenticated."""
    url = WEB + '/passport/web/account/info/?aid=1988'
    _, raw, _ = client.get(url, headers={'Cookie': cookie,
                                         'Accept': 'application/json',
                                         'Referer': WEB + '/'})
    try:
        j = json.loads(raw.decode('utf-8'))
    except Exception:
        raise ApiError('passport response was not JSON')
    data = j.get('data') or {}
    if (j.get('message') or '') != 'success' or not data.get('user_id_str'):
        raise ApiError('cookie is not signed in (message=%r)' % j.get('message'))
    return {
        'uid': str(data.get('user_id_str') or data.get('user_id')),
        'username': data.get('username') or '',
        'nickname': data.get('nickname') or '',
        'region': data.get('region') or '',
    }
