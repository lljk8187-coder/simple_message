"""TikTok 适配器 —— 包装 app/client.py（协议层不动）。

登录：'cookies'（贴 cookie 即全功能；发送走 B 档本地签名，无材料自动落 Z 档）。
弹窗官方登录（'popup'）作为可选入口在阶段 4 接到统一添加流程，本适配器已预留
popup_login 挂载点。

适配器内的两个私有细节：
- short_id：TikTok 发送/已读需要 (conv_id, short_id) 一对；short_id 只从会话
  列表（cmd 203）取得，这里做逐账号缓存，冷启动时自动补拉一次列表。
- send_limits 是保守的个人用量申报：单发最小间隔 8 秒、日上限 300 条。
  信任分越低（Z 档 1104）越不该贴近上限。
"""
import threading
import time

from . import registry
from .. import client as cl
from .base import (PlatformAdapter, Account, Conversation, Message,
                   CAP_SEND, CAP_MARK_READ, CAP_REALTIME)

# ------------------------------------------------------- 弹窗登录：材料收割
# 开浏览器的**唯一理由**是取这两样东西：wid（即 device_id）与签名材料。
# 材料在 localStorage 里是密文，解密必须在该站点的 JS 上下文里做，所以这段
# 必须跑在页面内（而不是把密文抓回本地再解）。
WID_JS = """
() => {
  try {
    const el = document.querySelector('#__UNIVERSAL_DATA_FOR_REHYDRATION__');
    if (!el) return null;
    const data = JSON.parse(el.textContent).__DEFAULT_SCOPE__['webapp.app-context'];
    return data.wid || null;
  } catch (e) { return null; }
}
"""

MATERIALS_JS = """
async () => {
  const signRaw = localStorage.getItem('security-sdk/s_sdk_sign_data_key/tt_fetch');
  const cryptRaw = localStorage.getItem('security-sdk/s_sdk_crypt_sdk');
  if (!signRaw || !cryptRaw) return {error: 'materials not in localStorage yet'};
  const s = JSON.parse(JSON.parse(signRaw).data);
  if (!s.encrypt_ticket || !s.ts_sign) return {error: 'sign data incomplete'};
  const b = Uint8Array.from(atob(s.encrypt_ticket), c => c.charCodeAt(0));
  const k = await crypto.subtle.importKey('raw',
      new TextEncoder().encode('tt-ticket-guard-iv'), 'PBKDF2', false, ['deriveKey']);
  const kk = await crypto.subtle.deriveKey(
      {name: 'PBKDF2', salt: new TextEncoder().encode('secure-salt'),
       iterations: 1000, hash: 'SHA-256'}, k,
      {name: 'AES-GCM', length: 128}, false, ['decrypt']);
  const ticket = new TextDecoder().decode(
      await crypto.subtle.decrypt({name: 'AES-GCM', iv: b.slice(0, 12)}, kk, b.slice(12)));
  const crypt = JSON.parse(JSON.parse(cryptRaw).data);
  const private_key = (crypt.ec_privateKey || '')
      .replace(/-----[A-Z ]+-----/g, '').replace(/\\s+/g, '');
  if (!ticket || !private_key) return {error: 'materials incomplete'};
  return {ticket, private_key, ts_sign: s.ts_sign};
}
"""


@registry.register
class TikTokAdapter(PlatformAdapter):
    platform = 'tiktok'
    display_name = 'TikTok'
    auth_kind = 'cookies'
    capabilities = (CAP_SEND, CAP_MARK_READ, CAP_REALTIME)
    send_limits = {'min_interval_s': 8, 'daily_cap': 300}

    def __init__(self, config=None):
        super().__init__(config)
        self._http = None
        self._lock = threading.Lock()
        self._short = {}                 # (uid, conv_id) -> short_id

    # ---------------------------------------------------------- 弹窗登录

    def popup_login_spec(self):
        return {
            'login_url': 'https://www.tiktok.com/login',
            'required_cookies': ('sessionid', 'sessionid_ss'),
            'cookie_domains': ('tiktok',),
            'hint': '在窗口里登录 TikTok（密码 / 扫码 / 验证码都行）。'
                    '登录完成后会自动收割签名材料（ticket + 私钥），'
                    '这一步是最高信任档的输入。',
            # 登录类 cookie：开窗口前清掉，否则上次的登录态会立刻命中判据、
            # 窗口秒关（同平台就登不了第二个账号）。设备标识 ttwid / msToken /
            # tt_chain_token 必须保留——换新设备反而更容易吃风控。
            'clear_login_keys': (
                'sessionid', 'sessionid_ss', 'sid_tt', 'sid_guard',
                'uid_tt', 'uid_tt_ss', 'sid_ucp_v1', 'ssid_ucp_v1',
                'passport_auth_status', 'passport_auth_status_ss',
                'multi_sids', 'tt_session_tlb_tag', 'store-idc',
                'store-country-code', 'store-country-code-src',
                'tt-target-idc', 'tt-target-idc-sign', 'store-country-sign',
                'last_login_method', 'passport_fe_beating_status',
            ),
            'collect_materials': self._collect_materials,
        }

    def _collect_materials(self, page, ctx, cookie_str):
        """页面内收割 wid（device_id）与 ticket / 私钥 / ts_sign。

        必须在登录后的页面上下文里跑：材料在 localStorage 是密文，
        密钥派生与解密只有该站点的 JS 能做。
        """
        time.sleep(4)                    # 等安全 SDK 初始化完再读
        wid = None
        for _ in range(10):
            try:
                wid = page.evaluate(WID_JS)
            except Exception:
                wid = None
            if wid:
                break
            time.sleep(2)
        mats = None
        for _ in range(20):
            try:
                mats = page.evaluate(MATERIALS_JS)
            except Exception:
                mats = None
            if mats and not mats.get('error'):
                break
            time.sleep(3)
        if not mats or mats.get('error'):
            raise RuntimeError('materials not readable: %s'
                               % (mats or {}).get('error', 'timeout'))
        return {'ticket': mats['ticket'],
                'private_key': mats['private_key'],
                'ts_sign': mats['ts_sign'],
                'device_id': wid or ''}

    # ------------------------------------------------------------ 内部工具

    def _client(self):
        with self._lock:
            if self._http is None:
                self._http = cl.HttpClient(proxy=self._proxy, detect=False)
            return self._http

    def _cache_short(self, sess, rows):
        uid = sess.uid
        with self._lock:
            for c in rows:
                if c.get('conv_id') and c.get('short_id'):
                    self._short[(uid, c['conv_id'])] = c['short_id']

    def _short_id(self, sess, conv_id):
        with self._lock:
            short = self._short.get((sess.uid, conv_id))
        if short:
            return short
        rows, _meta = cl.list_conversations(self._client(), sess)   # 冷启动补拉
        self._cache_short(sess, rows)
        return self._short.get((sess.uid, conv_id))

    def _profiles(self, sess, uids):
        try:
            return cl.user_profiles(self._client(), sess, uids) or {}
        except Exception:
            return {}

    # ------------------------------------------------------------ 认证

    def auth_fields(self):
        return [{'key': 'cookie', 'label': 'TikTok cookie（浏览器复制的整串）',
                 'secret': True}]

    def add_account(self, fields):
        cookie = (fields.get('cookie') or '').strip()
        if not cookie:
            raise ValueError('cookie 不能为空')
        info = cl.verify_cookie(self._client(), cookie)
        sess = cl.Session(
            cookie=cookie,
            device_id=(fields.get('device_id')
                       or self.config.get('default_device_id') or ''),
            uid=info['uid'], username=info['username'],
            nickname=info['nickname'], region=info.get('region', ''),
            guard=fields.get('guard') or {},
            ticket=fields.get('ticket') or '',
            private_key=fields.get('private_key'),
            ts_sign=fields.get('ts_sign') or '')
        acct = Account(platform='tiktok',
                       name=(fields.get('name') or info['username'] or info['uid']),
                       uid=info['uid'], username=info['username'],
                       nickname=info['nickname'])
        return sess, acct

    def popup_login(self, context):
        """弹窗官方登录（推荐入口）：登录完成 hub 自动收 cookie + 三件套。"""
        from .. import login_browser
        flow = login_browser.BrowserLogin(
            context['store'], context['hub'], context['client'],
            profile_dir=context['profile_dir'], proxy=self._proxy)
        flow.start()
        return flow

    # ------------------------------------------------------ 会话持久化

    def session_dump(self, sess):
        return sess.to_dict()          # 含 private_key 的 hex 形态与 guard JSON

    def session_load(self, d):
        return cl.Session.from_dict(d)

    # -------------------------------------------------------------- 读

    def conversations(self, sess):
        rows, _meta = cl.list_conversations(self._client(), sess)
        self._cache_short(sess, rows)
        profiles = self._profiles(sess, [c.get('peer_uid') for c in rows])
        out = []
        for c in rows:
            last = c.get('last') or {}
            prof = profiles.get(str(c.get('peer_uid') or ''), {})
            out.append(Conversation(
                platform='tiktok', account='', conv_id=c['conv_id'],
                peer_uid=str(c.get('peer_uid') or ''),
                peer_nickname=prof.get('nickname') or '',
                peer_unique=prof.get('unique_id') or '',
                last_text=last.get('text') or '',
                last_ms=int(last.get('ms') or 0),
                unread=int(c.get('unread') or 0)))
        return out

    def messages(self, sess, conv_id, before_ms=None, limit=30):
        short = self._short_id(sess, conv_id)
        if not short:
            raise ValueError('unknown conversation (no short_id): %r' % conv_id)
        rows = cl.list_messages(self._client(), sess, conv_id, short,
                                anchor_us=before_ms, limit=limit)
        return [Message(platform='tiktok', account='', msg_id=str(r['msg_id']),
                        conv_id=str(r.get('conv_id') or conv_id),
                        sender=str(r.get('sender') or ''),
                        outgoing=1 if r.get('outgoing') else 0,
                        text=r.get('text') or '', ms=int(r.get('ms') or 0),
                        status='sent',
                        kind=r.get('kind') or 'text')
                for r in rows]

    def poll(self, sess, state):
        """cmd 204 增量：state = 上次游标（str/int，None 从 0 起）。"""
        ok, cursor, _interval, msgs, _unread = cl.combo_poll(
            self._client(), sess, int(state or 0))
        events = []
        for m in msgs:
            md = Message(platform='tiktok', account='', msg_id=str(m['msg_id']),
                         conv_id=str(m.get('conv_id') or ''),
                         sender=str(m.get('sender') or ''),
                         outgoing=1 if m.get('outgoing') else 0,
                         text=m.get('text') or '', ms=int(m.get('ms') or 0),
                         status='sent',
                         kind=m.get('kind') or 'text')
            events.append({'type': 'message', **md.to_dict()})
        return events, str(cursor)

    # -------------------------------------------------------------- 写

    def send(self, sess, conv_id, text):
        short = self._short_id(sess, conv_id)
        if not short:
            raise ValueError('unknown conversation (no short_id): %r' % conv_id)
        return cl.send_message(self._client(), sess, conv_id, short, text)

    def mark_read(self, sess, conv_id, read_index):
        """read_index = 已读到哪条的时间戳（微秒）；hub 传最新一条消息的 us。"""
        short = self._short_id(sess, conv_id)
        if not short:
            raise ValueError('unknown conversation (no short_id): %r' % conv_id)
        return cl.mark_read(self._client(), sess, conv_id, short, read_index)
