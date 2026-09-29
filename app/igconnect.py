"""Instagram connector — the third platform adapter.

Auth model differs from TikTok/X: username + password through instagrapi's
private mobile API, with the device fingerprint + session persisted via
get_settings() (dict, stored in the hub DB). First login from a new
environment usually draws a verification challenge (email/SMS code); the
hub runs login in a background thread whose challenge handler blocks on an
Event until the user submits the code via /api/ig/code — the hub stays
responsive while Instagram's code is in flight, and the two-phase state is
visible at /api/ig/state.

instagrapi is synchronous, so there is no event-loop bridging; calls run
directly in hub threads (same model as the TikTok client). Live-validated
shapes: DirectThread{id, users, messages, last_activity_at},
DirectMessage{id, user_id, thread_id, timestamp, item_type,
is_sent_by_viewer, text}.
"""
import os
import shutil
import threading

LAZY_ERR = 'instagrapi is not installed — run: pip install instagrapi'


def _install_proxy(cl, proxy):
    """显式把代理装到 instagrapi 的**全部**传输上。

    只给 Client(proxy=...) 并不够：3.x 的私有走 curl（会带上），但
    requests 系的 public/graphql 会话不带显式代理时会回落到进程环境变量
    ——而环境变量里常是一条死代理（502 Bad Gateway）。requests 的语义是
    显式 session.proxies 优先于环境（setdefault），所以写死即根治。
    """
    if not proxy:
        return
    proxies = {'http': proxy, 'https': proxy}
    for attr in ('public', 'private', 'graphql'):
        s = getattr(cl, attr, None)
        if s is not None and hasattr(s, 'proxies'):
            try:
                s.proxies = dict(proxies)
            except Exception:
                pass


def _fix_nonascii_ca_bundle():
    """curl on Windows cannot open CA bundles under non-ASCII paths — curl
    error 77, "error adding trust anchors from locations: CAfile". The hub
    commonly runs under a user directory whose name is not ASCII (e.g.
    C:\\Users\\刘海丽\\...), where certifi's bundle lives, so instagrapi's
    private curl transport dies before any TLS happens. Copy the bundle to
    an ASCII-only location once and point certifi.where() at it; curl_cffi
    reads that at session creation, so patching the module attribute before
    any session exists is sufficient."""
    import certifi
    src = certifi.where()
    if src.isascii():
        return src
    base = os.environ.get('PROGRAMDATA') or r'C:\ProgramData'
    if not base.isascii():
        base = r'C:\ProgramData'
    dst_dir = os.path.join(base, 'tk-message-demo')
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, 'cacert.pem')
    if (not os.path.exists(dst)
            or os.path.getsize(dst) != os.path.getsize(src)):
        shutil.copyfile(src, dst)
    certifi.where = lambda: dst
    return dst


_fix_nonascii_ca_bundle()


def _to_ms(dt):
    if dt is None:
        return 0
    try:
        return int(dt.timestamp() * 1000)
    except Exception:
        return 0


# ------------------------------------------------------- interactive login

class IGLogin:
    """One interactive login run: background thread + code handoff.

    Phases: starting -> challenge|twofa -> verifying -> success | error.
    submit_code() unblocks the waiting handler inside instagrapi's login.
    """

    def __init__(self, username, password, proxy=None):
        self.username = username
        self.password = password
        self.proxy = proxy
        self.phase = 'starting'
        self.detail = ''
        self.client = None
        self._code_event = threading.Event()
        self._code = ''
        self._lock = threading.Lock()

    def state(self):
        with self._lock:
            return {'phase': self.phase, 'detail': self.detail,
                    'username': self.username}

    def submit_code(self, code):
        self._code = (code or '').strip()
        self._code_event.set()

    def _challenge_handler(self, username, choice=None):
        """Replaces instagrapi's input()-based handler: blocks this background
        login thread until the hub user submits the code."""
        with self._lock:
            if self.phase == 'starting':
                self.phase = 'challenge'
            self.detail = 'code sent via %s' % (choice or 'email/sms')
        self._code_event.wait(timeout=600)
        code = self._code
        if not code:
            raise RuntimeError('no verification code within 10 minutes')
        self._code_event.clear()               # re-arm if IG asks again
        self._code = ''
        with self._lock:
            self.phase = 'verifying'
        return code

    def _wait_code(self, phase, detail):
        with self._lock:
            self.phase = phase
            self.detail = detail
        self._code_event.wait(timeout=600)
        code = self._code
        if not code:
            raise RuntimeError('no code provided within 10 minutes')
        self._code_event.clear()
        self._code = ''
        return code

    def run(self):
        """Blocking login. Returns the logged-in Client; updates phase."""
        try:
            from instagrapi import Client
        except ImportError:
            self._fail(LAZY_ERR)
            raise RuntimeError(LAZY_ERR)
        cl = Client(proxy=self.proxy)
        cl.delay_range = [1, 3]
        _install_proxy(cl, self.proxy)
        cl.challenge_code_handler = self._challenge_handler
        self.client = cl
        try:
            cl.login(self.username, self.password)
        except Exception as e:
            if 'TwoFactor' in type(e).__name__:
                code = self._wait_code('twofa', str(e))
                try:
                    cl.login(self.username, self.password,
                             verification_code=code)
                except Exception as e2:
                    self._fail('%s: %s' % (type(e2).__name__, e2))
                    raise
            else:
                self._fail('%s: %s' % (type(e).__name__, e))
                raise
        with self._lock:
            self.phase = 'success'
        return cl

    def _fail(self, detail):
        with self._lock:
            self.phase = 'error'
            self.detail = detail


# ------------------------------------------------------- persisted session

class IGSession:
    """One logged-in Instagram account backed by persisted settings."""

    def __init__(self, settings, username, password, proxy=None, client=None):
        from instagrapi import Client
        self._cl = client or Client(proxy=proxy)
        self._cl.delay_range = [1, 3]
        _install_proxy(self._cl, proxy)
        if settings:
            self._cl.set_settings(settings)
        self._cl.username = username
        self._cl.password = password
        self.username = username
        self.password = password
        self._me_uid = None

    # ------------------------------------------------------------ lifecycle

    def ensure_login(self):
        """Validate the stored session; re-login with the stored password
        when Instagram rejects it (may raise ChallengeRequired — the user
        re-adds the account interactively in that case).

        sessionid 导入的会话没有密码：鉴权已在 settings 里，直接放行。
        """
        if not self.password:
            return True
        return self._cl.login(self.username, self.password)

    @classmethod
    def from_sessionid(cls, sessionid, proxy=None):
        """用浏览器 web session 的 sessionid 建会话（无需账号密码）。

        IG 的 web 与私有 API 共用同一个 sessionid（形如 ``<uid>%3A...``），
        instagrapi 的 login_by_sessionid 从中推导 ds_user_id 并装好
        Authorization 头；sessionid 无效会抛 PrivateError/ValidationError。
        """
        from instagrapi import Client
        cl = Client(proxy=proxy)
        cl.delay_range = [1, 3]
        _install_proxy(cl, proxy)
        cl.login_by_sessionid(sessionid.strip())
        sess = cls(cl.get_settings(), cl.username or '', '', proxy=proxy,
                   client=cl)
        sess._ensured = True             # 刚建好，无需再 ensure
        return sess

    def settings(self):
        return self._cl.get_settings()

    # ------------------------------------------------------------- identity

    def verify(self):
        me = self._cl.account_info()
        self._me_uid = str(me.pk)
        return {'uid': str(me.pk), 'username': me.username or '',
                'name': me.full_name or ''}

    def _me(self):
        if not self._me_uid:
            self._me_uid = str(self._cl.user_id)
        return self._me_uid

    # -------------------------------------------------------------- inbox

    def conversations(self):
        me = self._me()
        out = []
        for t in self._cl.direct_threads(amount=20):
            peer = None
            for u in (t.users or []):
                if str(u.pk) != me:
                    peer = u
                    break
            msgs = t.messages or []
            last = max(msgs, key=lambda m: _to_ms(m.timestamp)) if msgs else None
            out.append({
                'platform': 'instagram',
                'conv_id': str(t.id),
                'peer_uid': str(peer.pk) if peer else '',
                'peer_nickname': (peer.full_name or '') if peer else '',
                'peer_unique': (peer.username or '') if peer else '',
                'peer_avatar': (peer.profile_pic_url or '') if peer else '',
                'last_text': (last.text if (last and last.text) else
                              ('[%s]' % last.item_type if last else '')),
                'last_ms': _to_ms(last.timestamp) if last else
                           _to_ms(getattr(t, 'last_activity_at', None)),
                'last_from_me': bool(last.is_sent_by_viewer) if last else False,
                'unread': 0,
            })
        out.sort(key=lambda c: c['last_ms'], reverse=True)
        return out

    # ------------------------------------------------------------- history

    def history(self, thread_id, amount=30):
        me = self._me()
        rows = []
        for m in self._cl.direct_messages(int(thread_id), amount=amount):
            rows.append({
                'platform': 'instagram',
                'msg_id': str(m.id),
                'conv_id': str(thread_id),
                'sender': str(m.user_id or ''),
                'outgoing': 1 if (m.is_sent_by_viewer or str(m.user_id) == me) else 0,
                'text': m.text or ('[%s]' % m.item_type if m.item_type != 'text' else ''),
                'ms': _to_ms(m.timestamp),
                'us': _to_ms(m.timestamp) * 1000,
            })
        rows.sort(key=lambda x: x['ms'])
        return rows

    def send(self, thread_id, text):
        m = self._cl.direct_answer(int(thread_id), text)
        return {'ok': True, 'msg_id': str(m.id) if m else '',
                'ms': _to_ms(getattr(m, 'timestamp', None))}

    def mark_seen(self, thread_id):
        self._cl.direct_send_seen(int(thread_id))
        return {'ok': True}
