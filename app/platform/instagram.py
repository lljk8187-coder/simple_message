"""Instagram 适配器 —— 包装 app/igconnect.py。

登录：两条通道并存。
- 'password_2fa'（兜底）：页面输用户名密码 → IG 发验证码 → 填码；
  session 持久化后不再需要验证码。
- 'popup'（浏览器登录）：从已登录的 instagram.com 抓 sessionid，交给
  instagrapi 的 login_by_sessionid —— web 与私有 API 共用同一个
  sessionid（形如 <uid>%3A...），所以这条路走得通。
  **更正**：本文件早先写着"IG 私有接口不认浏览器 web session、别试图用
  cookie 导入"，该断言未经实测且不成立（instagrapi 3.0.14 有
  login_by_sessionid，且它正是吃 web 的 sessionid），2026-09-29 推翻。
  IG 网页登录常撞 challenge，账密通道因此保留为兜底。

阶段 2 附带的修复：igconnect 现在把代理显式装到全部传输上——此前 requests
系的会话回落到进程环境变量里的死代理，登录必报 502。
"""
import threading

from . import registry
from .. import igconnect
from .base import (PlatformAdapter, Account, Conversation, Message,
                   NeedCode, CAP_SEND, CAP_MARK_READ)


def _pick_cookie(text, key):
    """从 Cookie 头样式的字符串里取一个值（浏览器登录给来的是整串）。"""
    for part in (text or '').split(';'):
        k, _, v = part.strip().partition('=')
        if k == key:
            return v.strip()
    return ''


@registry.register
class InstagramAdapter(PlatformAdapter):
    platform = 'instagram'
    display_name = 'Instagram'
    auth_kind = 'password_2fa'
    capabilities = (CAP_SEND, CAP_MARK_READ)
    send_limits = {'min_interval_s': 20, 'daily_cap': 150}

    # ------------------------------------------------------------ 认证

    def popup_login_spec(self):
        return {
            'login_url': 'https://www.instagram.com/accounts/login/',
            'required_cookies': ('sessionid', 'ds_user_id'),
            'cookie_domains': ('instagram.com',),
            'hint': '在窗口里登录 Instagram（可能要过验证码/挑战）。'
                    '登录后自动抓 sessionid 导入，比输密码更少触发风控。',
            # 登录类 cookie：开窗口前清掉，否则上次的 sessionid/ds_user_id
            # 会让判据立刻成立、窗口秒关。设备标识 ig_did / mid / datr 保留。
            'clear_login_keys': ('sessionid', 'ds_user_id', 'rur',
                                 'csrftoken'),
        }

    def auth_fields(self):
        return [{'key': 'username', 'label': 'Instagram 用户名', 'secret': False},
                {'key': 'password', 'label': '密码', 'secret': True}]

    def add_account(self, fields):
        # 通道一：浏览器登录给来的 sessionid（或整串 cookie）直接建会话
        sid = (fields.get('sessionid') or '').strip()
        if not sid and fields.get('cookie'):
            sid = _pick_cookie(fields['cookie'], 'sessionid')
        if sid:
            try:
                sess = igconnect.IGSession.from_sessionid(sid,
                                                          proxy=self._proxy)
            except Exception as e:
                raise RuntimeError('sessionid 无效或已过期（%s）' % e)
            info = sess.verify()
            acct = Account(platform='instagram',
                           name=(fields.get('name') or info['username']
                                 or info['uid']),
                           uid=info['uid'], username=info['username'],
                           nickname=info['name'])
            return sess, acct

        # 通道二：账密 + 验证码（原路径，作为兜底保留）
        username = (fields.get('username') or '').strip()
        password = (fields.get('password') or '').strip()
        if not username or not password:
            raise ValueError('用户名和密码必填')
        login = igconnect.IGLogin(username, password, proxy=self._proxy)
        th = threading.Thread(target=self._safe_run, args=(login,), daemon=True)
        login._thread = th
        th.start()
        th.join(timeout=90)
        if login.phase == 'success':
            return self._finish(login)
        if login.phase in ('challenge', 'twofa', 'verifying'):
            # 验证码在路上：线程挂起等码，hub 引导用户 → submit_code
            raise NeedCode(state=login, message='verification code required')
        if login.phase == 'error':
            raise RuntimeError(login.detail or 'login failed')
        raise RuntimeError('login timed out — please retry')

    def _safe_run(self, login):
        try:
            login.run()
        except Exception:
            pass                       # phase='error' 已由 login.run 标记

    def submit_code(self, sess, code):
        """sess = add_account 时挂起的 IGLogin 句柄。"""
        login = sess
        login.submit_code(code)
        th = getattr(login, '_thread', None)
        if th is not None:
            th.join(timeout=180)
        if login.phase == 'success':
            return self._finish(login)
        raise RuntimeError(login.detail or ('login failed: %s' % login.phase))

    def _finish(self, login):
        """登录成功 → 持久化会话 + 账号信息。"""
        sess = igconnect.IGSession(login.client.get_settings(), login.username,
                                   login.password, proxy=self._proxy,
                                   client=login.client)
        sess._ensured = True           # 刚登录完，无需再 ensure
        info = sess.verify()
        acct = Account(platform='instagram',
                       name=info['username'] or info['uid'],
                       uid=info['uid'], username=info['username'],
                       nickname=info['name'])
        return sess, acct

    # ------------------------------------------------------ 会话持久化

    def session_dump(self, sess):
        """含账号密码：IG 的会话恢复依赖凭据重登（instagrapi 机制如此）。"""
        return {'settings': sess.settings(), 'username': sess.username,
                'password': sess.password}

    def session_load(self, d):
        sess = igconnect.IGSession(d.get('settings') or {},
                                   d.get('username') or '',
                                   d.get('password') or '',
                                   proxy=self._proxy)
        return sess                    # 首次调用时惰性 ensure_login

    def session_status(self, sess):
        try:
            self._ensure(sess)
            sess.verify()
            return 'ok'
        except Exception:
            return 'error'

    def _ensure(self, sess):
        """重启后首次使用时校验/恢复会话（instagrapi 要求显式 login 一轮）。"""
        if getattr(sess, '_ensured', False):
            return
        sess.ensure_login()
        sess._ensured = True

    # -------------------------------------------------------------- 读

    def conversations(self, sess):
        self._ensure(sess)
        return [Conversation(platform='instagram', account='', **{
                    k: c[k] for k in Conversation.__dataclass_fields__ if k in c})
                for c in sess.conversations()]
    def messages(self, sess, conv_id, before_ms=None, limit=30):
        self._ensure(sess)
        rows = sess.history(conv_id, amount=max(limit, 30))
        if before_ms:
            rows = [r for r in rows if r.get('ms', 0) < before_ms]
        rows = rows[-limit:]
        return [Message(platform='instagram', account='',
                        msg_id=str(r['msg_id']), conv_id=str(r['conv_id']),
                        sender=str(r.get('sender') or ''),
                        outgoing=1 if r.get('outgoing') else 0,
                        text=r.get('text') or '', ms=int(r.get('ms') or 0),
                        status='sent')
                for r in rows]

    # -------------------------------------------------------------- 写

    def send(self, sess, conv_id, text):
        self._ensure(sess)
        return sess.send(conv_id, text)

    def mark_read(self, sess, conv_id, read_index):
        self._ensure(sess)
        return sess.mark_seen(conv_id)
