"""X (Twitter) 适配器 —— 包装 app/xconnect.py。

登录：'cookies'（auth_token + ct0，x.com F12 可得）。弹窗官方登录在阶段 4
作为可选入口接入（twikit 只吃 cookie，弹窗登录后同样是从浏览器收割 cookie）。

conv_id = 对端 user_id（X 的 DM 按对端寻址）。
实时收信没有全局游标可依（twikit 无收件箱增量端点），因此不声明
CAP_REALTIME —— 阶段 4 的 hub 统一轮询负责按会话拉新。
"""
from . import registry
from .. import xconnect
from .base import (PlatformAdapter, Account, Conversation, Message, CAP_SEND)


@registry.register
class XAdapter(PlatformAdapter):
    platform = 'x'
    display_name = 'X (Twitter)'
    auth_kind = 'cookies'
    capabilities = (CAP_SEND,)
    send_limits = {'min_interval_s': 15, 'daily_cap': 100}

    # ---------------------------------------------------------- 弹窗登录

    def popup_login_spec(self):
        return {
            'login_url': 'https://x.com/i/flow/login',
            'required_cookies': ('auth_token', 'ct0'),
            'cookie_domains': ('x.com', 'twitter.com'),
            'hint': '在窗口里登录 X（可能要求手机号/邮箱验证）。'
                    '登录后自动抓取 auth_token 与 ct0，无需手工复制。',
            # 登录类 cookie：不清掉的话，上次登录的账号会让判据立刻成立、
            # 窗口秒关；访客标识 guest_id / gt 保留。
            'clear_login_keys': ('auth_token', 'ct0', 'twid', 'kdt',
                                 'auth_multi'),
        }

    # ------------------------------------------------------------ 认证

    def auth_fields(self):
        return [{'key': 'cookie',
                 'label': 'X cookie（须含 auth_token 和 ct0）',
                 'secret': True}]

    def add_account(self, fields):
        cookie = (fields.get('cookie') or '').strip()
        if not cookie:
            raise ValueError('cookie 不能为空')
        sess = xconnect.XSession(cookie, proxy=self._proxy).start()
        info = sess.verify()                       # 顺便证明 cookie 可用
        acct = Account(platform='x',
                       name=(fields.get('name') or info['username'] or info['uid']),
                       uid=info['uid'], username=info['username'],
                       nickname=info['name'])
        return sess, acct

    # ------------------------------------------------------ 会话持久化

    def session_dump(self, sess):
        return {'cookie': sess.cookie_str}

    def session_load(self, d):
        return xconnect.XSession(d.get('cookie') or '',
                                 proxy=self._proxy).start()

    def session_status(self, sess):
        try:
            sess.verify()
            return 'ok'
        except Exception:
            return 'error'

    # -------------------------------------------------------------- 读

    def conversations(self, sess):
        out = []
        for c in sess.conversations():
            c['last_from_me'] = 1 if c.pop('outgoing', False) else 0
            out.append(Conversation(platform='x', account='', **{
                k: c[k] for k in Conversation.__dataclass_fields__ if k in c}))
        return out

    def messages(self, sess, conv_id, before_ms=None, limit=30):
        rows, _cursor = sess.history(conv_id)
        if before_ms:
            rows = [r for r in rows if r.get('ms', 0) < before_ms]
        rows = rows[-limit:]
        return [Message(platform='x', account='', msg_id=str(r['msg_id']),
                        conv_id=str(r.get('conv_id') or conv_id),
                        sender=str(r.get('sender') or ''),
                        outgoing=1 if r.get('outgoing') else 0,
                        text=r.get('text') or '', ms=int(r.get('ms') or 0),
                        status='sent')
                for r in rows]

    # -------------------------------------------------------------- 写

    def send(self, sess, conv_id, text):
        out = sess.send(conv_id, text)
        out.setdefault('ok', True)
        return out
