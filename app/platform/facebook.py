"""Facebook Messenger 适配器 —— 包装 app/fbconnect.py（fbchat-v2 E2EE 桥）。

登录：'cookies'（facebook.com 的 c_user + xs；datr/fr 有则更稳）。
1:1 私聊收发/已读走 E2EE 桥子进程；会话列表走 GraphQL INBOX 批量。
当前无可用 FB 账号：适配器就绪但 UI 暂不展示，有号后即启。
"""
from . import registry
from .. import fbconnect
from .base import (PlatformAdapter, Account, Conversation, Message,
                   CAP_SEND, CAP_MARK_READ, CAP_REALTIME)


@registry.register
class FacebookAdapter(PlatformAdapter):
    platform = 'facebook'
    display_name = 'FB Messenger'
    auth_kind = 'cookies'
    capabilities = (CAP_SEND, CAP_MARK_READ, CAP_REALTIME)
    send_limits = {'min_interval_s': 10, 'daily_cap': 200}

    # ------------------------------------------------------------ 认证

    def auth_fields(self):
        return [{'key': 'cookie',
                 'label': 'Facebook cookie（须含 c_user 和 xs）',
                 'secret': True}]

    def add_account(self, fields):
        cookie = (fields.get('cookie') or '').strip()
        if not cookie:
            raise ValueError('cookie 不能为空')
        sess = fbconnect.FBSession(cookie, proxy=self._proxy).start()
        info = sess.verify()                      # 拉自己的 uid，cookie 无效会抛
        acct = Account(platform='facebook',
                       name=(fields.get('name') or info['uid']),
                       uid=info['uid'], username=info['username'],
                       nickname=info['name'])
        return sess, acct

    # ------------------------------------------------------ 会话持久化

    def session_dump(self, sess):
        return {'cookie': sess.cookie_str}

    def session_load(self, d):
        return fbconnect.FBSession(d.get('cookie') or '',
                                   proxy=self._proxy).start()

    # -------------------------------------------------------------- 读

    def conversations(self, sess):
        return [Conversation(platform='facebook', account='', **{
                    k: c[k] for k in Conversation.__dataclass_fields__ if k in c})
                for c in sess.conversations()]

    def messages(self, sess, conv_id, before_ms=None, limit=30):
        rows = sess.history(conv_id)
        if before_ms:
            rows = [r for r in rows if r.get('ms', 0) < before_ms]
        rows = rows[-limit:]
        return [Message(platform='facebook', account='',
                        msg_id=str(r['msg_id']), conv_id=str(r['conv_id']),
                        sender=str(r.get('sender') or ''),
                        outgoing=1 if r.get('outgoing') else 0,
                        text=r.get('text') or '', ms=int(r.get('ms') or 0),
                        status='sent')
                for r in rows]

    def poll(self, sess, state):
        """E2EE 桥的实时事件排水；事件形状由桥决定，未识别的原样透传。"""
        events = []
        for e in sess.drain_events():
            if isinstance(e, dict) and e.get('text') is not None:
                events.append({'type': 'message', 'platform': 'facebook',
                               'conv_id': str(e.get('thread_id') or ''),
                               'msg_id': str(e.get('message_id') or ''),
                               'sender': str(e.get('sender_id') or ''),
                               'text': e.get('text') or '',
                               'ms': fbconnect._now_ms()})
            else:
                events.append({'type': 'raw', 'event': e})
        return events, state
