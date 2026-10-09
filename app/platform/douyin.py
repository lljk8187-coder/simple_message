"""抖音适配器 —— 包装 app/dyconnect.py（桌面客户端同款纯 HTTPS 协议）。

登录：'cookies'（从已登录的桌面客户端/浏览器导出，须含 sessionid 等
.douyin.com 域登录 cookie）。移动端登录风控对模拟器极严（实测短信通道
直接禁发），桌面端扫码是获取登录态最省力的入口。

conv_id = '0:1:<uid>:<peer>'（平台原生格式，直接用于 send 信封）。
ticket 由服务端随 get_info_list 下发、每次发送取最新（会话级滚动票据）。
v1 能力：send + conversations；messages/poll 的增量解析下一步接入。
"""
from . import registry
from .. import dyconnect
from .base import (PlatformAdapter, Account, Conversation, CAP_SEND)


@registry.register
class DouyinAdapter(PlatformAdapter):
    platform = 'douyin'
    display_name = '抖音'
    auth_kind = 'cookies'
    capabilities = (CAP_SEND,)
    # 保守申报：桌面客户端官方心跳 5s/发消息走用户手速；我们取 20s，
    # 与"账号存活 > 送达速度"原则一致（比 TikTok 的 8s 更保守，国内实名号）
    send_limits = {'min_interval_s': 20, 'daily_cap': 80}

    # ------------------------------------------------------------ 认证

    def auth_fields(self):
        return [{'key': 'cookie',
                 'label': '抖音 cookie（.douyin.com 域，须含 sessionid）',
                 'secret': True}]

    def add_account(self, fields):
        cookie = (fields.get('cookie') or '').strip()
        if not cookie:
            raise ValueError('cookie 不能为空')
        if 'sessionid' not in cookie:
            raise ValueError('cookie 里没有 sessionid——请从已登录客户端完整复制')
        sess = dyconnect.DySession(cookie, proxy=self._proxy)
        convs = sess.refresh_conversations()      # 顺便证明 cookie 可用
        if not convs:
            raise ValueError('cookie 无效或该账号暂无任何会话（无法验证）')
        # conversation_id = '0:1:<uid>:<peer>'，取自己的 uid
        uid = convs[0]['conv_id'].split(':')[2]
        acct = Account(platform='douyin',
                       name=(fields.get('name') or uid),
                       uid=uid, username='', nickname='')
        return sess, acct

    # ------------------------------------------------------ 会话持久化

    def session_dump(self, sess):
        return {'cookie': sess.cookie, 'uid': sess.uid}

    def session_load(self, d):
        sess = dyconnect.DySession(d.get('cookie') or '', proxy=self._proxy,
                                   uid=d.get('uid') or '')
        sess.refresh_conversations()
        return sess

    def session_status(self, sess):
        try:
            sess.refresh_conversations()
            return 'ok'
        except Exception:
            return 'error'

    # -------------------------------------------------------------- 读

    def conversations(self, sess):
        convs = sess.refresh_conversations()
        out = []
        for c in convs:
            my_uid = sess.uid
            parts = c['conv_id'].split(':')
            peer = parts[3] if len(parts) > 3 else ''
            out.append(Conversation(platform='douyin', account='',
                                    conv_id=c['conv_id'],
                                    peer_uid=peer,
                                    last_ms=0))
        return out

    # -------------------------------------------------------------- 写

    def send(self, sess, conv_id, text):
        out = sess.send(conv_id, text)
        out.setdefault('ok', True)
        return out
