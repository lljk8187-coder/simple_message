"""抖音适配器 —— 包装 app/dyconnect.py（桌面客户端同款纯 HTTPS 协议）。

登录：'cookies'（从已登录的桌面客户端/浏览器导出，须含 sessionid 等
.douyin.com 域登录 cookie）。移动端登录风控对模拟器极严（实测短信通道
直接禁发），桌面端扫码是获取登录态最省力的入口。

发送：凭据来自一次"登录收割"产出的 send_blob JSON（setup_send_credentials
的参数集：verify_fp/msToken/tg私钥+ticket+ts_sign/ree_pub/UA/dtrait）。
只有 cookie 也能入账（仅收信模式），send 时会报缺凭据的清晰错误。

平台硬约束（均为实测，详见仓库 docs 与日报 2026-10-08/09）：
- 单座位：web IM 一账号同时只有一个 init 座位，新 init 踢旧座 ⇒
  通道账号必须专用（不要同时在浏览器里登录使用同一账号）；
- 就绪窗：每次进程启动 init 后约 8 分钟内 send 被服务端拒绝 ⇒
  hub 重启后抖音发送自然延迟解禁，属预期行为；
- 陌生人列表端点 ≈1 次/2-3 分钟，超频 429 ⇒ conversations/status
  走 STRANGER_TTL_S 节流缓存；
- 陌生人会话 MGet=empty：get_info_list 只服务常规会话，陌生人详情
  仅 stranger 列表响应自带的字段。

conv_id = '0:1:<uid>:<peer>'（平台原生格式，直接用于 send 信封）。
ticket 由服务端随 get_info_list 下发（会话级滚动），发送前现取最新。
v1 能力：send + conversations；messages/poll 的增量解析下一步接入。
"""
import json
import time

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

    STRANGER_TTL_S = 180    # 实测 stranger 列表 ≈1次/2-3分钟，超频 429

    # send_blob 必需键（= setup_send_credentials 的必填参数）
    _SEND_BLOB_KEYS = ('verify_fp', 'ms_token', 'tg_private_pem',
                       'tg_ticket', 'tg_ts_sign', 'tg_ree_pub')

    # ------------------------------------------------------------ 认证

    def auth_fields(self):
        return [{'key': 'cookie',
                 'label': '抖音 cookie（.douyin.com 域，须含 sessionid）',
                 'secret': True},
                {'key': 'send_blob',
                 'label': '发送凭据 JSON（登录收割产出；不填则仅收信）',
                 'secret': True},
                {'key': 'uid',
                 'label': '数字 uid（可选；conv_id 第三段或 IndexedDB 库名前缀）'},
                {'key': 'known_convs',
                 'label': '已知会话种子 JSON（MGet 接入前桥接；[[conv_id,short_id],...]）'}]

    def _setup_send(self, sess, blob, strict=False):
        """装配发送凭据。strict=True（用户手填）缺字段直接报错；
        strict=False（session_load 恢复）缺字段静默降级为仅收信。"""
        if not blob:
            return
        missing = [k for k in self._SEND_BLOB_KEYS if not blob.get(k)]
        if missing:
            if strict:
                raise ValueError('send_blob 缺少字段: %s' % ', '.join(missing))
            return
        sess.setup_send_credentials(
            verify_fp=blob['verify_fp'], ms_token=blob['ms_token'],
            tg_private_pem=blob['tg_private_pem'], tg_ticket=blob['tg_ticket'],
            tg_ts_sign=blob['tg_ts_sign'], tg_ree_pub=blob['tg_ree_pub'],
            user_agent=blob.get('user_agent') or None,
            session_dtrait=blob.get('session_dtrait') or '')
        # 原样留存私钥 PEM：session_dump 回存需要（dyconnect 只留派生钥）
        sess._tg_private_pem = blob['tg_private_pem']

    def add_account(self, fields):
        cookie = (fields.get('cookie') or '').strip()
        if not cookie:
            raise ValueError('cookie 不能为空')
        if 'sessionid' not in cookie:
            raise ValueError('cookie 里没有 sessionid——请从已登录客户端完整复制')
        blob = {}
        raw = (fields.get('send_blob') or '').strip()
        if raw:
            try:
                blob = json.loads(raw)
            except ValueError:
                raise ValueError('send_blob 不是合法 JSON')
            if not isinstance(blob, dict):
                raise ValueError('send_blob 必须是 JSON 对象')
        sess = dyconnect.DySession(cookie, proxy=self._proxy)
        self._setup_send(sess, blob, strict=True)
        # init 成功即证明 cookie 可用。stranger 列表允许为空——常规会话不在
        # stranger 面（MGet 端点尚未接入，v1 靠 known_convs 种子桥接）
        sess.refresh_conversations()
        pairs = []
        for c in (fields.get('known_convs') or []):
            try:
                pairs.append((c[0], int(c[1])))
            except (TypeError, ValueError, IndexError):
                raise ValueError('known_convs 项须为 [conv_id, short_id] 二元组')
        if pairs:
            sess.refresh_conversation_info(pairs)
        sess._known_convs = pairs          # 持久化：重启后 session_load 重新种子
        sess._conv_cache = list(sess._tickets.values())   # 种子结果并入会话面
        sess._conv_at = time.time()
        # conversation_id = '0:1:<uid>:<peer>'，取自己的 uid
        uid = (fields.get('uid') or '').strip()
        if not uid and sess._conv_cache:
            uid = sess._conv_cache[0]['conv_id'].split(':')[2]
        acct = Account(platform='douyin',
                       name=(fields.get('name') or uid),
                       uid=uid, username='', nickname='')
        return sess, acct

    # ------------------------------------------------------ 会话持久化

    def session_dump(self, sess):
        d = {'cookie': sess.cookie, 'uid': sess.uid}
        c = getattr(sess, '_send_cred', None)
        pem = getattr(sess, '_tg_private_pem', '')
        if c and pem:
            d.update({'verify_fp': c.get('verify_fp', ''),
                      'ms_token': c.get('ms_token', ''),
                      'tg_ticket': c.get('tg_ticket', ''),
                      'tg_ts_sign': c.get('tg_ts_sign', ''),
                      'ree_pub': c.get('ree_pub', ''),
                      'dtrait': c.get('dtrait', ''),
                      'ua': c.get('ua', ''),
                      'tg_private_pem': pem})
        kc = getattr(sess, '_known_convs', None)
        if kc:
            d['known_convs'] = kc
        return d

    def session_load(self, d):
        sess = dyconnect.DySession(d.get('cookie') or '', proxy=self._proxy,
                                   uid=d.get('uid') or '')
        if d.get('tg_private_pem'):
            self._setup_send(sess, {
                'verify_fp': d.get('verify_fp', ''),
                'ms_token': d.get('ms_token', ''),
                'tg_private_pem': d['tg_private_pem'],
                'tg_ticket': d.get('tg_ticket', ''),
                'tg_ts_sign': d.get('tg_ts_sign', ''),
                'tg_ree_pub': d.get('ree_pub', ''),
                'user_agent': d.get('ua') or None,
                'session_dtrait': d.get('dtrait') or ''})
        convs = sess.refresh_conversations()
        kc = []
        for c in (d.get('known_convs') or []):
            try:
                kc.append((c[0], int(c[1])))
            except (TypeError, ValueError, IndexError):
                continue
        if kc:
            sess.refresh_conversation_info(kc)
        sess._known_convs = kc
        sess._conv_cache = list(sess._tickets.values())
        sess._conv_at = time.time()
        return sess

    def session_status(self, sess):
        try:
            self._refresh_cached(sess)
            return 'ok'
        except Exception:
            return 'error'

    # -------------------------------------------------------------- 读

    def _refresh_cached(self, sess):
        """init → stranger 列表 → info_list，带 STRANGER_TTL_S 节流：
        陌生人端点超频 429，缓存期内直接信任上一次结果（存活检测延迟 ≤ TTL）。"""
        now = time.time()
        cached = getattr(sess, '_conv_cache', None)
        if cached and now - getattr(sess, '_conv_at', 0) < self.STRANGER_TTL_S:
            return cached
        convs = sess.refresh_conversations()
        sess._conv_cache = convs
        sess._conv_at = now
        return convs

    def conversations(self, sess):
        convs = self._refresh_cached(sess)
        out = []
        for c in convs:
            parts = c['conv_id'].split(':')
            peer = parts[3] if len(parts) > 3 else ''
            out.append(Conversation(platform='douyin', account='',
                                    conv_id=c['conv_id'],
                                    peer_uid=peer,
                                    last_ms=0))
        return out

    # -------------------------------------------------------------- 写

    def send(self, sess, conv_id, text):
        # ticket 会话级滚动：已知 short_id 的会话发送前现取最新
        info = sess._tickets.get(conv_id)
        if info and info.get('conv_short_id'):
            sess.refresh_conversation_info(
                [(conv_id, int(info['conv_short_id']))])
        out = sess.send(conv_id, text)
        out.setdefault('ok', True)
        return out
