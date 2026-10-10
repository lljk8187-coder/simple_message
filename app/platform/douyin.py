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
会话面：get_message_by_init 响应即全量会话列表（含常规会话 ticket 与
最近 ≤20 条消息）——**无需 MGet 端点**（10-09 逆向定论）。
消息页：读 init 缓存（DySession.messages），低频重新 init 刷新增量
（INIT_REFRESH_S；重复 init 会重置就绪窗 ⇒ 刷新后 8 分钟内不能发，
保守语义对齐服务端）。
dtrait 头：可选——实测缺省发送成功（10-09 hub 实发验证）。
"""
import json
import time

from . import registry
from .. import dyconnect
from .base import (PlatformAdapter, Account, Conversation, Message,
                   CAP_SEND, CAP_SEND_MEDIA)


@registry.register
class DouyinAdapter(PlatformAdapter):
    platform = 'douyin'
    display_name = '抖音'
    auth_kind = 'cookies'
    capabilities = (CAP_SEND, CAP_SEND_MEDIA)   # 媒体当前支持 video_card（转发）
    # 保守申报：桌面客户端官方心跳 5s/发消息走用户手速；我们取 20s，
    # 与"账号存活 > 送达速度"原则一致（比 TikTok 的 8s 更保守，国内实名号）
    send_limits = {'min_interval_s': 20, 'daily_cap': 80}

    STRANGER_TTL_S = 180    # 实测 stranger 列表 ≈1次/2-3分钟，超频 429
    INIT_REFRESH_S = 900    # 低频重新 init：新常规会话只随 init 下发；会重置就绪窗

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
        sess.uid = uid                        # 必须回写：WS 推送 URL/access_key 绑定 uid
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
        if not (sess.uid or '').strip():
            # 兜底：存量 dump 可能缺 uid（WS 推送 URL 依赖它）——从 conv_id 派生
            for cid in sess._tickets:
                parts = cid.split(':')
                if len(parts) > 2 and parts[2].isdigit():
                    sess.uid = parts[2]
                    break
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
        陌生人端点超频 429，缓存期内直接信任上一次结果（存活检测延迟 ≤ TTL）。
        常规收信已由 gum 心跳实时接管（10-10 实时化）——init 仅在启动/
        add_account 时做一次，不再周期重跑（每次 init 重置 8 分钟就绪窗）。"""
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
        self._fill_profiles(sess)
        uid = str(sess.uid or '')
        msgs = getattr(sess, '_msgs', {})
        profiles = getattr(sess, '_profiles', {})
        sec_by_conv = getattr(sess, '_sec_by_conv', {})
        out = []
        for c in convs:
            cid = c['conv_id']
            parts = cid.split(':')
            peer = parts[3] if len(parts) > 3 else ''
            conv_msgs = msgs.get(cid) or []
            last = conv_msgs[-1] if conv_msgs else None
            prof = profiles.get(sec_by_conv.get(cid, ''), {})
            out.append(Conversation(platform='douyin', account='',
                                    conv_id=cid,
                                    peer_uid=peer,
                                    peer_nickname=prof.get('nickname', ''),
                                    peer_avatar=prof.get('avatar', ''),
                                    last_text=(last or {}).get('text', ''),
                                    last_ms=(last or {}).get('ms', 0),
                                    last_from_me=1 if last and last.get('sender_uid') == uid else 0,
                                    unread=0))
        return out

    PROFILE_TTL_S = 600      # 用户资料缓存（昵称/头像变更不敏感）

    def _fill_profiles(self, sess):
        """批量拉会话对端资料（A2）并缓存。对端 sec_uid 从该会话消息的
        sender_sec_uid 提取（init/core 不带资料；有消息即有）。"""
        now = time.time()
        profiles = getattr(sess, '_profiles', None)
        if profiles is None:
            profiles = sess._profiles = {}
        if now - getattr(sess, '_prof_at', 0) < self.PROFILE_TTL_S and profiles:
            return
        uid = str(sess.uid or '')
        sec_by_conv = {}
        for cid, lst in (getattr(sess, '_msgs', {}) or {}).items():
            for m in reversed(lst):
                if m.get('sender_uid') != uid and m.get('sender_sec_uid'):
                    sec_by_conv[cid] = m['sender_sec_uid']
                    break
        need = sorted({s for s in sec_by_conv.values() if s not in profiles})
        if need:
            try:
                profiles.update(sess.get_user_infos(need))
                sess._prof_at = now
            except Exception:
                return                      # 资料拉取失败不阻塞会话列表
        sess._sec_by_conv = sec_by_conv

    def messages(self, sess, conv_id, before_ms=None, limit=30):
        self._refresh_cached(sess)
        rows = sess.messages(conv_id, before_ms=before_ms, limit=limit)
        # 缓存不足 limit（首屏或翻到边界）→ get_history 自动补页
        # （游标链 10-10 逆向 cmd 301；_hist_done 标记会话已确认到底）
        fetches = 0
        done = getattr(sess, '_hist_done', None)
        if done is None:
            done = sess._hist_done = set()
        while len(rows) < limit and fetches < 3 and conv_id not in done:
            anchor = sess.oldest_cached_us(conv_id)
            if not anchor:
                break
            hist = getattr(sess, '_hist_cursor', None)
            if hist is None:
                hist = sess._hist_cursor = {}
            cursor = hist.get(conv_id) or anchor
            try:
                page = sess.get_history(conv_id, cursor)
            except Exception:
                break
            fetches += 1
            if not page['has_more'] or not page['cursor']:
                done.add(conv_id)
                break
            hist[conv_id] = page['cursor']
            rows = sess.messages(conv_id, before_ms=before_ms, limit=limit)
        uid = str(sess.uid or '')
        if not uid and rows:
            # conv_id = '0:1:<uid>:<peer>'，uid 缺失时从消息里补
            parts = rows[0]['conv_id'].split(':')
            uid = parts[2] if len(parts) > 2 else ''
        return [Message(platform='douyin', account='',
                        msg_id=m['msg_id'], conv_id=m['conv_id'],
                        sender=m['sender_uid'],
                        outgoing=1 if m['sender_uid'] == uid else 0,
                        text=m['text'], ms=m['ms'], status='sent',
                        kind=m['kind'],
                        attachments=tuple(m.get('attachments') or ()))
                for m in rows]

    # -------------------------------------------------------------- 写

    def send(self, sess, conv_id, text):
        # ticket 会话级滚动：已知 short_id 的会话发送前现取最新
        info = sess._tickets.get(conv_id)
        if info and info.get('conv_short_id'):
            sess.refresh_conversation_info(
                [(conv_id, int(info['conv_short_id']))])
        out = sess.send(conv_id, text)
        # 本地回显：发出的消息并进 init 缓存（服务器 msg_id 要等下次 init 校正，
        # 期间消息页不能"发完就没"）
        msgs = getattr(sess, '_msgs', None)
        if msgs is not None:
            msgs.setdefault(conv_id, []).append({
                'conv_id': conv_id,
                'msg_id': 'local-%d' % int(time.time() * 1000),
                'conv_short_id': (info or {}).get('conv_short_id', 0),
                'kind': 'text',
                'sender_uid': str(sess.uid or ''),
                'text': text,
                'ms': int(time.time() * 1000),
                'sender_sec_uid': ''})
        out.setdefault('ok', True)
        return out

    def send_media(self, sess, conv_id, attachments, text=''):
        """发带载荷的消息（CAP_SEND_MEDIA）。支持 video_card（站内转发）
        与 image（data_b64 → upload 五步链 → msg_type=27 引用加密 oid）。"""
        info = sess._tickets.get(conv_id)
        if info and info.get('conv_short_id'):
            sess.refresh_conversation_info(
                [(conv_id, int(info['conv_short_id']))])
        out = sess.send_media(conv_id, attachments, text=text)
        # 本地回显：载荷摘要进 init 缓存（服务器 msg_id 等下次 init 校正）
        msgs = getattr(sess, '_msgs', None)
        if msgs is not None:
            first = next((dict(a) for a in (attachments or [])
                          if a.get('type') in ('video_card', 'image')), None)
            if first and first.get('type') == 'image':
                first = {'type': 'image', 'title': '[图片]'}   # 二进制不进缓存
            elif first and not isinstance(first.get('content'), dict):
                first = {k: v for k, v in first.items() if k != 'content'}
            msgs.setdefault(conv_id, []).append({
                'conv_id': conv_id,
                'msg_id': 'local-%d' % int(time.time() * 1000),
                'conv_short_id': (info or {}).get('conv_short_id', 0),
                'kind': 'media',
                'sender_uid': str(sess.uid or ''),
                'text': (first or {}).get('title') or '[媒体消息]',
                'ms': int(time.time() * 1000),
                'sender_sec_uid': '',
                'attachments': ([first] if first else [])})
        out.setdefault('ok', True)
        return out
