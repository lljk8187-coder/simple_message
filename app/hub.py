"""统一编排层：账号生命周期、逐平台会话登记、同步循环、统一读写分发。

继承 sync.Hub（TikTok 轮询与 SSE 总线的全部机制原样保留），在其上补齐
四平台：会话登记表、启动恢复、逐平台同步循环、以及面向路由层的统一
读写入口。server.py 只做路由；"跨平台怎么干"的知识全部住在这里。
"""
import json
import threading
import time
import uuid

from .sync import Hub as _SyncHub
from .platform import registry
from .platform.base import NeedCode
from .dispatch import Dispatcher


class Hub(_SyncHub):
    def __init__(self, store, client, config):
        super().__init__(store, client, config)
        registry.load_adapters()       # 登记全部适配器（缺失的可选平台自动跳过）
        self.x_sessions = {}        # name -> xconnect.XSession
        self.ig_sessions = {}       # name -> igconnect.IGSession
        self.fb_sessions = {}       # name -> fbconnect.FBSession
        self.dy_sessions = {}       # name -> dyconnect.DySession
        self.pending = {}           # token -> {'platform','state','username'}
        self.dispatch = Dispatcher(store, self, config)   # 代发队列（阶段 2）
        from .canary import Canary
        self.canary = Canary()    # 协议金丝雀：统一出口采样（09-30 设计案）

    # ------------------------------------------------------------ 金丝雀

    def _guarded(self, name, fn):
        """统一出口采样：成功记 ok，失败四分类记录后原样上抛（金丝雀 V1）。"""
        try:
            r = fn()
        except Exception as e:
            self.canary.record_err(name, e)
            raise
        self.canary.record_ok(name)
        return r

    def canary_snapshot(self):
        return self.canary.snapshot()

    # ------------------------------------------------------------ 适配器

    def adapter(self, platform):
        """取平台适配器实例（config 注入代理等运行环境）。"""
        return registry.get(platform)(self.config)

    def _platform(self, name):
        row = self.store.get_account(name) or {}
        return row.get('platform') or 'tiktok'

    def session(self, name):
        """任意平台的会话对象；未加载抛 KeyError。"""
        if name in self.sessions:
            return self.sessions[name]
        for reg in (self.x_sessions, self.ig_sessions, self.fb_sessions,
                    self.dy_sessions):
            if name in reg:
                return reg[name]
        raise KeyError('account %r is not loaded' % name)

    def loaded(self, name):
        try:
            self.session(name)
            return True
        except KeyError:
            return False

    def write_tier(self, name):
        """信任分标签：TikTok 看签名档位；其它平台用平台标识。"""
        plat = self._platform(name)
        if plat != 'tiktok':
            return {'x': 'X', 'instagram': 'IG', 'facebook': 'FB'}.get(plat)
        sess = self.sessions.get(name)
        if not sess:
            return None
        from . import client as api
        _guard, tier = api.ticket_guard_headers(sess, '/v1/message/send')
        return tier

    # ------------------------------------------------------------ 代发队列

    def platform_of(self, name):
        """账号属于哪个平台（未知账号按历史行为默认 tiktok）。"""
        return self._platform(name)

    def resolve_peer(self, platform, account, conv_id):
        """把会话解析成"对端是谁"，用于跨账号判重与黑名单；取不到返回 ''。

        TikTok: conv_id = `0:1:<我>:<对方>` → 直接拆（peer_of）；
        X:      conv_id 本身就是对端 uid；
        其它:   conv_id 是 thread id，对端只在会话行里 → 查库补。
        """
        conv_id = str(conv_id or '')
        if not conv_id:
            return ''
        if platform == 'tiktok':
            try:
                from . import client as api
                return str(api.peer_of(conv_id, self.session(account).uid) or '')
            except Exception:
                return ''
        if platform == 'x':
            return conv_id
        try:
            for c in self.store.list_conversations(account):
                if c['conv_id'] == conv_id:
                    return str(c.get('peer_uid') or '')
        except Exception:
            pass
        return ''

    def create_campaign(self, text, targets, **kw):
        """建代发任务（入队即冻结配置）。返回 {'campaign_id','queued','deduped'}。"""
        return self.dispatch.create_campaign(text, targets, **kw)

    def campaigns(self, limit=50):
        """任务列表（带逐状态进度），交给路由层直接序列化。"""
        out = []
        for c in self.store.list_campaigns(limit):
            c = dict(c)
            c['progress'] = self.store.campaign_progress(c['campaign_id'])
            out.append(c)
        return out

    def campaign_action(self, campaign_id, action, actor='local'):
        """暂停 / 继续 / 取消。只允许合法迁移，每个动作都写审计。"""
        camp = self.store.get_campaign(campaign_id)
        if not camp:
            raise KeyError('unknown campaign: %s' % campaign_id)
        status = camp.get('status') or ''
        a = (action or '').strip().lower()
        if a == 'pause':
            if status not in ('queued', 'running'):
                raise ValueError('cannot pause a %s campaign' % status)
            self.store.set_campaign_status(campaign_id, 'paused')
        elif a == 'resume':
            if status != 'paused':
                raise ValueError('campaign is not paused')
            self.store.set_campaign_status(campaign_id, 'running')
        elif a == 'cancel':
            if status in ('done', 'cancelled'):
                raise ValueError('campaign is already %s' % status)
            self.store.set_campaign_status(campaign_id, 'cancelled',
                                           finished_ms=int(time.time() * 1000))
            n = self.store.cancel_pending_items(campaign_id)
            self.store.audit(actor, 'campaign.cancel', campaign_id,
                             {'cancelled_items': n})
            return self.store.get_campaign(campaign_id)
        else:
            raise ValueError('unknown action: %s' % action)
        self.store.audit(actor, 'campaign.%s' % a, campaign_id, None)
        return self.store.get_campaign(campaign_id)

    def audit_log(self, limit=100, target=None, action=None):
        """审计查询（append-only 表的唯一读口）。"""
        return self.store.list_audit(limit=limit, target=target, action=action)

    # ---------------------------------------------------- 添加账号（统一入口）

    def add_account(self, platform, fields):
        """统一添加入口。返回结果 dict；IG 需要验证码时返回
        {'need_code': True, 'pending_id': token}，凭 token 走 submit_code。"""
        if platform == 'tiktok':
            return self._add_tiktok(fields)
        if platform == 'x':
            return self._add_x(fields)
        if platform == 'instagram':
            return self._add_instagram(fields)
        if platform == 'facebook':
            return self._add_facebook(fields)
        if platform == 'douyin':
            return self._add_douyin(fields)
        raise KeyError('unknown platform %r' % platform)

    def _add_tiktok(self, fields):
        from . import client as api
        cookie = (fields.get('cookie') or '').strip()
        if not cookie:
            raise ValueError('cookie 不能为空')
        cookie = ' '.join(cookie.split())
        private_key = None
        key_text = (fields.get('private_key') or '').strip()
        if key_text:
            private_key = api.signing.parse_private_key(key_text)
        info = api.verify_cookie(self.client, cookie)
        name = (fields.get('name') or '').strip() or info['username'] or info['uid']
        guard = fields.get('guard') or {}
        if isinstance(guard, str):
            try:
                guard = json.loads(guard) if guard else {}
            except Exception:
                guard = {}
        sess = api.Session(
            cookie=cookie,
            device_id=(fields.get('device_id') or self.config['default_device_id']),
            uid=info['uid'], username=info['username'], nickname=info['nickname'],
            region=info.get('region', ''),
            guard=guard, ticket=(fields.get('ticket') or ''),
            private_key=private_key, ts_sign=(fields.get('ts_sign') or ''))
        self.store.save_account(name, sess, info)
        self.attach(name, sess)
        try:
            self.sync_conversations(name)
        except Exception as e:
            self._set_status(name, 'warn', 'initial sync failed: %s' % e)
        _guard, tier = api.ticket_guard_headers(sess, '/v1/message/send')
        return {'ok': True, 'name': name, 'uid': info['uid'],
                'username': info['username'], 'platform': 'tiktok',
                'write_tier': tier, 'writable': tier is not None}

    def _add_x(self, fields):
        ad = self.adapter('x')
        sess, acct = ad.add_account(fields)          # 含 verify，cookie 无效即抛
        name = acct.name
        self.store.save_x_account(name, acct.uid, acct.username,
                                  acct.nickname, ad.session_dump(sess)['cookie'])
        self.x_sessions[name] = sess
        self.start_x_sync(name, sess)
        return {'ok': True, 'name': name, 'uid': acct.uid,
                'username': acct.username, 'platform': 'x'}

    def _add_instagram(self, fields):
        ad = self.adapter('instagram')
        try:
            sess, acct = ad.add_account(fields)
        except NeedCode as e:
            token = uuid.uuid4().hex
            self.pending[token] = {'platform': 'instagram', 'state': e.state,
                                   'username': fields.get('username') or ''}
            return {'need_code': True, 'pending_id': token,
                    'username': fields.get('username') or '',
                    'detail': '验证码已发送，请在页面输入'}
        name = acct.name
        self.store.save_ig_account(name, acct.uid, acct.username, acct.nickname,
                                   json.dumps(ad.session_dump(sess)))
        self.ig_sessions[name] = sess
        self.start_x_sync(name, sess, interval=20)
        return {'ok': True, 'name': name, 'uid': acct.uid,
                'username': acct.username, 'platform': 'instagram'}

    def submit_code(self, pending_id, code):
        """两段式登录第二段：凭 pending_id 提交验证码。"""
        pend = self.pending.pop(pending_id, None)
        if not pend:
            raise KeyError('no pending login for %r' % pending_id)
        ad = self.adapter(pend['platform'])
        sess, acct = ad.submit_code(pend['state'], code)
        name = acct.name
        self.store.save_ig_account(name, acct.uid, acct.username, acct.nickname,
                                   json.dumps(ad.session_dump(sess)))
        self.ig_sessions[name] = sess
        self.start_x_sync(name, sess, interval=20)
        return {'ok': True, 'name': name, 'uid': acct.uid,
                'username': acct.username, 'platform': pend['platform']}

    def pending_state(self, pending_id):
        pend = self.pending.get(pending_id)
        if not pend:
            raise KeyError('no pending login for %r' % pending_id)
        st = pend['state'].state() if hasattr(pend['state'], 'state') else {}
        st['platform'] = pend['platform']
        return st

    def _add_facebook(self, fields):
        ad = self.adapter('facebook')
        sess, acct = ad.add_account(fields)
        name = acct.name
        self.store.save_platform_account(name, acct.uid, acct.username,
                                         acct.nickname, ad.session_dump(sess)['cookie'],
                                         'facebook')
        self.fb_sessions[name] = sess
        self.start_fb_sync(name, sess)
        threading.Thread(target=self._fb_bridge, args=(name, sess),
                         daemon=True).start()
        return {'ok': True, 'name': name, 'uid': acct.uid, 'platform': 'facebook',
                'note': 'E2EE 桥后台启动中；桥连上后 1:1 收发即 live'}

    def _fb_bridge(self, name, sess):
        try:
            out = sess.start_e2ee()
            print('fb e2ee %s: %s' % (name, out))
        except Exception as e:
            print('fb e2ee %s failed: %s' % (name, e))

    def _add_douyin(self, fields):
        ad = self.adapter('douyin')
        sess, acct = ad.add_account(fields)      # 含 verify（init→stranger→info_list），无效即抛
        name = acct.name
        self.store.save_platform_account(name, acct.uid, acct.username,
                                         acct.nickname,
                                         json.dumps(ad.session_dump(sess)), 'douyin')
        self.dy_sessions[name] = sess
        self.start_dy_sync(name, sess)
        self._start_dy_realtime(name, sess)
        return {'ok': True, 'name': name, 'uid': acct.uid, 'platform': 'douyin',
                'conversations': len(sess._conv_cache),
                'note': 'init 完成，发送立即可用（就绪窗已证伪移除）'}

    def _start_dy_realtime(self, name, sess):
        """gum 心跳实时收信：新消息即时经 bus 推给前端（SSE 已有通路）。

        未知会话（新对端）会临时入 _conv_cache 并触发 conversations 事件，
        ticket 留空——首次回复该会话前由 conversations() 的 info_list 补齐。"""
        ad = self.adapter('douyin')

        def on_messages(fresh):
            by_conv = {}
            for m in fresh:
                by_conv.setdefault(m['conv_id'], []).append(m)
            new_conv = False
            for cid, msgs in by_conv.items():
                if not any(c.get('conv_id') == cid
                           for c in (getattr(sess, '_conv_cache', None) or [])):
                    info = sess._tickets.get(cid) or {}
                    parts = cid.split(':')
                    sess._conv_cache = (sess._conv_cache or []) + [{
                        'conv_id': cid, 'conv_short_id': info.get('conv_short_id', 0),
                        'ticket': info.get('ticket', ''),
                        'peer_uid': parts[3] if len(parts) > 3 else ''}]
                    new_conv = True
                self.bus.publish({'type': 'message', 'account': name,
                                  'conv_id': cid, 'messages': msgs})
            self.bus.publish({'type': 'conversations', 'account': name})

        sess.start_realtime(on_messages)

    # ---------------------------------------------------- 启动恢复

    def rehydrate_all(self):
        """把库里所有账号按平台恢复会话；失败的平台标 down 不挡启动。"""
        from . import client as api
        for row in self.store.list_accounts():
            name = row['name']
            plat = row.get('platform') or 'tiktok'
            full = self.store.get_account(name) or {}
            if plat == 'tiktok':
                sess = api.Session.from_dict(full)
                self.attach(name, sess)
                continue
            try:
                if plat == 'x':
                    sess = self.adapter('x').session_load(
                        {'cookie': full.get('cookie') or ''})
                    self.x_sessions[name] = sess
                    self.start_x_sync(name, sess)
                elif plat == 'instagram':
                    try:
                        saved = json.loads(full.get('cookie') or '{}')
                    except Exception:
                        saved = {}

                    def _ig(name=name, saved=saved):
                        try:
                            sess = self.adapter('instagram').session_load(saved)
                            sess.ensure_login()
                            sess._ensured = True
                            self.ig_sessions[name] = sess
                            self.start_x_sync(name, sess, interval=20)
                            print('ig session %s restored' % name)
                        except Exception as e:
                            print('ig session %s failed: %s' % (name, e))

                    threading.Thread(target=_ig, daemon=True).start()
                    continue
                elif plat == 'facebook':
                    sess = self.adapter('facebook').session_load(
                        {'cookie': full.get('cookie') or ''})
                    self.fb_sessions[name] = sess
                    self.start_fb_sync(name, sess)
                    threading.Thread(target=self._fb_bridge, args=(name, sess),
                                     daemon=True).start()
                elif plat == 'douyin':
                    try:
                        saved = json.loads(full.get('cookie') or '{}')
                    except Exception:
                        saved = {}
                    sess = self.adapter('douyin').session_load(saved)
                    self.dy_sessions[name] = sess
                    self.start_dy_sync(name, sess)
                    self._start_dy_realtime(name, sess)
                else:
                    continue
            except Exception as e:
                print('%s session %s failed: %s' % (plat, name, e))

    # ---------------------------------------------------- 逐平台同步循环

    def start_x_sync(self, name, sess, interval=10):
        """X 会话轮询：会话列表 delta + 逐会话新消息，推 SSE（与 TikTok 同形）。

        首轮只建基线不推事件（避免启动刷屏）。同步搬自旧 server.py，行为不变。
        """
        def loop():
            last = {}
            seeded = False
            while True:
                try:
                    convs = sess.conversations()
                    incoming = []
                    changed = False
                    for c in convs:
                        cid = c['conv_id']
                        ms = c.get('last_ms') or 0
                        prev = last.get(cid)
                        if prev is not None and ms > prev and not c.get('last_from_me'):
                            incoming.append((cid, prev))
                        if prev is None or ms != prev:
                            changed = True
                        last[cid] = ms
                    if seeded and changed:
                        self.bus.publish({'type': 'conversations', 'account': name})
                    for cid, prev_ms in incoming:
                        try:
                            rows, _cursor = sess.history(cid)
                            fresh = [m for m in rows if m['ms'] > prev_ms]
                            if fresh:
                                self.bus.publish({'type': 'message', 'account': name,
                                                  'conv_id': cid, 'messages': fresh})
                        except Exception:
                            pass
                    seeded = True
                except Exception:
                    pass
                import time as _time
                _time.sleep(interval)

        threading.Thread(target=loop, name='x-sync-%s' % name, daemon=True).start()

    def start_dy_sync(self, name, sess, interval=180):
        """抖音同步：会话面 delta + incoming 消息播报。适配器内置 180s 节流
        （stranger 端点限频 ≈1 次/2-3 分钟），周期取同值=每周期最多一次网络刷新。
        消息内容来自 init 缓存（适配器低频重新 init 刷新，INIT_REFRESH_S=15min）。"""
        import time as _time

        def loop():
            last = {}
            seeded = False
            while True:
                try:
                    convs = self.conversations(name)
                    changed = False
                    incoming = []
                    for c in convs:
                        cid = c['conv_id']
                        ms = c.get('last_ms') or 0
                        prev = last.get(cid)
                        if prev is not None and ms > prev and not c.get('last_from_me'):
                            incoming.append((cid, prev))
                        if prev is None or ms != prev:
                            changed = True
                        last[cid] = ms
                    if seeded and changed:
                        self.bus.publish({'type': 'conversations', 'account': name})
                    for cid, prev_ms in incoming:
                        try:
                            rows, _cursor, _conv = self.messages(name, cid, limit=50)
                            fresh = [m for m in rows if m['ms'] > prev_ms]
                            if fresh:
                                self.bus.publish({'type': 'message', 'account': name,
                                                  'conv_id': cid, 'messages': fresh})
                        except Exception:
                            pass
                    seeded = True
                except Exception:
                    pass
                _time.sleep(interval)

        threading.Thread(target=loop, name='dy-sync-%s' % name, daemon=True).start()

    def start_fb_sync(self, name, sess, interval=12):
        """FB 同步：会话列表 delta + E2EE 桥事件泵（行为同旧 server.py）。"""
        import time as _time

        def loop():
            last = {}
            seeded = False
            while True:
                try:
                    convs = sess.conversations()
                    changed = False
                    for c in convs:
                        ms = c.get('last_ms') or 0
                        prev = last.get(c['conv_id'])
                        if prev is None or ms != prev:
                            changed = True
                        last[c['conv_id']] = ms
                    if seeded and changed:
                        self.bus.publish({'type': 'conversations', 'account': name})
                    seeded = True
                except Exception:
                    pass
                try:
                    for ev in sess.drain_events():
                        data = ev.get('data') or {}
                        tid = str(data.get('threadId') or '')
                        if not tid:
                            continue
                        ms = int(data.get('timestampMs') or 0)
                        sender = str(data.get('senderId') or '')
                        row = {'platform': 'facebook',
                               'msg_id': str(data.get('id') or ''),
                               'conv_id': tid, 'sender': sender,
                               'outgoing': 1 if sender == sess.me_id else 0,
                               'text': data.get('text') or '',
                               'ms': ms, 'us': ms * 1000}
                        sess._remember(row)
                        if row['outgoing']:
                            continue
                        self.bus.publish({'type': 'message', 'account': name,
                                          'conv_id': tid, 'messages': [row]})
                except Exception:
                    pass
                _time.sleep(interval)

        threading.Thread(target=loop, name='fb-sync-%s' % name, daemon=True).start()

    # ---------------------------------------------------- 统一读写分发

    def conversations(self, name):
        """会话列表：TikTok 走库存（含资料合并），其它平台适配器现取。"""
        plat = self._platform(name)
        if plat == 'tiktok':
            return self._guarded(name, lambda: self._tiktok_conversations(name))
        return self._guarded(name, lambda: self._conv_other(plat, name))

    def _tiktok_conversations(self, name):
        self.sync_conversations(name)
        return self.store.list_conversations(name)

    def _conv_other(self, plat, name):
        ad = self.adapter(plat)
        sess = self.session(name)
        rows = [c.to_dict() for c in ad.conversations(sess)]
        for r in rows:
            r['account'] = name
        return rows

    def messages(self, name, conv_id, before_us=None, limit=30):
        """消息页。返回 (messages, next_cursor, conversation_row)。"""
        plat = self._platform(name)
        conv = next((c for c in self.store.list_conversations(name)
                     if c['conv_id'] == conv_id), None) if plat == 'tiktok' else None
        if plat != 'tiktok':
            return self._guarded(name, lambda: self._msgs_other(
                plat, name, conv_id, before_us, limit))

        if not conv:
            raise KeyError('unknown conversation')
        if before_us is None:
            self.ensure_history(name, conv_id, conv['short_id'])
        stored = self.store.list_messages(name, conv_id, limit=limit,
                                          before_us=before_us)
        cursor = None
        if len(stored) < limit:
            oldest = min((m['us'] for m in stored), default=before_us or None)
            fetched, cursor = self.fetch_more(name, conv_id, conv['short_id'],
                                              before_us=oldest, limit=limit)
            self.store.save_messages(name, fetched)
            stored = self.store.list_messages(name, conv_id, limit=limit,
                                              before_us=before_us)
        # TikTok 私有媒体代理需要账号会话 cookie：附件的 /api/img URL 补 acct
        for m in stored:
            for a in (m.get('attachments') or []):
                u = a.get('url') or ''
                if u.startswith('/api/img') and 'acct=' not in u:
                    a['url'] = u + '&acct=' + name
        return stored, cursor, conv

    def _msgs_other(self, plat, name, conv_id, before_us, limit):
        ad = self.adapter(plat)
        sess = self.session(name)
        before_ms = (before_us // 1000) if before_us else None
        rows = [m.to_dict() for m in
                ad.messages(sess, conv_id, before_ms=before_ms, limit=limit)]
        for r in rows:
            r['account'] = name
        # 翻页信号：返回本页最旧一条的 us 作为 next_cursor（前端回传
        # before_us 驱动下一页；适配器内部维护平台原生游标）
        cursor = None
        if len(rows) >= limit:
            cursor = min(int(r['ms']) for r in rows) * 1000
        return rows, cursor, None

    def send(self, name, conv_id, text, audit=True, attachments=None):
        """统一发送入口。audit=False 供代发队列使用（它自己写 dispatch.* 审计，
        否则一次群发会留下两份记录）。attachments 非空且适配器申报
        CAP_SEND_MEDIA 时走 send_media（10-10 契约扩展）。"""
        plat = self._platform(name)
        if attachments and plat != 'tiktok':
            from .platform.base import CAP_SEND_MEDIA
            ad = self.adapter(plat)
            if CAP_SEND_MEDIA not in ad.capabilities:
                return {'ok': False, 'error': '%s 不支持媒体发送' % plat}
            sess = self.session(name)
            res = self._guarded(name, lambda: ad.send_media(sess, conv_id, attachments, text=text))
            if audit:
                self._audit_send(name, conv_id, text or '[媒体]',
                                 res if isinstance(res, dict) else {'ok': bool(res)})
            return res
        if plat == 'tiktok':
            sess = self.sessions[name]
            conv = next((c for c in self.store.list_conversations(name)
                         if c['conv_id'] == conv_id), None)
            if not conv or not conv['short_id']:
                return {'ok': False, 'error': 'unknown conversation (no short_id)'}
            from . import client as api
            result = self._guarded(name, lambda: api.send_message(
                self.client, sess, conv_id, conv['short_id'], text))
            if result.get('ok'):
                self.nudge(name, conv_id)
            if audit:
                self._audit_send(name, conv_id, text, result)
            return result
        ad = self.adapter(plat)
        sess = self.session(name)
        res = self._guarded(name, lambda: ad.send(sess, conv_id, text))
        if audit:
            self._audit_send(name, conv_id, text,
                             res if isinstance(res, dict) else {'ok': bool(res)})
        return res

    # ------------------------------------------------------- 冷建联（纯协议）

    def resolve_target_uid(self, name, target):
        """把"对象"统一成 uid：纯数字直接认，@username / username 走主页 SSR。

        返回 (uid, error)。不抛异常——队列需要把失败原因写进审计而不是炸掉 worker。
        """
        t = str(target or '').strip()
        if not t:
            return '', 'target is empty'
        if t.isdigit():
            return t, ''
        try:
            from . import client as api
            prof = api.profile_by_username(self.client, self.session(name), t)
            return prof['uid'], ''
        except Exception as e:
            return '', '%s: %s' % (type(e).__name__, str(e)[:120])

    def _render_cold_text(self, name, target, uid, text):
        """填 {nickname}/{unique_id}/{uid}。只在文案里真的出现 {} 时才查资料，
        避免给每条冷发都多打一次请求。"""
        if '{' not in (text or ''):
            return text
        prof = {}
        try:
            from . import client as api
            if str(target or '').isdigit():
                prof = (api.user_profiles(self.client, self.session(name), [uid])
                        or {}).get(str(uid)) or {}
            else:
                prof = api.profile_by_username(self.client, self.session(name), target)
        except Exception:
            prof = {}
        out = text
        for k, v in (('{nickname}', prof.get('nickname') or ''),
                     ('{unique_id}', prof.get('unique_id') or ''),
                     ('{uid}', str(uid or ''))):
            out = out.replace(k, str(v))
        return out

    def send_cold(self, name, target, text, audit=True):
        """冷建联发送：对象可以是 uid 或 @username，无需事先存在会话。

        与 send() 的区别：send() 只对"已存在的会话"发（要求库里有 short_id），
        冷目标两样都没有。这里走 cmd 609 建会话 + WS 通道，并把新会话落库，
        这样会话列表/历史/后续聊天立刻就接得上。
        """
        plat = self._platform(name)
        if plat != 'tiktok':
            return {'ok': False, 'stage': 'unsupported',
                    'error': '冷建联目前仅支持 TikTok（%s 未实现）' % plat}
        uid, err = self.resolve_target_uid(name, target)
        if not uid:
            res = {'ok': False, 'stage': 'profile', 'error': err, 'target': target}
            if audit:
                self._audit_cold(name, target, text, res)
            return res
        ad = self.adapter(plat)
        sess = self.session(name)
        text = self._render_cold_text(name, target, uid, text)
        try:
            res = self._guarded(name, lambda: ad.send_to_peer(
                sess, uid, text, cli=self.client))
        except Exception as e:
            res = {'ok': False, 'stage': 'send',
                   'error': '%s: %s' % (type(e).__name__, str(e)[:120])}
        res.setdefault('target', target)
        res['uid'] = uid
        conv_id = res.get('conv_id')
        if conv_id:
            # 落库：新会话立刻出现在列表里，short_id 也就此缓存下来
            try:
                self.store.save_conversations(name, [{
                    'conv_id': conv_id, 'short_id': str(res.get('short_id') or ''),
                    'peer_uid': uid, 'updated_ms': int(time.time() * 1000),
                    'unread': 0}])
            except Exception:
                pass
        if audit:
            self._audit_cold(name, target, text, res)
        return res

    def _audit_cold(self, name, target, text, res):
        try:
            self.store.audit('local' if res.get('ok') else 'system', 'message.cold',
                             res.get('conv_id') or str(target),
                             {'account': name, 'target': str(target),
                              'uid': res.get('uid'), 'ok': bool(res.get('ok')),
                              'stage': res.get('stage'),
                              'skipped': res.get('skipped'),
                              'landed': res.get('landed'),
                              'tier': res.get('tier'),
                              'msg_id': res.get('msg_id'),
                              'error': res.get('error'),
                              'text': (text or '')[:120]})
        except Exception:
            pass                      # 审计不能反过来把发送搞挂

    def _audit_send(self, name, conv_id, text, result):
        """手工单发的留痕（谁、何时、给谁、发了什么、结果）。"""
        try:
            self.store.audit('local', 'message.send', conv_id,
                             {'account': name, 'ok': bool(result.get('ok')),
                              'tier': result.get('tier'),
                              'guard_result': result.get('guard_result'),
                              'error': result.get('error') or result.get('biz_msg'),
                              'text': (text or '')[:120]})
        except Exception:
            pass                      # 审计不能反过来把发送搞挂

    def mark_read(self, name, conv_id):
        """已读回执：X 暂无；TikTok 用最新消息 us；IG/FB 按会话标已读。"""
        plat = self._platform(name)
        if plat == 'x':
            return {'ok': False, 'skipped': 'X read receipts not supported yet'}
        ad = self.adapter(plat)
        sess = self.session(name)
        if plat == 'tiktok':
            latest = self.store.latest_message(name, conv_id)
            if not latest:
                return {'ok': False, 'skipped': 'no messages to mark'}
            conv = next((c for c in self.store.list_conversations(name)
                         if c['conv_id'] == conv_id), None)
            if not conv or not conv['short_id']:
                return {'ok': False, 'skipped': 'unknown conversation'}
            from . import client as api
            return api.mark_read(self.client, sess, conv_id, conv['short_id'],
                                 latest['us'])
        return ad.mark_read(sess, conv_id, 0)

    # ------------------------------------------------------------ 删除账号

    def drop(self, name):
        plat = self._platform(name)
        if plat == 'x':
            sess = self.x_sessions.pop(name, None)
            if sess:
                sess.close()
        elif plat == 'facebook':
            sess = self.fb_sessions.pop(name, None)
            if sess:
                sess.close()
        elif plat == 'instagram':
            self.ig_sessions.pop(name, None)
        elif plat == 'douyin':
            sess = self.dy_sessions.pop(name, None)
            if sess:
                sess.stop_realtime()   # 停 WS 循环：只 pop 引用不停线程，
                                       # 删除账号后会话信令继续刷（10-12 实测）
        self.detach(name)
        self.store.delete_account(name)
