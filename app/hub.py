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
        self.pending = {}           # token -> {'platform','state','username'}
        self.dispatch = Dispatcher(store, self, config)   # 代发队列（阶段 2）

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
        for reg in (self.x_sessions, self.ig_sessions, self.fb_sessions):
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
            self.sync_conversations(name)
            return self.store.list_conversations(name)
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
            ad = self.adapter(plat)
            sess = self.session(name)
            before_ms = (before_us // 1000) if before_us else None
            rows = [m.to_dict() for m in
                    ad.messages(sess, conv_id, before_ms=before_ms, limit=limit)]
            for r in rows:
                r['account'] = name
            return rows, None, None

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
        return stored, cursor, conv

    def send(self, name, conv_id, text, audit=True):
        """统一发送入口。audit=False 供代发队列使用（它自己写 dispatch.* 审计，
        否则一次群发会留下两份记录）。"""
        plat = self._platform(name)
        if plat == 'tiktok':
            sess = self.sessions[name]
            conv = next((c for c in self.store.list_conversations(name)
                         if c['conv_id'] == conv_id), None)
            if not conv or not conv['short_id']:
                return {'ok': False, 'error': 'unknown conversation (no short_id)'}
            from . import client as api
            result = api.send_message(self.client, sess, conv_id,
                                      conv['short_id'], text)
            if result.get('ok'):
                self.nudge(name, conv_id)
            if audit:
                self._audit_send(name, conv_id, text, result)
            return result
        ad = self.adapter(plat)
        sess = self.session(name)
        res = ad.send(sess, conv_id, text)
        if audit:
            self._audit_send(name, conv_id, text,
                             res if isinstance(res, dict) else {'ok': bool(res)})
        return res

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
        self.detach(name)
        self.store.delete_account(name)
