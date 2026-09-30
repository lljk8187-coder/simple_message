"""代发队列 —— 把"点一次按钮、同步发完"升级成持久化任务（阶段 2 内核）。

为什么要有它：原来的 `/api/batch/send` 是在 HTTP 请求里 sleep 着逐条发，上限 50 条、
结果只回一次 —— 关掉页面就断，失败无法续跑，谁发过什么也没留痕。

现在的形态：
    任务(campaigns) 是数据 → 队列项(dispatch_items) 逐条落库 → 一个 worker 排水。
    排水时每个目标先过三道闸门，再按限速等，然后调 `hub.send()`，最后把结果和
    审计一起写下（审计只增不改）。

三条不可让步的约束（见记忆里的产品原则 **账号存活 > 送达速度 > 功能丰富**）：
  1. **单 worker 串行**，跨账号也不并发 —— "同一文案 → 多个目标"本身就是各平台
     风控的经典特征，并发只会同时抬高频率与突发度。
  2. **限速取更保守者**：任务里把间隔设得再小也没用，平台申报的 `min_interval_s`
     兜底（TikTok 8s / X 15s / IG 20s）。
  3. **崩在"发送中"的项不自动重发**（标 `unknown` 留给人工）—— 同一个人收到两条
     一样的话，比漏一条更像机器人。

平台无关：本文件没有任何平台分支；间隔值来自适配器申报的 `send_limits`。
闸门：去重在**入队时**已完成（重复项根本不进队列），黑名单与已发过滤在排水时判定。
"""
import threading
import time
import uuid

TICK_S = 1.0                                    # 空闲时的轮询间隔
ALREADY_SENT_WINDOW_MS = 7 * 24 * 3600 * 1000   # 已发过滤窗口：7 天
MAX_SLEEP_S = 3600.0                            # 单次等待上限（防呆）


def _now_ms():
    return int(time.time() * 1000)


class Dispatcher:
    """一个后台线程 + 一张队列表。可重复 start/stop（测试用）。"""

    def __init__(self, store, hub, config=None):
        self.store = store
        self.hub = hub
        self.config = config or {}
        self._stop = threading.Event()
        self._thread = None
        self._last_send = {}          # account -> 上次发送时刻(ms)
        self._batch_pos = {}          # campaign_id -> 本批已处理条数

    # ------------------------------------------------------------ 生命周期

    def start(self):
        n = self.store.recover_inflight()
        if n:
            # 崩溃留下的"发送中"：只标注，不重发（见模块头第 3 条）
            self.store.audit('system', 'dispatch.orphan', '',
                             {'count': n, 'note': 'crashed while sending — '
                                                  'not resent, verify manually'})
            print('[dispatch] %d item(s) were left "sending" by a crash -> '
                  'unknown (not resent)' % n, flush=True)
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name='dispatch',
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()

    def status(self):
        return {'running': bool(self._thread and self._thread.is_alive()),
                'tick_s': TICK_S}

    # --------------------------------------------------------------- 建任务

    def create_campaign(self, text, targets, batch_size=5, interval_s=60,
                        schedule_ms=0, actor='local'):
        """建任务并入队。返回 {'campaign_id', 'queued', 'deduped'}。

        黑名单/已发过滤**不在这里**拦——它们在排水时判定并标 `skipped`，
        这样"为什么没发"在队列和审计里都看得见，而不是悄悄消失。
        """
        text = (text or '').strip()
        if not text:
            raise ValueError('text is required')
        if not targets:
            raise ValueError('targets are required')

        items = []
        for t in targets:
            if not isinstance(t, dict):
                continue
            account = (t.get('account') or '').strip()
            conv_id = (t.get('conv_id') or '').strip()
            if not account or not conv_id:
                continue
            platform = self.hub.platform_of(account)
            items.append({'platform': platform, 'account': account,
                          'conv_id': conv_id,
                          'peer_uid': self.hub.resolve_peer(platform, account,
                                                            conv_id)})
        if not items:
            raise ValueError('targets are required')

        campaign_id = uuid.uuid4().hex[:12]
        self.store.create_campaign(campaign_id, text, created_by=actor,
                                   schedule_ms=schedule_ms,
                                   batch_size=max(1, int(batch_size or 1)),
                                   interval_s=max(0, int(interval_s or 0)))
        res = self.store.enqueue_items(campaign_id, items)
        self.store.audit(actor, 'campaign.create', campaign_id,
                         {'text': text[:120], 'queued': res['queued'],
                          'deduped': res['deduped'], 'total_targets': len(items),
                          'batch_size': batch_size, 'interval_s': interval_s,
                          'schedule_ms': schedule_ms})
        out = dict(res)
        out['campaign_id'] = campaign_id
        return out

    # ---------------------------------------------------------------- worker

    def _loop(self):
        while not self._stop.is_set():
            worked = False
            try:
                worked = self._step()
            except Exception as e:
                # worker 不能因为一次异常就死掉：记日志、喘口气、继续
                print('[dispatch] %s: %s' % (type(e).__name__, e), flush=True)
            if not worked:
                self._stop.wait(TICK_S)

    def _step(self):
        """做一件小事。返回 True = 刚有进展（不必等 tick）。"""
        camp = self.store.next_active_campaign(_now_ms())
        if not camp:
            return False
        cid = camp['campaign_id']

        if camp.get('status') == 'queued':          # 首次被调度到 → 配置自此冻结
            self.store.set_campaign_status(cid, 'running', started_ms=_now_ms())
            self.store.audit('system', 'campaign.start', cid,
                             {'batch_size': camp.get('batch_size'),
                              'interval_s': camp.get('interval_s')})

        item = self.store.next_pending_item(cid)
        if not item:
            prog = self.store.campaign_progress(cid)    # 全部终态 → 收尾
            self.store.set_campaign_status(cid, 'done', finished_ms=_now_ms())
            self.store.audit('system', 'campaign.done', cid, prog)
            return True

        reason = self._gate(camp, item)
        if reason:
            self.store.mark_item(cid, item['seq'], 'skipped', skip_reason=reason)
            self.store.audit('system', 'dispatch.skipped', item['conv_id'],
                             {'campaign_id': cid, 'seq': item['seq'],
                              'account': item['account'], 'reason': reason})
            return True

        self._pace(camp, item)
        self.store.mark_item(cid, item['seq'], 'sending', bump_attempts=True)
        try:
            # audit=False：队列自己写 dispatch.* 审计，避免一次群发留两份记录
            res = self.hub.send(item['account'], item['conv_id'], camp['text'],
                                audit=False)
            if not isinstance(res, dict):
                res = {'ok': bool(res)}
        except Exception as e:
            res = {'ok': False, 'error': '%s: %s' % (type(e).__name__, e)}

        if res.get('ok'):
            guard = res.get('guard_result')
            self.store.mark_item(cid, item['seq'], 'sent', sent_ms=_now_ms(),
                                 guard_result=None if guard is None else str(guard))
            self.store.audit('system', 'dispatch.sent', item['conv_id'],
                             {'campaign_id': cid, 'seq': item['seq'],
                              'account': item['account'], 'tier': res.get('tier'),
                              'guard_result': guard})
        else:
            err = (res.get('error') or res.get('biz_msg')
                   or res.get('biz_code') or 'send failed')
            self.store.mark_item(cid, item['seq'], 'failed', error=str(err))
            self.store.audit('system', 'dispatch.failed', item['conv_id'],
                             {'campaign_id': cid, 'seq': item['seq'],
                              'account': item['account'], 'error': str(err)[:200]})

        self._last_send[item['account']] = _now_ms()
        self._batch_pos[cid] = self._batch_pos.get(cid, 0) + 1
        return True

    # ---------------------------------------------------------------- 闸门

    def _gate(self, camp, item):
        """排水时的两道闸门（去重已在入队时完成）。返回原因或 None。"""
        platform = item['platform']
        account = item['account']
        peer_uid = item.get('peer_uid') or ''
        if self.store.is_blocked(platform, account, peer_uid):
            return 'blocked'
        if self.store.sent_recently(platform, account, peer_uid,
                                    camp['text'], ALREADY_SENT_WINDOW_MS):
            return 'already-sent'
        return None

    # ---------------------------------------------------------------- 限速

    def _pace(self, camp, item):
        """两道节奏：批间隔（每 batch_size 条）+ 平台申报的单条最小间隔。"""
        pos = self._batch_pos.get(camp['campaign_id'], 0)
        size = int(camp.get('batch_size') or 0)
        if pos and size and pos % size == 0:
            self._sleep(int(camp.get('interval_s') or 0))

        declared = 0
        try:
            limits = self.hub.adapter(item['platform']).send_limits or {}
            declared = int(limits.get('min_interval_s') or 0)
        except Exception:
            declared = 0
        last = self._last_send.get(item['account'])
        if last and declared:
            self._sleep(declared - (_now_ms() - last) / 1000.0)

    def _sleep(self, seconds):
        """可被打断的等待（停止服务时立刻退出，不留长睡线程）。"""
        if seconds and seconds > 0:
            self._stop.wait(min(float(seconds), MAX_SLEEP_S))
