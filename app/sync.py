"""Background sync + a tiny in-process event bus for SSE.

The site's own incremental endpoint (204) only advances a cursor and returns the
poll interval — it carries no message bodies (measured: 117 bytes on an idle
tick). So freshness comes from re-reading, at a polite cadence:

  * conversation list  : every `list_interval` seconds
  * recent conversations: every `msg_interval` seconds (the focused one first)

Reads are cheap and unsigned; nothing here writes.
"""
import json
import queue
import threading
import time
import traceback

from . import client as api


class EventBus:
    def __init__(self, maxsize=200):
        self._lock = threading.Lock()
        self._subs = []
        self._recent = []
        self._maxsize = maxsize

    def subscribe(self):
        q = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            self._subs.append(q)
            recent = list(self._recent[-20:])
        for ev in recent:
            try:
                q.put_nowait(ev)
            except queue.Full:
                break
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, event):
        with self._lock:
            self._recent.append(event)
            if len(self._recent) > self._maxsize:
                self._recent = self._recent[-self._maxsize:]
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass


class Hub:
    def __init__(self, store, client, config):
        self.store = store
        self.client = client
        self.config = config
        self.bus = EventBus()
        self.sessions = {}          # name -> api.Session
        self.focus = {}             # name -> conv_id (client-visible priority)
        self.status = {}            # name -> {'state','detail','ts'}
        self._last_list = {}        # name -> monotonic ts
        self._last_msgs = {}
        self._last_focus = {}
        self._combo_cursor = {}     # name -> µs cursor from the 204 probe
        self._probe_skips = {}      # name -> consecutive quiet probes
        self._stop = threading.Event()
        self._thread = None

    # ------------------------------------------------------------ lifecycle

    def attach(self, name, sess):
        self.sessions[name] = sess

    def detach(self, name):
        self.sessions.pop(name, None)
        self.status.pop(name, None)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name='hub-sync', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    # --------------------------------------------------------------- status

    def _set_status(self, name, state, detail=''):
        prev = self.status.get(name, {}).get('state')
        self.status[name] = {'state': state, 'detail': detail, 'ts': int(time.time() * 1000)}
        if prev != state:
            self.bus.publish({'type': 'status', 'account': name,
                              'state': state, 'detail': detail})

    # ------------------------------------------------------------ sync loop

    def _loop(self):
        while not self._stop.is_set():
            try:
                names = list(self.sessions.keys())
                for name in names:
                    if self._stop.is_set():
                        break
                    try:
                        self._sync_one(name)
                    except Exception as e:  # keep the loop alive
                        self._set_status(name, 'error', '%s: %s' % (type(e).__name__, e))
                self._sleep(2.0)
            except Exception:
                traceback.print_exc()
                self._sleep(5.0)

    def _sleep(self, seconds):
        end = time.monotonic() + seconds
        while not self._stop.is_set() and time.monotonic() < end:
            time.sleep(min(0.2, max(0.0, end - time.monotonic())))

    def _sync_one(self, name):
        sess = self.sessions.get(name)
        if not sess:
            return
        now = time.monotonic()
        cfg = self.config

        if now - self._last_list.get(name, 0) >= cfg['list_interval']:
            self._last_list[name] = now
            self.sync_conversations(name)

        # The conversation currently on screen gets a much tighter loop — that is
        # where a user actually notices latency. Everything else keeps the slow cadence.
        focused = self.focus.get(name)
        if focused and now - self._last_focus.get(name, 0) >= cfg['focus_interval']:
            self._last_focus[name] = now
            self.sync_conversation(name, focused, cfg['focus_page_size'])

        if now - self._last_msgs.get(name, 0) >= cfg['msg_interval']:
            self._last_msgs[name] = now
            # The 204 combo IS the incremental protocol: one request per tick
            # carries any newer messages plus per-conversation unread counts.
            # Full re-reads stay as a safety net (every 10th quiet tick, plus
            # whenever the probe fails).
            ok, new_cursor, interval, messages, unread = api.combo_poll(
                self.client, sess, self._combo_cursor.get(name) or
                int(time.time() * 1_000_000) - 600_000_000)
            if ok:
                self._combo_cursor[name] = new_cursor
                if unread:
                    self.store.apply_unread(name, unread)
                    self.bus.publish({'type': 'conversations', 'account': name})
                if messages:
                    self.store.save_messages(name, messages)
                    grouped = {}
                    for m in messages:
                        grouped.setdefault(m['conv_id'], []).append(m)
                    for conv_id, msgs in grouped.items():
                        self.bus.publish({'type': 'message', 'account': name,
                                          'conv_id': conv_id, 'messages': msgs})
                    self.bus.publish({'type': 'conversations', 'account': name})
                self._probe_skips[name] = 0
                return
            self._probe_skips[name] = self._probe_skips.get(name, 0) + 1
            if self._probe_skips[name] < 10:
                return
            self._probe_skips[name] = 0
            self.sync_recent_messages(name)

    def nudge(self, name, conv_id=None):
        """Poll this account on the next tick, focused conversation first.

        Called right after a send: the server needs a moment before the new
        message is visible to reads, so waiting out the normal interval would add
        a full cycle on top of that delay.
        """
        if conv_id:
            self.focus[name] = conv_id
        self._last_focus[name] = 0
        self._last_msgs[name] = 0

    def sync_conversations(self, name):
        sess = self.sessions[name]
        convs, meta = api.list_conversations(self.client, sess)
        self.store.save_conversations(name, convs)

        # The list payload carries each conversation's most recent message. Ingest
        # those too: it is what surfaces new messages in conversations we do not
        # poll individually (anything outside the most-recent N).
        fresh = self.store.save_messages(name, [c['last'] for c in convs if c.get('last')])
        if fresh:
            grouped = {}
            for m in fresh:
                grouped.setdefault(m['conv_id'], []).append(m)
            for conv_id, msgs in grouped.items():
                self.bus.publish({'type': 'message', 'account': name,
                                  'conv_id': conv_id, 'messages': msgs})

        self._fill_profiles(name, convs)
        self._set_status(name, 'ok')
        self.bus.publish({'type': 'conversations', 'account': name})
        return convs, meta

    def _fill_profiles(self, name, convs=None):
        """Nicknames are not in the conversation payload — fetch them in one batch."""
        missing = self.store.missing_profiles(name, limit=50)
        if not missing:
            return
        sess = self.sessions[name]
        try:
            profiles = api.user_profiles(self.client, sess, missing)
            if profiles:
                self.store.save_profiles(name, profiles)
        except Exception as e:
            self._set_status(name, 'warn', 'profile lookup failed: %s' % e)

    def sync_conversation(self, name, conv_id, limit=None):
        """Poll one conversation; safe to call directly from a request handler."""
        convs = self.store.list_conversations(name)
        row = next((c for c in convs if c['conv_id'] == conv_id), None)
        if not row:
            return []
        return self._poll_conversation(name, row['conv_id'], row['short_id'],
                                       limit or self.config['poll_page_size'])

    def _poll_conversation(self, name, conv_id, short_id, limit):
        sess = self.sessions[name]
        try:
            msgs, _ = api.list_messages(self.client, sess, conv_id, short_id, limit=limit)
        except Exception as e:
            self._set_status(name, 'warn', 'message poll failed: %s' % e)
            return []
        fresh = self.store.save_messages(name, msgs)
        if fresh:
            self.store.save_conversations(name, [{
                'conv_id': conv_id, 'short_id': short_id,
                'peer_uid': api.peer_of(conv_id, sess.uid),
                'updated_ms': max((m['ms'] for m in fresh), default=0),
                'last': max(fresh, key=lambda m: m['ms']),
            }])
            self.bus.publish({'type': 'message', 'account': name,
                              'conv_id': conv_id, 'messages': fresh})
        return fresh

    def sync_recent_messages(self, name):
        """Round-robin the most recent conversations.

        The focused conversation is skipped here — it already has its own faster
        loop, and polling it twice per cycle would just double the requests.
        """
        targets = []
        focused = self.focus.get(name)
        for c in self.store.active_conversations(name, limit=self.config['poll_conversations']):
            if focused and c['conv_id'] == focused:
                continue
            targets.append(c)
        for t in targets:
            if self._stop.is_set():
                return
            self._poll_conversation(name, t['conv_id'], t['short_id'],
                                    self.config['poll_page_size'])
            time.sleep(0.35)          # be gentle between conversations

    # ---------------------------------------------------------- one-shot ops

    def ensure_history(self, name, conv_id, short_id, target=40):
        """First open of a conversation: pull a page if we have nothing stored."""
        if self.store.has_messages(name, conv_id):
            return
        self.fetch_more(name, conv_id, short_id, limit=target)

    def fetch_more(self, name, conv_id, short_id, before_us=None, limit=20):
        sess = self.sessions[name]
        msgs, meta = api.list_messages(self.client, sess, conv_id, short_id,
                                       anchor_us=before_us, limit=limit)
        self.store.save_messages(name, msgs)
        return msgs, meta.get('next_cursor')
