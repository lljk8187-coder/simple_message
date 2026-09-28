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

        if now - self._last_msgs.get(name, 0) >= cfg['msg_interval']:
            self._last_msgs[name] = now
            self.sync_recent_messages(name)

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

    def sync_recent_messages(self, name):
        """Poll the focused conversation first, then the most recent ones."""
        sess = self.sessions[name]
        targets = []
        focused = self.focus.get(name)
        if focused:
            row = [c for c in self.store.list_conversations(name) if c['conv_id'] == focused]
            if row:
                targets.append({'conv_id': row[0]['conv_id'], 'short_id': row[0]['short_id']})
        for c in self.store.active_conversations(name, limit=self.config['poll_conversations']):
            if all(t['conv_id'] != c['conv_id'] for t in targets):
                targets.append(c)

        for t in targets:
            if self._stop.is_set():
                return
            try:
                msgs, _ = api.list_messages(self.client, sess, t['conv_id'], t['short_id'],
                                            limit=self.config['poll_page_size'])
            except Exception as e:
                self._set_status(name, 'warn', 'message poll failed: %s' % e)
                continue
            fresh = self.store.save_messages(name, msgs)
            if fresh:
                self.store.save_conversations(name, [{
                    'conv_id': t['conv_id'], 'short_id': t['short_id'],
                    'peer_uid': api.peer_of(t['conv_id'], sess.uid),
                    'updated_ms': max((m['ms'] for m in fresh), default=0),
                    'last': max(fresh, key=lambda m: m['ms']),
                }])
                self.bus.publish({'type': 'message', 'account': name,
                                  'conv_id': t['conv_id'], 'messages': fresh})
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
