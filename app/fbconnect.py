"""Facebook Messenger connector — the fourth platform adapter.

FB 1:1 chats are end-to-end encrypted (Signal protocol) since 2024-11; this
adapter therefore runs the fbchat-v2 E2EE bridge — a Go subprocess resolved
through fbchat-v2's checksummed release download (pinned SHA256, trusted-host
allowlist) — as a persistent component. Receiving 1:1 messages, sending into
1:1 chats (send_e2ee_message) and mark-read all flow through that bridge;
the conversation list comes from the GraphQL INBOX batch; group sends use
the classic SendAPI. Auth = pasted facebook.com cookie string (needs
`c_user` + `xs`; bridge also uses `datr`/`fr` when present).

fbchat-v2 is async → the same background-loop bridge as the X connector.
Incoming 1:1 events accumulate in `self._events`; `drain_events()` hands
them to the hub sync loop.
"""
import asyncio
import json
import threading
import urllib.parse

LAZY_ERR = 'fbchat-v2 is not installed — run: pip install fbchat-v2'
REQUIRED_COOKIES = ('c_user', 'xs')


# ------------------------------------------------------------------ cookies

def parse_cookies(text):
    """Accept the raw `Cookie:` header string from DevTools, or a dict/JSON."""
    if isinstance(text, dict):
        d = dict(text)
    else:
        if not text or not text.strip():
            raise ValueError('cookies are empty')
        text = text.strip()
        if text.startswith('{'):
            d = json.loads(text)
        else:
            d = {}
            for part in text.replace('\n', '; ').split(';'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    d[k.strip()] = v.strip().strip('"')
    if not isinstance(d, dict) or not d:
        raise ValueError('cookies did not parse into a dict')
    missing = [k for k in REQUIRED_COOKIES if not d.get(k)]
    if missing:
        raise ValueError('cookie missing required key(s): %s' % ', '.join(missing))
    return d


def _cookie_header(cookies):
    return '; '.join('%s=%s' % (k, v) for k, v in cookies.items())


# ------------------------------------------------------------------- bridge

class _Loop:
    """One background thread owning one asyncio loop for a session."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def call(self, coro, timeout=120):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)


# ----------------------------------------------------------------- session

class FBSession:
    """One logged-in Facebook account (cookie auth + E2EE bridge)."""

    def __init__(self, cookie_str, proxy=None, e2ee_bin=None):
        self.cookie_str = cookie_str
        self.proxy = proxy
        self.e2ee_bin = e2ee_bin
        self._dataFB = None
        self._listener = None
        self._bridge_ready = False
        self._loop = None
        self.me_id = None
        self._events = []                 # raw 1:1 events from the bridge
        self._conv_meta = {}              # conv_id -> {peer_uid, is_group, chat_jid}
        self._seen_rows = {}              # conv_id -> [accumulated live rows]

    # ------------------------------------------------------------ lifecycle

    def start(self):
        cookies = parse_cookies(self.cookie_str)
        self._loop = _Loop()
        self._loop.call(self._boot(cookies))
        return self

    async def _boot(self, cookies):
        from fbchat_v2._core._session import dataGetHome
        data = await dataGetHome(_cookie_header(cookies))
        if not isinstance(data, dict) or not data:
            raise RuntimeError('facebook session creation failed '
                               '(cookie invalid or Cloudflare/bot wall)')
        missing = [k for k in ('fb_dtsg', 'FacebookID', 'cookieFacebook')
                   if not data.get(k)]
        if missing:
            raise RuntimeError('session missing %s' % ', '.join(missing))
        self._dataFB = data
        self.me_id = str(data['FacebookID'])

    def close(self):
        if self._listener:
            try:
                self._listener.stop()
            except Exception:
                pass
            self._listener = None
        if self._loop:
            self._loop.stop()
            self._loop = None

    # ------------------------------------------------------------- identity

    def verify(self):
        return {'uid': self.me_id or '', 'username': '', 'name': ''}

    # -------------------------------------------------------------- inbox

    def conversations(self):
        return self._loop.call(self._conversations())

    async def _conversations(self):
        from fbchat_v2._features._thread._all_thread_data import func as all_threads
        result = await all_threads.func(self._dataFB)
        if not isinstance(result, dict):
            raise RuntimeError('unexpected thread-list response')
        if result.get('error'):
            raise RuntimeError(str(result['error']))
        batch = json.loads(result['dataGet'])['o0']
        nodes = ((batch.get('data') or {}).get('viewer') or {}
                 ).get('message_threads', {}).get('nodes', [])
        me = self.me_id
        out = []
        for node in nodes:
            tid = str((node.get('thread_key') or {}).get('thread_fbid') or '')
            if not tid:
                continue
            actors = []
            for edge in (node.get('all_participants') or {}).get('edges', []):
                actor = (edge.get('node') or {}).get('messaging_actor') or {}
                if str(actor.get('id')) and str(actor.get('id')) != me:
                    actors.append(actor)
            peer = actors[0] if actors else {}
            is_group = len(actors) > 1
            if node.get('name'):
                display = node['name']
            elif not is_group and peer:
                display = peer.get('name') or ('uid %s' % peer.get('id'))
            else:
                display = 'group %s' % tid
            snippet_sender = str(node.get('snippet_sender') or '')
            avatar = ((peer.get('big_image_src') or {}).get('uri', '') if peer else '')
            out.append({
                'platform': 'facebook',
                'conv_id': tid,
                'peer_uid': ','.join(a.get('id', '') for a in actors),
                'peer_nickname': display,
                'peer_unique': (peer.get('username') or '') if peer else '',
                'peer_avatar': avatar,
                'last_text': node.get('snippet') or '',
                'last_ms': int(node.get('updated_time') or 0) * 1000,
                'last_from_me': snippet_sender == me,
                'unread': 0,
            })
            self._conv_meta[tid] = {
                'peer_uid': out[-1]['peer_uid'],
                'is_group': is_group,
                'chat_jid': (out[-1]['peer_uid'].split(',')[0] + '@msgr')
                            if out[-1]['peer_uid'] and not is_group else None,
            }
        out.sort(key=lambda c: c['last_ms'], reverse=True)
        return out

    # ------------------------------------------------- E2EE listener (1:1)

    def start_e2ee(self, timeout=90):
        """Bring up the bridge + MQTT listener. Blocks until E2EE ready."""
        return self._loop.call(self._start_e2ee(), timeout=timeout + 30)

    async def _start_e2ee(self):
        from fbchat_v2._messaging._listening_e2ee import listeningE2EEEvent
        self._listener = listeningE2EEEvent(
            self._dataFB, enable_e2ee=True,
            binary_path=self.e2ee_bin, e2ee_memory_only=True)
        self._listener.on_message(self._on_bridge_event)
        task = asyncio.create_task(self._listener.connect_mqtt())
        ready = await asyncio.to_thread(
            self._listener.wait_until_connected, 90, require_e2ee=True)
        if not ready:
            raise RuntimeError('E2EE listener not ready within 90s')
        self._bridge_ready = True
        return {'connected': True, 'task': str(task)}

    def _on_bridge_event(self, event):
        """Runs on the bridge poll thread — a list append is all we do here."""
        try:
            self._events.append(event)
        except Exception:
            pass

    def drain_events(self):
        """Hand accumulated raw bridge events to the caller (sync loop)."""
        evs, self._events = self._events, []
        return evs

    def e2ee_ready(self):
        return self._bridge_ready

    # ------------------------------------------------------------- history

    def history(self, conv_id):
        """1:1 E2EE chats have no fetchable server history — what we return
        is everything seen live since the session started."""
        rows = list(self._seen_rows.get(str(conv_id), []))
        rows.sort(key=lambda x: x['ms'])
        return rows, None

    def _remember(self, row):
        self._seen_rows.setdefault(row['conv_id'], []).append(row)

    # ------------------------------------------------------------- actions

    def send(self, conv_id, text):
        """1:1 → bridge E2EE send; group → classic SendAPI."""
        return self._loop.call(self._send(str(conv_id), text))

    async def _send(self, conv_id, text):
        meta = self._conv_meta.get(conv_id) or {}
        if meta.get('chat_jid') and self._bridge_ready:
            out = await self._listener.send_e2ee_message(meta['chat_jid'], text)
            row = {
                'platform': 'facebook', 'msg_id': str((out or {}).get('id') or ''),
                'conv_id': conv_id, 'sender': self.me_id or '', 'outgoing': 1,
                'text': text,
                'ms': int((out or {}).get('timestampMs') or 0) or _now_ms(),
                'us': 0,
            }
            row['us'] = row['ms'] * 1000
            self._remember(row)
            return {'ok': True, 'msg_id': row['msg_id'], 'ms': row['ms'],
                    'via': 'e2ee'}
        from fbchat_v2._messaging._send import api as SendAPI
        await SendAPI().send(self._dataFB, text, conv_id)
        return {'ok': True, 'msg_id': '', 'via': 'sendapi'}

    def mark_seen(self, conv_id, watermark_ms=0):
        """Best-effort read receipt through the bridge (async op table)."""
        if not self._bridge_ready:
            return {'ok': False, 'skipped': 'E2EE bridge not ready'}
        return self._loop.call(self._mark_seen(str(conv_id), int(watermark_ms)))

    async def _mark_seen(self, conv_id, watermark_ms):
        from fbchat_v2._messaging._bridge_actions import BridgeActions
        if getattr(self._listener, '_bridge', None) is None:
            return {'ok': False, 'skipped': 'bridge not connected'}
        actions = BridgeActions(self._listener._bridge)
        await actions.mark_read(conv_id, watermark_ms)
        return {'ok': True}


def _now_ms():
    import time
    return int(time.time() * 1000)


# ------------------------------------------------------------------- probe

def probe(cookie_str, proxy=None):
    """Cookie validation without the bridge: session creation + thread list.
    (E2EE bridge needs the binary; the hub starts it per account.)"""
    report = {}
    sess = FBSession(cookie_str, proxy=proxy)
    try:
        sess.start()
        report['verify'] = {'uid': sess.me_id}
        try:
            convs = sess.conversations()
            report['conversations'] = {'count': len(convs),
                                       'first': convs[0] if convs else None}
        except Exception as e:
            report['conversations'] = {'error': '%s: %s'
                                       % (type(e).__name__, e)}
    except Exception as e:
        report['verify'] = {'error': '%s: %s' % (type(e).__name__, e)}
    finally:
        sess.close()
    return report
