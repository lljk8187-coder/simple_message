"""X (Twitter) connector — the second platform adapter.

Auth is the cookie pair from any logged-in x.com browser session
(`auth_token` + `ct0`, `twid` optional) — the same paste-cookie UX as the
TikTok side. Under the hood twikit drives the v1.1 DM endpoints, whose
paths are stable (no rotating GraphQL queryIds); the inbox list wraps the
same 1.1 `inbox_initial_state` call twikit defines as a constant but never
wrapped. Raw calls MUST go through `Client.request()`: X now demands the
`X-Client-Transaction-Id` header on most endpoints and twikit mints it there.

twikit is asyncio-native while the hub is sync threading, so each session
owns one background thread + event loop and bridges calls with
`asyncio.run_coroutine_threadsafe`. Live validation needs real cookies:
run the `/api/x/probe` endpoint or `probe_x.py` with them and every call
reports its own error if X's answer deviates from the shapes parsed here.
"""
import asyncio
import json
import threading

LAZY_ERR = ('twikit is not installed — run: pip install twikit '
            '(X connector optional dependency)')


# ------------------------------------------------------------------ cookies

def parse_cookies(text):
    """Accept the raw `Cookie:` header string from DevTools, or a JSON dict.

    Returns a plain dict; raises ValueError when the mandatory pair is
    missing so callers can reject an import before any network call.
    """
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
    missing = [k for k in ('auth_token', 'ct0') if not d.get(k)]
    if missing:
        raise ValueError('cookie missing required key(s): %s' % ', '.join(missing))
    return d


def ms_from_time(t):
    """X message timestamps arrive as strings; normalize to epoch-ms ints."""
    try:
        n = int(str(t))
    except (TypeError, ValueError):
        return 0
    if 0 < n < 10 ** 12:          # seconds — upgrade to ms
        n *= 1000
    return n


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

    def call(self, coro, timeout=90):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)


# ----------------------------------------------------------------- session

# inbox_initial_state params — the v1.1 boilerplate set seen in the wild.
# If X rejects it, the probe surfaces the raw error and this dict is the
# first thing to adjust.
_INBOX_PARAMS = {
    'include_email': 'false',
    'include_ext_media_color': 'false',
    'include_ext_media_availability': 'true',
    'include_ext_alt_text': 'true',
    'include_cards': '1',
    'send_error_codes': 'true',
    'tweet_mode': 'compat',
    'filter_low_quality': 'false',
    'include_quote_count': 'true',
}


class XSession:
    """One logged-in X account. Sync facade over an async twikit client."""

    def __init__(self, cookie_str, proxy=None):
        self.cookie_str = cookie_str
        self.proxy = proxy
        self._client = None
        self._loop = None

    # ------------------------------------------------------------ lifecycle

    def start(self):
        try:
            from twikit import Client
        except ImportError:
            raise RuntimeError(LAZY_ERR)
        cookies = parse_cookies(self.cookie_str)
        self._client = Client('en-US', proxy=self.proxy)
        self._client.set_cookies(cookies, clear_cookies=True)   # plain dict storage
        self._loop = _Loop()
        return self

    def close(self):
        if self._loop:
            self._loop.stop()
            self._loop = None

    # ------------------------------------------------------------- identity

    def verify(self):
        """Who am I — cheap round trip that also proves the cookies work."""
        u = self._loop.call(self._client.user())
        return {'uid': str(u.id), 'username': u.screen_name, 'name': u.name}

    # -------------------------------------------------------------- inbox

    def conversations(self):
        """Normalized DM conversation list.

        Shape mirrors the TikTok hub rows: conv_id, peer_uid, peer name,
        last message text + ms, unread left to the frontend baseline.
        """
        data, _ = self._loop.call(self._conversations_raw())
        state = data.get('inbox_initial_state') or {}
        me = str(self._loop.call(self._client.user_id()))
        convs = state.get('conversations') or {}
        users = state.get('user_events') or {}
        latest = {}
        for entry in state.get('entries') or []:
            msg = entry.get('message') or {}
            cid = msg.get('conversation_id')
            if not cid:
                continue
            if cid not in latest or ms_from_time(msg.get('time')) > latest[cid]['ms']:
                latest[cid] = {
                    'text': msg.get('text') or '',
                    'ms': ms_from_time(msg.get('time')),
                    'sender_id': str(msg.get('sender_id') or ''),
                }
        out = []
        for cid, conv in convs.items():
            participants = [str(p.get('id') or '') for p in (conv.get('participants') or [])]
            peers = [p for p in participants if p and p != me]
            peer_uid = peers[0] if peers else ''
            u = users.get(peer_uid) or {}
            last = latest.get(cid, {})
            out.append({
                'platform': 'x',
                'conv_id': cid,
                'peer_uid': peer_uid,
                'peer_nickname': u.get('name') or '',
                'peer_unique': u.get('screen_name') or '',
                'last_text': last.get('text') or '',
                'last_ms': last.get('ms') or 0,
                'outgoing': (last.get('sender_id') == me) if last else False,
                'unread': 0,
            })
        out.sort(key=lambda c: c['last_ms'], reverse=True)
        return out

    async def _conversations_raw(self):
        from twikit.client.v11 import Endpoint
        return await self._client.request(
            'GET', Endpoint.DM_INBOX,
            params=_INBOX_PARAMS, headers=self._client._base_headers)

    # ------------------------------------------------------------- history

    def history(self, peer_uid, max_id=None):
        """Messages with one peer, oldest first (hub message shape)."""
        result = self._loop.call(self._client.get_dm_history(str(peer_uid), max_id))
        me = str(self._loop.call(self._client.user_id()))
        out = []
        for m in result:
            out.append({
                'platform': 'x',
                'msg_id': str(m.id),
                'conv_id': str(peer_uid),
                'sender': str(m.sender_id),
                'outgoing': 1 if str(m.sender_id) == me else 0,
                'text': m.text or '',
                'ms': ms_from_time(m.time),
                'us': ms_from_time(m.time) * 1000,
            })
        out.sort(key=lambda x: x['ms'])
        return out, (getattr(result, 'next_cursor', None))

    def send(self, peer_uid, text):
        m = self._loop.call(self._client.send_dm(str(peer_uid), text))
        return {'ok': True, 'msg_id': str(m.id),
                'ms': ms_from_time(getattr(m, 'time', 0))}


# ------------------------------------------------------------------- probe

def probe(cookie_str, proxy=None, with_history_uid=None):
    """One-shot validation run (own loop, closes after).

    Returns a dict of per-call results so a single paste of cookies answers
    verify / inbox / history / send-reachability in one go. Never raises for
    a failing stage — the stage carries the exception text instead.
    """
    report = {}
    sess = XSession(cookie_str, proxy=proxy)
    try:
        sess.start()
        try:
            report['verify'] = sess.verify()
        except Exception as e:
            report['verify'] = {'error': '%s: %s' % (type(e).__name__, e)}
            return report                      # cookies unusable — stop here
        try:
            convs = sess.conversations()
            report['conversations'] = {'count': len(convs),
                                       'first': convs[0] if convs else None}
        except Exception as e:
            report['conversations'] = {'error': '%s: %s' % (type(e).__name__, e)}
        if with_history_uid:
            try:
                msgs, cursor = sess.history(with_history_uid)
                report['history'] = {'count': len(msgs),
                                     'last': msgs[-1] if msgs else None}
            except Exception as e:
                report['history'] = {'error': '%s: %s' % (type(e).__name__, e)}
        report['send_ready'] = True            # send needs a willing peer; UI-level
    finally:
        sess.close()
    return report
