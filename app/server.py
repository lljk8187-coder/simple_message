"""HTTP API + static front end + SSE event stream."""
import json
import os
import queue
import re
import threading
import time
import traceback
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from . import client as api
from . import harvest

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'web')


def _guard_present(fields):
    """True when `guard` holds real headers. It may be a dict or JSON text — and
    the DB stores accounts with no headers as '{}' (a truthy string), so parse
    before trusting it."""
    g = fields.get('guard')
    if isinstance(g, str):
        try:
            g = json.loads(g) if g else {}
        except Exception:
            g = {}
    return bool(g)


def pool_fill(store, fields):
    """Borrow signing materials from the shared pool for a cookie-only account.

    Measured 2026-09-28: the server binds message identity to the cookie, not to
    the ticket. An account that imported only a cookie sent successfully through
    another account's ticket/headers — guard_result=1003 (degraded trust, the
    pair is simply not the requester's own), message delivered, sender
    attribution correct. Borrowing therefore makes "paste a cookie and go"
    fully functional; per-account harvesting stays the path to result=0.

    `fields` is a dict with optional guard / ticket / private_key entries (guard
    may be a dict or canonical JSON text, matching both call sites). Missing
    fields are filled individually, so a half-equipped account only borrows what
    it lacks. Returns (fields, source) — source is non-empty only when something
    was borrowed.
    """
    if all((fields.get('ticket'), fields.get('private_key'), _guard_present(fields))):
        return fields, None            # complete own set — nothing to borrow
    pool = store.pool_get()
    if not pool or not (pool.get('ticket') or pool.get('private_key') or pool.get('guard')):
        return fields, None
    d = dict(fields)
    borrowed = []
    if not d.get('ticket'):
        d['ticket'] = pool.get('ticket') or ''
        borrowed.append('ticket')
    if not d.get('private_key'):
        d['private_key'] = pool.get('private_key') or ''
        borrowed.append('private_key')
    if not _guard_present(d):
        d['guard'] = pool.get('guard') or ''
        borrowed.append('guard')
    return d, ('%s from %s' % ('+'.join(borrowed), pool.get('source') or 'pool')
               if borrowed else None)


def pool_refresh(store, ticket, private_key, guard, source=''):
    """Remember a complete set of signing materials as the shared pool, so the
    next cookie-only import can send without running the harvest wizard itself."""
    if not (ticket or private_key or guard):
        return
    store.pool_put(ticket, private_key, guard, source)


class Handler(BaseHTTPRequestHandler):
    server_version = 'tk-message-demo/1.0'
    protocol_version = 'HTTP/1.1'

    hub = None          # injected by create_server
    store = None
    client = None
    config = None
    _pending = None     # harvest.Pending

    # ------------------------------------------------------------- helpers

    def log_message(self, fmt, *args):
        if self.config.get('access_log', True):
            print('[%s] %s' % (time.strftime('%H:%M:%S'), fmt % args))

    def _send(self, code, body, ctype='application/json; charset=utf-8', extra=None):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str),
                   extra=extra)

    def _err(self, e, code=500):
        if isinstance(e, api.ApiError):
            self._json({'error': str(e), 'status': e.status, 'biz_code': e.biz_code}, 502)
        else:
            self._json({'error': type(e).__name__, 'detail': str(e)}, code)

    def _body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode('utf-8'))
        except Exception:
            return {}

    # --------------------------------------------------------------- routes

    ROUTES = [
        ('GET', r'^/$', 'index'),
        ('GET', r'^/index\.html$', 'index'),
        ('GET', r'^/api/config$', 'get_config'),
        ('GET', r'^/api/accounts$', 'list_accounts'),
        ('POST', r'^/api/accounts$', 'add_account'),
        ('GET', r'^/api/accounts/(?P<name>[^/]+)$', 'account_detail'),
        ('DELETE', r'^/api/accounts/(?P<name>[^/]+)$', 'drop_account'),
        ('POST', r'^/api/accounts/(?P<name>[^/]+)/sync$', 'force_sync'),
        ('GET', r'^/api/accounts/(?P<name>[^/]+)/conversations$', 'conversations'),
        ('GET', r'^/api/accounts/(?P<name>[^/]+)/messages$', 'messages'),
        ('POST', r'^/api/accounts/(?P<name>[^/]+)/send$', 'send'),
        ('POST', r'^/api/accounts/(?P<name>[^/]+)/focus$', 'focus'),
        ('GET', r'^/api/events$', 'events'),
        ('GET', r'^/api/harvest$', 'harvest_get'),
        ('POST', r'^/api/harvest$', 'harvest_post'),
        ('DELETE', r'^/api/harvest$', 'harvest_clear'),
        ('GET', r'^/api/harvest/script$', 'harvest_script'),
        ('POST', r'^/api/harvest/apply$', 'harvest_apply'),
        ('GET', r'^/api/pool$', 'pool'),
        ('GET', r'^/api/health$', 'health'),
    ]

    def _dispatch(self, method):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Optional bearer auth. Static pages stay open so the browser can load
        # the front end; everything under /api requires the token when one is
        # configured. With no token configured (the default) this is a no-op.
        token = self.config.get('access_token') or ''
        if token and path.startswith('/api/') and path != '/api/health':
            supplied = ''
            auth = self.headers.get('Authorization') or ''
            if auth.startswith('Bearer '):
                supplied = auth[len('Bearer '):].strip()
            if not supplied:
                supplied = (query.get('token') or [''])[0]
            if supplied != token:
                self._json({'error': 'unauthorized'}, 401,
                           extra={'WWW-Authenticate': 'Bearer'})
                return

        for m, pattern, handler in self.ROUTES:
            if m != method:
                continue
            match = re.match(pattern, path)
            if match:
                fn = getattr(self, 'h_' + handler, None)
                if not fn:
                    return self._json({'error': 'handler missing'}, 500)
                try:
                    return fn(query, **match.groupdict())
                except api.ApiError as e:
                    return self._err(e, 502)
                except Exception as e:
                    traceback.print_exc()
                    return self._err(e)
        self._json({'error': 'not found', 'path': path}, 404)

    def do_GET(self):
        self._dispatch('GET')

    def do_POST(self):
        self._dispatch('POST')

    def do_DELETE(self):
        self._dispatch('DELETE')

    def do_OPTIONS(self):
        # /api/harvest is posted to from the TikTok page, so a Private Network
        # Access preflight can land here even though the beacon itself is no-cors.
        self._send(204, b'', 'text/plain', {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Private-Network': 'true',
        })

    # -------------------------------------------------------------- handlers

    def h_index(self, q):
        path = os.path.join(WEB_DIR, 'index.html')
        with open(path, 'rb') as f:
            self._send(200, f.read(), 'text/html; charset=utf-8')

    def h_health(self, q):
        self._json({'ok': True, 'ts': int(time.time() * 1000),
                    'proxy': self.client.proxy, 'accounts': len(self.hub.sessions)})

    def h_get_config(self, q):
        cfg = dict(self.config)
        cfg.pop('access_log', None)
        self._json({'config': cfg, 'proxy': self.client.proxy})

    def h_list_accounts(self, q):
        out = []
        for a in self.store.list_accounts():
            st = self.hub.status.get(a['name'], {})
            a['status'] = st.get('state', 'idle')
            a['status_detail'] = st.get('detail', '')
            a['stats'] = self.store.stats(a['name'])
            sess = self.hub.sessions.get(a['name'])
            guard, tier = api.ticket_guard_headers(sess, '/v1/message/send') if sess else (None, None)
            a['write_tier'] = tier
            a['writable'] = guard is not None
            out.append(a)
        self._json({'accounts': out})

    def h_add_account(self, q):
        body = self._body()
        cookie = (body.get('cookie') or '').strip()
        if not cookie:
            return self._json({'error': 'cookie is required'}, 400)
        cookie = ' '.join(cookie.split())
        name = (body.get('name') or '').strip()

        private_key = None
        key_text = (body.get('private_key') or '').strip()
        if key_text:
            try:
                private_key = api.signing.parse_private_key(key_text)
            except Exception as e:
                return self._json({'error': 'private key not understood: %s' % e}, 400)

        info = api.verify_cookie(self.client, cookie)
        if not name:
            name = info['username'] or info['uid']

        # Keep the shared pool fresh with whatever materials came with this
        # import, and borrow from it when the import carries none.
        guard_in = body.get('guard')
        if isinstance(guard_in, str):
            try:
                guard_in = json.loads(guard_in) if guard_in else {}
            except Exception:
                guard_in = {}
        pool_refresh(self.store, body.get('ticket') or '', key_text,
                     guard_in or {}, source=name or (info.get('username') or ''))

        fields, borrowed = pool_fill(self.store, {
            'guard': guard_in or {}, 'ticket': body.get('ticket') or '',
            'private_key': private_key, 'ts_sign': body.get('ts_sign') or '',
        })
        borrowed_guard = fields['guard']
        if isinstance(borrowed_guard, str):
            try:
                borrowed_guard = json.loads(borrowed_guard) if borrowed_guard else {}
            except Exception:
                borrowed_guard = {}

        sess = api.Session(
            cookie=cookie,
            device_id=(body.get('device_id') or self.config['default_device_id']),
            uid=info['uid'], username=info['username'], nickname=info['nickname'],
            region=info['region'],
            guard=borrowed_guard, ticket=(fields['ticket'] or ''),
            private_key=fields['private_key'], ts_sign=(fields['ts_sign'] or ''),
        )
        self.store.save_account(name, sess, info)
        self.hub.attach(name, sess)
        try:
            self.hub.sync_conversations(name)
        except Exception as e:
            self.hub._set_status(name, 'warn', 'initial sync failed: %s' % e)
        _, tier = api.ticket_guard_headers(sess, '/v1/message/send') if sess else (None, None)
        self._json({'name': name, 'uid': info['uid'], 'username': info['username'],
                    'write_tier': tier, 'writable': tier is not None,
                    'borrowed_from': borrowed})

    def h_account_detail(self, q, name):
        row = self.store.get_account(name)
        if not row:
            return self._json({'error': 'no such account'}, 404)
        row.pop('cookie', None)
        row['status'] = self.hub.status.get(name, {}).get('state', 'idle')
        row['stats'] = self.store.stats(name)
        self._json(row)

    def h_drop_account(self, q, name):
        self.hub.detach(name)
        self.store.delete_account(name)
        self._json({'ok': True})

    def h_force_sync(self, q, name):
        if name not in self.hub.sessions:
            return self._json({'error': 'account not loaded'}, 404)
        convs, meta = self.hub.sync_conversations(name)
        self._json({'ok': True, 'conversations': len(convs), 'meta': meta.get('meta')})

    def h_conversations(self, q, name):
        self._require(name)
        self._json({'conversations': self.store.list_conversations(name)})

    def h_messages(self, q, name):
        self._require(name)
        conv_id = (q.get('conv_id') or [''])[0]
        if not conv_id:
            return self._json({'error': 'conv_id is required'}, 400)
        limit = int((q.get('limit') or ['30'])[0])
        before = (q.get('before_us') or [''])[0]
        before_us = int(before) if before.isdigit() else None

        conv = next((c for c in self.store.list_conversations(name)
                     if c['conv_id'] == conv_id), None)
        if not conv:
            return self._json({'error': 'unknown conversation'}, 404)

        if before_us is None:
            self.hub.ensure_history(name, conv['conv_id'], conv['short_id'])

        stored = self.store.list_messages(name, conv_id, limit=limit, before_us=before_us)
        cursor = None
        if len(stored) < limit:
            # ran out of local rows — ask the server for the next page
            oldest = min((m['us'] for m in stored), default=before_us or None)
            try:
                fetched, cursor = self.hub.fetch_more(name, conv['conv_id'],
                                                      conv['short_id'],
                                                      before_us=oldest, limit=limit)
                self.store.save_messages(name, fetched)
                stored = self.store.list_messages(name, conv_id, limit=limit, before_us=before_us)
            except api.ApiError as e:
                cursor = None
                if not stored:
                    raise e
        self._json({'messages': stored, 'next_cursor': cursor,
                    'conversation': conv})

    def h_send(self, q, name):
        self._require(name)
        sess = self.hub.sessions[name]
        guard, tier = api.ticket_guard_headers(sess, '/v1/message/send')
        if guard is None:
            return self._json({'error': 'no write credentials for this account '
                                        '(needs guard headers, or ticket + ts_sign + private key)'}, 400)
        body = self._body()
        conv_id = (body.get('conv_id') or '').strip()
        text = (body.get('text') or '').strip()
        if not conv_id or not text:
            return self._json({'error': 'conv_id and text are required'}, 400)
        conv = next((c for c in self.store.list_conversations(name)
                     if c['conv_id'] == conv_id), None)
        if not conv or not conv['short_id']:
            return self._json({'error': 'unknown conversation (no short_id)'}, 404)
        result = api.send_message(self.client, sess, conv_id, conv['short_id'], text)
        if result.get('ok'):
            # read-back is not instantaneous on this API, so poll this conversation
            # hard for the next few seconds rather than waiting out a whole interval
            self.hub.nudge(name, conv_id)
        self._json(result)

    def h_focus(self, q, name):
        if name in self.hub.sessions:
            conv_id = (self._body().get('conv_id') or '')
            self.hub.nudge(name, conv_id)       # pull it now, don't wait for the tick
        self._json({'ok': True})

    # ------------------------------------------------------- harvest (credentials)

    CORS = {'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Private-Network': 'true'}

    def h_harvest_script(self, q):
        """The console script the user pastes into the signed-in TikTok page."""
        base = 'http://' + (self.headers.get('Host') or '127.0.0.1:8788')
        self._send(200, harvest.build_script(base),
                   'text/plain; charset=utf-8', self.CORS)

    def h_harvest_post(self, q):
        """Receives the page's report. Text/plain body: a beacon cannot set JSON."""
        payload = self._body()
        if not isinstance(payload, dict) or not payload:
            return self._json({'error': 'empty or unparseable payload'}, 400, self.CORS)
        rec = self._pending.put(payload)
        self._json({'ok': True, 'received_at': rec['received_at'],
                    'summary': harvest.summarise(payload)}, extra=self.CORS)

    def h_harvest_get(self, q):
        rec = self._pending.get()
        if not rec:
            return self._json({'pending': None})
        self._json({'pending': {'received_at': rec['received_at'],
                                'summary': harvest.summarise(rec['payload']),
                                'raw': rec['payload']}})

    def h_harvest_clear(self, q):
        self._pending.clear()
        self._json({'ok': True})

    def h_harvest_apply(self, q):
        """Attach a harvest to an account, creating it if the cookie is supplied."""
        rec = self._pending.get()
        if not rec:
            return self._json({'error': 'nothing has been harvested yet'}, 400)
        p = rec['payload']
        body = self._body()

        name = (body.get('name') or '').strip()
        cookie = ' '.join((body.get('cookie') or '').split())

        existing = self.store.get_account(name) if name else None
        prev = api.Session.from_dict(existing) if existing else None
        if prev:
            cookie = cookie or prev.cookie
        if not cookie:
            return self._json({
                'error': 'a cookie is required — the session id is HttpOnly, so the page '
                         'script cannot read it; paste it once here'}, 400)

        private_key = None
        key_text = (p.get('private_key') or '').strip()
        if key_text:
            try:
                private_key = api.signing.parse_private_key(key_text)
            except Exception as e:
                return self._json({'error': 'harvested private key not understood: %s' % e}, 400)

        info = api.verify_cookie(self.client, cookie)
        if not name:
            name = info['username'] or info['uid']

        sess = api.Session(
            cookie=cookie,
            device_id=(body.get('device_id') or (prev.device_id if prev else '')
                       or self.config['default_device_id']),
            uid=info['uid'], username=info['username'], nickname=info['nickname'],
            region=info['region'],
            guard=(prev.guard if prev else {}),
            ticket=(p.get('ticket') or (prev.ticket if prev else '')),
            private_key=private_key or (prev.private_key if prev else None),
            ts_sign=(p.get('ts_sign') or (prev.ts_sign if prev else '')),
        )
        self.store.save_account(name, sess, info)
        self.hub.attach(name, sess)
        # A successful harvest produces a complete, fresh set of signing
        # materials — remember them as the shared pool for cookie-only imports.
        pool_refresh(self.store, sess.ticket,
                     ('%064x' % sess.private_key) if sess.private_key else '',
                     sess.guard or {}, source=name)
        try:
            self.hub.sync_conversations(name)
        except Exception as e:
            self.hub._set_status(name, 'warn', 'initial sync failed: %s' % e)
        _, tier = api.ticket_guard_headers(sess, '/v1/message/send')
        self._pending.clear()
        self._json({'ok': True, 'name': name, 'uid': info['uid'],
                    'username': info['username'], 'write_tier': tier})

    def _require(self, name):
        if name not in self.hub.sessions:
            raise api.ApiError('account %r is not loaded' % name)

    def h_pool(self, q):
        """Status of the shared signing-material pool."""
        pool = self.store.pool_get() or {}
        has = bool(pool.get('ticket') or pool.get('private_key') or pool.get('guard'))
        self._json({'has_materials': has, 'source': pool.get('source') or '',
                    'updated_at': pool.get('updated_at'),
                    'note': 'cookie-only imports borrow these materials; sends '
                            'made with borrowed materials score guard_result=1003 '
                            '(degraded trust, still delivered)'})

    # ------------------------------------------------------------------ SSE

    def h_events(self, q):
        account = (q.get('account') or [None])[0]
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache, no-transform')
        self.send_header('Connection', 'keep-alive')
        self.send_header('X-Accel-Buffering', 'no')
        self.end_headers()
        sub = self.hub.bus.subscribe()
        try:
            self._sse_write({'type': 'hello', 'account': account,
                             'ts': int(time.time() * 1000)})
            while True:
                try:
                    ev = sub.get(timeout=20)
                except queue.Empty:
                    self._sse_write({'type': 'ping', 'ts': int(time.time() * 1000)})
                    continue
                if account and ev.get('account') not in (None, account):
                    continue
                self._sse_write(ev)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.hub.bus.unsubscribe(sub)

    def _sse_write(self, obj):
        payload = 'data: ' + json.dumps(obj, ensure_ascii=False, default=str) + '\n\n'
        self.wfile.write(payload.encode('utf-8'))
        self.wfile.flush()


def create_server(host, port, hub, store, client, config):
    Handler.hub = hub
    Handler.store = store
    Handler.client = client
    Handler.config = config
    Handler._pending = harvest.Pending()
    return ThreadingHTTPServer((host, port), Handler)
