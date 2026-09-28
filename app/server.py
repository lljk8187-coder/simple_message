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

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'web')


class Handler(BaseHTTPRequestHandler):
    server_version = 'tk-message-demo/1.0'
    protocol_version = 'HTTP/1.1'

    hub = None          # injected by create_server
    store = None
    client = None
    config = None

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

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str))

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
        ('GET', r'^/api/health$', 'health'),
    ]

    def _dispatch(self, method):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
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
        sess = api.Session(
            cookie=cookie,
            device_id=(body.get('device_id') or self.config['default_device_id']),
            uid=info['uid'], username=info['username'], nickname=info['nickname'],
            region=info['region'],
            guard=body.get('guard') or {}, ticket=(body.get('ticket') or ''),
            private_key=private_key, ts_sign=(body.get('ts_sign') or ''),
        )
        self.store.save_account(name, sess, info)
        self.hub.attach(name, sess)
        try:
            self.hub.sync_conversations(name)
        except Exception as e:
            self.hub._set_status(name, 'warn', 'initial sync failed: %s' % e)
        _, tier = api.ticket_guard_headers(sess, '/v1/message/send') if sess else (None, None)
        self._json({'name': name, 'uid': info['uid'], 'username': info['username'],
                    'write_tier': tier, 'writable': tier is not None})

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

    def _require(self, name):
        if name not in self.hub.sessions:
            raise api.ApiError('account %r is not loaded' % name)

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
    return ThreadingHTTPServer((host, port), Handler)
