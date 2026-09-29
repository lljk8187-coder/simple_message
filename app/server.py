"""HTTP API + static front end + SSE event stream.

重构后的路由面只有一套：/api/accounts/... 对所有平台通用。平台差异全部
住在 app/hub.py（编排）与 app/platform/*（适配器）里——本文件只做路由、
鉴权、SSE 管道与静态页。
"""
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
from . import login_browser

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'web')


class Handler(BaseHTTPRequestHandler):
    server_version = 'tk-message-demo/2.0'
    protocol_version = 'HTTP/1.1'

    hub = None          # app.hub.Hub — injected by create_server
    store = None
    client = None
    config = None
    _pending = None     # harvest.Pending
    login_flow = None   # login_browser.BrowserLogin（TikTok 弹窗官方登录）

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
        ('POST', r'^/api/accounts/code$', 'account_code'),
        ('GET', r'^/api/accounts/pending/(?P<pid>[^/]+)$', 'account_pending'),
        ('GET', r'^/api/accounts/(?P<name>[^/]+)$', 'account_detail'),
        ('DELETE', r'^/api/accounts/(?P<name>[^/]+)$', 'drop_account'),
        ('POST', r'^/api/accounts/(?P<name>[^/]+)/sync$', 'force_sync'),
        ('GET', r'^/api/accounts/(?P<name>[^/]+)/conversations$', 'conversations'),
        ('GET', r'^/api/accounts/(?P<name>[^/]+)/messages$', 'messages'),
        ('POST', r'^/api/accounts/(?P<name>[^/]+)/send$', 'send'),
        ('POST', r'^/api/accounts/(?P<name>[^/]+)/read$', 'mark_read'),
        ('POST', r'^/api/accounts/(?P<name>[^/]+)/focus$', 'focus'),
        ('POST', r'^/api/x/probe$', 'x_probe'),
        ('POST', r'^/api/batch/send$', 'batch_send'),
        ('GET', r'^/api/events$', 'events'),
        ('GET', r'^/api/harvest$', 'harvest_get'),
        ('POST', r'^/api/harvest$', 'harvest_post'),
        ('DELETE', r'^/api/harvest$', 'harvest_clear'),
        ('GET', r'^/api/harvest/script$', 'harvest_script'),
        ('POST', r'^/api/harvest/apply$', 'harvest_apply'),
        ('POST', r'^/api/login/browser$', 'login_start'),
        ('GET', r'^/api/login/state$', 'login_state'),
        ('POST', r'^/api/login/cancel$', 'login_cancel'),
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
                except KeyError as e:
                    return self._json({'error': str(e)}, 404)
                except ValueError as e:
                    return self._json({'error': str(e)}, 400)
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
                    'proxy': self.client.proxy, 'accounts': len(self.store.list_accounts())})

    def h_get_config(self, q):
        cfg = dict(self.config)
        cfg.pop('access_log', None)
        self._json({'config': cfg, 'proxy': self.client.proxy})

    def h_list_accounts(self, q):
        out = []
        for a in self.store.list_accounts():
            a['platform'] = a.get('platform') or 'tiktok'
            name = a['name']
            loaded = self.hub.loaded(name)
            a['status'] = 'ok' if loaded else 'down'
            a['writable'] = loaded
            a['write_tier'] = self.hub.write_tier(name) if loaded else None
            if a['platform'] == 'tiktok':
                st = self.hub.status.get(name, {})
                a['status_detail'] = st.get('detail', '')
                a['stats'] = self.store.stats(name)
            else:
                a['stats'] = {'conversations': 0, 'messages': 0}
            out.append(a)
        self._json({'accounts': out})

    def h_add_account(self, q):
        """统一添加入口：{platform: 'tiktok'|'x'|'instagram'|'facebook', ...}。

        IG 需要验证码时返回 {need_code: true, pending_id}，
        凭 pending_id 走 POST /api/accounts/code。
        """
        body = self._body()
        platform = (body.get('platform') or 'tiktok').strip()
        self._json(self.hub.add_account(platform, body))

    def h_account_code(self, q):
        """两段式登录第二段：{pending_id, code}。"""
        body = self._body()
        self._json(self.hub.submit_code((body.get('pending_id') or '').strip(),
                                        (body.get('code') or '').strip()))

    def h_account_pending(self, q, pid):
        self._json({'state': self.hub.pending_state(pid)})

    def h_account_detail(self, q, name):
        row = self.store.get_account(name)
        if not row:
            return self._json({'error': 'no such account'}, 404)
        row.pop('cookie', None)
        row['platform'] = row.get('platform') or 'tiktok'
        row['status'] = 'ok' if self.hub.loaded(name) else 'down'
        row['stats'] = self.store.stats(name)
        self._json(row)

    def h_drop_account(self, q, name):
        self.hub.drop(name)
        self._json({'ok': True})

    def h_force_sync(self, q, name):
        convs = self.hub.conversations(name)
        self._json({'ok': True, 'conversations': len(convs)})

    def h_conversations(self, q, name):
        self._json({'conversations': self.hub.conversations(name)})

    def h_messages(self, q, name):
        conv_id = (q.get('conv_id') or [''])[0]
        if not conv_id:
            return self._json({'error': 'conv_id is required'}, 400)
        limit = int((q.get('limit') or ['30'])[0])
        before = (q.get('before_us') or [''])[0]
        before_us = int(before) if before.isdigit() else None
        messages, cursor, conv = self.hub.messages(name, conv_id,
                                                   before_us=before_us, limit=limit)
        self._json({'messages': messages, 'next_cursor': cursor,
                    'conversation': conv})

    def h_send(self, q, name):
        body = self._body()
        conv_id = (body.get('conv_id') or '').strip()
        text = (body.get('text') or '').strip()
        if not conv_id or not text:
            return self._json({'error': 'conv_id and text are required'}, 400)
        self._json(self.hub.send(name, conv_id, text))

    def h_mark_read(self, q, name):
        """已读回执。效果在对方视角的"已读"标记——本地未读徽章仍由前端基线管理。"""
        body = self._body()
        conv_id = (body.get('conv_id') or '').strip()
        if not conv_id:
            return self._json({'error': 'conv_id is required'}, 400)
        self._json(self.hub.mark_read(name, conv_id))

    def h_focus(self, q, name):
        if self.hub.loaded(name):
            conv_id = (self._body().get('conv_id') or '')
            self.hub.nudge(name, conv_id)       # pull it now, don't wait for the tick
        self._json({'ok': True})

    def h_x_probe(self, q):
        """Stateless X cookie validation — verify/inbox/history per stage."""
        body = self._body()
        cookies = body.get('cookies')
        if isinstance(cookies, str):
            cookies = cookies.strip()
        if not cookies:
            return self._json({'error': 'cookies are required'}, 400)
        try:
            from . import xconnect
        except ImportError:
            return self._json({'error': 'xconnect module unavailable'}, 500)
        try:
            report = xconnect.probe(
                cookies, proxy=self.client.proxy,
                with_history_uid=(body.get('history_uid') or None))
            self._json({'ok': 'error' not in (report.get('verify') or {}),
                        'report': report})
        except Exception as e:
            self._json({'ok': False, 'error': '%s: %s' % (type(e).__name__, e)})

    # ---------------------------------------------------- batch sending

    def h_batch_send(self, q):
        """Send one text to many conversations, sequentially with a delay.

        Deliberately rate-limited: identical content to many recipients is
        the exact traffic shape every platform's risk control hunts for, so
        the loop is serial, delays between sends, hard target cap, and
        per-target results instead of fire-and-forget."""
        body = self._body()
        text = (body.get('text') or '').strip()
        targets = body.get('targets') or []
        if not text:
            return self._json({'error': 'text is required'}, 400)
        if not isinstance(targets, list) or not targets:
            return self._json({'error': 'targets are required'}, 400)
        if len(targets) > 50:
            return self._json({'error': 'too many targets (max 50)'}, 400)
        try:
            delay = max(0, min(int(body.get('delay_ms') or 2000), 10000))
        except (TypeError, ValueError):
            delay = 2000
        results = []
        for i, t in enumerate(targets):
            if not isinstance(t, dict):
                continue
            account = (t.get('account') or '').strip()
            conv_id = (t.get('conv_id') or '').strip()
            entry = {'account': account, 'conv_id': conv_id,
                     'label': t.get('label') or ''}
            if i and delay:
                time.sleep(delay / 1000.0)
            try:
                entry.update(self.hub.send(account, conv_id, text))
            except api.ApiError as e:
                entry.update({'ok': False, 'error': str(e)})
            except Exception as e:
                entry.update({'ok': False,
                              'error': '%s: %s' % (type(e).__name__, e)})
            if 'ok' not in entry:
                entry['ok'] = False
            results.append(entry)
        sent = sum(1 for r in results if r.get('ok'))
        self._json({'ok': sent == len(results) and bool(results),
                    'sent': sent, 'failed': len(results) - sent,
                    'results': results})

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
            device_id=(body.get('device_id') or (prev.device_id if prev else '')),
            uid=info['uid'], username=info['username'], nickname=info['nickname'],
            region=info['region'],
            guard=(prev.guard if prev else {}),
            ticket=(p.get('ticket') or (prev.ticket if prev else '')),
            private_key=private_key or (prev.private_key if prev else None),
            ts_sign=(p.get('ts_sign') or (prev.ts_sign if prev else '')),
        )
        self.store.save_account(name, sess, info)
        self.hub.attach(name, sess)
        try:
            self.hub.sync_conversations(name)
        except Exception as e:
            self.hub._set_status(name, 'warn', 'initial sync failed: %s' % e)
        _, tier = api.ticket_guard_headers(sess, '/v1/message/send')
        self._pending.clear()
        self._json({'ok': True, 'name': name, 'uid': info['uid'],
                    'username': info['username'], 'write_tier': tier})

    # ------------------------------------------------------- TikTok 弹窗登录

    def h_login_start(self, q):
        """{platform} 缺省为 tiktok（兼容旧调用）。平台差异见适配器的
        popup_login_spec()。"""
        body = self._body()
        platform = (body.get('platform') or 'tiktok').strip()
        started, state = self.login_flow.start(platform)
        self._json({'started': started, 'state': state})

    def h_login_state(self, q):
        self._json({'state': self.login_flow.get_state()})

    def h_login_cancel(self, q):
        self.login_flow.cancel()
        self._json({'ok': True, 'state': self.login_flow.get_state()})

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

    # 弹窗登录的浏览器 profile 跟随 --data-dir：原先硬编码为 <项目>/data，
    # 于是换库（例如 --data-dir data-test）测试时仍复用同一浏览器身份，
    # 登录态会串味。现在 profile 落在 <data_dir>/login-profile/<平台>。
    data_dir = config.get('data_dir') or 'data'
    if not os.path.isabs(data_dir):
        data_dir = os.path.abspath(os.path.join(
            os.path.dirname(WEB_DIR), data_dir))
    Handler.login_flow = login_browser.BrowserLogin(
        store, hub, client,
        profile_root=os.path.join(data_dir, 'login-profile'),
        proxy=client.proxy)
    return ThreadingHTTPServer((host, port), Handler)
