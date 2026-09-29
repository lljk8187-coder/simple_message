"""Optional one-time browser login (route C2).

Launches a headed Chrome with a disposable profile and lets the user log in to
TikTok however they like — password, QR scan, captcha: the browser handles all
of it natively. When a session appears, the flow harvests everything the hub
needs directly from the logged-in page:

  cookie string    <- session cookies of the new login
  wid (device id)  <- /messages hydration data
  private key PEM  <- localStorage security-sdk/s_sdk_crypt_sdk  (plaintext PEM)
  ts_sign          <- localStorage security-sdk/s_sdk_sign_data_key/*
  ticket           <- decrypt(encrypt_ticket) via the page's own crypto.subtle
                      (AES-128-GCM, PBKDF2("tt-ticket-guard-iv","secure-salt",1000))

Everything then proceeds exactly like a normal import: Session is created with
the account's own materials (tier B, result=0) and the browser is closed.

The only dependency is `playwright` (pip install playwright). The browser
driven is the system Chrome (channel="chrome"), so no browser download is
needed. The core hub stays zero-dependency: without playwright, this module
simply reports the install hint and the console one-liner remains the
fallback.
"""
import json
import threading
import time

# localStorage keys inside the logged-in origin
KEY_CRYPT = 'security-sdk/s_sdk_crypt_sdk'
KEY_SIGN = 'security-sdk/s_sdk_sign_data_key/tt_fetch'

MATERIALS_JS = """
async () => {
  const signRaw = localStorage.getItem('security-sdk/s_sdk_sign_data_key/tt_fetch');
  const cryptRaw = localStorage.getItem('security-sdk/s_sdk_crypt_sdk');
  if (!signRaw || !cryptRaw) return {error: 'materials not in localStorage yet'};
  const s = JSON.parse(JSON.parse(signRaw).data);
  if (!s.encrypt_ticket || !s.ts_sign) return {error: 'sign data incomplete'};
  const b = Uint8Array.from(atob(s.encrypt_ticket), c => c.charCodeAt(0));
  const k = await crypto.subtle.importKey('raw',
      new TextEncoder().encode('tt-ticket-guard-iv'), 'PBKDF2', false, ['deriveKey']);
  const kk = await crypto.subtle.deriveKey(
      {name: 'PBKDF2', salt: new TextEncoder().encode('secure-salt'),
       iterations: 1000, hash: 'SHA-256'}, k,
      {name: 'AES-GCM', length: 128}, false, ['decrypt']);
  const ticket = new TextDecoder().decode(
      await crypto.subtle.decrypt({name: 'AES-GCM', iv: b.slice(0, 12)}, kk, b.slice(12)));
  const crypt = JSON.parse(JSON.parse(cryptRaw).data);
  const private_key = (crypt.ec_privateKey || '')
      .replace(/-----[A-Z ]+-----/g, '').replace(/\\s+/g, '');
  if (!ticket || !private_key) return {error: 'materials incomplete'};
  return {ticket, private_key, ts_sign: s.ts_sign};
}
"""

WID_JS = """
() => {
  try {
    const el = document.querySelector('#__UNIVERSAL_DATA_FOR_REHYDRATION__');
    if (!el) return null;
    const data = JSON.parse(el.textContent).__DEFAULT_SCOPE__['webapp.app-context'];
    return data.wid || null;
  } catch (e) { return null; }
}
"""


class BrowserLogin:
    """One headful login window -> full account import. See module docstring."""

    def __init__(self, store, hub, client, profile_dir, proxy=None):
        self.store = store
        self.hub = hub
        self.client = client
        self.profile_dir = profile_dir
        self.proxy = proxy
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self.state = {'phase': 'idle', 'detail': '', 'ts': 0}

    # ---------------------------------------------------------------- state

    def _set(self, phase, detail=''):
        with self._lock:
            self.state = {'phase': phase, 'detail': detail,
                          'ts': int(time.time() * 1000)}

    def get_state(self):
        with self._lock:
            return dict(self.state)

    # ------------------------------------------------------------ control

    def start(self):
        with self._lock:
            if self.state['phase'] in ('starting', 'waiting-login', 'collecting'):
                return False, dict(self.state)
            self._cancel.clear()
        threading.Thread(target=self._run, daemon=True).start()
        return True, self.get_state()

    def cancel(self):
        self._cancel.set()
        self._set('cancelled', 'cancelled by user')

    # ----------------------------------------------------------- the flow

    def _run(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self._set('error', 'playwright is not installed — run: '
                               'pip install playwright  (or harvest via the '
                               'console one-liner, see docs)')
            return

        try:
            self._collect()
        except Exception as e:
            self._set('error', '%s: %s' % (type(e).__name__, e))

    def _collect(self):
        from playwright.sync_api import sync_playwright

        self._set('starting', 'launching chrome')
        with sync_playwright() as p:
            launch = dict(
                headless=False,
                proxy={'server': self.proxy} if self.proxy else None,
                viewport=None,
                # Look less like an automated browser: Google outright blocks
                # OAuth from automation-flagged windows ("this browser or app
                # may not be secure"), and TikTok's own checks get cheaper too.
                args=['--disable-blink-features=AutomationControlled',
                      '--no-default-browser-check', '--no-first-run'],
                ignore_default_args=['--enable-automation'])
            try:
                ctx = p.chromium.launch_persistent_context(
                    self.profile_dir, channel='chrome', **launch)
            except Exception:
                # channel="chrome" needs system Chrome; fall back to bundled
                ctx = p.chromium.launch_persistent_context(self.profile_dir, **launch)
            try:
                ctx.add_init_script(
                    "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
                self._drive(ctx)
            finally:
                try:
                    ctx.close()
                except Exception:
                    pass

    def _drive(self, ctx):
        if self._cancel.is_set():
            self._set('cancelled', 'cancelled while opening browser')
            return
        self._set('waiting-login', 'log in to TikTok in the opened window '
                                   '(password / QR / captcha — anything works)')
        page = ctx.new_page()
        page.goto('https://www.tiktok.com/login', timeout=60000)

        # -- wait for the session cookie (login complete)
        # 30 min: fresh-environment logins often draw TikTok email/captcha
        # verification, and the mail-code endpoint rate-limits ("访问频繁")
        # for minutes at a time — 10 was not enough to wait that out.
        deadline = time.time() + 1800
        cookie_str = ''
        while time.time() < deadline:
            if self._cancel.is_set():
                return
            try:
                jars = ctx.cookies(['https://www.tiktok.com'])
            except Exception:
                jars = []
            names = {c['name'] for c in jars}
            if 'sessionid' in names and 'sessionid_ss' in names:
                cookie_str = '; '.join(
                    '%s=%s' % (c['name'], c['value']) for c in jars
                    if 'tiktok' in (c.get('domain') or ''))
                break
            time.sleep(2)
        else:
            self._set('error', 'no login detected within 10 minutes')
            return

        self._set('collecting', 'login detected — collecting materials')
        time.sleep(4)                       # let the security SDK initialize
        if self._cancel.is_set():
            return

        # -- wid from hydration data
        wid = None
        for _ in range(10):
            try:
                wid = page.evaluate(WID_JS)
            except Exception:
                wid = None
            if wid:
                break
            time.sleep(2)

        # -- materials from localStorage (ticket decrypted in-page)
        mats = None
        for _ in range(20):
            if self._cancel.is_set():
                return
            try:
                mats = page.evaluate(MATERIALS_JS)
            except Exception:
                mats = None
            if mats and not mats.get('error'):
                break
            time.sleep(3)
        if not mats or mats.get('error'):
            self._set('error', 'materials not readable: %s'
                      % (mats or {}).get('error', 'timeout'))
            return

        # -- verify + import exactly like a normal account
        from . import client as api
        from .client import signing
        info = api.verify_cookie(self.client, cookie_str)
        name = info['username'] or info['uid']
        sess = api.Session(
            cookie=cookie_str,
            device_id=wid or self.hub.config.get('default_device_id', ''),
            uid=info['uid'], username=info['username'],
            nickname=info['nickname'], region=info['region'],
            guard={}, ticket=mats['ticket'],
            private_key=signing.parse_private_key(mats['private_key']),
            ts_sign=mats['ts_sign'])
        prev = self.store.get_account(name)
        if prev:
            merged = api.Session.from_dict({**prev, 'cookie': sess.cookie,
                                            'device_id': sess.device_id})
            for k in ('ticket', 'private_key', 'ts_sign', 'guard'):
                v = getattr(sess, k if k != 'guard' else 'guard')
                if isinstance(v, dict):
                    setattr(merged, 'guard', v)
                elif v:
                    setattr(merged, k, v)
            sess = merged
        self.store.save_account(name, sess, info)
        self.hub.attach(name, sess)
        try:
            self.hub.sync_conversations(name)
        except Exception as e:
            self.hub._set_status(name, 'warn', 'initial sync failed: %s' % e)
        _, tier = api.ticket_guard_headers(sess, '/v1/message/send')
        self._set('done', 'imported %s (tier %s)'
                  % (name, tier or 'Z'))
