"""浏览器登录 —— 四平台共用的一套流程（平台差异由适配器声明）。

流程：开一个带持久化 profile 的 headful Chrome → 打开该平台的登录页 →
你在窗口里登录（密码 / 扫码 / 验证码都行，浏览器原生处理）→ 驱动轮询
cookie，等"登录完成判据"（spec.required_cookies 全部出现）成立 → 抓该域的
cookie 串 →（可选）调用适配器的 collect_materials 在**页面内**收割额外材料
（如 TikTok 的 ticket / 私钥 / ts_sign）→ 统一交给
`hub.add_account(platform, fields)` 落库 —— 与手工导入完全同一条路径，
所以两条入口不会分叉。

平台差异**不含任何 if**：全部来自 `PlatformAdapter.popup_login_spec()`：
  login_url / required_cookies / cookie_domains / hint / collect_materials

profile 按平台分目录（<profile_root>/<platform>），各站登录态互不污染；
profile_root 由 server 传入（跟随 --data-dir），所以换库即换浏览器身份。

唯一依赖是 playwright（pip install playwright）。浏览器优先用系统 Chrome
（channel="chrome"），拿不到才回落内置 chromium。缺少 playwright 时本模块
只报安装提示，不影响内核。
"""
import asyncio
import os
import sys
import threading
import time
from urllib.parse import urlsplit

# 等登录完成的时长：新环境登录常触发邮箱/验证码验证，而这些端点会限流
#（"访问频繁"可能要等好几分钟），10 分钟不够，给 30 分钟。
LOGIN_WAIT_S = 1800


class BrowserLogin:
    """一次 headful 登录窗口 → 一个账号落库。按平台可重复使用。"""

    def __init__(self, store, hub, client, profile_root, proxy=None):
        self.store = store
        self.hub = hub
        self.client = client
        self.profile_root = profile_root
        self.proxy = proxy
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self.state = {'phase': 'idle', 'detail': '', 'ts': 0, 'platform': ''}

    # ---------------------------------------------------------------- state

    def _set(self, phase, detail='', platform=None, **extra):
        with self._lock:
            st = {'phase': phase, 'detail': detail,
                  'ts': int(time.time() * 1000),
                  'platform': (platform if platform is not None
                               else self.state.get('platform') or '')}
            st.update(extra)
            self.state = st

    def get_state(self):
        with self._lock:
            return dict(self.state)

    # ------------------------------------------------------------ control

    def spec_for(self, platform):
        """取平台的弹窗登录声明；不支持时返回 None。"""
        try:
            ad = self.hub.adapter(platform)
        except Exception:
            return None
        try:
            return ad.popup_login_spec()
        except Exception:
            return None

    def start(self, platform='tiktok'):
        spec = self.spec_for(platform)
        if not spec:
            self._set('error', '%s 不支持浏览器登录' % platform, platform)
            return False, self.get_state()
        with self._lock:
            if self.state['phase'] in ('starting', 'waiting-login',
                                       'collecting'):
                return False, dict(self.state)
            self._cancel.clear()
        self._set('starting', 'launching chrome', platform)
        threading.Thread(target=self._run, args=(platform, spec),
                         daemon=True).start()
        return True, self.get_state()

    def cancel(self):
        self._cancel.set()
        self._set('cancelled', 'cancelled by user')

    # ----------------------------------------------------------- the flow

    def _run(self, platform, spec):
        try:
            from playwright.sync_api import sync_playwright       # noqa: F401
        except ImportError:
            self._set('error', 'playwright is not installed — run: '
                               'pip install playwright', platform)
            return
        # Windows 上 twikit（由 xconnect 导入）会把全局事件循环策略改成
        # WindowsSelectorEventLoopPolicy，而 Selector 循环不支持创建子进程 ——
        # playwright 恰恰靠子进程拉起自己的驱动，于是
        # asyncio.base_events._make_subprocess_transport 抛 NotImplementedError
        #（表现：点一下按钮、一秒内就报红）。
        # 在这里临时切回 Proactor，用完恢复：twikit 的 loop 早已建好不受影响，
        # 恢复后 twikit 之后新建的 loop 仍拿到它期望的 Selector。
        saved_policy = None
        if sys.platform == 'win32':
            try:
                saved_policy = asyncio.get_event_loop_policy()
                asyncio.set_event_loop_policy(
                    asyncio.WindowsProactorEventLoopPolicy())
            except Exception:
                saved_policy = None
        try:
            self._collect(platform, spec)
        except Exception as e:
            # 带调用栈：这条链路穿过 playwright 与三个平台库，只报类名无法定位
            #（曾出现消息为空的 NotImplementedError，无法判断是谁抛的）。
            import traceback
            tb = traceback.format_exc()
            print('[login/%s] %s' % (platform, tb), flush=True)
            lines = [l.strip() for l in tb.splitlines()
                     if l.strip() and not l.strip().startswith('Traceback')]
            tail = ' <- '.join(lines[-3:])[:300]
            self._set('error', '%s: %s  %s' % (type(e).__name__, e, tail),
                      platform)
        finally:
            if saved_policy is not None:
                try:
                    asyncio.set_event_loop_policy(saved_policy)
                except Exception:
                    pass

    def _collect(self, platform, spec):
        from playwright.sync_api import sync_playwright

        profile_dir = os.path.join(self.profile_root, platform)
        os.makedirs(profile_dir, exist_ok=True)
        self._set('starting', 'launching chrome', platform)
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
                    profile_dir, channel='chrome', **launch)
            except Exception:
                # channel="chrome" needs system Chrome; fall back to bundled
                ctx = p.chromium.launch_persistent_context(profile_dir, **launch)
            try:
                ctx.add_init_script(
                    "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
                self._drive(ctx, platform, spec)
            finally:
                try:
                    ctx.close()
                except Exception:
                    pass

    def _drive(self, ctx, platform, spec):
        if self._cancel.is_set():
            self._set('cancelled', 'cancelled while opening browser', platform)
            return

        required = tuple(spec.get('required_cookies') or ())
        domains = tuple(spec.get('cookie_domains') or ())
        origin = '{0.scheme}://{0.netloc}'.format(urlsplit(spec['login_url']))

        self._set('waiting-login',
                  spec.get('hint') or ('log in to %s in the opened window'
                                       % origin), platform)
        page = ctx.new_page()
        page.goto(spec['login_url'], timeout=60000)

        # -- 等登录判据成立（required_cookies 全部出现）
        deadline = time.time() + LOGIN_WAIT_S
        cookie_str = ''
        while time.time() < deadline:
            if self._cancel.is_set():
                self._set('cancelled', 'cancelled during login', platform)
                return
            try:
                jars = ctx.cookies()
            except Exception:
                jars = []
            names = {c['name'] for c in jars}
            if required and all(r in names for r in required):
                keep = [c for c in jars
                        if not domains
                        or any(d in (c.get('domain') or '') for d in domains)]
                cookie_str = '; '.join('%s=%s' % (c['name'], c['value'])
                                       for c in keep)
                break
            time.sleep(2)
        else:
            self._set('error', 'no login detected within %d minutes'
                      % (LOGIN_WAIT_S // 60), platform)
            return

        fields = {'cookie': cookie_str}

        # -- 平台专属材料收割（可选；必须跑在页面上下文里）
        hook = spec.get('collect_materials')
        if hook:
            self._set('collecting', 'login detected — collecting materials',
                      platform)
            extra = hook(page, ctx, cookie_str)
            if extra:
                fields.update(extra)

        # -- 与手工导入同一条落库路径
        res = self.hub.add_account(platform, fields) or {}
        if res.get('need_code'):
            self._set('need-code',
                      res.get('detail') or '验证码需要手动输入', platform,
                      pending_id=res.get('pending_id'))
            return
        self._set('done', 'imported %s' % (res.get('name') or '?'), platform)
