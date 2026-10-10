"""协议金丝雀（V1，2026-10-10 落地 09-30 设计案）。

定位：不加新网络层——挂在 hub 统一调用出口，把同步循环/前端轮询的
天然流量当作免费探测，按失败特征四分类，区分「要处理账号」与「要改
代码」。适配器/连接器零改动；分类失败不影响原调用（记录后原样上抛）。

四分类：
  auth      凭据失效（401/403/验证码/登录态关键词）→ 该账号需重登
  protocol  协议漂移（签名被拒/解析失败/意外结构）    → 代码要更新
  ratelimit 限流（429/频率窗口）                      → 正常，等待
  network   网络/代理（超时/SSL/连接拒绝）            → 检查代理出口

判定基于异常类型与消息特征匹配（越靠前的规则越优先）。未知异常归入
'unknown' 并保留原文——新的漂移形态先观察再补规则。
"""

import re
import time

# 分类规则：(类名, 编译好的特征)。顺序即优先级——auth 最先（401/403 的响应体
# 里可能带任何字样）；network 先于 protocol（SSL EOF 的 "UNEXPECTED_EOF" 会
# 撞上 protocol 的 "unexpected"，网络问题必须优先归类）。
_RULES = [
    ('ratelimit', re.compile(r'429|rate.?limit|flood|too many requests', re.I)),
    ('auth', re.compile(r'401|403|unauthorized|forbidden|need.?code|verification code'
                        r'|sessionid|登录态|登录已过期|cookie.*(失效|invalid|expired)', re.I)),
    ('network', re.compile(r'timeout|timed out|ssl|connection|refused|unreachable'
                           r'|proxy|urlerror|eof|reset|broken pipe|getaddrinfo', re.I)),
    ('protocol', re.compile(r'unexpected session|unexpected response|signature|a_bogus'
                            r'|verify.*(fail|error)|protobuf|parse|decode|keyerror'
                            r'|missing field|no such field|no attribute', re.I)),
]


def classify(exc):
    """异常 → ('auth'|'protocol'|'ratelimit'|'network'|'unknown', 摘要)。"""
    text = '%s: %s' % (type(exc).__name__, exc)
    for cls, pat in _RULES:
        if pat.search(text):
            return cls, text[:200]
    return 'unknown', text[:200]


class Canary:
    """每账号健康记录。内存态（重启归零可接受——金丝雀看的是近期趋势）。"""

    def __init__(self, keep_errors=20):
        self.keep_errors = keep_errors
        self.health = {}      # name -> {'status','last_ok','last_err','counts'}

    def _acct(self, name):
        return self.health.setdefault(name, {
            'status': 'unknown', 'last_ok': 0, 'last_err': None,
            'last_err_class': None, 'counts': {},
        })

    def record_ok(self, name):
        h = self._acct(name)
        h['status'] = 'ok'
        h['last_ok'] = time.time()

    def record_err(self, name, exc):
        cls, summary = classify(exc)
        h = self._acct(name)
        h['status'] = cls
        h['last_err'] = {'class': cls, 'summary': summary, 'ts': time.time()}
        h['counts'][cls] = h['counts'].get(cls, 0) + 1
        # 连续同类错误才升级为通道级信号；单次失败可能只是瞬时抖动

    def snapshot(self):
        """API 视图：每账号状态 + 距上次成功秒数 + 最近错误 + 计数。"""
        now = time.time()
        out = {}
        for name, h in self.health.items():
            entry = {
                'status': h['status'],
                'last_ok_ago': int(now - h['last_ok']) if h['last_ok'] else None,
                'last_error': h['last_err'],
                'counts': dict(h['counts']),
            }
            # 漂移信号：protocol 类错误出现即为红牌（代码要更新的唯一硬指标）
            entry['protocol_drift'] = h['counts'].get('protocol', 0) > 0
            out[name] = entry
        return out

    def drift_accounts(self):
        """返回出现 protocol 类错误的账号名列表（金丝雀报警口）。"""
        return [n for n, h in self.health.items()
                if h['counts'].get('protocol', 0) > 0]
