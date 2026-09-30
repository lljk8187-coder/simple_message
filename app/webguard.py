"""webguard.py — TikTok Web 风控参数层：X-Bogus 经典算法完整复刻 + msToken 策略封装。

=======================================================================
实证结论（2026-09-30，js-reverse MCP 实测 TikTok 线上，Chrome/154 真实会话）
=======================================================================
1. X-Bogus 已在现行 web 端退役：
   - www.tiktok.com/api/* 与 mssdk.tiktokw.us 真实流量中 X-Bogus 均为字面常量 "1"；
   - 真正的新签名是 X-Gnarly（~500 字符），由 VM 混淆的 webmssdk_ex.js 2.0.0.1667 生成；
   - window.byted_acrawler 公开 API 已无 sign()（仅剩 frontierSign/registerWsSigner/report 等），
     即经典 X-Bogus 生成器已从线上 SDK 移除；
   - 与之互证：本项目 mark_read 用随机 24 位 X-Bogus 一直被服务端接受（E2E 已验证）。
2. msToken 不是客户端"算"出来的，是服务端发证：
   - 首发: GET  mssdk.tiktokw.us/web/resource?eq=<SDK 加密 blob> → Set-Cookie: msToken
   - 续发: POST mssdk.tiktokw.us/web/report  body={"magic":538969122,"version":1,
           "dataType":8,"strData":"<~10KB 加密环境报告>"} → Set-Cookie: msToken
   - 轮转: 之后每个 API 响应都 Set-Cookie 一个新 msToken（一次页面加载实测轮转 19+ 次），
     客户端始终取 cookie 里最新值回填到请求；
   - Cookie 属性（实测）: Max-Age/Expires=10 天, Secure, SameSite=None，
     domain 随发证域（tiktokw.us 及各 API 域各持一份）；
   - 真正难复刻的是 strData 加密报告本体（webmssdk VM 混淆）；token 值是服务端随机发的。
3. im-api.tiktok.com（本项目实际调用的接口）真实请求最"干净"：
   - URL 无查询串 —— 没有 X-Bogus、没有 X-Gnarly、URL 里连 msToken 都不放；
   - msToken 放在 protobuf 请求体 params 字段 Web-Sdk-Ms-Token；verifyFp 为空；
   - 本项目现状（查询串 msToken + 随机 X-Bogus）实测同样被服务端接受。

模块定位（诚实边界）：
- x_bogus(): 逐字节保真复刻经典算法（移植自公开语料参考实现 yvbbrjdr/X-Bogus.py gist，
  经 1000 组随机用例差分一致 + 固定向量金标准对齐），供 legacy 端点、
  或未来服务端恢复校验时启用；对现行 TikTok web 接口无增益（服务端不校验）。
- msToken 层：只封装"获取与维持策略"（提取/形态校验/过期/发证常量），
  不提供"凭空生成真 msToken"——那在密码学上不可行，绕过它需要复刻 VM 混淆的报告生成器。

自检方式（python -m app.webguard 或 python app/webguard.py）：
- 两组合金标准向量（时间戳/UA/查询串固定 → 输出必须逐字符一致）；
  金标准由未改动的参考实现在冻结时钟下产出（当前线上已无真实 X-Bogus 可抓包对齐——
  官方客户端自己都发常量 "1"，见实证结论 1）；
- 结构自检：输出恒为 28 字符、字符集校验、解码回字节后首两字节必为 [2, 255]；
- --reference <path> 差分模式：加载任意外部参考实现做 N 组随机用例逐字节比对。

常见校验失败细节（在"服务端确实校验"的端点上才需要关注）：
- 参数顺序：X-Bogus 覆盖的是"发出去的那一串"查询串原文，发出前重排参数即失效；
- URL 编码：签什么发什么——%20 与 +、大小写 hex、保留字符是否转义必须前后一致；
- 空值处理：GET 场景 form='' 不是"不参与"，md5(md5(b'')) 是固定盐值，漏掉即错；
- 时间戳：嵌入 ts 为秒级 int(time.time())，时钟漂移过大会被拒；
- UA：参与运算的 UA 必须与请求头 User-Agent 逐字节一致（含括号内空格）；
- 拼接顺序：X-Bogus 作为最后一个查询参数以 & 追加（官方行为）；
- msToken：cookie 缺失/过期/截断，或查询串里的值与 cookie 值不一致。
"""

from __future__ import annotations

import base64
import functools
import hashlib
import secrets
import string
import time
from urllib.parse import parse_qs, urlparse

__all__ = [
    'x_bogus', 'append_x_bogus', 'extract_ms_token', 'ms_token_looks_real',
    'fake_ms_token', 'append_ms_token',
    'MS_TOKEN_MAX_AGE_S', 'MSSDK_REPORT_MAGIC', 'MSSDK_REPORT_URL', 'MSSDK_RESOURCE_URL',
]

# ---------------------------------------------------------------- X-Bogus --

# 自定义 base64 字母表（网上标准表被替换过，这就是"伪标准 base64"的坑）
_X_BOGUS_SHORT_STR = 'Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe='
# UA 的 RC4 密钥：['\x00', '\x01', '\x0e']
_X_BOGUS_UA_KEY = ['\u0000', '\u0001', '\u000e']
# 魔数尾部（4 字节常量）
_X_BOGUS_MAGIC_TAIL = (88, 194, 176, 26)
# 前缀版本标记：编码进 token 的头两个字节
_X_BOGUS_PREFIX = (2, 255)
# 奇偶交错后重排用的下标序列
_REINDEX = (0, 10, 1, 11, 2, 12, 3, 13, 4, 14, 5, 15, 6, 16, 7, 17, 8, 18, 9)


def _rc4(key: str, data: str) -> bytearray:
    """逐字节保真移植参考实现的 RC4（_0x30492c）：按 ord() 取字符值。"""
    d = list(range(256))
    c = 0
    for i in range(256):
        c = (c + d[i] + ord(key[i % len(key)])) % 256
        e = d[i]
        d[i] = d[c]
        d[c] = e
    t = 0
    c = 0
    ret = bytearray(len(data))
    for i, ch in enumerate(data):
        t = (t + 1) % 256
        c = (c + d[t]) % 256
        e = d[t]
        d[t] = d[c]
        d[c] = e
        ret[i] = ord(ch) ^ d[(d[t] + d[c]) % 256]
    return ret


def _double_md5_bytes(text: str) -> bytes:
    """md5(md5(text).digest()) —— 参考实现里 payload/form 各做一次双重 MD5。"""
    return hashlib.md5(hashlib.md5(text.encode()).digest()).digest()


def _arr2(payload: str, ua: str, form: str, ts: int) -> list[int]:
    salt_payload = list(_double_md5_bytes(payload))              # 查询串盐：双重 MD5 取 [14],[15]
    salt_form = list(_double_md5_bytes(form))                    # GET 时 form=''，是固定盐不是"不参与"
    salt_ua = list(hashlib.md5(                                  # UA 盐：RC4 → 标准base64 → 单次 MD5
        base64.b64encode(_rc4(_X_BOGUS_UA_KEY, ua))).digest())
    arr1 = [
        64, 0, 1, 14,                                            # 定长头
        salt_payload[14], salt_payload[15],
        salt_form[14], salt_form[15],
        salt_ua[14], salt_ua[15],
        (ts >> 24) & 255, (ts >> 16) & 255, (ts >> 8) & 255, ts & 255,   # 时间戳 4 字节大端
        *_X_BOGUS_MAGIC_TAIL,
    ]
    arr1.append(functools.reduce(lambda a, b: a ^ b, arr1))      # XOR 校验和（第 19 字节）
    return arr1[::2] + arr1[1::2]                                # 奇偶位交错重排


def _garbled(arr2: list[int]) -> bytearray:
    p = bytes(arr2[i] for i in _REINDEX)                          # 再重排一次
    body = _rc4('\u00ff', ''.join(chr(i) for i in p))             # 密钥 ['ÿ'] = 单字节 255
    return bytearray(_X_BOGUS_PREFIX) + body                      # 21 字节（含 [2,255] 头）


def x_bogus(url_or_query: str, user_agent: str,
            timestamp: int | None = None, form: str = '') -> str:
    """计算经典 X-Bogus（28 字符）。

    url_or_query: 完整 URL（取 ? 后部分）或裸查询串原文——
                  必须与实际发出的查询串逐字节一致（不重排、不再编码）。
    user_agent:   必须与请求头 User-Agent 逐字节一致。
    timestamp:    秒级时间戳；None 则取当前时间（测试时固定它）。
    form:         POST 表单原文；GET 传 ''（默认）。
    """
    q = url_or_query.split('?', 1)[1] if '?' in url_or_query else url_or_query
    ts = int(timestamp) if timestamp is not None else int(time.time())
    g = _garbled(_arr2(q, user_agent, form, ts))
    ret = []
    for i in range(0, 21, 3):                                     # 21 字节 → 7 组 × 4 字符 = 28
        base_num = g[i] << 16 | g[i + 1] << 8 | g[i + 2]
        for j in range(18, -1, -6):
            ret.append(_X_BOGUS_SHORT_STR[(base_num >> j) & 63])
    return ''.join(ret)


def append_x_bogus(url: str, user_agent: str,
                   timestamp: int | None = None, form: str = '') -> str:
    """按官方行为把 X-Bogus 以最后一个查询参数追加到 URL。"""
    return f'{url}&X-Bogus={x_bogus(url, user_agent, timestamp, form)}'


# ----------------------------------------------------------------- msToken --
# msToken 是服务端签发的会话级随机值（见模块头"实证结论 2"），客户端职责只有：
#   ①带着真会话收 Set-Cookie（浏览器登录/页面加载天然完成）；
#   ②每次请求回填 cookie 里的最新值；
#   ③注意 10 天有效期——离线冻结的 cookie jar 过期后必须重新走页面登录收割。

MS_TOKEN_MAX_AGE_S = 10 * 86400          # 实测 Set-Cookie: expires=+10 天
MSSDK_REPORT_MAGIC = 538969122           # 实测 web/report 请求体 magic 字段
MSSDK_REPORT_URL = 'https://mssdk.tiktokw.us/web/report'
MSSDK_RESOURCE_URL = 'https://mssdk.tiktokw.us/web/resource'
# 实测真实 msToken 形态：base64url 字符集、以 "==" 结尾、长度 148~172（不同端点略异）
_MS_TOKEN_CHARS = frozenset(string.ascii_letters + string.digits + '_-=')


def extract_ms_token(cookie_header: str | dict) -> str | None:
    """从 Cookie 头字符串（或 dict）里提取 msToken；没有则 None。"""
    if isinstance(cookie_header, dict):
        return cookie_header.get('msToken')
    for part in cookie_header.split(';'):
        name, _, value = part.strip().partition('=')
        if name == 'msToken' and value:
            return value
    return None


def ms_token_looks_real(token: str | None) -> bool:
    """形态校验（非服务端校验）：base64url 字符集、== 结尾、长度在实测区间。"""
    if not token:
        return False
    return (96 <= len(token) <= 200 and token.endswith('==')
            and set(token) <= _MS_TOKEN_CHARS)


def fake_ms_token(length: int = 148) -> str:
    """生成形态逼真的伪 msToken。

    ⚠️ 仅用于占位/测试：这是随机值，不是服务端签发，强校验端点会拒绝；
    本项目 TikTok 通道请始终用浏览器会话 cookie 里的真值（Session.ms_token）。
    """
    body = ''.join(secrets.choice(string.ascii_letters + string.digits + '_-')
                   for _ in range(max(4, length - 2)))
    return body + '=='


def append_ms_token(url: str, token: str) -> str:
    """把 msToken 以查询参数追加（配合 quote 使用；本项目 client.py 已内建同等逻辑）。"""
    from urllib.parse import quote
    return f'{url}&msToken={quote(token)}'


# ------------------------------------------------------------------ 自检 ----

# 金标准向量：由未改动的公开参考实现（yvbbrjdr/X-Bogus.py gist 8d41ac82）
# 在冻结时钟下产出。当前线上已无真实 X-Bogus 生成器可抓包对齐（官方客户端发常量 "1"），
# 这是对齐公开语料的"已知参数→已知输出"测试。
_GOLDEN_V1 = {
    'ts': 1790754167,
    'query': ('aid=1988&version_code=1.0.0&app_name=tiktok_web&device_platform=web_pc'
              '&msToken=121Elz2y2OyHF_e3oXv2kWGyY7JgLIYaSzsujVxeJ80PU58UWh3xZvh7yWWjpSVUa79'
              'GixTn8bTsVqfRVYnLU7r5v3Nv5gr83l2w4HvkEldOJrmZKfgXzaYFVDNs6NmV1OK41BYp8eId5xXp'
              'coKrlxCgJruXsdEHWceXQmBtxg=='),
    'ua': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
           '(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36'),
    'expect': 'DFSzswVO6bbANSP9CfiG4KXAIQ5M',
}
_GOLDEN_V2 = {
    'ts': 1700000000,
    'query': 'aid=1988&device_platform=web_pc',
    'ua': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
           '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
    'expect': 'DFSzswVO4hbANy5ntmWx-VXAIQ-I',
}


def _self_test() -> int:
    failures = 0
    for tag, v in (('V1', _GOLDEN_V1), ('V2', _GOLDEN_V2)):
        got = x_bogus(v['query'], v['ua'], timestamp=v['ts'])
        ok = got == v['expect']
        failures += (not ok)
        print(f'[{ "PASS" if ok else "FAIL" }] 金标准{tag}: {got}'
              + ('' if ok else f'  != 期望 {v["expect"]}'))

    got_url = append_x_bogus('https://www.tiktok.com/api/test/?' + _GOLDEN_V2['query'],
                             _GOLDEN_V2['ua'], timestamp=_GOLDEN_V2['ts'])
    ok = got_url.endswith('&X-Bogus=' + _GOLDEN_V2['expect'])
    failures += (not ok)
    print(f'[{"PASS" if ok else "FAIL"}] append_x_bogus 拼接位置与值')

    # 结构自检：28 字符、字符集合法、解码回首字节必为 [2, 255]
    ok = (len(_GOLDEN_V1['expect']) == 28
          and set(_GOLDEN_V1['expect']) <= set(_X_BOGUS_SHORT_STR[:64]))
    failures += (not ok)
    print(f'[{"PASS" if ok else "FAIL"}] 输出形态: 28 字符 + 自定义字母表')

    rev = {ch: i for i, ch in enumerate(_X_BOGUS_SHORT_STR[:64])}
    head = []
    e = _GOLDEN_V1['expect']
    for i in range(0, 21, 3):
        n = (rev[e[i]] << 18) | (rev[e[i + 1]] << 12) | (rev[e[i + 2]] << 6) | rev[e[i + 3]]
        head.extend([(n >> 16) & 255, (n >> 8) & 255, n & 255])
    ok = head[0] == 2 and head[1] == 255
    failures += (not ok)
    print(f'[{"PASS" if ok else "FAIL"}] 解码回字节: 前缀 {head[:2]} == [2, 255]')

    # msToken 层自检
    raw = ('tt_chain_token=abc; msToken=121Elz2y2OyHF_e3oXv2kWGyY7JgLIYaSzsujVxeJ80PU58UWh3'
           'xZvh7yWWjpSVUa79GixTn8bTsVqfRVYnLU7r5v3Nv5gr83l2w4HvkEldOJrmZKfgXzaYFVDNs6NmV1O'
           'K41BYp8eId5xXpcoKrlxCgJruXsdEHWceXQmBtxg==; sid_tt=xyz')
    tok = extract_ms_token(raw)
    ok = tok is not None and tok.endswith('==') and ms_token_looks_real(tok)
    failures += (not ok)
    print(f'[{"PASS" if ok else "FAIL"}] extract_ms_token 从 Cookie 头提取 + 形态校验 '
          f'(len={len(tok or "")})')

    ok = ms_token_looks_real(fake_ms_token()) and not ms_token_looks_real('short')
    failures += (not ok)
    print(f'[{"PASS" if ok else "FAIL"}] fake_ms_token 形态 / 弱值拒绝')

    print('自检结果:', '全部通过' if failures == 0 else f'{failures} 项失败')
    return failures


def _diff_reference(path: str, n: int = 1000) -> int:
    """差分模式：与外部参考实现逐字节比对 N 组随机用例（用于移植验证）。"""
    import importlib.util
    import random as _rnd
    spec = importlib.util.spec_from_file_location('_ref', path)
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)

    alphabet = string.ascii_letters + string.digits + '=&%.-_~+'
    rng = _rnd.Random(20260930)
    real_time = time.time
    mismatches = 0
    for case in range(n):
        q = ''.join(rng.choice(alphabet) for _ in range(rng.randint(1, 300)))
        ua = ''.join(rng.choice(string.printable[:94]) for _ in range(rng.randint(10, 200)))
        ts = rng.randint(1_000_000_000, 2_500_000_000)
        time.time = lambda t=ts: t          # 冻结参考实现的时钟
        try:
            want = ref.x_bogus('https://x.test/?' + q, ua)
        finally:
            time.time = real_time
        got = x_bogus(q, ua, timestamp=ts)
        if got != want:
            mismatches += 1
            if mismatches <= 3:
                print(f'MISMATCH #{case}: got={got} want={want}\n  q={q!r}\n  ua={ua!r} ts={ts}')
    print(f'差分 {n} 组随机用例: {"全部一致" if mismatches == 0 else f"{mismatches} 组不一致"}')
    return mismatches


if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 3 and sys.argv[1] == '--reference':
        sys.exit(1 if _diff_reference(sys.argv[2]) else 0)
    sys.exit(1 if _self_test() else 0)
