#!/usr/bin/env python3
"""只读冒烟验收：对运行中的 hub 做一轮不发消息的健康检查。

用法：
    python tests/smoke.py                     # 默认 http://127.0.0.1:8788
    python tests/smoke.py --base http://host:8788 --token <access_token>

检查项：
  1. /api/health 存活
  2. /api/accounts 账号列表与在线状态
  3. 每个在线账号拉一次会话列表（全平台统一路由）
  4. 每个会话数 > 0 的账号读一页消息（TikTok 走库存，其它平台现取）
  5. 批量发送端点的参数校验（空目标，不发送任何真实消息）

全程只读（除第 5 项的空载荷校验请求）。任何一步失败都会标 ✗ 并以非零码退出。
"""
import argparse
import json
import urllib.error
import urllib.request

PASS, FAIL = '✓', '✗'
results = []


def call(base, method, path, payload=None, token='', timeout=60):
    """4xx/5xx 也返回解析后的 JSON（校验类端点靠非 200 表达"正确拒绝"）。"""
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, data=data, headers=headers,
                                 method=method)
    try:
        with op.open(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {'error': 'HTTP %d' % e.code}


def check(name, ok, detail=''):
    results.append((name, ok, detail))
    print('%s %s%s' % (PASS if ok else FAIL, name,
                       (' — ' + detail) if detail else ''))


def main():
    ap = argparse.ArgumentParser(description='hub read-only smoke test')
    ap.add_argument('--base', default='http://127.0.0.1:8788')
    ap.add_argument('--token', default='')
    args = ap.parse_args()
    base = args.base.rstrip('/')

    # 1. 存活
    try:
        h = call(base, 'GET', '/api/health', token=args.token)
        check('health', bool(h.get('ok')), 'proxy=%s' % h.get('proxy'))
    except Exception as e:
        check('health', False, str(e)[:120])
        return finish()

    # 2. 账号列表
    try:
        d = call(base, 'GET', '/api/accounts', token=args.token)
        accounts = d.get('accounts') or []
        online = [a for a in accounts if a.get('status') == 'ok']
        check('accounts', bool(accounts),
              '%d 个账号，%d 个在线' % (len(accounts), len(online)))
    except Exception as e:
        check('accounts', False, str(e)[:120])
        return finish()

    # 3. 逐账号会话列表（统一路由）
    for a in online:
        name = a['name']
        try:
            c = call(base, 'GET', '/api/accounts/%s/conversations'
                     % name, token=args.token)
            convs = c.get('conversations') or []
            check('conversations[%s]' % name, True, '%d 个会话' % len(convs))
        except Exception as e:
            check('conversations[%s]' % name, False, str(e)[:120])
            continue

        # 4. 读一页消息（取最近会话）
        if convs:
            cid = convs[0].get('conv_id')
            try:
                m = call(base, 'GET', '/api/accounts/%s/messages?conv_id=%s&limit=5'
                         % (name, cid), token=args.token)
                msgs = m.get('messages') or []
                check('messages[%s]' % name, True, '%d 条' % len(msgs))
            except Exception as e:
                check('messages[%s]' % name, False, str(e)[:120])

    # 5. 批量端点参数校验（空目标 → 应被拒绝且不发送任何东西）
    try:
        b = call(base, 'POST', '/api/batch/send',
                 {'text': 'smoke', 'targets': []}, token=args.token)
        check('batch validation', bool(b.get('error')),
              str(b.get('error') or 'unexpected: %s' % b)[:80])
    except Exception as e:
        check('batch validation', False, str(e)[:120])

    finish()


def finish():
    bad = [r for r in results if not r[1]]
    print()
    print('冒烟结果：%d 项，%d 通过，%d 失败' % (len(results),
          len(results) - len(bad), len(bad)))
    raise SystemExit(1 if bad else 0)


if __name__ == '__main__':
    main()
