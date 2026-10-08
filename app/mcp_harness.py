"""MCP (Model Context Protocol) stdio server — 把消息中心的 HTTP API 暴露为
AI 可调用的工具（harness 接入层）。

定位与边界（分支 harness-mcp）：
- 只做 HTTP 转发：本进程不 import 项目模块、不直接碰 hub.db —— 与 hub 进程
  完全隔离，本进程崩溃不影响消息中心本身。
- 身份可追溯：每个请求都带 `X-Operator` 头（默认 mcp-harness），hub 的
  append-only 审计会把 AI 的每一步操作记成独立操作员（server.py 的 _actor()
  现成支持）。
- 写操作显式化：send_message 是真实发送；create_campaign 要求 AI 在参数里
  传 confirm=true（hub 侧还有一道同样校验，双重确认）。
- 登录 / 凭据 / harvest 端点刻意不暴露 —— AI 不应能启动浏览器登录流程或
  触碰凭据。

协议：MCP stdio transport = 换行分隔的 JSON-RPC 2.0（UTF-8）。
  initialize / notifications/initialized / tools/list / tools/call / ping。
  stdout 只输出 JSON-RPC；一切日志走 stderr。

运行（由 MCP 客户端拉起，stdio 挂接）：
  python -m app.mcp_harness
环境变量：
  HUB_BASE_URL   默认 http://127.0.0.1:8788
  HUB_TOKEN      hub 配置了 access_token 时必填（Bearer）
  HUB_OPERATOR   审计里的操作员名，默认 mcp-harness

WorkBuddy / Claude 系客户端的 mcp.json 配置示例：
  {"command": "<python>", "args": ["-m", "app.mcp_harness"], "cwd": "<项目根>"}
  注意本模块无第三方依赖，托管解释器即可运行。
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

SERVER_NAME = 'simple-message-harness'
SERVER_VERSION = '0.1.0'

BASE_URL = os.environ.get('HUB_BASE_URL', 'http://127.0.0.1:8788').rstrip('/')
TOKEN = os.environ.get('HUB_TOKEN', '')
OPERATOR = os.environ.get('HUB_OPERATOR', 'mcp-harness')
TIMEOUT_S = 15

PROTOCOL_VERSION = '2024-11-05'   # 兼容面最宽；客户端给什么版本就 echo 什么


def log(msg):
    print('[mcp-harness] %s' % msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- HTTP 转发

class HubError(Exception):
    def __init__(self, status, body):
        super().__init__('HTTP %s: %s' % (status, body[:300]))
        self.status = status
        self.body = body


def hub_request(method, path, body=None, query=None):
    url = BASE_URL + path
    if query:
        url += '?' + urllib.parse.urlencode(query)
    data = None
    headers = {'Accept': 'application/json',
               'X-Operator': OPERATOR}
    if TOKEN:
        headers['Authorization'] = 'Bearer ' + TOKEN
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode('utf-8')
        headers['Content-Type'] = 'application/json; charset=utf-8'
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        raise HubError(e.code, e.read().decode('utf-8', 'replace'))
    except urllib.error.URLError as e:
        raise HubError(0, 'hub unreachable: %s' % e.reason)


def call_tool(name, args):
    """工具分派。返回 (payload_dict, is_error)。"""
    try:
        if name == 'hub_health':
            status, body = hub_request('GET', '/api/health')
        elif name == 'list_accounts':
            status, body = hub_request('GET', '/api/accounts')
        elif name == 'list_conversations':
            _req(name, args, ['account'])
            status, body = hub_request(
                'GET', '/api/accounts/%s/conversations' % _quote(args['account']))
        elif name == 'get_history':
            _req(name, args, ['account', 'conv_id'])
            status, body = hub_request(
                'GET', '/api/accounts/%s/messages' % _quote(args['account']),
                query=_drop_none({'conv_id': args['conv_id'],
                                  'limit': args.get('limit'),
                                  'before_us': args.get('before_us')}))
        elif name == 'sync_account':
            _req(name, args, ['account'])
            status, body = hub_request(
                'POST', '/api/accounts/%s/sync' % _quote(args['account']), body={})
        elif name == 'mark_read':
            _req(name, args, ['account', 'conv_id'])
            status, body = hub_request(
                'POST', '/api/accounts/%s/read' % _quote(args['account']),
                body={'conv_id': args['conv_id']})
        elif name == 'send_message':
            _req(name, args, ['account', 'conv_id', 'text'])
            status, body = hub_request(
                'POST', '/api/accounts/%s/send' % _quote(args['account']),
                body={'conv_id': args['conv_id'], 'text': args['text']})
        elif name == 'create_campaign':
            _req(name, args, ['text', 'targets', 'confirm'])
            if args['confirm'] is not True:
                raise ValueError('confirm must be exactly true — this queues a '
                                 'real send to every target')
            status, body = hub_request(
                'POST', '/api/campaigns',
                body=_drop_none({'text': args['text'],
                                 'targets': args['targets'],
                                 'confirm': True,
                                 'batch_size': args.get('batch_size'),
                                 'interval_s': args.get('interval_s'),
                                 'schedule_ms': args.get('schedule_ms')}))
        elif name == 'list_campaigns':
            status, body = hub_request('GET', '/api/campaigns',
                                       query=_drop_none({'limit': args.get('limit')}))
        elif name == 'campaign_detail':
            _req(name, args, ['cid'])
            status, body = hub_request(
                'GET', '/api/campaigns/%s' % _quote(args['cid']))
        elif name == 'campaign_action':
            _req(name, args, ['cid', 'action'])
            if args['action'] not in ('pause', 'resume', 'cancel'):
                raise ValueError("action must be one of pause|resume|cancel")
            status, body = hub_request(
                'POST', '/api/campaigns/%s/%s' % (_quote(args['cid']), args['action']),
                body={})
        elif name == 'query_audit':
            status, body = hub_request(
                'GET', '/api/audit',
                query=_drop_none({'limit': args.get('limit'),
                                  'target': args.get('target'),
                                  'action': args.get('action')}))
        elif name == 'list_blocks':
            status, body = hub_request('GET', '/api/blocks')
        else:
            raise KeyError('unknown tool: %s' % name)
        payload = json.loads(body) if body.strip() else {'ok': True}
        if status >= 400:
            return payload, True
        return payload, False
    except HubError as e:
        try:
            return json.loads(e.body), True
        except Exception:
            return {'error': 'hub HTTP %s' % e.status, 'detail': e.body[:500]}, True
    except KeyError as e:
        return {'error': 'missing required argument: %s' % (e.args[0] if e.args else e)}, True
    except (ValueError, TypeError) as e:
        return {'error': str(e)}, True
    except Exception as e:
        return {'error': '%s: %s' % (type(e).__name__, e)}, True


def _req(name, args, required):
    if not isinstance(args, dict):
        raise ValueError('%s expects an object of arguments' % name)
    for key in required:
        if args.get(key) in (None, ''):
            raise KeyError(key)


def _quote(value):
    return urllib.parse.quote(str(value), safe='')


def _drop_none(d):
    return {k: v for k, v in d.items() if v is not None}


# ---------------------------------------------------------------- 工具清单

def _schema(props, required):
    return {'type': 'object', 'properties': props, 'required': required,
            'additionalProperties': False}


def tool_specs():
    send_note = ('REAL SEND. Goes through the same rate limits, blacklist and '
                 'dedup as the web UI. The operator name "%s" is recorded in '
                 'the hub audit log for every call.' % OPERATOR)
    return [
        {'name': 'hub_health', 'description':
            'Check the message hub is reachable. Returns account count and proxy. '
            'Read-only, no auth needed. Call this first to verify connectivity.',
         'inputSchema': _schema({}, [])},
        {'name': 'list_accounts', 'description':
            'List all connected accounts across platforms (tiktok/x/instagram/'
            'facebook) with status (ok/down), write tier and message stats.',
         'inputSchema': _schema({}, [])},
        {'name': 'list_conversations', 'description':
            'List conversations (chats) of one account, newest first. Read-only.',
         'inputSchema': _schema({'account': {'type': 'string',
                                             'description': 'account name from list_accounts'}},
                                ['account'])},
        {'name': 'get_history', 'description':
            'Fetch recent messages of one conversation. Read-only. '
            'Message kinds: text/tip/reaction/media/unknown.',
         'inputSchema': _schema({
             'account': {'type': 'string'},
             'conv_id': {'type': 'string'},
             'limit': {'type': 'integer', 'description': 'default 30', 'maximum': 100},
             'before_us': {'type': 'integer',
                           'description': 'pagination cursor from next_cursor'}},
             ['account', 'conv_id'])},
        {'name': 'sync_account', 'description':
            'Force a conversation-list refresh for one account right now. '
            'Use before get_history when you need the very latest state.',
         'inputSchema': _schema({'account': {'type': 'string'}}, ['account'])},
        {'name': 'mark_read', 'description':
            'Send a read receipt for a conversation (the peer will see "read").',
         'inputSchema': _schema({'account': {'type': 'string'},
                                 'conv_id': {'type': 'string'}},
                                ['account', 'conv_id'])},
        {'name': 'send_message', 'description':
            'Send one chat message from an account to a conversation. ' + send_note,
         'inputSchema': _schema({'account': {'type': 'string'},
                                 'conv_id': {'type': 'string'},
                                 'text': {'type': 'string', 'maxLength': 4000}},
                                ['account', 'conv_id', 'text'])},
        {'name': 'create_campaign', 'description':
            'Queue a bulk send of one text to many conversations. ' + send_note +
            ' Requires confirm=true explicitly; the queue is serial, rate-limited, '
            'deduped and blacklist-filtered.',
         'inputSchema': _schema({
             'text': {'type': 'string', 'maxLength': 4000},
             'targets': {'type': 'array', 'maxItems': 50, 'items': {
                 'type': 'object',
                 'properties': {'account': {'type': 'string'},
                                'conv_id': {'type': 'string'},
                                'label': {'type': 'string'}},
                 'required': ['account', 'conv_id']}},
             'confirm': {'type': 'boolean',
                         'description': 'must be exactly true'},
             'batch_size': {'type': 'integer', 'description': 'default 5'},
             'interval_s': {'type': 'integer', 'description': 'default 60'},
             'schedule_ms': {'type': 'integer',
                             'description': 'start later; 0 = start now'}},
             ['text', 'targets', 'confirm'])},
        {'name': 'list_campaigns', 'description':
            'List bulk-send campaigns with progress. Read-only.',
         'inputSchema': _schema({'limit': {'type': 'integer', 'maximum': 200}}, [])},
        {'name': 'campaign_detail', 'description':
            'Full detail of one campaign: config, progress, per-item results.',
         'inputSchema': _schema({'cid': {'type': 'string'}}, ['cid'])},
        {'name': 'campaign_action', 'description':
            'Pause / resume / cancel a queued campaign.',
         'inputSchema': _schema({'cid': {'type': 'string'},
                                 'action': {'type': 'string',
                                            'enum': ['pause', 'resume', 'cancel']}},
                                ['cid', 'action'])},
        {'name': 'query_audit', 'description':
            'Read the append-only audit log (every send, block change, campaign '
            'action, with operator name). Read-only. Filter by action e.g. '
            'message.send / campaign.create.',
         'inputSchema': _schema({'limit': {'type': 'integer', 'maximum': 500},
                                 'target': {'type': 'string'},
                                 'action': {'type': 'string'}}, [])},
        {'name': 'list_blocks', 'description':
            'List blacklisted peers (per platform / per account). Read-only.',
         'inputSchema': _schema({}, [])},
    ]


RULES = (
    'Usage rules: read-only tools are always safe. send_message and '
    'create_campaign send REAL messages from REAL accounts — never use them '
    'without the user\'s explicit intent, and never invent recipients. '
    'Bulk sending identical text to many peers looks like spam to platform '
    'risk control; prefer short target lists.'
)


# ---------------------------------------------------------------- JSON-RPC

def handle(msg):
    method = msg.get('method')
    msg_id = msg.get('id')
    is_notification = msg_id is None

    if method == 'initialize':
        client_ver = (msg.get('params') or {}).get('protocolVersion')
        return {'jsonrpc': '2.0', 'id': msg_id, 'result': {
            'protocolVersion': client_ver or PROTOCOL_VERSION,
            'capabilities': {'tools': {}},
            'serverInfo': {'name': SERVER_NAME, 'version': SERVER_VERSION}}}

    if method in ('notifications/initialized', 'initialized'):
        return None    # 纯通知，不回复

    if method == 'ping':
        return {'jsonrpc': '2.0', 'id': msg_id, 'result': {}}

    if method == 'tools/list':
        return {'jsonrpc': '2.0', 'id': msg_id, 'result': {
            'tools': tool_specs()}}

    if method == 'tools/call':
        params = msg.get('params') or {}
        payload, is_err = call_tool(params.get('name') or '',
                                    params.get('arguments') or {})
        return {'jsonrpc': '2.0', 'id': msg_id, 'result': {
            'content': [{'type': 'text',
                         'text': json.dumps(payload, ensure_ascii=False,
                                            default=str)}],
            'isError': is_err}}

    if is_notification:
        return None    # 未知通知忽略
    return {'jsonrpc': '2.0', 'id': msg_id, 'error':
            {'code': -32601, 'message': 'method not found: %s' % method}}


def serve():
    log('starting, hub=%s operator=%s token=%s'
        % (BASE_URL, OPERATOR, 'set' if TOKEN else 'not set'))
    out = sys.stdout.buffer
    for raw in sys.stdin.buffer:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line.decode('utf-8'))
        except Exception as e:
            log('unparseable line dropped: %s' % e)
            continue
        try:
            reply = handle(msg)
        except Exception as e:
            log('handler crash: %r' % e)
            if msg.get('id') is not None:
                reply = {'jsonrpc': '2.0', 'id': msg['id'],
                         'error': {'code': -32603, 'message': 'internal error'}}
            else:
                reply = None
        if reply is not None:
            out.write(json.dumps(reply, ensure_ascii=False).encode('utf-8'))
            out.write(b'\n')
            out.flush()
    log('stdin closed, bye')


if __name__ == '__main__':
    serve()
