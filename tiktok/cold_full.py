"""TikTok 陌生人冷建联 —— 纯协议全链路（单发 / 批量）。

用法:
    # 单发
    python tiktok/cold_full.py wikipedia "你好 {nickname}"
    # 批量（命令行列表）
    python tiktok/cold_full.py @user1 @user2 --text "hi {nickname}" --interval 12
    # 批量（文件：每行一个 username，可选 "username|专属文案"）
    python tiktok/cold_full.py --batch targets.txt --text "hi {nickname}"

可选参数:
    --account N     使用 hub.db 里的哪个账号会话（默认 jakson）
    --interval N    每条之间的最小间隔秒数（默认 10，叠加 ±25% 抖动）
    --out FILE      逐条结果写入 JSONL
    --no-verify     跳过 HTTP 回读验证（省一次请求，只看 ACK）
    --dry-run       只抓 uid / 建会话，不发送
    --limit N       最多发送 N 条

全链路（无浏览器、无 UI）：
    @username --SSR--> uid --cmd 609--> (conv_id, short_id) --WS--> 发送帧
    --> ACK(cmd 100, biz_code) --> HTTP 回读确认落地
"""
import argparse
import json
import os
import random
import re
import sys
import time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

from cold_probe import load_session
from tkws import build_frame, access_key, _cookie_val, wait_ack
from miniws import MiniWs
from app import client as cl

UNI_RE = re.compile(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', re.S)
SEQ = 10001          # SDK global counter start; verified accepted by the server


# ------------------------------------------------------------------ helpers

def scrape_uid(http, username, retries=2):
    """Profile page SSR -> {uid, nickname, unique_id} or {'error': ...}."""
    url = cl.WEB + '/@' + username
    for attempt in range(retries + 1):
        try:
            _status, raw, _hdrs = http.get(url)
        except Exception as e:
            if attempt == retries:
                return {'error': 'profile HTTP: %s' % str(e)[:60]}
            time.sleep(2)
            continue
        html = raw.decode('utf-8', 'ignore')
        m = UNI_RE.search(html)
        if not m:
            if attempt == retries:
                return {'error': 'no SSR block (bot wall?)'}
            time.sleep(2)
            continue
        try:
            data = json.loads(m.group(1))
            ui = data['__DEFAULT_SCOPE__']['webapp.user-detail']['userInfo']['user']
            uid = ui.get('id') or ui.get('id_str')
            if not uid:
                raise KeyError('id')
            return {'uid': str(uid), 'nickname': ui.get('nickname', ''),
                    'unique_id': ui.get('uniqueId', username)}
        except (KeyError, TypeError):
            if attempt == retries:
                return {'error': 'user-detail missing'}
            time.sleep(2)
    return {'error': 'unknown'}


def ws_path(sess):
    return ('/ws/v2?aid=1459&fpid=9&access_key=%s&device_platform=web&ttwid=%s&Web-Sdk-Ms-Token=%s'
            % (access_key(sess.device_id),
               quote(_cookie_val(sess.cookie, 'ttwid').replace('%7C', '|'), safe=''),
               quote(sess.ms_token, safe='')))


def open_ws(sess, proxy, retries=2):
    """One WS connection per message (proven path; reconnect beats multiplexing)."""
    headers = {'Cookie': sess.cookie, 'Origin': 'https://www.tiktok.com',
               'User-Agent': cl.UA_DEFAULT}
    last = None
    for attempt in range(retries + 1):
        try:
            ws = MiniWs('im-ws.tiktok.com', ws_path(sess), headers, proxy=proxy, timeout=15)
            ws.send_binary(b'hi')
            time.sleep(0.4)
            return ws
        except Exception as e:
            last = e
            time.sleep(2 + attempt * 2)
    raise ConnectionError('ws connect failed: %s' % str(last)[:80])


def render(template, prof):
    """Fill {nickname}/{unique_id}/{uid}; .replace avoids brace-escaping issues."""
    out = template
    for k, v in (('{nickname}', prof.get('nickname', '')),
                 ('{unique_id}', prof.get('unique_id', '')),
                 ('{uid}', str(prof.get('uid', '')))):
        out = out.replace(k, str(v or ''))
    return out


def verify(http, sess, conv_id, short_id, cid, retries=4):
    """Read the conversation back and look for our client_message_id."""
    for attempt in range(retries):
        try:
            msgs, _meta = cl.list_messages(http, sess, conv_id, short_id, limit=10)
            if any(m.get('cid') == cid for m in (msgs or [])):
                return True
        except Exception:
            pass
        if attempt < retries - 1:
            time.sleep(3)
    return False


def send_one(sess, http, proxy, prof, text, dry_run=False, do_verify=True):
    """One target end-to-end. Returns a result dict."""
    res = {'uid': prof.get('uid'), 'nickname': prof.get('nickname', ''),
           'unique_id': prof.get('unique_id', ''), 'text': text}
    t0 = time.time()
    try:
        conv = cl.create_conversation(http, sess, prof['uid'])
    except Exception as e:
        res.update(ok=False, stage='create', error=str(e)[:120])
        return res
    res.update(conv_id=conv['conv_id'], short_id=conv['short_id'])
    if dry_run:
        res.update(ok=True, stage='dry-run')
        return res

    try:
        ws = open_ws(sess, proxy)
    except Exception as e:
        res.update(ok=False, stage='ws-connect', error=str(e)[:120])
        return res

    ack = {}
    try:
        frame, cid, tier = build_frame(sess, conv['conv_id'], conv['short_id'], text, seq=SEQ)
        res['cid'] = cid
        ws.send_binary(frame)
        ack, _others = wait_ack(ws, seq=SEQ, cid=cid, timeout=12)
    except Exception as e:
        res.update(ok=False, stage='ws-send', error=str(e)[:120])
        res['elapsed'] = round(time.time() - t0, 1)
        return res
    finally:
        try:
            ws.close()
        except Exception:
            pass

    res.update(ack_kind=ack.get('kind'), biz_code=ack.get('biz_code'),
               biz_msg=ack.get('biz_msg'), msg_id=ack.get('msg_id'))
    if ack.get('kind') != 'ack':
        res.update(ok=False, stage='ack', error=ack.get('error') or 'no ACK in 12s')
    elif ack.get('biz_code') != 0:
        res.update(ok=False, stage='ack',
                   error='biz_code=%s %s' % (ack.get('biz_code'), ack.get('biz_msg')))
    else:
        res.update(ok=True, stage='ack')
        if do_verify:
            res['landed'] = verify(http, sess, conv['conv_id'], conv['short_id'], cid)
            if not res['landed']:
                # Measured 2026-10-21: a 2nd message to a not-yet-accepted
                # stranger still returns biz_code=0 but never lands. The drop is
                # invisible in the ACK, so read-back is the only reliable judge.
                res.update(ok=False, stage='verify',
                           error='ACK ok but dropped — 对方未接受前仅 1 条配额，'
                                 '重复发送/限流时服务端静默丢弃')
    res['elapsed'] = round(time.time() - t0, 1)
    return res


# ------------------------------------------------------------------ targets

def load_targets(args):
    """[(username, custom_text_or_None), ...] from positional args and --batch."""
    out = [(name.lstrip('@'), None) for name in args.targets]
    if args.batch:
        with open(args.batch, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '|' in line:
                    name, custom = line.split('|', 1)
                elif '\t' in line:
                    name, custom = line.split('\t', 1)
                else:
                    name, custom = line, ''
                out.append((name.strip().lstrip('@'), custom.strip() or None))
    return out


def main():
    ap = argparse.ArgumentParser(description='TikTok 陌生人冷建联（纯协议）')
    ap.add_argument('targets', nargs='*', help='@用户名 列表')
    ap.add_argument('--text', default='', help='消息模板，支持 {nickname} {unique_id} {uid}')
    ap.add_argument('--batch', help='目标文件，每行 username 或 username|专属文案')
    ap.add_argument('--account', default='jakson')
    ap.add_argument('--db', default='data/hub.db')
    ap.add_argument('--interval', type=float, default=10.0)
    ap.add_argument('--out', help='逐条结果写入 JSONL')
    ap.add_argument('--no-verify', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--limit', type=int, default=0)
    args = ap.parse_args()

    # 兼容老写法: cold_full.py wikipedia "文案"
    if len(args.targets) == 2 and not args.text and ' ' in args.targets[1]:
        args.text, args.targets = args.targets[1], args.targets[:1]
    if not args.targets and not args.batch:
        ap.error('至少给一个 @用户名 或 --batch 文件')
    if not args.text:
        args.text = 'hi {nickname}'

    targets = load_targets(args)
    if args.limit:
        targets = targets[:args.limit]

    sess = load_session(args.db, args.account)
    proxy = cl.detect_proxy() or 'http://127.0.0.1:10809'
    http = cl.HttpClient(proxy=proxy)
    print('[init] account=%s uid=%s proxy=%s targets=%d interval=%.0fs'
          % (args.account, sess.uid, proxy, len(targets), args.interval), flush=True)

    results = []
    out_fh = open(args.out, 'a', encoding='utf-8') if args.out else None
    for idx, (name, custom) in enumerate(targets, 1):
        tag = '[%d/%d] @%s' % (idx, len(targets), name)
        prof = scrape_uid(http, name)
        if not prof or prof.get('error') or not prof.get('uid'):
            res = {'unique_id': name, 'ok': False, 'stage': 'profile',
                   'error': (prof or {}).get('error', 'not found')}
        else:
            text = custom or render(args.text, prof)
            print('%s uid=%s (%s) -> %r'
                  % (tag, prof['uid'], prof.get('nickname'), text), flush=True)
            res = send_one(sess, http, proxy, prof, text,
                           dry_run=args.dry_run, do_verify=not args.no_verify)
        res['target'] = name
        results.append(res)
        if out_fh:
            out_fh.write(json.dumps(res, ensure_ascii=False) + '\n')
            out_fh.flush()
        if res.get('ok'):
            print('%s  OK  %s | cid=%s | msg_id=%s | landed=%s | %.1fs'
                  % (tag, res.get('stage'), str(res.get('cid', '-'))[:8],
                     res.get('msg_id', '-'), res.get('landed', '-'),
                     res.get('elapsed', 0)), flush=True)
        else:
            print('%s  FAIL %s | %s' % (tag, res.get('stage'), res.get('error')), flush=True)
        if idx < len(targets):
            time.sleep(args.interval * random.uniform(0.75, 1.25))

    if out_fh:
        out_fh.close()

    ok = sum(1 for r in results if r.get('ok'))
    print('\n===== 汇总: %d/%d 成功 =====' % (ok, len(results)))
    for r in results:
        if not r.get('ok'):
            print('  FAIL @%s [%s] %s' % (r.get('target'), r.get('stage'), r.get('error')))
    sys.exit(0 if ok == len(results) else 1)


if __name__ == '__main__':
    main()
