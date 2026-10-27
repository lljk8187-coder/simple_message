# -*- coding: utf-8 -*-
"""obb815 A/B 内容因素实验（10-27 用户批准）。
干净目标交替发送 短文案/商业话术，唯一变量=内容；记录每条 landed。"""
import sys, json, time, sqlite3, urllib.request, datetime, os

sys.path.insert(0, r'D:\wbtools\workspace\simple-message')

CID = 'f3a35874f271'
BASE = 'http://127.0.0.1:8788'
N = 13                      # 本轮实验目标数
INTERVAL = 16               # 与 jakson 触发时一致的节奏（秒）
LOG = r'D:\wbtools\workspace\simple-message\ab-experiment.log'

SHORT = 'Hi! Quick hello from our team \U0001F44B'
LONG = ('Hi! Love your content \u2014 the energy in your videos is exactly the style '
        'our brand looks for. \u2728\n'
        'We are a jewelry label working with creators on paid collabs: free product '
        'plus payment for a short feature video.\n'
        'If that sounds interesting, just reply Yes and I will send over the details!')


def log(msg):
    line = '%s | %s' % (datetime.datetime.now().astimezone().isoformat(timespec='seconds'), msg)
    print(line, flush=True)
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


def api(path, payload=None):
    req = urllib.request.Request(BASE + path, method='POST' if payload else 'GET')
    if payload:
        req.add_header('Content-Type', 'application/json')
        req.data = json.dumps(payload).encode()
    return json.load(urllib.request.urlopen(req, timeout=120))


con = sqlite3.connect(r'D:\wbtools\workspace\simple-message\data\hub.db')
con.row_factory = sqlite3.Row
targets = con.execute(
    "SELECT seq, peer_uid FROM dispatch_items WHERE campaign_id=? AND status IN ('queued','failed') "
    "AND peer_uid NOT LIKE '@%' ORDER BY seq LIMIT ?", (CID, N)).fetchall()
log('START obb815 A/B | 目标数: %d | 间隔: %ds' % (len(targets), INTERVAL))
# 预占位：立刻全部标记，防止 jakson 探测自动化并发抢同一目标（双发污染）
seqs = [t['seq'] for t in targets]
con.execute("UPDATE dispatch_items SET status='skipped', skip_reason='ab-obb815-reserved' "
            "WHERE campaign_id=? AND seq IN (%s)" % ','.join('?' * len(seqs)), [CID] + seqs)
con.commit()

res = {'short': [], 'long': []}
for i, t in enumerate(targets):
    kind = 'short' if i % 2 == 0 else 'long'
    text = SHORT if kind == 'short' else LONG
    t0 = time.time()
    try:
        r = api('/api/accounts/obb815/send-cold', {'target': t['peer_uid'], 'text': text})
        landed = bool(r.get('landed'))
        summary = 'stage=%s tier=%s guard=%s err=%s' % (
            r.get('stage'), r.get('tier'), r.get('guard_result'), str(r.get('error'))[:60])
    except Exception as e:
        landed, summary = None, 'NETWORK/HTTP fail: %s' % str(e)[:90]
    res[kind].append(landed)
    log('  #%d seq=%s uid=%s | %s | landed=%s | %.1fs | %s'
        % (i + 1, t['seq'], t['peer_uid'], kind, landed, time.time() - t0, summary))
    # 标记已消耗（防 resume 重复发送）
    con.execute("UPDATE dispatch_items SET status='skipped', skip_reason=?, error=? "
                "WHERE campaign_id=? AND seq=?",
                ('ab-obb815-' + kind, summary[:100], CID, t['seq']))
    con.commit()
    if i < len(targets) - 1:
        time.sleep(INTERVAL)

log('END | short: %s | long: %s' % (res['short'], res['long']))
s_ok, l_ok = res['short'].count(True), res['long'].count(True)
s_n, l_n = len(res['short']), len(res['long'])
if s_ok == s_n and l_ok == l_n:
    log('CONCLUSION: %d/%d 全通过（含商业话术）——新号配额>=%d，本轮未见内容差异' % (s_ok + l_ok, s_n + l_n, s_n + l_n))
elif s_ok == s_n and l_ok < l_n:
    log('CONCLUSION: 短文案 %d/%d 全过、商业话术 %d/%d 被拦——**内容因素实锤**（首次被拦位置见日志）'
        % (s_ok, s_n, l_ok, l_n))
else:
    log('CONCLUSION: 混合结果 short=%d/%d long=%d/%d——需人工分析' % (s_ok, s_n, l_ok, l_n))
