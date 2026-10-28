# -*- coding: utf-8 -*-
"""把受控浏览器抓到的 17 页 get_by_user_init 响应离线解析，灌入 hub 库。
一次性存量修复：hub HTTP 通道无法复现官方的 SDK 会话分页（10-28 实测），
老会话（10-12/10-13 手动发送的）掉出接口第一页后在 hub 永久不可见。
灌入后由 cmd 204 增量流维持，不会再丢。"""
import sys, glob, sqlite3, time
sys.path.insert(0, r'D:\wbtools\workspace\simple-message')
from app import client as api
pb = api.pb

UID = '7676292495719728141'          # jakson
ACCOUNT = 'jakson'
now = int(time.time() * 1000)

convs = {}
msgs = []
files = sorted(glob.glob(r'D:\wbtools\workspace\dy-recon\init-pages\*.bin'))
print('页面文件:', len(files))
for fp in files:
    body = open(fp, 'rb').read()
    if len(body) < 200:
        continue                      # 空页
    top = pb.parse(body)
    f6 = pb.blob(top, 6)
    if not f6:
        continue
    b203 = pb.blob(pb.parse(f6), 203)
    if not b203:
        continue
    inner = pb.parse(b203)
    # 消息条目 → newest per conv
    newest = {}
    for entry in pb.all_of(inner, 1):
        m = api.parse_message(entry[3], UID)
        if not m or not m.get('conv_id'):
            continue
        cur = newest.get(m['conv_id'])
        if cur is None or m['ms'] > cur['ms']:
            newest[m['conv_id']] = m
    msgs.extend(newest.values())
    # 会话容器
    for entry in pb.all_of(inner, 2):
        it = pb.parse(entry[3])
        conv_id = pb.text(pb.blob(it, 1)) or ''
        if not conv_id:
            continue
        short_id = pb.one(it, 2)
        parts = []
        holder = pb.blob(it, 6)
        if holder:
            for p in pb.all_of(pb.parse(holder), 1):
                u = pb.one(pb.parse(p[3]), 1)
                if u:
                    parts.append(str(u))
        ums = int(pb.one(it, 13) or 0)
        if ums > 1e17:               # 纳秒 → 毫秒
            ums //= 1e6
        prev = convs.get(conv_id)
        cand = {'conv_id': conv_id, 'short_id': str(short_id) if short_id else '',
                'peer_uid': api.peer_of(conv_id, UID), 'participants': parts,
                'updated_ms': ums, 'unread': 0, 'last': newest.get(conv_id)}
        if prev is None or cand['updated_ms'] > prev['updated_ms']:
            convs[conv_id] = cand

print('解析出会话: %d | 最新消息: %d' % (len(convs), len(msgs)))
new_names = []
con = sqlite3.connect(r'D:\wbtools\workspace\simple-message\data\hub.db')
have = {r[0] for r in con.execute("select conv_id from conversations where account=?", (ACCOUNT,))}
for cid in convs:
    if cid not in have:
        p = con.execute("select nickname from profiles where account=? and uid=?",
                        (ACCOUNT, convs[cid]['peer_uid'])).fetchone()
        new_names.append((cid, p[0] if p else '?'))

# 灌入（复用 store 的 UPSERT 逻辑语义）
for c in convs.values():
    last = c.get('last') or {}
    con.execute("""INSERT INTO conversations
         (account, conv_id, short_id, peer_uid, last_text, last_ms,
          last_from_me, updated_ms, synced_ms, unread)
       VALUES (?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(account, conv_id) DO UPDATE SET
         short_id=excluded.short_id, peer_uid=excluded.peer_uid,
         last_text=COALESCE(excluded.last_text, conversations.last_text),
         last_ms=MAX(COALESCE(excluded.last_ms,0), COALESCE(conversations.last_ms,0)),
         updated_ms=MAX(COALESCE(excluded.updated_ms,0), COALESCE(conversations.updated_ms,0)),
         synced_ms=excluded.synced_ms""",
        (ACCOUNT, c['conv_id'], c['short_id'], c['peer_uid'],
         last.get('text'), last.get('ms'), 1 if last.get('outgoing') else 0,
         c['updated_ms'], now, 0))
con.commit()
n_after = con.execute("select count(*) from conversations where account=?", (ACCOUNT,)).fetchone()[0]
print('灌入后 jakson 会话总数:', n_after, '| 新增:', n_after - len(have))
print('新增会话样例:')
for cid, nick in new_names[:12]:
    print('  ', cid[:40], '|', nick)
