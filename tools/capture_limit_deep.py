# -*- coding: utf-8 -*-
"""深挖影子限流信号：WS 发送保留 _others 全帧 + HTTP 响应完整 body。
jakson 仍被限时运行；对比正常形态即可定位官方"等待重试"提示的数据源。"""
import sys, json, shutil, tempfile, datetime, time
sys.path.insert(0, r'D:\wbtools\workspace\simple-message')
from app.store import Store
from app import client as api, tkws
from app.platform.tiktok import TikTokAdapter

OUT = r'D:\wbtools\workspace\simple-message\rate-limit-raw-response.log'

# 完整 HTTP body 捕获
cap = []
_orig_post = api.HttpClient.post
def post_spy(self, path, **kw):
    r = _orig_post(self, path, **kw)
    if '/v1/message/send' in path:
        cap.append({'path': path, 'http': r[0], 'body': r[1] or b'',
                    'headers': {k.lower(): v for k, v in (r[2] or {}).items()}})
    return r
api.HttpClient.post = post_spy

tmp = tempfile.mktemp(suffix='.db')
shutil.copyfile(r'D:\wbtools\workspace\simple-message\data\hub.db', tmp)
s = Store(tmp)
sess = api.Session.from_dict(s.get_account('jakson'))
ad = TikTokAdapter(config={'proxy': 'http://127.0.0.1:7897'})
cli = ad._client()

row = s._db.execute("select seq, peer_uid from dispatch_items where campaign_id='f3a35874f271' "
                    "and status='queued' and peer_uid not like '@%' order by seq limit 1").fetchone()
uid = str(row['peer_uid'])
print('目标:', uid, 'seq:', row['seq'])

conv = api.create_conversation(cli, sess, uid)
conv_id, short = conv['conv_id'], conv['short_id']
print('conv:', conv_id[:40])

# 底层 WS 发送：保留 _others
ws = tkws.open_ws(sess, proxy='http://127.0.0.1:7897')
frame, cid, tier = tkws.build_frame(sess, conv_id, short, 'Hi! Quick hello from our team \U0001F44B')
ws.send_binary(frame)
ack, others = tkws.wait_ack(ws, seq=None, cid=cid, timeout=25)   # seq=None 宽收，others 带走全部
try: ws.close()
except Exception: pass
# 建会话后立刻回读，拿"被吞"的现场
time.sleep(3)
msgs, _m = api.list_messages(cli, sess, conv_id, short, limit=5)

s._db.execute("update dispatch_items set status='skipped', skip_reason='raw-capture-probe2', "
              "error=? where campaign_id='f3a35874f271' and seq=?", (str(ack)[:100], row['seq']))
s._db.commit()

stamp = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
with open(OUT, 'a', encoding='utf-8') as f:
    f.write('\n===== %s | deep-capture | target=%s conv=%s =====\n' % (stamp, uid, conv_id))
    f.write('WS ack: %s\n' % json.dumps(ack, default=str, ensure_ascii=False))
    f.write('WS others (%d 帧): %s\n' % (len(others), json.dumps(others, default=str, ensure_ascii=False)[:3000]))
    f.write('回读消息数: %d（0=被吞实锤）\n' % len(msgs))
    for c in cap:
        f.write('HTTP %s %s len=%d\n' % (c['http'], c['path'], len(c['body'])))
        f.write('  body_full_hex: %s\n' % c['body'].hex())
print('ack:', ack.get('kind'), 'biz:', ack.get('biz_code'), '| others:', len(others), '| 回读:', len(msgs))
print('→', OUT)
