# -*- coding: utf-8 -*-
"""抓影子限流发送的完整原始响应（定位官方客户端"等待重试"提示的信号字段）。
jakson 当前被限（10:03 触发），此时发送的响应即"被限流形态"；对照 10-27 14:39
obb815 的落地形态（正常）。dump WS ack 全字段 + HTTP 响应原始 body/全响应头。"""
import sys, json, shutil, tempfile, datetime
sys.path.insert(0, r'D:\wbtools\workspace\simple-message')
from app.store import Store
from app import client as api
from app.platform.tiktok import TikTokAdapter

OUT = r'D:\wbtools\workspace\simple-message\rate-limit-raw-response.log'

# 捕获 client.post 的完整原始响应（body bytes + 响应头 dict）
cap = []
_orig_post = api.HttpClient.post
def post_spy(self, path, **kw):
    r = _orig_post(self, path, **kw)
    if '/v1/message/send' in path or 'conversation' in path:
        try:
            cap.append({'path': path, 'http': r[0], 'body_len': len(r[1] or b''),
                        'body_hex_head': (r[1] or b'')[:400].hex(),
                        'resp_headers': {k.lower(): v for k, v in (r[2] or {}).items()}})
        except Exception as e:
            cap.append({'path': path, 'capture_err': str(e)})
    return r
api.HttpClient.post = post_spy

tmp = tempfile.mktemp(suffix='.db')
shutil.copyfile(r'D:\wbtools\workspace\simple-message\data\hub.db', tmp)
s = Store(tmp)
full = s.get_account('jakson')
sess = api.Session.from_dict(full)
ad = TikTokAdapter(config={'proxy': 'http://127.0.0.1:7897'})

# 取一个干净目标
con = s._db
row = con.execute("select seq, peer_uid from dispatch_items where campaign_id='f3a35874f271' "
                  "and status='queued' and peer_uid not like '@%' order by seq limit 1").fetchone()
uid = row['peer_uid']
print('目标:', uid, 'seq:', row['seq'])

res = ad.send_to_peer(sess, uid, 'Hi! Quick hello from our team \U0001F44B')
con.execute("update dispatch_items set status='skipped', skip_reason='raw-capture-probe', "
            "error=? where campaign_id='f3a35874f271' and seq=?", (str(res)[:100], row['seq']))
con.commit()

stamp = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
with open(OUT, 'a', encoding='utf-8') as f:
    f.write('\n===== %s | target=%s =====\n' % (stamp, uid))
    f.write('send_to_peer result: %s\n' % json.dumps(
        {k: v for k, v in res.items() if k != 'http_fallback'}, ensure_ascii=False, default=str))
    if 'http_fallback' in res:
        f.write('http_fallback(parsed): %s\n' % json.dumps(res['http_fallback'], default=str))
    for c in cap:
        f.write('--- %s http=%s len=%s\n' % (c['path'], c['http'], c['body_len']))
        f.write('headers: %s\n' % json.dumps(c.get('resp_headers', {}), ensure_ascii=False))
        f.write('body_hex[:400]: %s\n' % c.get('body_hex_head'))
print('landed:', res.get('landed'), '| stage:', res.get('stage'), '| err:', str(res.get('error'))[:80])
print('捕获 HTTP 响应数:', len(cap), '→', OUT)
