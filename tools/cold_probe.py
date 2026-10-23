"""冷建联一次性探针：验证 cmd 100 对「自构 conv_id + short_id=0」的接受度。

用法:
    python tools/cold_probe.py <db> <account> <peer_uid> "<text>"

流程: 取账号 session -> 拉对端资料确认 uid 有效 -> 自构 conv_id(升序)
    -> cmd 100 短id=0 发送 -> 成功则回读会话列表确认真实 short_id。
测完可删。
"""
import json
import sqlite3
import sys
import time

sys.path.insert(0, '.')

from app import client as cl


def load_session(db, name):
    con = sqlite3.connect(db)
    cols = [r[1] for r in con.execute('pragma table_info(accounts)')]
    row = con.execute('select * from accounts where name=?', (name,)).fetchone()
    if not row:
        raise SystemExit('account not found: %s' % name)
    return cl.Session.from_dict(dict(zip(cols, row)))


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else 'data/hub.db'
    account = sys.argv[2] if len(sys.argv) > 2 else 'jakson'
    peer = str(sys.argv[3])
    text = sys.argv[4]
    sess = load_session(db, account)
    http = cl.HttpClient(proxy=None, detect=True)

    prof = cl.user_profiles(http, sess, [peer])
    p = prof.get(peer)
    print('profile:', json.dumps(p, ensure_ascii=False))
    if not p:
        print('!! profile lookup failed -- uid 可能无效')

    a, b = sorted([sess.uid, peer], key=int)
    conv_id = '0:1:%s:%s' % (a, b)
    print('conv_id:', conv_id, '| tier B ready:', cl.signable(sess))

    r = cl.send_message(http, sess, conv_id, 0, text)
    print('send:', json.dumps(r, ensure_ascii=False))

    if r.get('ok'):
        time.sleep(4)
        rows, _meta = cl.list_conversations(http, sess)
        for c in rows:
            if c['conv_id'] == conv_id:
                print('conv appeared | short_id =', c['short_id'],
                      '| last:', json.dumps((c.get('last') or {}).get('text', ''),
                                            ensure_ascii=False))
                break
        else:
            print('conv not in list yet (轮询未覆盖，属正常，稍后 203 可见)')


if __name__ == '__main__':
    main()
