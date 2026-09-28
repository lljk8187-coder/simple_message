#!/usr/bin/env python3
"""tk-message-demo — self-hosted TikTok direct-message hub.

Run:  python run.py            (uses config.json if present, else defaults)
Cold start on a new host needs nothing but Python 3.9+ and network access.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import client as api          # noqa: E402
from app import server as web          # noqa: E402
from app.store import Store            # noqa: E402
from app.sync import Hub               # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))

DEFAULTS = {
    'host': '127.0.0.1',
    'port': 8788,
    'proxy': None,                 # None = auto-detect; 'direct' forces no proxy
    'data_dir': 'data',
    # A device id is only an environment self-report (it is not signed), so the
    # value observed in this browser is a fine default. Override per account when
    # you import credentials from a different machine.
    'default_device_id': '7689040904044463629',
    'list_interval': 60,           # seconds between conversation-list refreshes
    'msg_interval': 12,            # seconds between message polls
    'focus_interval': 4,           # seconds between polls of the conversation on screen
    'focus_page_size': 12,         # messages fetched per focus poll
    'poll_conversations': 8,       # how many recent conversations get polled
    'poll_page_size': 20,
    'access_log': True,
    # When set, every /api call (except /api/health and the static page) must
    # present this token via `Authorization: Bearer <token>` or `?token=`.
    # Empty by default: local use needs no auth; set it before exposing the port.
    'access_token': '',
}


def load_config(path):
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            cfg.update(json.load(f))
    return cfg


def main():
    ap = argparse.ArgumentParser(description='tk-message-demo server')
    ap.add_argument('--config', default=os.path.join(BASE, 'config.json'))
    ap.add_argument('--host')
    ap.add_argument('--port', type=int)
    ap.add_argument('--proxy', help="proxy URL, or 'direct' to disable")
    ap.add_argument('--data-dir')
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.host:
        cfg['host'] = args.host
    if args.port:
        cfg['port'] = args.port
    if args.data_dir:
        cfg['data_dir'] = args.data_dir
    if args.proxy:
        cfg['proxy'] = None if args.proxy == 'direct' else args.proxy

    data_dir = cfg['data_dir']
    if not os.path.isabs(data_dir):
        data_dir = os.path.join(BASE, data_dir)
    os.makedirs(data_dir, exist_ok=True)

    store = Store(os.path.join(data_dir, 'hub.db'))
    if cfg.get('proxy') == 'direct':
        client = api.HttpClient(proxy=None, detect=False)
    else:
        client = api.HttpClient(proxy=cfg.get('proxy'))
    hub = Hub(store, client, cfg)

    # Rehydrate every stored account so a restart resumes without re-importing.
    # Cookie-only accounts borrow signing materials from the shared pool here —
    # without this a restart would silently drop their write ability.
    for row in store.list_accounts():
        full = store.get_account(row['name'])
        full, borrowed = web.pool_fill(store, full)
        sess = api.Session.from_dict(full)
        sess.borrowed = borrowed or ''
        hub.attach(row['name'], sess)
    hub.start()

    httpd = web.create_server(cfg['host'], cfg['port'], hub, store, client, cfg)
    print('tk-message-demo')
    print('  data     : %s' % os.path.join(data_dir, 'hub.db'))
    print('  proxy    : %s' % (client.proxy or '(direct)'))
    print('  accounts : %s' % (', '.join(hub.sessions) or '(none yet)'))
    print('  listening: http://%s:%d' % (cfg['host'], cfg['port']))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nbye')
    finally:
        hub.stop()


if __name__ == '__main__':
    main()
