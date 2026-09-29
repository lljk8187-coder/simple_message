"""SQLite persistence: accounts, conversations, messages.

A single connection guarded by a lock keeps this dependency-free and good enough
for a handful of accounts. Swap for a pool if it ever becomes a bottleneck.
"""
import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
  name       TEXT PRIMARY KEY,
  uid        TEXT NOT NULL,
  username   TEXT,
  nickname   TEXT,
  avatar     TEXT,
  region     TEXT,
  cookie     TEXT,
  device_id  TEXT,
  ticket     TEXT,
  guard      TEXT,
  private_key TEXT,
  ts_sign    TEXT,
  created_at INTEGER,
  updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS conversations (
  account     TEXT NOT NULL,
  conv_id     TEXT NOT NULL,
  short_id    TEXT,
  peer_uid    TEXT,
  peer_name   TEXT,
  peer_avatar TEXT,
  last_text   TEXT,
  last_ms     INTEGER,
  last_from_me INTEGER,
  updated_ms  INTEGER,
  synced_ms   INTEGER,
  unread      INTEGER,
  PRIMARY KEY (account, conv_id)
);

CREATE TABLE IF NOT EXISTS messages (
  account   TEXT NOT NULL,
  conv_id   TEXT NOT NULL,
  msg_id    TEXT NOT NULL,
  sender    TEXT,
  outgoing  INTEGER,
  text      TEXT,
  ms        INTEGER,
  us        INTEGER,
  awe_type  INTEGER,
  cid       TEXT,
  PRIMARY KEY (account, msg_id)
);
CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(account, conv_id, us);

CREATE TABLE IF NOT EXISTS profiles (
  account  TEXT NOT NULL,
  uid      TEXT NOT NULL,
  nickname TEXT,
  unique_id TEXT,
  avatar   TEXT,
  fetched_ms INTEGER,
  PRIMARY KEY (account, uid)
);
"""


class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or '.', exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)
            self._migrate()
            self._db.commit()

    def _migrate(self):
        """Add columns introduced after the first release, so an old hub.db keeps working."""
        cols = {r['name'] for r in self._db.execute('PRAGMA table_info(accounts)')}
        for name, ddl in (('private_key', 'TEXT'), ('ts_sign', 'TEXT'),
                          ('platform', "TEXT NOT NULL DEFAULT 'tiktok'")):
            if name not in cols:
                self._db.execute('ALTER TABLE accounts ADD COLUMN %s %s' % (name, ddl))
        ccols = {r['name'] for r in self._db.execute('PRAGMA table_info(conversations)')}
        if 'unread' not in ccols:
            self._db.execute('ALTER TABLE conversations ADD COLUMN unread INTEGER')
            # conversations seen before this column existed have a meaningful count
            # waiting on the server; 0 here would look authoritative until the next
            # list sync, so start them at NULL (rendered as "unknown") instead.
            self._db.execute('UPDATE conversations SET unread = NULL')

    # ------------------------------------------------------------ accounts

    def save_account(self, name, sess, profile=None):
        p = profile or {}
        d = sess.to_dict()
        now = int(time.time() * 1000)
        with self._lock:
            self._db.execute(
                """INSERT INTO accounts (name, uid, username, nickname, avatar, region,
                       cookie, device_id, ticket, guard, private_key, ts_sign,
                       created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(name) DO UPDATE SET
                     uid=excluded.uid, username=excluded.username, nickname=excluded.nickname,
                     avatar=excluded.avatar, region=excluded.region, cookie=excluded.cookie,
                     device_id=excluded.device_id, ticket=excluded.ticket, guard=excluded.guard,
                     private_key=excluded.private_key, ts_sign=excluded.ts_sign,
                     updated_at=excluded.updated_at""",
                (name, sess.uid, sess.username, sess.nickname or p.get('nickname', ''),
                 sess.avatar or p.get('avatar', ''), sess.region, sess.cookie,
                 sess.device_id, sess.ticket, json.dumps(sess.guard or {}),
                 d['private_key'], d['ts_sign'], now, now))
            self._db.commit()

    def save_x_account(self, name, uid, username='', nickname='', cookie_json=''):
        """Store an X (Twitter) account: cookie JSON in the cookie column,
        no TikTok signing materials. Caller guards against name collisions
        with existing TikTok accounts."""
        now = int(time.time() * 1000)
        with self._lock:
            self._db.execute(
                """INSERT INTO accounts (name, uid, username, nickname, cookie,
                                         platform, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(name) DO UPDATE SET
                     uid=excluded.uid, username=excluded.username,
                     nickname=excluded.nickname, cookie=excluded.cookie,
                     platform='x', updated_at=excluded.updated_at""",
                (name, uid, username, nickname, cookie_json, 'x', now, now))
            self._db.commit()

    def save_platform_account(self, name, uid, username='', nickname='',
                              cookie_json='', platform='x'):
        """Generic non-TikTok account store (platform explicit). Caller
        guards against name collisions with other platforms."""
        now = int(time.time() * 1000)
        with self._lock:
            self._db.execute(
                """INSERT INTO accounts (name, uid, username, nickname, cookie,
                                         platform, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(name) DO UPDATE SET
                     uid=excluded.uid, username=excluded.username,
                     nickname=excluded.nickname, cookie=excluded.cookie,
                     platform=excluded.platform, updated_at=excluded.updated_at""",
                (name, uid, username, nickname, cookie_json, platform, now, now))
            self._db.commit()

    def save_ig_account(self, name, uid, username='', nickname='', cookie_json=''):
        """Store an Instagram account: cookie column holds JSON with the
        instagrapi settings dict + password (re-login needs it). Caller
        guards against name collisions with other platforms."""
        now = int(time.time() * 1000)
        with self._lock:
            self._db.execute(
                """INSERT INTO accounts (name, uid, username, nickname, cookie,
                                         platform, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(name) DO UPDATE SET
                     uid=excluded.uid, username=excluded.username,
                     nickname=excluded.nickname, cookie=excluded.cookie,
                     platform='instagram', updated_at=excluded.updated_at""",
                (name, uid, username, nickname, cookie_json, 'instagram', now, now))
            self._db.commit()

    def get_account(self, name):
        with self._lock:
            row = self._db.execute('SELECT * FROM accounts WHERE name=?', (name,)).fetchone()
        return dict(row) if row else None

    def list_accounts(self):
        with self._lock:
            rows = self._db.execute(
                'SELECT name, uid, username, nickname, avatar, region, platform, '
                'updated_at FROM accounts ORDER BY updated_at DESC').fetchall()
        return [dict(r) for r in rows]

    def delete_account(self, name):
        with self._lock:
            for sql in ('DELETE FROM accounts WHERE name=?',
                        'DELETE FROM conversations WHERE account=?',
                        'DELETE FROM messages WHERE account=?',
                        'DELETE FROM profiles WHERE account=?'):
                self._db.execute(sql, (name,))
            self._db.commit()

    # ---------------------------------------------------------- profiles

    def get_profiles(self, account):
        with self._lock:
            rows = self._db.execute('SELECT * FROM profiles WHERE account=?',
                                    (account,)).fetchall()
        return {r['uid']: dict(r) for r in rows}

    def save_profiles(self, account, profiles):
        now = int(time.time() * 1000)
        with self._lock:
            for uid, p in (profiles or {}).items():
                self._db.execute(
                    """INSERT INTO profiles (account, uid, nickname, unique_id, avatar, fetched_ms)
                       VALUES (?,?,?,?,?,?)
                       ON CONFLICT(account, uid) DO UPDATE SET
                         nickname=excluded.nickname, unique_id=excluded.unique_id,
                         avatar=excluded.avatar, fetched_ms=excluded.fetched_ms""",
                    (account, uid, p.get('nickname', ''), p.get('unique_id', ''),
                     p.get('avatar', ''), now))
            self._db.commit()

    # ----------------------------------------------------- conversations

    def save_conversations(self, account, convs):
        now = int(time.time() * 1000)
        with self._lock:
            for c in convs:
                last = c.get('last') or {}
                self._db.execute(
                    """INSERT INTO conversations
                         (account, conv_id, short_id, peer_uid, last_text, last_ms,
                          last_from_me, updated_ms, synced_ms, unread)
                       VALUES (?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(account, conv_id) DO UPDATE SET
                         short_id=excluded.short_id, peer_uid=excluded.peer_uid,
                         last_text=COALESCE(excluded.last_text, conversations.last_text),
                         last_ms=MAX(COALESCE(excluded.last_ms,0), COALESCE(conversations.last_ms,0)),
                         last_from_me=COALESCE(excluded.last_from_me, conversations.last_from_me),
                         updated_ms=excluded.updated_ms, synced_ms=excluded.synced_ms,
                         unread=COALESCE(excluded.unread, conversations.unread)""",
                    (account, c['conv_id'], c.get('short_id', ''), c.get('peer_uid', ''),
                     last.get('text'), last.get('ms'), 1 if last.get('outgoing') else 0,
                     c.get('updated_ms') or 0, now, c.get('unread')))
            self._db.commit()

    def apply_unread(self, account, unread_list):
        """Authoritative unread counts pushed by the 204 combo (f9 entries).

        Keyed on short_id with a conv_id fallback, because the server reports
        both and older rows may predate a short_id.
        """
        with self._lock:
            for u in unread_list:
                if u.get('short_id'):
                    self._db.execute(
                        'UPDATE conversations SET unread=? WHERE account=? AND short_id=?',
                        (u.get('unread'), account, u['short_id']))
                if u.get('conv_id'):
                    self._db.execute(
                        'UPDATE conversations SET unread=? WHERE account=? AND conv_id=?',
                        (u.get('unread'), account, u['conv_id']))
            self._db.commit()

    def list_conversations(self, account):
        # NB: select columns explicitly. `c.*` plus `p.avatar AS peer_avatar` yields two
        # columns with the same name, and sqlite3.Row resolves that to the first (NULL).
        # ORDER BY last_ms, not updated_ms: the list payload reports the *same*
        # updated_ms for every conversation, so ordering by it is meaningless.
        with self._lock:
            rows = self._db.execute(
                """SELECT c.account, c.conv_id, c.short_id, c.peer_uid,
                          c.last_text, c.last_ms, c.last_from_me, c.updated_ms, c.synced_ms,
                          c.unread,
                          p.nickname  AS peer_nickname,
                          p.unique_id AS peer_unique,
                          p.avatar    AS peer_avatar
                     FROM conversations c
                     LEFT JOIN profiles p ON p.account = c.account AND p.uid = c.peer_uid
                    WHERE c.account = ?
                    ORDER BY COALESCE(c.last_ms, c.updated_ms, 0) DESC""",
                (account,)).fetchall()
        return [dict(r) for r in rows]

    def active_conversations(self, account, limit=6):
        with self._lock:
            rows = self._db.execute(
                'SELECT conv_id, short_id FROM conversations WHERE account=? '
                'ORDER BY COALESCE(last_ms, updated_ms, 0) DESC LIMIT ?',
                (account, limit)).fetchall()
        return [dict(r) for r in rows]

    def missing_profiles(self, account, limit=50):
        with self._lock:
            rows = self._db.execute(
                """SELECT c.peer_uid FROM conversations c
                   LEFT JOIN profiles p ON p.account=c.account AND p.uid=c.peer_uid
                  WHERE c.account=? AND c.peer_uid<>'' AND p.uid IS NULL
                  LIMIT ?""", (account, limit)).fetchall()
        return [r['peer_uid'] for r in rows]

    # ---------------------------------------------------------- messages

    def save_messages(self, account, msgs):
        """Insert messages; return the ones that were genuinely new."""
        fresh = []
        with self._lock:
            for m in msgs:
                if not m or not m.get('msg_id'):
                    continue
                if m.get('kind') == 'command':
                    continue    # session-control events are not chat bubbles
                cur = self._db.execute(
                    'SELECT 1 FROM messages WHERE account=? AND msg_id=?',
                    (account, m['msg_id'])).fetchone()
                if cur:
                    continue
                self._db.execute(
                    """INSERT OR IGNORE INTO messages
                         (account, conv_id, msg_id, sender, outgoing, text, ms, us, awe_type, cid)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (account, m.get('conv_id', ''), m['msg_id'], m.get('sender', ''),
                     1 if m.get('outgoing') else 0, m.get('text', ''), m.get('ms') or 0,
                     m.get('us') or 0, m.get('awe_type') or 0,
                     (m.get('ext') or {}).get('s:client_message_id')))
                fresh.append(m)
            self._db.commit()
        return fresh

    def list_messages(self, account, conv_id, limit=30, before_us=None):
        sql = ('SELECT * FROM messages WHERE account=? AND conv_id=?')
        args = [account, conv_id]
        if before_us:
            sql += ' AND us < ?'
            args.append(int(before_us))
        sql += ' ORDER BY us DESC LIMIT ?'
        args.append(int(limit))
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        return [dict(r) for r in reversed(rows)]

    def latest_message(self, account, conv_id):
        """Newest message of a conversation — read_index source for mark_read."""
        with self._lock:
            row = self._db.execute(
                """SELECT msg_id, us FROM messages
                   WHERE account=? AND conv_id=? AND us IS NOT NULL
                   ORDER BY us DESC LIMIT 1""",
                (account, conv_id)).fetchone()
        return dict(row) if row else None

    def has_messages(self, account, conv_id):
        with self._lock:
            row = self._db.execute('SELECT COUNT(1) AS n FROM messages WHERE account=? AND conv_id=?',
                                   (account, conv_id)).fetchone()
        return (row['n'] or 0) > 0

    def stats(self, account):
        with self._lock:
            c = self._db.execute('SELECT COUNT(1) n FROM conversations WHERE account=?',
                                 (account,)).fetchone()['n']
            m = self._db.execute('SELECT COUNT(1) n FROM messages WHERE account=?',
                                 (account,)).fetchone()['n']
        return {'conversations': c, 'messages': m}
