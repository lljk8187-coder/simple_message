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

-- ── 阶段 2 预备表（统一消息中心内核：联系人 / 代发 / 审计）──────────
-- 本阶段只建结构不写入；写入方法随代发队列一起落地。

CREATE TABLE IF NOT EXISTS contacts (
  contact_id   TEXT PRIMARY KEY,          -- 内部 id（uuid）
  display_name TEXT,
  note         TEXT,
  tags         TEXT,                       -- 逗号分隔
  created_ms   INTEGER
);

-- 一个联系人（Contact）在各平台的身份挂靠
CREATE TABLE IF NOT EXISTS channel_identities (
  contact_id  TEXT NOT NULL,
  platform    TEXT NOT NULL,
  account     TEXT NOT NULL,               -- hub 账号名
  peer_uid    TEXT NOT NULL,               -- 平台侧对端 id
  created_ms  INTEGER,
  PRIMARY KEY (platform, account, peer_uid)
);

-- 代发任务（一条文案 + 目标会话集），Brevo 语义：调度后配置冻结，可暂停/重排
CREATE TABLE IF NOT EXISTS campaigns (
  campaign_id TEXT PRIMARY KEY,
  text        TEXT NOT NULL,
  created_by  TEXT,
  schedule_ms INTEGER,                     -- 首批发送时间
  batch_size  INTEGER,                     -- 每批人数
  interval_s  INTEGER,                     -- 批间隔秒
  status      TEXT,                        -- draft|queued|running|paused|done|cancelled
  created_ms  INTEGER
);

-- 队列项：逐目标的状态机 queued→sending→sent|failed（含平台信任分留痕）
CREATE TABLE IF NOT EXISTS dispatch_items (
  campaign_id  TEXT NOT NULL,
  seq          INTEGER NOT NULL,
  platform     TEXT,
  account      TEXT,
  conv_id      TEXT,
  status       TEXT,
  error        TEXT,
  sent_ms      INTEGER,
  guard_result TEXT,
  PRIMARY KEY (campaign_id, seq)
);

-- 审计日志：append-only，谁/何时/对谁/什么动作/结果
CREATE TABLE IF NOT EXISTS audit_log (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ms  INTEGER,
  actor  TEXT,
  action TEXT,
  target TEXT,
  detail TEXT                            -- JSON
);
"""


class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or '.', exist_ok=True)
        self._lock = threading.RLock()
        needs_upgrade = self._needs_upgrade(path)
        if needs_upgrade:
            # 任何 schema 升级前先留一份快照；升级一次性、自动、无需人工。
            stamp = time.strftime('%Y%m%d-%H%M%S')
            backup = '%s.backup-%s' % (path, stamp)
            try:
                import shutil
                shutil.copyfile(path, backup)
                self.backup_path = backup
            except OSError:
                self.backup_path = None
        else:
            self.backup_path = None
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)
            self._migrate()
            self._db.commit()

    @staticmethod
    def _needs_upgrade(path):
        """True when an existing pre-versioned DB is about to be upgraded."""
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return False
        try:
            con = sqlite3.connect(path)
            try:
                ver = con.execute('PRAGMA user_version').fetchone()[0]
                has_accounts = con.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='accounts'").fetchone()
                return ver < 1 and bool(has_accounts)
            finally:
                con.close()
        except sqlite3.Error:
            return False

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
        # 版本化：阶段 1 重构（统一模型 + 阶段 2 预备表）之后即为 version 1。
        self._db.execute('PRAGMA user_version = 1')

    # ------------------------------------------------------------ accounts

    def _ensure_platform_free(self, name, platform):
        """账号名全平台唯一：同名已被其它平台占用时拒绝写入。

        这是 (platform, name) 唯一性的落地形态——以全局唯一的 name 为键、
        platform 为属性，避免重建四张表；跨平台撞名要求换一个标签名。
        """
        with self._lock:
            row = self._db.execute('SELECT platform FROM accounts WHERE name=?',
                                   (name,)).fetchone()
        if row and (row['platform'] or 'tiktok') != platform:
            raise ValueError('账号名 %r 已被 %s 平台占用，请换一个名字'
                             % (name, row['platform'] or 'tiktok'))

    def save_account(self, name, sess, profile=None):
        p = profile or {}
        self._ensure_platform_free(name, getattr(sess, 'platform', '') or 'tiktok')
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
        no TikTok signing materials."""
        self._ensure_platform_free(name, 'x')
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
        """Generic non-TikTok account store (platform explicit)."""
        self._ensure_platform_free(name, platform)
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
        instagrapi settings dict + password (re-login needs it)."""
        self._ensure_platform_free(name, 'instagram')
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
