"""平台适配器统一契约 —— 整个消息中心的地基（重构阶段 1 的"标准规格书"）。

核心思想：消息中心内核只认本文件定义的「统一消息模型」和「通道契约」，
任何平台的特殊行为（签名、加密、验证码、实时推送方式）全部封在各平台的
适配器内部。内核代码与前端永远不出现平台名。

──────────────────────────────────────────────────────────────────────
统一消息模型（四个数据形状）
──────────────────────────────────────────────────────────────────────
  Account       一个已接入的通道账号（hub 内以 platform+name 唯一）
  Conversation  通道账号 × 对端 的会话
  Message       一条消息
  Contact       一个真实的人（跨平台身份聚合的锚点；阶段 2 启用）

所有字段都是简单类型（str/int），适配器负责把平台原生结构翻译成这些形状；
内核负责存储、展示、代发队列与审计。`to_dict()` 用于 JSON 边界（API/SSE/落库）。

──────────────────────────────────────────────────────────────────────
通道契约（PlatformAdapter）
──────────────────────────────────────────────────────────────────────
每个平台实现一个适配器子类，并向 registry 注册。三类声明 + 三组方法：

声明
  platform / display_name    通道标识与展示名
  auth_kind                  登录方式：
                               'popup'        弹出真实浏览器官方登录，
                                              登录完成 hub 自动收割（信任分最高）
                               'cookies'      粘贴已登录 cookie
                               'password_2fa' 密码登录，可能需要验证码
  capabilities               能力集合：'send' / 'mark_read' / 'realtime' 的子集
  send_limits                发信限速申报：{'min_interval_s': 秒, 'daily_cap': 条}
                             —— 代发队列读它来排水，跑量红线由契约强制

认证
  auth_fields()              添加账号表单的字段声明
  add_account(fields)        用表单数据完成登录，返回 (sess, Account)
  submit_code(sess, code)    password_2fa 的第二段：提交验证码
  popup_login(context)       auth_kind='popup' 的平台实现；context 由 hub 提供
                             （浏览器 profile 目录、代理等），返回登录流程句柄

会话持久化（hub 重启后恢复账号，适配器自代表示）
  session_dump(sess) -> dict
  session_load(dict) -> sess
  session_status(sess) -> 'ok' | 'error'

读写
  conversations(sess) -> [Conversation]
  messages(sess, conv_id, before_ms=None, limit=30) -> [Message]（旧→新排序）
  send(sess, conv_id, text) -> {'ok': bool, ...平台细节}
  mark_read(sess, conv_id, read_index) -> {'ok': bool, ...}（无此能力则不实现）
  poll(sess, state) -> (events, new_state)（realtime 平台的增量收取）

调用约定：所有方法**同步阻塞**，hub 在工作线程里调用；适配器内部若需异步
（asyncio 库）自行桥接，不把复杂度漏给内核。方法内不打印、不弹窗，错误用
异常抛出，由 hub 统一记录审计。
"""
from dataclasses import dataclass, asdict

__all__ = ['Account', 'Conversation', 'Message', 'Contact', 'PlatformAdapter',
           'NeedCode', 'CAP_SEND', 'CAP_MARK_READ', 'CAP_REALTIME']


# ------------------------------------------------------------ 统一消息模型

@dataclass
class Account:
    """已接入的通道账号。hub 内以 (platform, name) 唯一。"""
    platform: str                    # 'tiktok' | 'x' | 'instagram' | 'facebook' | 'email'
    name: str                        # hub 内展示名（默认=平台用户名）
    uid: str = ''                    # 平台侧用户 id
    username: str = ''               # 平台侧用户名/handle
    nickname: str = ''               # 平台侧昵称

    def to_dict(self):
        return asdict(self)


@dataclass
class Conversation:
    """通道账号 × 对端 的会话。conv_id 的格式由适配器自定（跨平台不比较）。

    account 字段由 hub 盖章（适配器可以留空——hub 知道自己用哪个账号调的）。
    last_from_me 与 peer_avatar 是前端渲染依赖：能取到就填，取不到留默认。
    """
    platform: str
    account: str                     # 所属 hub 账号名（hub 盖章）
    conv_id: str
    peer_uid: str = ''               # 对端平台 id
    peer_nickname: str = ''          # 对端昵称
    peer_unique: str = ''            # 对端 handle/unique id
    peer_avatar: str = ''            # 对端头像 URL（可空）
    last_text: str = ''              # 最新一条消息预览
    last_ms: int = 0                 # 最新活动时间（毫秒）
    last_from_me: int = 0            # 最新一条是否本方发出
    unread: int = 0                  # 未读提示数（前端本地基线管理）

    def to_dict(self):
        return asdict(self)


@dataclass
class Message:
    """一条消息。status 走 'sent' | 'pending' | 'failed'（乐观气泡用 pending）。"""
    platform: str
    account: str
    msg_id: str
    conv_id: str
    sender: str = ''                 # 发送者平台 id
    outgoing: int = 0                # 1 = 本方发出
    text: str = ''
    ms: int = 0                      # 毫秒时间戳
    status: str = 'sent'

    def to_dict(self):
        return asdict(self)


@dataclass
class Contact:
    """一个真实的人：跨平台身份聚合的锚点（阶段 2 的联系人层启用）。

    ChannelIdentity 在数据库层：(contact_id, platform, account, peer_uid)。
    """
    contact_id: str
    display_name: str = ''
    note: str = ''
    tags: str = ''                   # 逗号分隔标签

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------- 通道契约

# 能力名常量（capabilities 用）
CAP_SEND = 'send'
CAP_MARK_READ = 'mark_read'
CAP_REALTIME = 'realtime'


class NeedCode(Exception):
    """add_account 中途需要验证码。

    state 携带登录句柄（适配器自定义），hub 引导用户提交后原样传回
    adapter.submit_code(state, code)。
    """
    def __init__(self, state=None, message='verification code required'):
        super().__init__(message)
        self.state = state


class PlatformAdapter:
    """所有平台适配器的基类。子类必须设置类属性并覆写对应方法。"""

    platform = ''                    # 平台标识（registry 的键）
    display_name = ''                # 展示名（前端标签）
    auth_kind = ''                   # 'popup' | 'cookies' | 'password_2fa'
    capabilities = ()                # (CAP_SEND, CAP_MARK_READ, CAP_REALTIME) 子集
    send_limits = {'min_interval_s': 0, 'daily_cap': 0}
    #                                     0 = 未申报；代发队列对 0 采取保守默认值

    def __init__(self, config=None):
        # config：hub 注入的运行环境，至少含 'proxy'；各适配器按需取其他键。
        self.config = config or {}
        self._proxy = self.config.get('proxy')

    # ------------------------------------------------------------ 认证

    def auth_fields(self):
        """添加账号表单需要的字段声明（auth_kind 非 'popup' 时使用）。

        返回 [{'key': str, 'label': str, 'secret': bool}]，secret=True 的字段
        前端按密码框渲染且不回显。
        """
        return []

    def add_account(self, fields):
        """用表单数据完成登录。

        返回 (sess, Account)；需要验证码时抛 NeedCode 异常（见下），
        hub 引导用户走 submit_code。失败抛异常，hub 记审计并返回错误。
        """
        raise NotImplementedError

    def submit_code(self, sess, code):
        """password_2fa 第二段：提交验证码，成功返回 (sess, Account)。"""
        raise NotImplementedError('%s does not use a verification code'
                                  % (self.platform or '?'))

    def popup_login(self, context):
        """auth_kind='popup' 的平台实现。

        context 由 hub 提供：{'profile_dir': 浏览器持久目录,
                              'proxy': 出口代理或 None,
                              'on_event': 状态回调(可选)}。
        返回登录流程句柄（含 start/cancel/state），具体形态由适配器定义。
        """
        raise NotImplementedError('%s does not support popup login'
                                  % (self.platform or '?'))

    # ------------------------------------------------------ 会话持久化

    def session_dump(self, sess):
        """把会话转成可持久化 dict（hub 存库；重启后 session_load 恢复）。"""
        raise NotImplementedError

    def session_load(self, d):
        """从 session_dump 的 dict 恢复会话。"""
        raise NotImplementedError

    def session_status(self, sess):
        """会话健康度：'ok' | 'error'（hub 的账号列表展示用）。"""
        return 'ok'

    # -------------------------------------------------------------- 读

    def conversations(self, sess):
        """会话列表，按 last_ms 降序。"""
        raise NotImplementedError

    def messages(self, sess, conv_id, before_ms=None, limit=30):
        """某会话的消息，旧→新排序；before_ms 用于向上翻页。"""
        raise NotImplementedError

    def poll(self, sess, state):
        """实时增量收取（CAP_REALTIME 平台）。

        state 是适配器上次留下的游标/水位（hub 原样保管，可为 None）。
        返回 (events, new_state)；events = [{'type': 'message'|'conversation',
        ...统一模型字段}]。
        """
        raise NotImplementedError

    # -------------------------------------------------------------- 写

    def send(self, sess, conv_id, text):
        """发一条文本消息。返回 {'ok': bool, ...平台细节（信任分等）}。"""
        raise NotImplementedError

    def mark_read(self, sess, conv_id, read_index):
        """上报已读（CAP_MARK_READ 平台）。read_index 语义由适配器定义。"""
        raise NotImplementedError
