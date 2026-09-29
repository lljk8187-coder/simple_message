# ARCHITECTURE — tk-message-demo

一句话：**自托管的多平台私信消息中心**。内核只认统一消息模型；平台差异全部
封在适配器里；发送的频控由契约强制而非纪律约束。

> 本文件是"每个文件干什么 + 三张图"。协议层的实现依据在 README「协议摘要」
> 与 `app/platform/base.py` 的模块注释里。

---

## 一、分层总览

```
Web 控制台（web/index.html，单文件静态页）
        │  只调一套接口：/api/accounts/<name>/...
        ▼
app/server.py          路由 + Bearer 鉴权 + SSE 管道 + 静态页（约 430 行，无业务逻辑）
        ▼
app/hub.py             统一编排：账号生命周期、四平台会话登记、启动恢复、
        │              逐平台同步循环、统一读写分发、IG 两段式 pending 管理
        ▼
通道契约（app/platform/base.py + registry.py）
        │  PlatformAdapter：auth_kind / capabilities / send_limits
        │  add_account / submit_code / conversations / messages /
        │  send / mark_read / poll / session_dump·load
        ▼
适配器（app/platform/tiktok|x|instagram|facebook.py）——只做"翻译"
        ▼
协议连接器（app/client.py | xconnect.py | igconnect.py | fbconnect.py）
        ▼
各平台
```

**加一个新平台 = 写一个适配器文件 + registry 追加一行。** server.py、hub.py、
前端都不用动——这就是这次重构换来的东西。

---

## 二、文件职责（一句话版）

| 文件 | 职责 |
|---|---|
| `run.py` | 入口：配置 → Store → HttpClient → Hub → rehydrate_all → server |
| `app/hub.py` | 编排核心：账号增删/恢复/在线状态；统一 conversations/messages/send/mark_read 分发；X/FB 同步循环；IG pending 管理 |
| `app/server.py` | 纯路由层：统一 `/api/accounts/...` 面、批量发送、SSE、收割端点、弹窗登录端点 |
| `app/platform/base.py` | **标准规格书**：统一数据形状 + 适配器契约 + NeedCode + 限速申报语义 |
| `app/platform/registry.py` | 平台名 → 适配器类；load_adapters 容错缺失模块 |
| `app/platform/tiktok.py` | TikTok 翻译官：short_id 缓存、档位透传、profiles 富化 |
| `app/platform/x.py` | X 翻译官：conv_id=对端 uid；无已读回执（如实声明） |
| `app/platform/instagram.py` | IG 翻译官：两段式登录（NeedCode 契约）、懒 ensure_login |
| `app/platform/facebook.py` | FB 翻译官：E2EE 桥事件经 poll 排水 |
| `app/client.py` | TikTok 协议：protobuf 信封、203/204/301/100/2002、签名档位 B/A/Z |
| `app/signing.py` | 手写 P-256 ECDSA（标准库）：群律/DER/PKCS#8 |
| `app/proto.py` | protobuf varint / length-delimited 编解码 |
| `app/xconnect.py` | X 连接器：twikit 封装 + 自实现收件箱（v1.1 inbox_initial_state） |
| `app/igconnect.py` | IG 连接器：instagrapi 封装、两段式登录句柄、代理显式安装 |
| `app/fbconnect.py` | FB 连接器：fbchat-v2 E2EE 桥封装（校验和下载的 Go 子进程） |
| `app/sync.py` | TikTok 轮询机制（204 增量+焦点快轮询）+ EventBus（hub.py 的基类） |
| `app/store.py` | SQLite：账号/会话/消息/资料 + 阶段 2 内核表（contacts/campaigns/audit…） |
| `app/harvest.py` | TikTok 凭据收割：控制台脚本生成 + 回传暂存 |
| `app/login_browser.py` | TikTok 弹窗官方登录：真实浏览器登录一次，自动收割全部凭据 |
| `web/index.html` | 前端：账号选择器（四通道标签）、会话/消息、批量发送面板 |
| `tests/smoke.py` | 只读冒烟验收（不发消息） |

---

## 三、登录/绑定（每通道一种，声明即生效）

| 通道 | auth_kind | 流程 | 之后的维护 |
|---|---|---|---|
| TikTok | `cookies`（+`popup` 挂载点） | 贴 cookie 即全功能；发送走 B 档（自有材料 `0` 分）或 Z 档（无材料 `1104`）自动选 | ticket/ts_sign 轮换由 beat 端点纯 HTTP 续期，私钥不换即免重收割 |
| X | `cookies` | 贴 x.com cookie（auth_token+ct0） | cookie 失效重贴 |
| Instagram | `password_2fa` | 页面输用户名密码 → IG 发验证码 → 页面填码 → session 持久化 | 之后免验证码；掉会话需重登 |
| FB | `cookies` | 贴 facebook.com cookie（c_user+xs） | E2EE 桥自动重连 |
| 邮箱（规划） | `password_2fa` 变体 | SMTP/IMAP 账号密码 | — |

**信任分体系（仅 TikTok 有）**：`0`（自有材料）＞ `1003`（会话被环境降级）＞
`1104`（无材料）——三种均送达；跑量场景请不要用 1003/1104。

## 四、数据流

**收**：适配器 poll/sync → hub.bus.publish（SSE）→ 前端刷新；TikTok 同时落库。
**发**：前端 → `POST /api/accounts/<name>/send` → hub.send → 适配器 send →
平台；TikTok 发送后立即 nudge 轮询回读确认。
**批量**：`POST /api/batch/send` → 逐目标串行 + 间隔 → 逐目标结果回报
（上限 50、间隔默认 2s——风控红线的第一道闸；阶段 2 升级为 Campaign 队列）。
**审计（规划）**：audit_log 表已建，阶段 2 接入每次发送/登录留痕。

## 五、设计决策备忘

1. **账号名全平台唯一**（以 name 为键、platform 为属性）：避免四张表复合键
   重建；撞名在存储层结构性拒绝。
2. **适配器不持有 hub 名**：Conversation.account 由 hub 盖章——适配器只认平台。
3. **限速是契约**：适配器申报 send_limits，队列读它排水——不是文档里的"请自觉"。
4. **协议层是资产**：client/xconnect/igconnect/fbconnect 的内部经过活体验证，
   重构只动了它们的集成面，内部一行未改。
5. **迁移自动化**：store 升级前自动快照 hub.db.backup-*；PRAGMA user_version 门控。

## 六、历史沿革（细节在日报与 git 历史）

09-24~28 TikTok 纯算逆向与单平台 hub → 09-28 B+Z 档定稿（弃借用）→
09-29 X/IG/FB 适配器 + 批量发送 → 09-29 下午统一架构重构（本文件所述形态）。
