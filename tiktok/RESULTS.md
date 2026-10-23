# TikTok 陌生人冷建联 —— 纯协议逆向成果记录

> 2026-10-20 · 状态：**全链路已打通并实测验证**（无浏览器、无 UI 自动化）
> 测试账号：jaksonl1226 / uid `7676292495719728141`（hub.db 会话名 `jakson`）
> 测试消息统一 `wb-` 前缀（区分账号主人 iPhone send 的消息）

---

## 一、最终能力

```
输入：@用户名 + 消息内容
输出：自动完成 抓uid → 建会话 → 协议发送 → 回读验证落地
```

实测记录（2026-10-20 18:2x）：

| 实验 | 对象 | 结果 |
|---|---|---|
| 热会话 WS 发送 | obb815（已接受会话） | LANDED: True |
| 冷建联全链路 | @wikipedia（陌生人） | LANDED: True，cmd 609 short_id=7698690886520209678 |

---

## 二、全链路四个环节

### 1. @用户名 → uid（SSR 抓取）

- `GET https://www.tiktok.com/@<name>`
- 解析 `<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__">` JSON
- 路径：`__DEFAULT_SCOPE__.webapp.user-detail.userInfo.user.**id**`
  （注意字段是 `id`，不是 `id_str`；另有 `uniqueId` / `nickname` / `secUid`）
- 代码：`tiktok/cold_full.py::scrape_uid`

### 2. 建陌生人会话（cmd 609）

- `POST https://im-api.tiktok.com/v2/conversation/create`，HTTP 即可，无需 WS
- 信封用 `create_envelope`（cmd 609 / sub 10007），载荷：
  `f609{ f1:1, f2:<对端uid>, f2:<自己uid> }`（升序）
- 响应：`f1` = 规范 conv_id，`f2` = 真实 short_id；幂等（已有会话返回现值）
- **必须走这一步**：对自构 conv_id 直接发 cmd 100 会 biz_code=0 但静默丢弃
- 代码：`app/client.py::create_conversation`

### 3. conv_id 自构公式（hub.db 67 条会话验证）

```
conv_id = '0:1:<较小uid>:<较大uid>'
```

### 4. WS 发送（唯一对陌生人有效的通道）

**为什么必须 WS**：HTTP `/v1/message/send` 对陌生人/待接受会话静默丢弃
（返回 biz_code=0 但不落地），对已接受会话才正常。UI 前端本身就走 WebSocket。

#### 连接与鉴权

- `wss://im-ws.tiktok.com/ws/v2?aid=1459&fpid=9&access_key=<md5>&device_platform=web&ttwid=<...>&Web-Sdk-Ms-Token=<...>`
- access_key 公式（与线上抓包逐字节一致）：
  `md5('9' + 'e1bd35ec9db7b8d846de66ed140b1ad9' + device_id + 'f8a69f1719916z')`
- device_id = iframe localStorage.ttwid = `7689040904044463629`
- 握手/心跳：双向 2 字节二进制 `hi`
- Headers：`Cookie` + `Origin: https://www.tiktok.com` + UA，代理用 HTTP CONNECT

#### 外层帧结构（二进制 protobuf）

```
{ f1: seq, f2: ts_ms, f3: 5, f4: 1,
  f5: repeated KV（X-Bogus 在最前，其后环境 KV 列表）,
  f7: 'pb',                      ← 字面量（非内容类型标记）
  f8: 内层信封（下述）,
  f15: repeated KV（tt-ticket-guard-* 签名，B 档本地 P-256 ECDSA）,
  f18: 1 }
```

#### 内层信封（f8）

```
{ f1: 100, f2: seq 回显（注意：不是 HTTP 子命令！）, f3: '1.8.2',
  f4: ''（空串，非 feature tag）, f5: 3, f6: 0, f7: '1132b10:master',
  f8: {100: 发送载荷}, f9: device_id, f11: 'web',
  f15: 环境 KV 列表, f18: 1 }
```

#### 发送载荷（f8.100）

```
{ f1: conv_id, f2: 1, f3: short_id,
  f4: JSON '{"aweType":0,"text":"..."}'（紧凑分隔符）,
  f5: ext（仅 s:mentioned_users 空值 + s:client_message_id 两个 KV）,
  f6: 7, f7: 'deprecated'（字面量，ticket 槽位在 WS 上已废弃）,
  f8: client_message_id }
```

#### 与"HTTP 帧拼 WS 帧"直觉的 6 处差异（构帧失败的根因）

1. 内层 f2 = seq 回显，不是 HTTP 的子命令 10000
2. ext 只带 `s:mentioned_users` + `s:client_message_id`，没有 HTTP 版的其他 KV
3. f7 是 `'deprecated'` 字面量，不是真实 ticket
4. 外层没有 f9（抓包里的 2193 另有所指）
5. guard KV 在外层 f15，不在 f5
6. 内层 f4 是空串，不是 feature tag

---

## 三、服务端回执结构（2026-10-21 捕获解码）

发送后服务端推两种帧，均在外层 `f8` 内层信封里带 cmd：

**ACK（发送回执）**
```
外层 f5 KV: is_ack=1, code=0, :x_frontier_msg_id, traceparent
f8 { f1: 100（cmd）, f2: seq 回显, f3: biz_code（0=接受）, f4: 'OK',
     f6 { 100 { f1: 服务端 msg_id, f4: client_message_id, f12: 1 } } }
```

**PUSH（新消息下发，cmd 500）**
```
f8 { f1: 500, f6 { 500 { f2: conv_id,
     f5 { f1: conv_id, f3: msg_id, f5: short_id, f7: 发送者 uid,
          f8: '{"aweType":0,"text":"..."}',
          f9: KVs（含 s:client_message_id、s:is_stranger、s:biz_aid） } } } }
```

解析器：`tkws.parse_down_frame()` / `tkws.wait_ack(ws, seq, cid)`

> ⚠️ **ACK 不等于落地**。平台规则（既有记录，2026-10-20 记忆第 17 行，UI 横幅明示）：
> 陌生人在对方回复前**只能发 1 条**。协议侧的表现是——第 2 条仍返回
> `biz_code=0 / 'OK'`，但消息**静默丢弃**。因此工具必须在**发送前**判断
> 「最后一条是否我方且对方未回」，并在发送后回读验证；只信 ACK 会把失败当成功。

---

## 四、批量 CLI

```bash
# 单发
python tiktok/cold_full.py wikipedia "你好 {nickname}"

# 批量（命令行）
python tiktok/cold_full.py @user1 @user2 --text "hi {nickname}" --interval 12

# 批量（文件；每行 username，或 username|专属文案）
python tiktok/cold_full.py --batch targets.txt --text "hi {nickname}" \
       --interval 10 --out tiktok/send-results.jsonl
```

参数：`--account`（选 hub.db 会话）、`--interval`（间隔秒，默认 10，±25% 抖动）、
`--out`（JSONL 逐条结果）、`--no-verify`、`--dry-run`（只抓 uid/建会话）、`--limit`。

模板变量：`{nickname}` `{unique_id}` `{uid}`。

**逐条状态**：`profile`（抓 uid 失败）→ `create`（cmd 609 失败）→ `ws-connect` →
`ack`（biz_code）→ `verify`（回读落地）。任一阶段失败单独报告，汇总末尾列出。

实测（2026-10-21）：
| 用例 | 结果 |
|---|---|
| @nasa 冷发 | OK ack，msg_id=7698927063546627597，landed=True |
| @wikipedia 第二次 | FAIL verify —— ACK ok 但被静默丢弃（配额策略） |
| 不存在的 handle | FAIL profile —— user-detail missing |

---

## 五、限制与风险

| 项 | 说明 |
|---|---|
| 陌生人配额 | 对方接受前**最多发 1 条**（服务端策略，UI 有横幅）；超出时 ACK 仍 ok 但静默丢弃 |
| 频率 | 一个号短时间冷联对象有限；建议单条间隔 ≥8s，冷号更长 |
| 签名材料 | B 档签名依赖登录时收割的 ticket + ts_sign + ec_private_key（过期需重新登录收割） |
| seq | SDK 全局计数器（抓包 10001~10033 区间），实测 10001 可用 |
| 出口 | 环境变量 HTTPS_PROXY(54289) 是死通道；活口 `http://127.0.0.1:10809`（HTTP），7897 已死 |

---

## 六、代码资产清单

| 文件 | 作用 |
|---|---|
| `app/tkws.py` | **生产通道**：WS 构帧 + ACK/PUSH 解析 + 纯 stdlib WS 客户端 |
| `app/platform/tiktok.py` | `send_to_peer()`：冷建联（609 → 预检 → WS → 回读 → HTTP 兜底） |
| `app/hub.py` | `send_cold()` / `resolve_target_uid()` / `{nickname}` 模板 |
| `app/dispatch.py` | 队列 cold item（排水时建会话、`pending_reply` 记 skip） |
| `tiktok/cold_full.py` | 研究沙盒：单发/批量脚本（生产请走 hub API） |
| `tiktok/cold_full.py` | **主入口**：单发/批量，@name → uid → cmd609 → WS 发送 → ACK → 回读验证 |
| `tiktok/tkws.py` | WS 构帧器 + 回执解析（`parse_down_frame`/`wait_ack`）+ access_key 公式 |
| `tiktok/miniws.py` | 纯 stdlib WS 客户端（CONNECT 隧道 + RFC6455 帧编解码，无 segfault 问题） |
| `tiktok/ws_send_warm.py` | 热会话验证脚本（突破性实验） |
| `tiktok/official-send-frame.bin/.b64` | 官方 UI 发送帧 3480 字节存档（逆向基准） |
| `tiktok/parse_official.py` | 官方帧解码工具 |
| `app/client.py` | 协议层：cmd 609 create_conversation、B 档 ticket_guard 签名、信封 |
| `tools/cold_probe.py` | 早期探针 + `load_session(db, name)` 工具函数 |

## 七、待办

> 定位说明：`tiktok/` 下这套脚本是**研究与验证沙盒**。生产路径应接入 hub 既有内核
> （campaigns + dispatch_items + dispatch.py + audit_log），不要另起一套批量逻辑——
> 队列、闸门、限速、审计在 `app/dispatch.py` 已经有实现。

- [x] 单发/批量验证脚本（研究沙盒）：`cold_full.py` 单发、批量、模板、间隔、JSONL
- [x] WS 回执解析：`tkws.parse_down_frame` / `wait_ack`（ACK / PUSH / biz_code / cid）
- [x] **接入 hub（已完成 2026-10-21）**：
  - [x] `app/tkws.py`：构帧器 + 纯 stdlib WS 客户端迁入 app（零第三方依赖）
  - [x] 适配器 `send_to_peer()`：609 幂等 → 1 条规则预检 → WS 发送 → 回读验证 → HTTP 兜底
  - [x] dispatch 支持 cold item（`conv_id` 空 + `peer_uid` 有值）：排水时建会话，发完回填 conv_id
  - [x] 闸门 `pending_reply`：最后一条是我方且对方未回 → skip（不消耗配额）
  - [x] 发送后回读验证（ACK ok 也可能是静默丢弃）
  - [x] 前端「群发任务」支持贴 @用户名/uid 列表作为冷目标
  - [x] API：`POST /api/accounts/<name>/send-cold`；任务目标支持 `{account, target}`
- [ ] 配额与频率跟踪：单号当日冷联计数、自动冷却（可挂在既有 send_limits 上）
- [ ] 多账号轮转：hub.db 多 session 分摊配额
- [ ] 长稳观察：B 档签名时效、609 幂等复用、限流恢复周期
- [ ] 撤回/清理 @wikipedia / @nasa / @natgeo / fiona 测试消息（可选，不影响链路）


