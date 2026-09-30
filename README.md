# tk-message-demo

自托管的多平台私信消息中心：**一个后端服务 + 一个静态页**。

支持 **TikTok / X (Twitter) / Instagram / Facebook Messenger** 四平台。多账号管理、
会话列表（昵称 + 头像）、历史消息向上滚动加载、新消息实时推送、发送消息、已读回执、
以及把一条消息同时发给多个自己会话的**批量发送**。

> **用途边界**：只用于管理**你自己**的账号。批量发送面向"给已知的多个自己的会话发同一条
> 消息"的场景，内置逐目标间隔与结果回报，**不是**营销外发工具；不含自动化互动、爬取他人
> 数据等能力。服务端只做两件事：读你自己会话的接口、代你发你自己写的消息。

---

## 为什么是"后端为核心"

这个站点的私信读接口**不需要签名**——只要带上你自己的会话 cookie，普通 HTTP 客户端就能
直接调用（实测：手写 136 字节的请求体即可拿到完整会话列表）。所以整个系统绝大部分是纯后端，
浏览器只在**取一次凭据**时出场。前端刻意保持成一个静态页，方便换主机、换域名、塞进任意反向代理。

---

## 要求

- Python **3.9+**（TikTok 全功能只用标准库，无需 pip install）
- 能访问对应平台（中国大陆需要代理，见[配置](#配置)）

## 平台支持

| 平台 | 登录方式 | 依赖 | 实时收信 | 已读回执 |
|---|---|---|---|---|
| **TikTok** | 弹窗登录（**密码 / 扫码**）或贴 cookie（可选：一行命令收割发送材料升级 `result=0`） | 无（纯标准库） | ✅ 204 增量轮询 | ✅ |
| **X (Twitter)** | 弹窗登录或贴 cookie（`auth_token` + `ct0`） | `pip install twikit` | ✅ 每账号会话轮询 | —（X 侧未见回执端点） |
| **Instagram** | 弹窗登录抓 sessionid，或两段式密码登录（首次要验证码，之后 session 持久化） | `pip install instagrapi` | ✅ | ✅ |
| **FB Messenger** | 贴 cookie（`c_user` + `xs`）；弹窗登录未接 | `pip install fbchat-v2`（自动下载校验过的 E2EE 桥） | ✅ MQTT | ✅ |

弹窗登录（TikTok / X / Instagram）另需 `pip install playwright`，而它**只在"登录这一次"**
用到：登录态抓到后浏览器自动关闭，日常收发不依赖它。TikTok 在窗口里请用**密码或扫码**，
**避免走 Google OAuth**（Google 对自动化窗口的判定更严，会直接拒绝登录）。

平台适配是统一的连接器接口（认证 / 会话列表 / 历史 / 发送 / 已读），新平台照此实现即可。
未安装某平台的依赖时，其余平台不受影响。

---

## 快速开始

```bash
python run.py
```

然后打开 <http://127.0.0.1:8788>，点右上角 **添加账号**，粘贴 cookie。

冷启动只有三步：

1. 准备一个可用的网络出口（直连或代理）
2. `python run.py`
3. 打开页面 → 添加账号 → 粘贴从浏览器复制的 cookie

数据落在 `data/hub.db`（SQLite）。重启后账号与历史自动恢复，无需重新导入。

---

## 目录结构

````
run.py                 入口：读配置、装配、全平台账号恢复、启动
config.example.json    配置模板（复制成 config.json 后生效）
app/
  hub.py               统一编排：账号生命周期、四平台会话登记、启动恢复、
                       逐平台同步循环、统一读写分发（conversations/messages/
                       send/mark_read 都从这里出）
  server.py            HTTP 路由（全平台一套 /api/accounts/...）、静态页、SSE
  platform/
    base.py            统一消息模型（Account/Conversation/Message/Contact）
                       + PlatformAdapter 通道契约（登录方式/能力/限速申报）
    registry.py        通道名 → 适配器登记表（缺失的可选平台自动跳过）
    tiktok.py          TikTok 适配器（包装 client.py）
    x.py               X 适配器（包装 xconnect）
    instagram.py       Instagram 适配器（包装 igconnect，两段式登录）
    facebook.py        FB 适配器（包装 fbconnect，E2EE 桥）
  client.py            TikTok 协议客户端：信封构造、各接口、双档签名
  signing.py           手写 P-256 ECDSA（标准库实现，含 PKCS#8 解析）
  proto.py             protobuf 线格式编解码（varint / length-delimited）
  xconnect.py          X 私有接口连接器（twikit 封装 + 收件箱自实现）
  igconnect.py         Instagram 连接器（instagrapi 封装，两段式 + sessionid 导入）
  fbconnect.py         FB 连接器（fbchat-v2 E2EE 桥封装）
  sync.py              TikTok 轮询机制 + 进程内事件总线（hub.py 的基类）
  harvest.py           TikTok 凭据收割：控制台脚本 + 回传端点
  login_browser.py     弹窗登录驱动（TikTok/X/IG 共用）：按适配器声明登录一次即自动抓取
  server.py            见上
web/
  index.html           单文件前端（含样式与脚本）
tests/
  smoke.py             只读冒烟验收（不发消息）
docs/
  credentials-acquisition-options.md   TikTok 凭据首次获取的方案对比
data/                  运行时生成，不要提交
````

架构总览见 [ARCHITECTURE.md](ARCHITECTURE.md)。

---

## 凭据从哪来

### cookie（必需，用来看和发的前提）

在浏览器里登录 `tiktok.com`，然后二选一：

- **devtools → Application/存储 → Cookies → `https://www.tiktok.com`**，全选复制；
- 或从任意一个发往 `tiktok.com` 的请求里复制 `Cookie` 请求头。

**必须包含 `sessionid`**。导入时服务端会调 `passport/web/account/info` 校验，
并自动识别出 uid / 用户名 / 昵称 —— 所以换个账号的 cookie 就是"换账号登录"，不需要别的步骤。

### 发送凭据（可选，不填也能发）

不填 = **Z 档**：服务端每次发送现生成一次性密钥、不带 ticket（信任分 `1104`，消息正常送达，
账号之间零绑定）。想要更高信任分时再填，**两种方式任选其一**：

**档位 B —— 本地签名（推荐，`result=0`）**

| 字段 | 说明 |
|---|---|
| `ticket` | 64 位十六进制，出现在发送请求体里 |
| **私钥** | 32 字节标量或 PKCS#8，hex 或 base64 |

服务端用自带的 P-256 实现（`app/signing.py`，仍是零依赖）对
`ticket=<ticket>&path=<path>&timestamp=<秒>` 做 ECDSA+SHA-256，输出 base64(DER)。
`ts_sign` 会**自动从请求头里提取**，不需要单独填。

好处：不再依赖某一组捕获的请求头，也就不受"它会不会过期"影响。实测这一档发出的请求
拿到的服务端信任结果与站点自己的客户端一致。

**材料从哪来（一次性）**：三件套诞生在登录浏览器的 localStorage 里（明文），
控制台一行命令即可导出（详见 `docs/credentials-acquisition-options.md`）；
之后 ticket/ts_sign 由 passport 心跳接口（`/passport/token/beat/web/`）纯 HTTP
自动续期，**无需再开浏览器**。

**档位 A —— 复用捕获的头**

| 字段 | 说明 |
|---|---|
| `tt-ticket-guard-public-key` | 一次真实发送请求里的同名头 |
| `tt-ticket-guard-client-data` | 同上 |
| `ticket` | 同上 |

取法：登录后打开私信页发一条消息，在 devtools → Network 里找到 `POST /v1/message/send`，
把这三个值抄下来。实测这组头在捕获后 47 分钟仍可用（该签名不覆盖请求体、也不做防重放），
但**不保证长期有效**。

**私钥从哪来**：它以明文 PEM 存放在登录浏览器的 `localStorage`（键
`security-sdk/s_sdk_crypt_sdk`），一行控制台命令即可导出全套材料（见
`docs/credentials-acquisition-options.md`）。也可以先用档位 A 跑起来，之后补上私钥
升级到档位 B —— 两者随时可切换，服务端按"能否本地签名"自动选档。

**浏览器登录（零手工升级，可选）**：在「添加账号」弹窗里选好平台后点「浏览器登录」——
会弹出一个 Chrome 窗口，在里面正常登录（密码/扫码/过码均可），登录完成 hub 自动抓取
登录态并入库（TikTok 还会额外收割签名材料），窗口自动关闭。该功能需要
`pip install playwright`（可选依赖，不影响其他功能；未安装时会提示改用一行命令方案）。

进入登录页之前会先清掉该平台上次的登录态 cookie（**保留设备标识**），所以同一个平台
可以连续登录多个账号；这一点是必需的：profile 是持久的，上次的登录态会让"登录完成"
判据立刻成立，窗口刚打开就被判成已登录、随即关闭。

**各平台的登录方式**：TikTok / X / Instagram 支持弹窗登录（FB 未接，仍贴 cookie）。
TikTok 在窗口里请用**密码或扫码**登录，**不要走 Google OAuth**（Google 对自动化窗口
判定更严，会直接拒绝）；X 登录后在窗口里自动抓 `auth_token`+`ct0`；Instagram 抓
`sessionid` 导入（账密+验证码通道仍保留作兜底）。

---

## 配置

复制 `config.example.json` 为 `config.json` 后按需修改。

| 键 | 默认 | 说明 |
|---|---|---|
| `host` / `port` | `127.0.0.1` / `8788` | 监听地址。放到公网前请自行加反向代理与鉴权 |
| `proxy` | `null` | `null` = 自动探测；填 URL 强制指定；填 `"direct"` 强制直连 |
| `data_dir` | `data` | SQLite 与运行数据目录 |
| `default_device_id` | 观测到的值 | 环境自述字段，不参与校验；换机器可覆盖 |
| `list_interval` | `60` | 会话列表刷新间隔（秒） |
| `msg_interval` | `12` | 消息轮询间隔（秒） |
| `poll_conversations` | `8` | 每轮轮询多少个最近会话 |
| `poll_page_size` | `20` | 每轮拉取的消息条数 |

**关于代理**：`HTTPS_PROXY` 环境变量里那个地址**未必能出网**（很多是宿主程序的内部通道）。
本服务不采信它，而是对候选列表逐个发一个 `HEAD` 实测，用第一个通的。
候选见 `app/client.py` 的 `PROXY_CANDIDATES`。

---

## 部署到新主机

服务本身是自包含的：

```bash
git clone <this repo>
cd tk-message-demo
python run.py --host 0.0.0.0 --port 8788
```

要点：

- 无第三方依赖，`python run.py` 即可；
- 换主机后**凭据仍然有效**（cookie 与账号绑定，不绑定机器），把 `data/hub.db` 一起拷过去即可恢复；
- 首次在新机器上跑，如果直连不通就配代理：`python run.py --proxy http://127.0.0.1:7890`；
- 公网部署请自行加一层鉴权，本服务没有任何登录保护。

---

## 协议摘要（实现依据）

均来自对真实会话的实测，不是猜的。

**统一信封**（请求体，无 query）：

```
f1 = 命令号    f2 = 子命令    f3 = "1.8.2"    f5 = 3    f6 = 0
f7 = "1132b10:master"    f8 = { f<命令号>: 载荷 }    f9 = device_id    f11 = "web"
```

| 用途 | cmd | 子命令 | 路径 | 载荷 |
|---|---|---|---|---|
| 会话列表 | 203 | 10001 | `/v2/message/get_by_user_init` | `{f1:0}` |
| 历史消息 | 301 | 10007 | `/v1/message/get_by_conversation` | `{f1 会话id, f2:1, f3 short_id, f4:1, f5 锚点微秒, f6 条数}` |
| 增量心跳 | 204 | 10040 | `/v1/message/get_by_user_combo` | `{f1:{f1:0, f2 游标, f3:50, f4:8}}` |
| 陌生人列表 | 1001 | — | `/v1/stranger/get_conversation_list` | f8 内层 **f1000**：`{f1 cursor, f2 count, f3 show_total_unread}` |
| 发送 | 100 | — | `/v1/message/send` | 见下 |
| 已读回执 | 2002 | 1 | `/v3/conversation/mark_read` | f8 内层 **f604**：`{f1 会话id, f2 short_id, f3:1, f4 read_index(最新消息微秒), f5/f6 未读计数}` |
| 用户资料 | — | — | `GET www.tiktok.com/tiktok/v1/im/user/profile/?aid=1988&user_ids=[...]` | 批量，JSON 返回 |

**已读回执（2002，已接入 hub）**：打开会话时自动发送（`POST /api/accounts/<name>/read`）。
read_index 取库里最新一条消息的微秒时间戳；f5/f6 传 0。实测两账号 `biz=0`。
注意：服务端会话计数（f11/f9）不因此归零——回执效果在**对方视角**的"已读"标记上，
本 hub 的未读徽章仍由前端本地基线管理。X-Bogus 用随机 24 位字母数字（web 客户端同款）。

**陌生人列表（1001）**：响应 f6 的内层 tag 也是 **f1000**（不是 1001）——
`{f1 next_cursor, f2 has_more, f3 total_unread（消息请求未读总数）, f4 StrangerConversation[]}`。
`300 v1/conversation/get_list` 是同义的老端点：即使按它自己的 proto 定义
（`cursor/count/show_total_unread`）正确构造也恒被 200001 拒绝，**不要用**。
两自有账号实测 `total_unread=0`、列表为空，与 web 端一致。

**会话列表响应有两个平行数组**，用会话 id 关联：

- 重复 `f1` = 各会话**最近的消息**（含正文、发送者、时间）
- 重复 `f2` = **会话元信息**（short_id、参与者）
- 尾部 `f3` = 下一页游标

**对方 uid 从会话 id 推导**：格式是 `0:1:<uidA>:<uidB>`，非本账号的那个就是对方。
（不要从载荷字段里读，部分字段带的是你自己的 uid。）

**单条消息字段**：`f3` 消息 id、`f7` 发送者 uid（等于自己即发出）、
`f8` 正文（`{"aweType":0,"text":"…"}` 明文）、`f10` 毫秒、`f13` 微秒、`f4` 微秒。

**发送**：信封**不能带 f2**（带上会返回参数错误）。载荷字段：
`f1` 会话 id、`f2` 会话类型=1、**`f3` short_id 必填**、`f4` 正文 JSON、
`f5` ext 映射（`s:client_message_id` 等）、`f6` 消息类型=7、`f7` ticket、`f8` client_message_id。

**实时机制（真增量协议）**：cmd 204（`get_by_user_combo`）是一个完整的增量通道，不是只回游标 ——

- 请求带"上次游标"（微秒），响应 `f1.f2` **直接携带范围内的新消息本体**（与 301 同构）；
  空闲时响应仅 117 字节。
- 响应 `f1.f9` 同时下发**每个会话的权威未读数**（`{short_id, conv_id, unread, total, ts}`），
  外层 `f5` 是下一个游标，`f6` 是服务端指定的轮询间隔（实测 30/60 浮动）。
- hub 的后台循环因此是**每 tick 一个请求**：有新消息 → 落库 + SSE 推送；未读 → 直接更新会话行。
  焦点会话保留独立快轮询（4 秒）压低显示延迟；每 10 个空闲 tick 强制一次全量重读兜底。
- 注意：游标传"当前时间"会永远拿到空响应 —— 它是**读取起点**，不是过滤条件。

**鉴权（可选）**：配置 `access_token` 后，除静态页与 `/api/health` 外的所有 `/api` 调用都要求
`Authorization: Bearer <token>`（SSE 用 `?token=`）。前端遇 401 会弹一次输入并记住。
默认为空 = 关闭，本地使用零摩擦；暴露到公网前务必设置。

**未读数（部分验证）**：会话条目 `f11`（203 与 `v1/conversation/list` 同值）随对方发来的
新消息精确 +1（快照差分实测 40→41），本地打开会话后以基线归零显示。但它的服务端语义
**没有完全锁定**：42 不匹配该会话任何消息计数子集（对方全部 63 条 / 仅文本 62 条 / 近两日 8 条）。
尝试用 `v3/conversation/mark_read`（cmd 2002，注意 RequestBody 内层字段号是 **604**，与命令号
两套体系；`read_message_index` 取最新消息的微秒时间戳，雪花 id 会被拒 `invalid read index`）
上报已读：请求被接受（`biz=0 OK`），但 f11 不归零。真实客户端的 mark_read 由 Web Worker 发出，
页面级抓包看不到它带了什么额外上下文 —— 这是已知盲区，留待附加 worker target 后对比。

---

## 已知限制与 roadmap

## 凭据收割

页面右上角 **收割凭据** 会给你一段脚本，粘到已登录的 `tiktok.com` 控制台里跑一次，
然后在页面上发一条消息。它能把写入所需的三样东西取出来：

| 取得到 | 怎么取 |
|---|---|
| 私钥（档位 B 用） | 钩 `crypto.subtle.importKey`，签名时会导入 PKCS#8 |
| 明文 `ticket` | 钩 `crypto.subtle.decrypt`，票据解密时返回明文 |
| `ts_sign` | 直接从 `localStorage` 读，本来就是明文 |

**取不到的两样，是有原因的**，不是没做：

- **会话 cookie**（`sessionid` 等是 `HttpOnly`）——页面 JS 永远读不到，所以要手工粘一次；
- **`tt-ticket-guard-*` 请求头 / 请求体**——SDK 启动时就缓存了 XHR/fetch 的原生引用，
  页面级的钩子看不到它自己的请求。

另外两个实测细节决定了脚本的写法：

- **IM 跑在同源 iframe 里**，每个 frame 是独立的 JS realm。装在顶层 window 的钩子
  根本看不到签名调用，所以脚本会遍历所有同源 frame，并周期性重扫（iframe 是延迟创建的）；
- **站点的 CSP 同时禁掉了到 `127.0.0.1` 的 `script-src` 与 `connect-src`**：
  用 `<script src>` 加载会得到 `failed - csp`，`sendBeacon` 返回 `true` 但服务端收不到。
  所以结果**不能自动回传**——脚本在页面右下角显示一个浮层，点「复制凭据 JSON」再粘回向导。
  （脚本里仍保留了自动回传的尝试，在无此 CSP 的站点上可以直接用。）

---

**限制**

- 发送需要一份该账号的写入凭据。**收割向导**能自动取到私钥 / `ticket` / `ts_sign`，
  但会话 cookie 里的 `sessionid` 是 `HttpOnly`，**要手工粘一次**；
  且受站点 CSP 所限，收割结果**要手工粘回**（见[凭据收割](#凭据收割)）。
- 档位 A 捕获的头在**长时间后可能失效**，届时表现为发送返回失败；重新取一次即可。
  档位 B 没有这个问题，但也仍依赖 `ticket`（会话级，重新登录后轮换）。
- 只支持文本消息。图片、表情、撤回等未实现。
- 无鉴权，不要直接暴露到公网。

**roadmap**

1. ✅ **档位 B（本地签名）**——已完成。`app/signing.py` 是手写的 P-256 ECDSA
   （标准库只有 `hashlib` / `secrets`，没有椭圆曲线），已用已知密钥做公钥点比对、
   自验签、以及端到端发送验证。
2. ✅ **凭据收割向导**——已完成。`app/harvest.py` 生成一段控制台脚本：遍历同源 frame
   钩 `crypto.subtle.importKey` / `decrypt`，并从 localStorage 读 `ts_sign`；
   页面右下角浮层显示捕获进度与结果，复制回向导即可保存。
   受站点 CSP 所限，回传这一步是手动的（见[凭据收割](#凭据收割)）。
3. ✅ **多平台**——X / Instagram / Facebook Messenger 适配器已完成（见[平台支持](#平台支持)）。
4. ✅ **批量发送**——`POST /api/batch/send`：一条消息发给多个自己会话，逐目标回报结果，
   内置逐目标间隔。
5. **消息类型扩展**——图片 / 表情。已读回执 TikTok/IG/FB 已实现（`v3/conversation/mark_read`）。
6. **推送接入**——如果后续能走通站点的推送通道，可以把轮询频率进一步降下来。

**已知限制**

- 发送需要一份该账号的写入凭据。**收割向导**能自动取到私钥 / `ticket` / `ts_sign`，
  但会话 cookie 里的 `sessionid` 是 `HttpOnly`，**要手工粘一次**；
  且受站点 CSP 所限，收割结果**要手工粘回**（见[凭据收割](#凭据收割)）。
- 档位 A 捕获的头在**长时间后可能失效**，届时表现为发送返回失败；重新取一次即可。
  档位 B 没有这个问题，但也仍依赖 `ticket`（会话级，重新登录后轮换）。
- 只支持文本消息。图片、表情、撤回等未实现。
- 无鉴权，不要直接暴露到公网。

---

## 许可

仅供个人在自有账号上使用。
