# 凭据首次获取——方案选择文档（待选型）

> 状态：**方案 3（Z 档）已确定为兜底**；方案 1 / 2 为候选分支，尚未实施。
> 背景：签名算法已纯算（`app/signing.py`）；ticket/ts_sign 的续期已纯算
> （`/passport/token/beat/web/` 响应头 `tt-ticket-guard-server-data` 明文返回当前
> ticket+ts_sign，已实测可从 Python 调用）；**首次签发绑定真实登录流程**，
> 无法对已有会话的新公钥签发（beat / account/info / send 露脸 + 延迟均实测不签发）。

## 材料生命周期（为什么收割是一次性的）

| 材料 | 生命周期 | 维持方式 |
|---|---|---|
| 私钥（P-256） | 永久（本地生成，跨登录不轮换） | 无需维持 |
| ticket / ts_sign | 会话级，会轮换 | beat 纯 HTTP 自动续，无需重收割 |
| cookie（sessionid） | 长效 | 过期才重导（届时自然重登录） |

需重做收割的情形：① sessionid 过期/登出（反正要重导 cookie）；② 浏览器本地
状态被清导致重新注册新密钥（旧材料作废，重读一次）。

## 方案 1：一行命令收割（每账号一次性 ~30 秒，推荐）

在已登录 TikTok 标签的控制台执行（自动复制到剪贴板），粘贴进 hub 导入框：

```js
(async()=>{const s=JSON.parse(JSON.parse(localStorage.getItem('security-sdk/s_sdk_sign_data_key/tt_fetch')).data);const b=Uint8Array.from(atob(s.encrypt_ticket),c=>c.charCodeAt(0));const k=await crypto.subtle.importKey('raw',new TextEncoder().encode('tt-ticket-guard-iv'),'PBKDF2',false,['deriveKey']);const kk=await crypto.subtle.deriveKey({name:'PBKDF2',salt:new TextEncoder().encode('secure-salt'),iterations:1000,hash:'SHA-256'},k,{name:'AES-GCM',length:128},false,['decrypt']);const ticket=new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12)},kk,b.slice(12)));const pk=JSON.parse(JSON.parse(localStorage.getItem('security-sdk/s_sdk_crypt_sdk')).data).ec_privateKey.replace(/-----[A-Z ]+-----/g,'').replace(/\s+/g,'');copy(JSON.stringify({ticket,private_key:pk,ts_sign:s.ts_sign}));return 'copied!'})()
```

产出：`{ticket, private_key(PKCS#8 b64), ts_sign}`。原理：`encrypt_ticket`
= AES-128-GCM(PBKDF2("tt-ticket-guard-iv","secure-salt",1000))，IV 前置 12 字节，
浏览器内现场解密。已实测 ticket 解出正确、PKCS#8 为 138 字节标准结构。

- 优点：零新依赖、result=0 自有材料、无跨账号绑定
- 缺点：每账号一次 30 秒手工动作（与导 cookie 同一时机，边际成本小）

## 方案 2：无头浏览器自动收割（零人工，部署重）

hub 导入 cookie 后自动以该 cookie 打开一次 IM 页（headless Chrome），等安全 SDK
初始化后读同款 localStorage 键完成收割，全程用户无感。

- 优点：用户体验零操作
- 缺点：部署机需要浏览器二进制 + 网络可达 TikTok；引入 Playwright/CDP 依赖，
  打破"零第三方依赖"原则

## 方案 3：Z 档零材料发送（已定兜底）

不收割任何材料：每次发送现生成一次性 P-256 密钥 + 空 client-data + 无 ticket，
实测 `biz_code=0`、`guard_result=1104`（信任最低但送达），matrix-tiktok 生产同款。

- 优点：彻底零依赖、账号完全独立
- 缺点：信任评级最低；若 TikTok 收紧（强制有效 ticket）此档失效

## 推荐组合

方案 1（一次性收割）+ beat 续期 + 方案 3 兜底：自有材料可用时走 `result=0`，
没有时自动落到 1104，任何账号永远可发。
