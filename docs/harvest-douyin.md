# 抖音账号从 0 添加（扫码收割 → 入账）

本文档描述如何从零添加一个抖音账号到 hub：受控浏览器扫码登录 → 采集发送凭据 →
装配校验 → 添加。全程约 10 分钟；登录动作由人完成（扫码/验证码），脚本只做采集。

> 原则：登录动作永远人工完成（自动化登录是高风控特征）。账号存活 > 一切。

## 前置

- Python 依赖已装（`pip install -r requirements.txt`，抖音通道只需核心三项）
- 一个可用的 DevTools MCP（如 js-reverse）：能开页面、执行 JS、抓网络请求
- 一个抖音账号（新号需先完成实名认证，否则 web 端无法扫码登录）

## 流程

### 1. 干净环境

受控浏览器打开 `https://www.douyin.com/`，执行站点数据清理
（cookies + localStorage + IndexedDB + sessionStorage），刷新页面。
这样登录产生的是全新会话与全新密钥组件。

### 2. 人工扫码

手机抖音 → 扫一扫 → 确认登录。二维码有时效，过期刷新重出。

### 3. 触发密钥组件

进入一次消息页（`https://www.douyin.com/message`），等待数秒。
IM 前端会初始化安全组件，在 IndexedDB `secure-store/cryptvalues` 写入：

- `security-sdk/s_sdk_crypt_sdk`（EC 私钥 PEM）
- `security-sdk/s_sdk_sign_data_key/web_protect`（ticket / ts_sign / client_cert）
- `security-sdk/s_sdk_cert_key`

### 4. 三步采集

用 DevTools MCP 执行（产物文件统一放一个目录，下称 `<dir>`）：

**① IndexedDB 全量记录** → `<dir>/harvest-idb-crypt.json`

```js
async () => {
  const out = await new Promise((res) => {
    const rq = indexedDB.open('secure-store');
    rq.onsuccess = () => {
      const db = rq.result;
      const tx = db.transaction('cryptvalues', 'readonly');
      const rk = tx.objectStore('cryptvalues').getAllKeys();
      const rv = tx.objectStore('cryptvalues').getAll();
      let keys, vals;
      const done = () => { if (keys && vals)
        res({ _keys: keys, _records: Object.fromEntries(keys.map((k, i) => [k, vals[i]])) }); };
      rk.onsuccess = () => { keys = rk.result; done(); };
      rv.onsuccess = () => { vals = rv.result; done(); };
    };
    rq.onerror = () => res('ERR');
  });
  return out;
}
```

**② 一条登录态请求头** → `<dir>/harvest-req-headers.json`

在网络请求列表里选一条 `www.douyin.com` 域的 XHR，导出完整请求头
（需要其中的 `cookie` 与 `user-agent`）。

**③ xmst** → `<dir>/harvest-xmst.json`

```js
() => ({ xmst: localStorage.getItem('xmst') })
```

### 5. 一键装配

```bash
python tools/harvest_douyin_send_blob.py --dir <dir>
```

脚本做离线一致性校验（私钥派生公钥 == client_cert、TG 头可签、a_bogus 可生成、
dump/load 回存无损），产出 `<dir>/send_blob.json`：`{cookie, uid, send_blob}`。

### 6. 入账

```bash
curl -X POST http://127.0.0.1:8788/api/accounts \
  -H "Content-Type: application/json" \
  -d "{\"platform\":\"douyin\",\"name\":\"dy-你的名字\",\"cookie\":\"<cookie>\",\"send_blob\":\"<send_blob 的 JSON 字符串>\"}"
```

hub 会做 init 验证（cookie 无效即拒绝）、拉会话面、推断自身 uid 并启动实时收信。
入账后发送立即可用，无需等待。

## 故障排查

- `cookie 里没有 sessionid`：扫码没完成或浏览器未登录
- IndexedDB 找不到 `secure-store`：没进过消息页，安全组件未初始化
- `公钥不一致`：idb 记录与请求头不是同一次登录会话采集的——全部重采
- 入账后收不到实时消息：确认入账返回的 `uid` 与登录账号一致（hub 从会话集合
  自动推断，异常时可在请求里显式传 `uid`）
