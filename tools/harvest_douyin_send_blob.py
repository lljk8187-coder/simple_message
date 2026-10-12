"""抖音 send_blob 收割装配脚本（受控浏览器三步采集 → 本命令一键出 blob）。

使用流程（完整收割 ≈2 分钟）：
  前置：受控浏览器里打开 https://www.douyin.com/ 且已完成扫码登录，
        并进入过一次消息页（触发 IM 安全组件在 IndexedDB 写入密钥组件）
  三步采集（可用 js-reverse 类 DevTools MCP 完成，详见 docs/harvest-douyin.md）：
  步骤① evaluate_script -> harvest-idb-crypt.json
      async () => { /* 读 IndexedDB secure-store/cryptvalues 全量记录，
                      _records 内含 s_sdk_crypt_sdk 与 s_sdk_sign_data_key/web_protect */ }
  步骤② list_network_requests 选一条 www.douyin.com 登录态 xhr（reqid）
        -> outputFile=harvest-req-headers.json, outputPart="all"
  步骤③ evaluate_script -> harvest-xmst.json
        () => ({xmst: localStorage.getItem('xmst')})
  步骤④ python tools/harvest_douyin_send_blob.py --dir <采集文件所在目录>

产出：<dir>/send_blob.json（cookie+uid+send_blob）。添加账号：
  POST /api/accounts  {platform:'douyin', cookie:<cookie>,
                       send_blob:<send_blob 的 JSON 字符串>}
校验：私钥派生公钥==client_cert（ree_pub 头同源）、TG 头可签、
      a_bogus 可生成、dump/load 回存无损（离线，零网络）。
"""
import argparse
import base64
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main():
    ap = argparse.ArgumentParser(description='assemble douyin send_blob from harvested files')
    ap.add_argument('--dir', default=os.path.dirname(os.path.abspath(__file__)),
                    help='采集文件（harvest-*.json）所在目录，默认脚本同目录')
    args = ap.parse_args()
    here = args.dir

    req = json.load(open(os.path.join(here, 'harvest-req-headers.json'), encoding='utf-8'))
    cookie = req['requestHeaders']['cookie']
    ua = req['requestHeaders']['user-agent']

    idb = json.load(open(os.path.join(here, 'harvest-idb-crypt.json'), encoding='utf-8'))
    recs = idb['_records']
    crypt = json.loads(json.loads(recs['security-sdk/s_sdk_crypt_sdk'])['data'])
    priv_pem = crypt['ec_privateKey']
    protect = json.loads(json.loads(
        recs['security-sdk/s_sdk_sign_data_key/web_protect'])['data'])
    ticket, ts_sign, client_cert = protect['ticket'], protect['ts_sign'], protect['client_cert']

    # 一致性校验：私钥派生公钥点必须 == client_cert（即 ree_pub 头的值源）
    from cryptography.hazmat.primitives import serialization
    priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    pub = priv.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)
    assert 'pub.' + base64.b64encode(pub).decode() == client_cert, '公钥不一致'

    verify_fp = next((p.split('=', 1)[1] for p in cookie.split('; ')
                      if p.startswith('s_v_web_id=')), '')
    assert verify_fp, 'cookie 里没有 s_v_web_id'

    xmst = json.load(open(os.path.join(here, 'harvest-xmst.json'), encoding='utf-8'))['xmst']

    blob = {'verify_fp': verify_fp, 'ms_token': xmst,
            'tg_private_pem': priv_pem, 'tg_ticket': ticket,
            'tg_ts_sign': ts_sign, 'tg_ree_pub': client_cert,
            'user_agent': ua, 'session_dtrait': ''}

    # 离线装配验证（零网络）：strict 装配 → TG 头可签 → a_bogus 可生成 → 回存无损
    from app.platform.registry import load_adapters, get
    load_adapters()
    ad = get('douyin')()
    ad._proxy = None
    from app import dyconnect
    s = dyconnect.DySession(cookie)
    ad._setup_send(s, blob, strict=True)
    cd = json.loads(base64.b64decode(s._tg_client_data('/v1/message/send')))
    assert cd['req_content'] == 'ticket,path,timestamp'
    assert 100 < len(s._abogus.get_value('aid=6383', body=b'x')) < 250
    d = ad.session_dump(s)
    assert d['tg_private_pem'] == priv_pem

    uid = next((p.split('=', 1)[1] for p in cookie.split('; ')
                if p.startswith('uid_tt=')), '') or '(从 user_info 或会话 conv_id 取)'
    out = os.path.join(here, 'send_blob.json')
    json.dump({'cookie': cookie, 'uid': uid, 'send_blob': blob},
              open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('BLOB_OK ->', out)
    print('  uid 需人工确认（hub 入账后自动回填）')


if __name__ == '__main__':
    main()
