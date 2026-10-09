# -*- coding: utf-8 -*-
"""抖音 imapi (imapi.douyin.com) a_bogus URL 签名算法 — Python 实现。

来源与验证
==========
本实现逆向自抖音网页端实际加载的 ``bdms_1.0.1.19_fix.js``（页面脚本 URL:
``https://p-pc-weboff.byteimg.com/tos-cn-i-9r5gewecjs/bdms_1.0.1.19_fix.js``），
算法家族与 Evil0ctal/Douyin_TikTok_Download_API 的 ABogus 一致，但针对
``POST /v1/message/send`` 的真实捕获样本（web-send-3905.json）做了
**字节级**校准，与期望输出逐字节一致。

与社区参考实现（abogus_ref.py）的分歧点
========================================
1. **body 摘要哈希空串**：XHR send 传二进制（ArrayBuffer/Uint8Array）时
   SDK 无法将其字符串化，body 摘要链哈希的是 ``""`` 而非请求体。
   即第三条链输入恒为 ``SM3(SM3("" + "dhzx"))``。
2. **环境探针常量不同**：
   - ``DETECT_FLAGS = 32``（社区版 14）——同时改变 UA 链 RC4 密钥
     （密钥 = ``(ENV_FLAGS//256, ENV_FLAGS%256, DETECT_FLAGS%256)`` = ``(0,1,32)``）
   - ``NR_FLAGS = 1``（社区版 0x21），``NR_TAG = (62, 4, 4, 15)``（社区版全 0）
3. **browser_info 为真实窗口几何**：默认
   ``"1126|847|1142|942|1920|1032|1920|1080|Win32"``
   （内窗宽|内窗高|外窗宽|外窗高|屏幕宽|可用高|屏幕宽|屏幕高|平台）。
4. 算法主体（SM3 双轮哈希链、自定义 RC4、噪声掩码展开、
   ``checksum = XOR(version + 50 字段)``、s4 字母表 base64、头部
   ``(3, 82)`` 掩码、version 块 ``(1,0,1,0)`` 掩码）与社区版一致。

输出形如 192 字符（含末尾 ``==`` 填充）的 base64 变体串；
放入 URL 时需按查询串规则百分号编码（``/``→``%2F``、``=``→``%3D``）。

本文件仅依赖 Python 标准库。
"""

from __future__ import annotations

import functools
from random import Random
from time import time

__all__ = ["ABogus", "DEFAULT_BROWSER_INFO"]

# ---------------------------------------------------------------------------
# SM3 (GB/T 32905-2016)，与 gmssl.sm3.sm3_hash 逐字节一致
# ---------------------------------------------------------------------------

_MASK = 0xFFFFFFFF

IV: tuple[int, ...] = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)
_T0 = 0x79CC4519
_T1 = 0x7A879D8A


def _rotl(value: int, bits: int) -> int:
    bits %= 32
    return ((value << bits) & _MASK) | (value >> (32 - bits))


def _sm3_pad(message: bytes) -> bytes:
    bit_length = len(message) * 8
    padded = message + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    return padded + bit_length.to_bytes(8, "big")


def _ff(index: int, x: int, y: int, z: int) -> int:
    if index < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _gg(index: int, x: int, y: int, z: int) -> int:
    if index < 16:
        return x ^ y ^ z
    return (x & y) | ((~x & _MASK) & z)


def _sm3_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    w = [int.from_bytes(block[i * 4 : i * 4 + 4], "big") for i in range(16)]
    for i in range(16, 68):
        x = w[i - 16] ^ w[i - 9] ^ _rotl(w[i - 3], 15)
        x = x ^ _rotl(x, 15) ^ _rotl(x, 23)
        w.append((x ^ _rotl(w[i - 13], 7) ^ w[i - 6]) & _MASK)
    w1 = [(w[i] ^ w[i + 4]) & _MASK for i in range(64)]
    a, b, c, d, e, f, g, h = state
    for j in range(64):
        t = _T0 if j < 16 else _T1
        ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & _MASK, 7)
        ss2 = ss1 ^ _rotl(a, 12)
        tt1 = (_ff(j, a, b, c) + d + ss2 + w1[j]) & _MASK
        tt2 = (_gg(j, e, f, g) + h + ss1 + w[j]) & _MASK
        d = c
        c = _rotl(b, 9)
        b = a
        a = tt1
        h = g
        g = _rotl(f, 19)
        f = e
        e = (tt2 ^ _rotl(tt2, 9) ^ _rotl(tt2, 17)) & _MASK
    return tuple((x ^ y) & _MASK for x, y in zip(state, (a, b, c, d, e, f, g, h), strict=True))


def sm3(message: bytes) -> bytes:
    """32 字节 SM3 摘要。"""
    state = IV
    padded = _sm3_pad(message)
    for offset in range(0, len(padded), 64):
        state = _sm3_compress(state, padded[offset : offset + 64])
    return b"".join(word.to_bytes(4, "big") for word in state)


def sm3_to_array(data) -> list[int]:
    """SM3 摘要的 32 个整数；str 按 UTF-8 编码。"""
    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, bytes):
        raw = data
    else:
        raw = bytes(data)
    return list(sm3(raw))


# ---------------------------------------------------------------------------
# 算法常量（针对 imapi 变体校准）
# ---------------------------------------------------------------------------

# s4 编码最终签名；s3 编码进入 UA 摘要链的 RC4 输出
ALPHABETS: dict[str, str] = {
    "s3": "ckdp1h4ZKsUB80/Mfvw36XIgR25+WQAlEi7NLboqYTOPuzmFjJnryx9HVGDaStCe",
    "s4": "Dkdpgh2ZmsQB80/MfvV36XI1R45-WUAlEixNLwoqYTOPuzKFjJnry79HbGcaStCe",
}

SALT = "dhzx"                      # 哈希前附加在输入末尾的盐
HEADER_MAGIC: tuple[int, int] = (3, 82)     # 签名头部两个明文字节
SDK_VERSION: tuple[int, int, int, int] = (1, 0, 1, 0)  # "1.0.1.19-fix.01"
PAYLOAD_KEY = 0xD3                 # RC4 单字节密钥（非标准 RC4）

# 环境探针常量（imapi 变体实测值）
ENV_FLAGS = 1
DETECT_FLAGS = 32                  # 社区版为 14
NR_FLAGS = 1                       # 社区版为 0x21
NR_TAG: tuple[int, int, int, int] = (62, 4, 4, 15)  # 社区版为全 0

TRIPWIRE_LOCKED = 3
CALL_BUCKET = 6
PAGE_ID = 6241
AID = 6383

# 2024-07-24T16:00:00Z，一个字段自此以双周为单位计数
FORTNIGHT_EPOCH_MS = 1_721_836_800_000

# 浏览器几何/环境报告（真实页面窗口值；可按目标环境替换）
DEFAULT_BROWSER_INFO = "1126|847|1142|942|1920|1032|1920|1080|Win32"

# 噪声掩码：三个数据字节与一个噪声字节混成四个载体字节
NOISE_MASKS: tuple[int, int, int] = (0x91, 0x42, 0x2C)
DATA_MASKS: tuple[int, int, int] = (0x6E, 0xBD, 0xD3)

# 50 个标量字段在载荷中的固定排列
FIELD_ORDER: tuple[str, ...] = (
    "L34", "L44", "L56", "L61", "L73", "L29", "L70", "L45", "L35", "L49",
    "L38", "L66", "L51", "L68", "L28", "L48", "L64", "L47", "L30", "L71",
    "L26", "L55", "L31", "L69", "L59", "L40", "L62", "L63", "L27", "L72",
    "L41", "L74", "L57", "L52", "L42", "L39", "L33", "L67", "L53", "L43",
    "L65", "L46", "L36", "L24", "L60", "L32", "L79", "L80", "L84", "L85",
)  # fmt: skip

# 摘要哨兵：字段取 digest[offset:] 中第一个不等于 sentinel 的字节
CANARIES: tuple[tuple[int, int, int], ...] = ((3, 11, 12), (4, 8, 9), (5, 12, 13))


class _DigestChain:
    __slots__ = ("slots", "indices", "canary")

    def __init__(self, slots, indices, canary):
        self.slots = slots
        self.indices = indices
        self.canary = canary


DIGEST_CHAINS: dict[str, _DigestChain] = {
    "query": _DigestChain(("L48", "L49", "L51"), (9, 18), CANARIES[0]),
    "body": _DigestChain(("L52", "L53", "L55"), (10, 19), CANARIES[1]),
    "user_agent": _DigestChain(("L56", "L57", "L59"), (11, 21), CANARIES[2]),
}

# 头部第二噪声字节的浏览器家族分桶
_HEADER_NOISE_BANDS: dict[str, int] = {
    "chrome": 0, "firefox": 40, "safari": 81, "edge": 125, "huawei": 170, "other": 210,
}
_TRIPWIRE_SET = 0xB2
_TRIPWIRE_FREE = 0x4D


# ---------------------------------------------------------------------------
# 基础原语
# ---------------------------------------------------------------------------

def _family_of(user_agent: str) -> str:
    ua = user_agent.lower()
    for name in ("edg", "huawei", "firefox", "chrome", "safari"):
        if name in ua:
            return {"edg": "edge"}.get(name, name)
    return "other"


def _header_noise(user_agent: str, rng: Random) -> int:
    base = _HEADER_NOISE_BANDS.get(_family_of(user_agent), _HEADER_NOISE_BANDS["other"])
    return (base + int(rng.random() * 40)) & 0xFF


def _probe_noise(rng: Random) -> int:
    value = int(rng.random() * 240)
    return value + value % 2 + 1 if value > 109 else value


def _tripwire_noise(rng: Random) -> int:
    return (int(rng.random() * 255) & _TRIPWIRE_FREE) | _TRIPWIRE_SET


def _mask_pair(pair, rng, *, low=None, high=None):
    """把两个字节摊到四个载体字节上，另一半填噪声。"""
    noise = int(rng.random() * 65535)
    low = noise & 0xFF if low is None else low & 0xFF
    high = (noise >> 8) & 0xFF if high is None else high & 0xFF
    return [
        (low & 0xAA) | (pair[0] & 0x55),
        (low & 0x55) | (pair[0] & 0xAA),
        (high & 0xAA) | (pair[1] & 0x55),
        (high & 0x55) | (pair[1] & 0xAA),
    ]


def _expand_noise(body: bytes, rng: Random) -> bytes:
    out = bytearray()
    for offset in range(0, len(body), 3):
        group = body[offset : offset + 3]
        if len(group) < 3:
            out.append(group[0])
            if len(group) > 1 and group[1]:
                out.append(group[1])
            continue
        noise = int(rng.random() * 1000) & 0xFF
        out.extend(
            (noise & mask) | (byte & data)
            for mask, data, byte in zip(NOISE_MASKS, DATA_MASKS, group, strict=True)
        )
        out.append(
            (group[0] & NOISE_MASKS[0])
            | (group[1] & NOISE_MASKS[1])
            | (group[2] & NOISE_MASKS[2])
        )
    return bytes(out)


def js_bytes(text: str) -> bytes:
    """按 SDK 的 charCodeAt 规则把字符串转为字节（非 UTF-8）。"""
    out = bytearray()
    units = text.encode("utf-16-le")
    for index in range(0, len(units), 2):
        code = units[index] | (units[index + 1] << 8)
        if code & 0xFF00:
            out.append(code >> 8)
        out.append(code & 0xFF)
    return bytes(out)


def _le_bytes(value: int, count: int) -> list[int]:
    return [(value >> (8 * index)) & 0xFF for index in range(count)]


def canary(digest: list[int], offset: int, sentinel: int, fallback: int) -> int:
    for byte in digest[offset:]:
        if byte != sentinel:
            return byte
    return fallback


def digest_of(text: str) -> list[int]:
    """SM3(SM3(text + SALT))。"""
    return sm3_to_array(sm3_to_array(text + SALT))


def body_digest_of(body) -> list[int]:
    """body 摘要链：二进制 body（bytes/None）对 SDK 不可见，哈希空串。

    str 输入按 SDK 字符串语义哈希（保留社区版行为）。
    """
    if isinstance(body, str):
        return digest_of(body)
    return digest_of("")


def user_agent_digest(user_agent: str) -> list[int]:
    """UA 链：RC4 加密 User-Agent → s3 base64 → 一次 SM3。

    RC4 密钥由环境探针构成：(ENV//256, ENV%256, DETECT%256) = (0,1,32)。
    """
    key = bytes((ENV_FLAGS // 256, ENV_FLAGS % 256, DETECT_FLAGS % 256))
    sealed = rc4(key, bytes(byte & 0xFF for byte in js_bytes(user_agent.strip())))
    return sm3_to_array(encode_base64(sealed, "s3"))


def rc4(key: bytes, data: bytes) -> bytes:
    """SDK 的非标准 RC4：S 盒降序初始化，密钥调度使用乘法。"""
    box = [0] * 256
    for i in range(256):
        box[255 - i] = i
    j = 0
    for i in range(256):
        j = (j * box[i] + j + key[i % len(key)]) % 256
        box[i], box[j] = box[j], box[i]

    out = bytearray(len(data))
    i = j = 0
    for index, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        out[index] = byte ^ box[(box[i] + box[j]) % 256]
    return bytes(out)


def encode_base64(data: bytes, alphabet: str = "s4") -> str:
    """SDK 字母表上的 base64 编码，字面量 "=" 填充。"""
    table = ALPHABETS[alphabet]
    out: list[str] = []
    for offset in range(0, len(data), 3):
        chunk = data[offset : offset + 3]
        block = int.from_bytes(chunk + b"\x00" * (3 - len(chunk)), "big")
        digits = [(block >> shift) & 0x3F for shift in (18, 12, 6, 0)]
        out.extend(table[digit] for digit in digits[: len(chunk) + 1])
    out.append("=" * ((4 - len(out) % 4) % 4))
    return "".join(out)


# ---------------------------------------------------------------------------
# 对外接口
# ---------------------------------------------------------------------------

class ABogus:
    """为单一浏览器身份计算 imapi 的 a_bogus。

    user_agent 必须与请求实际发送的 User-Agent 完全一致（签名绑定 UA）。
    browser_info 默认为校准用的真实窗口几何，可按需替换。
    """

    def __init__(
        self,
        user_agent: str,
        *,
        browser_info: str = DEFAULT_BROWSER_INFO,
        page_id: int = PAGE_ID,
        aid: int = AID,
        rng: Random | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.browser_info = browser_info
        self.page_id = page_id
        self.aid = aid
        self._rng = rng or Random()

    def _fields(self, query: str, body_digest: list[int], user_agent_dig: list[int], now_ms: int) -> dict[str, int]:
        digests = {
            "query": digest_of(query),
            "body": body_digest,
            "user_agent": user_agent_dig,
        }
        ink = now_ms - 1
        fortnights = (now_ms - FORTNIGHT_EPOCH_MS) // (1000 * 60 * 60 * 24 * 14)
        info_bytes = js_bytes(self.browser_info)
        tail_bytes = js_bytes(f"{(now_ms + 3) & 0xFF},")

        fields: dict[str, int] = {
            "L24": 41,
            "L26": fortnights,
            "L27": CALL_BUCKET,
            "L28": 3,
            "L35": ENV_FLAGS & 0xFF,
            "L36": (ENV_FLAGS // 256) & 0xFF,
            "L38": NR_FLAGS & 0xFF,
            "L39": (NR_FLAGS >> 8) & 0xFF,
            "L66": TRIPWIRE_LOCKED,
            "L79": len(info_bytes) & 0xFF,
            "L80": (len(info_bytes) >> 8) & 0xFF,
            "L84": len(tail_bytes) & 0xFF,
            "L85": (len(tail_bytes) >> 8) & 0xFF,
        }
        for index, byte in enumerate(_le_bytes(now_ms, 6)):
            fields[f"L{29 + index}"] = byte
        for index, byte in enumerate(_le_bytes(DETECT_FLAGS, 4)):
            fields[f"L{44 + index}"] = byte
        for index, byte in enumerate(NR_TAG):
            fields[f"L{40 + index}"] = byte
        for index, byte in enumerate(_le_bytes(ink, 6)):
            fields[f"L{60 + index}"] = byte
        for index, byte in enumerate(_le_bytes(self.page_id, 4)):
            fields[f"L{67 + index}"] = byte
        for index, byte in enumerate(_le_bytes(self.aid, 4)):
            fields[f"L{71 + index}"] = byte
        for name, chain in DIGEST_CHAINS.items():
            digest = digests[name]
            first, second = chain.indices
            written = (digest[first], digest[second], canary(digest, *chain.canary))
            for slot, value in zip(chain.slots, written, strict=True):
                fields[slot] = value
        return fields

    def get_value(
        self,
        query: str,
        *,
        body="",
        content_type: str = "",
        now_ms: int | None = None,
    ) -> str:
        """计算一次请求的 a_bogus。

        Args:
            query: 即将发送的完整 query 字符串（不含 a_bogus 本身），
                参数顺序需与实际请求一致。
            body: POST 请求体。传 bytes/bytearray/None（二进制 body）时
                摘要链哈希空串——与真实 SDK 行为一致（imapi protobuf 场景）；
                传 str 时按 SDK 字符串语义哈希。
            content_type: multipart/form-data 时 SDK 哈希前置空 body。
            now_ms: 毫秒时钟，测试时可固定。

        Returns:
            a_bogus 字符串（未做 URL 百分号编码，约 192 字符，含 ``==``）。
        """
        if "multipart/form-data" in (content_type or "").lower():
            body = ""
        now = now_ms if now_ms is not None else int(time() * 1000)
        if now < FORTNIGHT_EPOCH_MS:
            raise ValueError(f"clock is before the a_bogus epoch: {now}")

        body_digest = body_digest_of(body)
        ua_digest = user_agent_digest(self.user_agent)
        fields = self._fields(query, body_digest, ua_digest, now)

        version = _mask_pair(SDK_VERSION[:2], self._rng) + _mask_pair(
            SDK_VERSION[2:],
            self._rng,
            low=_probe_noise(self._rng),
            high=_tripwire_noise(self._rng),
        )

        checksum = 0
        for byte in version:
            checksum ^= byte
        for name in FIELD_ORDER:
            checksum ^= fields[name]

        body_bytes = bytes(fields[name] for name in FIELD_ORDER)
        body_bytes += js_bytes(self.browser_info)
        body_bytes += js_bytes(f"{(now + 3) & 0xFF},")
        body_bytes += bytes((checksum,))

        header = bytes(
            _mask_pair(
                HEADER_MAGIC, self._rng, high=_header_noise(self.user_agent, self._rng)
            )
        )
        frame = _expand_noise(body_bytes, self._rng)
        sealed = rc4(bytes((PAYLOAD_KEY,)), bytes(version) + frame)
        return encode_base64(header + sealed, "s4")


def _xor(bs) -> int:
    return functools.reduce(lambda a, b: a ^ b, bs)
