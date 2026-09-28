"""P-256 ECDSA signing, standard library only.

Why hand-rolled: this project ships with no third-party dependencies, and the
only thing it must sign is a short ASCII string with SHA-256. A minimal,
readable implementation is preferable here to pulling in a crypto package.

The scheme it serves (established by measurement, see README):

    payload = "ticket=<ticket>&path=<path>&timestamp=<unix seconds>"
    signature = ECDSA(P-256, SHA-256) over utf8(payload), DER-encoded, then base64

No low-level trickery is required — the site uses the standard construction, and
signatures produced here are accepted by the service with the same trust result
as its own client's.
"""
import hashlib
import secrets

# curve parameters (FIPS 186-4, secp256r1 / prime256v1)
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (GX, GY)

Point = None            # type alias: (x, y) or None for the point at infinity


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None                                  # P + (-P) = O
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k, pt):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def public_point(d):
    return _mul(d % N, G)


def public_key_raw(d):
    """Uncompressed SEC1 point: 0x04 || X(32) || Y(32) — the wire format used."""
    x, y = public_point(d)
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def spki_der(d):
    """DER SubjectPublicKeyInfo for the same key, matching what the site sends."""
    prefix = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
    return prefix + public_key_raw(d)


def _der_int(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')
    if raw[0] & 0x80:
        raw = b'\x00' + raw
    return b'\x02' + bytes([len(raw)]) + raw


def sign(payload, d, low_s=True):
    """ECDSA over SHA-256(payload). Returns DER bytes (r,s)."""
    z = int.from_bytes(hashlib.sha256(payload).digest(), 'big')
    while True:
        k = secrets.randbelow(N - 1) + 1
        point = _mul(k, G)
        if point is None:
            continue
        r = point[0] % N
        if r == 0:
            continue
        s = pow(k, -1, N) * (z + r * d) % N
        if s == 0:
            continue
        if low_s and s > N // 2:
            s = N - s                              # canonical low-s form
        body = _der_int(r) + _der_int(s)
        return b'\x30' + bytes([len(body)]) + body


def verify(payload, der_sig, d):
    """Self-check helper; not used on the request path."""
    z = int.from_bytes(hashlib.sha256(payload).digest(), 'big')
    r, s = _parse_der(der_sig)
    w = pow(s, -1, N)
    point = _add(_mul(z * w % N, G), _mul(r * w % N, public_point(d)))
    return point is not None and point[0] % N == r


def _parse_der(der):
    if der[0] != 0x30:
        raise ValueError('not a DER sequence')
    i = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    vals = []
    while i < len(der) and len(vals) < 2:
        if der[i] != 0x02:
            raise ValueError('expected an INTEGER')
        size = der[i + 1]
        vals.append(int.from_bytes(der[i + 2:i + 2 + size], 'big'))
        i += 2 + size
    if len(vals) != 2:
        raise ValueError('expected two integers')
    return vals


def scalar_from_pkcs8(data):
    """Pull the 32-byte private scalar out of a PKCS#8 blob.

    Accepts the 138-byte structure the site produces, or any PKCS#8 that exposes
    the scalar in a `04 20 <32 bytes>` block.
    """
    if len(data) == 138 and data[0] == 0x30:
        return int.from_bytes(data[36:68], 'big')
    marker = data.rfind(b'\x04\x20')
    if marker >= 0 and marker + 34 <= len(data):
        return int.from_bytes(data[marker + 2:marker + 34], 'big')
    raise ValueError('cannot locate the private scalar in this PKCS#8 blob')


def parse_private_key(text):
    """Accept a bare 32-byte scalar or a PKCS#8 blob, hex or base64 encoded."""
    import base64
    import re
    raw = (text or '').strip()
    if not raw:
        raise ValueError('empty private key')
    cleaned = re.sub(r'[\s:,-]', '', raw)
    data = None
    if re.fullmatch(r'[0-9a-fA-F]+', cleaned) and len(cleaned) % 2 == 0:
        data = bytes.fromhex(cleaned)
    else:
        try:
            data = base64.b64decode(cleaned, validate=True)
        except Exception as exc:
            raise ValueError('private key is neither hex nor base64') from exc
    if len(data) == 32:
        return int.from_bytes(data, 'big')
    return scalar_from_pkcs8(data)
