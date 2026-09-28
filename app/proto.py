"""Minimal protobuf wire-format codec.

Only what this protocol needs: varint, length-delimited, fixed32/64.
Deliberately dependency-free so the service runs on a bare Python install.
"""


def vi(n):
    """Encode an unsigned varint (arbitrary precision)."""
    n = int(n)
    if n < 0:
        raise ValueError('varint must be non-negative')
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field, wire):
    return vi(field * 8 + wire)


def vint(field, n):
    """field: varint"""
    return tag(field, 0) + vi(n)


def ld(field, data):
    """field: length-delimited (bytes / nested message)"""
    data = bytes(data)
    return tag(field, 2) + vi(len(data)) + data


def s(field, text):
    return ld(field, text.encode('utf-8'))


def sub(field, inner):
    return ld(field, inner)


def _read_vi(buf, i):
    v = 0
    shift = 0
    n = len(buf)
    while True:
        if i >= n:
            return None
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        if not (b & 0x80):
            return v, i
        shift += 7
        if shift > 70:
            return None


def parse(buf):
    """Decode into [(field, wire, varint|None, bytes|None), ...] or None if malformed."""
    out = []
    i = 0
    n = len(buf)
    while i < n:
        t = _read_vi(buf, i)
        if not t:
            return None
        key, i = t
        field, wire = key >> 3, key & 7
        if field == 0:
            return None
        if wire == 0:
            t = _read_vi(buf, i)
            if not t:
                return None
            v, i = t
            out.append((field, 0, v, None))
        elif wire == 2:
            t = _read_vi(buf, i)
            if not t:
                return None
            length, i = t
            if i + length > n:
                return None
            out.append((field, 2, None, buf[i:i + length]))
            i += length
        elif wire == 1:
            if i + 8 > n:
                return None
            out.append((field, 1, None, buf[i:i + 8]))
            i += 8
        elif wire == 5:
            if i + 4 > n:
                return None
            out.append((field, 5, None, buf[i:i + 4]))
            i += 4
        else:
            return None
    return out


def one(items, field, default=None):
    """First varint value of `field`."""
    for f, w, v, _ in items or ():
        if f == field and w == 0:
            return v
    return default


def blob(items, field):
    """First length-delimited payload of `field`."""
    for f, w, _, b in items or ():
        if f == field and w == 2:
            return b
    return None


def all_of(items, field, wire=2):
    return [it for it in items or () if it[0] == field and it[1] == wire]


def text(b):
    """Decode bytes as UTF-8 text, or None if it looks binary."""
    if b is None:
        return None
    try:
        t = b.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 and c not in '\t\n\r' for c in t):
        return None
    return t


def pairs(items):
    """Decode repeated {f1: key, f2: value} into a dict."""
    out = {}
    for it in items or ():
        inner = parse(it[3])
        if not inner:
            continue
        k = text(blob(inner, 1))
        if k is not None:
            out[k] = text(blob(inner, 2))
    return out
