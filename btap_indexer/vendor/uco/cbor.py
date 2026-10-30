"""Minimal deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding), stdlib only.

Supported: unsigned/negative integers, byte strings, text strings, arrays, maps, false/true/null.
Floats, tags, indefinite lengths and non-shortest heads are rejected by the decoder, so a decoded value
re-encodes to the same bytes (`canonical(b)` checks that)."""


class CBORError(ValueError):
    pass


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise CBORError("integer too large")


def encode(v) -> bytes:
    if v is False:
        return b"\xf4"
    if v is True:
        return b"\xf5"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, dict):
        items = sorted((encode(k), encode(x)) for k, x in v.items())
        for a, b in zip(items, items[1:]):
            if a[0] == b[0]:
                raise CBORError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise CBORError(f"unsupported type {type(v).__name__}")


MAX_DEPTH = 16       # SPEC §3.5: opening an array or map while 16 are already open is an error


def decode(data: bytes, max_depth: int = MAX_DEPTH):
    v, p = _dec(bytes(data), 0, 0, max_depth)
    if p != len(data):
        raise CBORError("trailing bytes")
    return v


def _dec(b: bytes, p: int, depth: int, max_depth: int):
    """depth = number of arrays and maps already open around this item."""
    if p >= len(b):
        raise CBORError("truncated")
    ib = b[p]
    p += 1
    major, ai = ib >> 5, ib & 31
    if major == 7:
        if ai == 20:
            return False, p
        if ai == 21:
            return True, p
        if ai == 22:
            return None, p
        raise CBORError("unsupported simple/float value")
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        size = 1 << (ai - 24)
        if p + size > len(b):
            raise CBORError("truncated head")
        n = int.from_bytes(b[p:p + size], "big")
        p += size
        if len(_head(0, n)) != 1 + size:
            raise CBORError("non-shortest integer head")
    else:
        raise CBORError("indefinite length or reserved additional info")
    if major == 0:
        return n, p
    if major == 1:
        return -1 - n, p
    if major in (2, 3):
        if p + n > len(b):
            raise CBORError("truncated string")
        s = b[p:p + n]
        p += n
        if major == 3:
            try:
                return s.decode("utf-8"), p
            except UnicodeDecodeError:
                raise CBORError("invalid utf-8")
        return s, p
    if major in (4, 5) and depth >= max_depth:
        raise CBORError(f"arrays and maps nested more than {max_depth} deep")
    if major == 4:
        if n > len(b) - p:
            raise CBORError("array length exceeds data")
        out = []
        for _ in range(n):
            x, p = _dec(b, p, depth + 1, max_depth)
            out.append(x)
        return out, p
    if major == 5:
        if 2 * n > len(b) - p:
            raise CBORError("map length exceeds data")
        out, last = {}, None
        for _ in range(n):
            k0 = p
            k, p = _dec(b, p, depth + 1, max_depth)
            kb = b[k0:p]
            if last is not None and kb <= last:
                raise CBORError("map keys not in deterministic order or duplicated")
            last = kb
            if isinstance(k, (list, dict)):
                raise CBORError("unsupported map key type")
            x, p = _dec(b, p, depth + 1, max_depth)
            out[k] = x
        return out, p
    raise CBORError("unsupported major type (tag)")


def canonical(data: bytes) -> bool:
    try:
        return encode(decode(data)) == bytes(data)
    except CBORError:
        return False
