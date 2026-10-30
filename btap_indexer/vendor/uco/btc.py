"""Bitcoin primitives needed by the indexer and tools: script tokenizer, minimal pushes, transaction and
block (de)serialization with witnesses, txids, varints, and the BIP-341 signature hash. Stdlib only."""
import hashlib
import struct

OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x00, 0x4c, 0x4d, 0x4e
OP_1NEGATE, OP_1, OP_16 = 0x4f, 0x51, 0x60
OP_IF, OP_ENDIF, OP_RETURN, OP_CHECKSIG = 0x63, 0x68, 0x6a, 0xac


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def dsha(b: bytes) -> bytes:
    return sha256(sha256(b))


def tagged(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + msg)


# ---- compact size (Bitcoin varint) and LEB128 (used inside UCO records) ----------------------------

def compact_size(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def read_compact(b: bytes, p: int):
    if p >= len(b):
        raise ValueError("truncated compact size")
    v = b[p]
    p += 1
    for mark, size, fmt in ((0xfd, 2, "<H"), (0xfe, 4, "<I"), (0xff, 8, "<Q")):
        if v == mark:
            if p + size > len(b):
                raise ValueError("truncated compact size")
            return struct.unpack_from(fmt, b, p)[0], p + size
    return v, p


def leb128(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7f
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def read_leb128(b: bytes, p: int, max_bytes: int = 5):
    """Reads a minimal LEB128 integer (at most max_bytes, no redundant trailing 0x80/0x00 groups)."""
    n, shift, start = 0, 0, p
    while True:
        if p >= len(b) or p - start >= max_bytes:
            raise ValueError("bad varint")
        byte = b[p]
        p += 1
        n |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            if byte == 0 and p - start > 1:
                raise ValueError("non-minimal varint")
            return n, p


# ---- script ----------------------------------------------------------------------------------------

def push(data: bytes) -> bytes:
    """Minimal data push (BIP-62 style, as rust-bitcoin's push_slice does for non-number data)."""
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xff:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xffff:
        return bytes([OP_PUSHDATA2]) + struct.pack("<H", n) + data
    return bytes([OP_PUSHDATA4]) + struct.pack("<I", n) + data


def script_tokens(s: bytes):
    """Yields (opcode, data) for every instruction; data is bytes for pushes (OP_0 gives b""), else None.
    Raises ValueError on a truncated push."""
    p = 0
    while p < len(s):
        op = s[p]
        p += 1
        if op <= 0x4e:
            if op < OP_PUSHDATA1:
                n = op
            else:
                size = {OP_PUSHDATA1: 1, OP_PUSHDATA2: 2, OP_PUSHDATA4: 4}[op]
                if p + size > len(s):
                    raise ValueError("truncated pushdata length")
                n = int.from_bytes(s[p:p + size], "little")
                p += size
            if p + n > len(s):
                raise ValueError("truncated push")
            yield op, s[p:p + n]
            p += n
        else:
            yield op, None


# ---- transactions ----------------------------------------------------------------------------------

_I32, _U32, _I64 = struct.Struct("<i").unpack_from, struct.Struct("<I").unpack_from, struct.Struct("<q").unpack_from


def parse_tx(raw: bytes, p: int = 0):
    """Parses one (possibly segwit) transaction starting at p. Returns (tx, end).
    Compact sizes below 0xfd (one byte) are read inline; read_compact handles the rest and every error."""
    start, end = p, len(raw)
    version = _I32(raw, p)[0]
    p += 4
    segwit = raw[p] == 0 and raw[p + 1] == 1
    if segwit:
        p += 2
    body = p                                       # inputs and outputs: the same bytes with or without witness
    canonical = True                               # every compact size minimal, so raw bytes == serialize_tx bytes
    if p < end and raw[p] < 0xfd:
        nin, p = raw[p], p + 1
    else:
        nin, p = read_compact(raw, p)
        canonical = _minimal(raw, body, p)
    vin = []
    for _ in range(nin):
        txid = raw[p:p + 32][::-1].hex()
        vout = _U32(raw, p + 32)[0]
        p += 36
        if p < end and raw[p] < 0xfd:
            sl, p = raw[p], p + 1
        else:
            q = p
            sl, p = read_compact(raw, p)
            canonical = canonical and _minimal(raw, q, p)
        ss = raw[p:p + sl]
        p += sl
        seq = _U32(raw, p)[0]
        p += 4
        vin.append({"txid": txid, "vout": vout, "script_sig": ss, "sequence": seq, "witness": []})
    if p < end and raw[p] < 0xfd:
        nout, p = raw[p], p + 1
    else:
        q = p
        nout, p = read_compact(raw, p)
        canonical = canonical and _minimal(raw, q, p)
    vout = []
    for _ in range(nout):
        value = _I64(raw, p)[0]
        p += 8
        if p < end and raw[p] < 0xfd:
            sl, p = raw[p], p + 1
        else:
            q = p
            sl, p = read_compact(raw, p)
            canonical = canonical and _minimal(raw, q, p)
        vout.append({"value": value, "spk": raw[p:p + sl]})
        p += sl
    body_end = p
    if segwit:
        for i in vin:
            if p < end and raw[p] < 0xfd:
                n, p = raw[p], p + 1
            else:
                n, p = read_compact(raw, p)
            w = i["witness"]
            for _ in range(n):
                if p < end and raw[p] < 0xfd:
                    sl, p = raw[p], p + 1
                else:
                    sl, p = read_compact(raw, p)
                w.append(raw[p:p + sl])
                p += sl
    locktime = _U32(raw, p)[0]
    p += 4
    tx = {"version": version, "vin": vin, "vout": vout, "locktime": locktime}
    if canonical:
        # the transaction without witness, as serialize_tx(tx, witness=False) would rebuild it
        stripped = raw[start:start + 4] + raw[body:body_end] + raw[p - 4:p] if segwit else raw[start:p]
    else:
        stripped = serialize_tx(tx, witness=False)
    tx["txid"] = sha256(sha256(stripped))[::-1].hex()
    tx["size"] = p - start
    tx["weight"] = len(stripped) * 3 + tx["size"]
    tx["vsize"] = (tx["weight"] + 3) // 4
    return tx, p


def _minimal(raw: bytes, q: int, p: int) -> bool:
    """True when the compact size in raw[q:p] is the shortest encoding of its value (what compact_size writes)."""
    return raw[q:p] == compact_size(read_compact(raw, q)[0])


def serialize_tx(tx, witness=True) -> bytes:
    has_wit = witness and any(i["witness"] for i in tx["vin"])
    out = bytearray(struct.pack("<i", tx["version"]))
    if has_wit:
        out += b"\x00\x01"
    out += compact_size(len(tx["vin"]))
    for i in tx["vin"]:
        out += bytes.fromhex(i["txid"])[::-1] + struct.pack("<I", i["vout"])
        out += compact_size(len(i["script_sig"])) + i["script_sig"] + struct.pack("<I", i["sequence"])
    out += compact_size(len(tx["vout"]))
    for o in tx["vout"]:
        out += struct.pack("<q", o["value"]) + compact_size(len(o["spk"])) + o["spk"]
    if has_wit:
        for i in tx["vin"]:
            out += compact_size(len(i["witness"]))
            for item in i["witness"]:
                out += compact_size(len(item)) + item
    out += struct.pack("<I", tx["locktime"])
    return bytes(out)


def parse_block(raw: bytes):
    header = raw[:80]
    n, p = read_compact(raw, 80)
    txs = []
    for _ in range(n):
        tx, p = parse_tx(raw, p)
        txs.append(tx)
    if p != len(raw):
        raise ValueError("trailing block bytes")
    return {"hash": dsha(header)[::-1].hex(), "prev": header[4:36][::-1].hex(), "txs": txs}


def tapscript_of(witness):
    """BIP-341: the script of a script-path spend is the second-to-last witness item, or the third-to-last
    when the last item is an annex (starts with 0x50); with an annex and only 2 items there is no script
    (a key-path spend with an annex). Same result as `ord` 0.29.0 (checked on 863 envelopes)."""
    if len(witness) < 2:
        return None
    if witness[-1][:1] == b"\x50":
        return witness[-3] if len(witness) >= 3 else None
    return witness[-2]


# ---- BIP-341 signature hash (SIGHASH_DEFAULT) ------------------------------------------------------

def sighash_taproot(tx, index: int, prevouts, leaf_hash: bytes = None) -> bytes:
    """prevouts: [(value, scriptPubKey)] for every input. Key path when leaf_hash is None."""
    ser_outpoints = b"".join(bytes.fromhex(i["txid"])[::-1] + struct.pack("<I", i["vout"]) for i in tx["vin"])
    msg = b"\x00\x00" + struct.pack("<i", tx["version"]) + struct.pack("<I", tx["locktime"])
    msg += sha256(ser_outpoints)
    msg += sha256(b"".join(struct.pack("<q", v) for v, _ in prevouts))
    msg += sha256(b"".join(compact_size(len(s)) + s for _, s in prevouts))
    msg += sha256(b"".join(struct.pack("<I", i["sequence"]) for i in tx["vin"]))
    msg += sha256(b"".join(struct.pack("<q", o["value"]) + compact_size(len(o["spk"])) + o["spk"] for o in tx["vout"]))
    msg += bytes([2 if leaf_hash is not None else 0]) + struct.pack("<I", index)
    if leaf_hash is not None:
        msg += leaf_hash + b"\x00" + b"\xff\xff\xff\xff"
    return tagged("TapSighash", msg)
