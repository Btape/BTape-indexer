"""Ordinals inscription envelopes: building and parsing, and inscription ids.

Parsing follows the envelope rules of `ord` (docs.ordinals.com, "Inscriptions"; ord 0.2x
`RawEnvelope::from_tapscript` and `ParsedEnvelope::from`) as pinned in docs/SPEC.md §3 (UCO v0.1):

  * every input's tapscript (BIP-341 script-path script) is scanned for  OP_FALSE OP_IF <"ord"> ... OP_ENDIF;
  * a tapscript that does not tokenize completely yields no envelopes; "empty push" means any push of zero
    bytes (OP_0, or OP_PUSHDATA1/2/4 with length 0), both for the envelope start and the body separator;
  * inside the envelope only pushes are allowed (OP_1..OP_16 / OP_1NEGATE count as one-byte pushes and set
    the `pushnum` flag); any other opcode, or a missing OP_ENDIF, means "no envelope";
  * the payload is a list of pushes; the body starts at the first empty push at an even position;
  * before it, pushes pair up as (tag, value); tag 5 (metadata) is chunked and concatenated, other tags take
    their first value; a lone trailing tag sets `incomplete_field`; an unknown even tag sets
    `unrecognized_even_field`; a tag seen twice sets `duplicate_field`;
  * the inscription id is <reveal txid>i<n>, n counting envelopes across all inputs of the transaction.

UCO uses inscriptions only as immutable, content-addressed definitions. It does not track sats, numbers,
curses or reinscriptions for any rule; `curses()` is reported for information only."""
import re

from . import btc

PROTOCOL_ID = b"ord"
TAG_CONTENT_TYPE, TAG_POINTER, TAG_PARENT, TAG_METADATA = 1, 2, 3, 5
TAG_METAPROTOCOL, TAG_CONTENT_ENCODING, TAG_DELEGATE = 7, 9, 11
KNOWN_TAGS = {1, 2, 3, 5, 7, 9, 11, 13, 15, 17}
CHUNK = 520


# ---- ids -------------------------------------------------------------------------------------------

def insc_id(txid: str, index: int) -> str:
    return f"{txid}i{index}"


ID_RE = re.compile(r"^[0-9a-f]{64}i(0|[1-9][0-9]{0,8})$")       # index: at most 9 digits (SPEC §3.4)


def split_id(s: str):
    """Text form of an inscription id (SPEC §3.4): 64 lowercase hex digits, "i", decimal index without
    leading zeros and of at most 9 digits."""
    if not isinstance(s, str) or not ID_RE.match(s):
        raise ValueError(f"bad inscription id {s!r}")
    txid, _, idx = s.partition("i")
    return txid, int(idx)


def id_to_ord_bytes(s: str) -> bytes:
    """ord's binary form (parent / delegate tags): txid in internal byte order, then the index as
    little-endian u32 with trailing zero bytes removed."""
    txid, idx = split_id(s)
    return bytes.fromhex(txid)[::-1] + idx.to_bytes(4, "little").rstrip(b"\x00")


def id_from_ord_bytes(b: bytes):
    if not 32 <= len(b) <= 36 or (len(b) > 32 and b[-1] == 0):
        return None
    return insc_id(b[:32][::-1].hex(), int.from_bytes(b[32:].ljust(4, b"\x00"), "little"))


def id_to_record_bytes(s: str) -> bytes:
    """UCO record form: 32-byte txid (internal order) then LEB128 index."""
    txid, idx = split_id(s)
    return bytes.fromhex(txid)[::-1] + btc.leb128(idx)


def id_from_record_bytes(b: bytes, p: int):
    if p + 32 > len(b):
        raise ValueError("truncated inscription id")
    txid = b[p:p + 32][::-1].hex()
    idx, p = btc.read_leb128(b, p + 32)
    return insc_id(txid, idx), p


# ---- building --------------------------------------------------------------------------------------

def _tag(t: int) -> bytes:
    return btc.push(bytes([t]))


def build_envelope(body: bytes, content_type: str = None, metaprotocol: str = None, metadata: bytes = None,
                   parents=(), content_encoding: str = None) -> bytes:
    s = bytearray([btc.OP_0, btc.OP_IF]) + btc.push(PROTOCOL_ID)
    if content_type is not None:
        s += _tag(TAG_CONTENT_TYPE) + btc.push(content_type.encode())
    for p in parents:
        s += _tag(TAG_PARENT) + btc.push(id_to_ord_bytes(p))
    if metadata is not None:
        for k in range(0, max(len(metadata), 1), CHUNK):
            s += _tag(TAG_METADATA) + btc.push(metadata[k:k + CHUNK])
    if metaprotocol is not None:
        s += _tag(TAG_METAPROTOCOL) + btc.push(metaprotocol.encode())
    if content_encoding is not None:
        s += _tag(TAG_CONTENT_ENCODING) + btc.push(content_encoding.encode())
    s += bytes([btc.OP_0])
    for k in range(0, len(body), CHUNK):
        s += btc.push(body[k:k + CHUNK])
    s += bytes([btc.OP_ENDIF])
    return bytes(s)


# ---- parsing ---------------------------------------------------------------------------------------

def raw_envelopes(tapscript: bytes):
    """Returns a list of (payload pushes, pushnum, stutter) for each envelope in one tapscript.
    A tapscript that does not tokenize to the end (a push runs past the end of the script) yields no
    envelopes at all, including any complete envelope before the bad push (SPEC §3.1 rule 2)."""
    try:
        toks = list(btc.script_tokens(tapscript))
    except ValueError:
        return []
    out = []
    i, stuttered = 0, False
    while i < len(toks):
        op, data = toks[i]
        i += 1
        if data != b"":
            continue
        # an empty push (OP_FALSE) was consumed; like ord, OP_IF and "ord" are consumed only if they match
        if not (i < len(toks) and toks[i] == (btc.OP_IF, None)):
            stuttered = i < len(toks) and toks[i][1] == b""
            continue
        i += 1
        if not (i < len(toks) and toks[i][1] == PROTOCOL_ID):
            stuttered = False
            continue
        i += 1
        payload, pushnum, ok = [], False, False
        while i < len(toks):
            o, d = toks[i]
            i += 1
            if o == btc.OP_ENDIF:
                ok = True
                break
            if d is not None:
                payload.append(d)
            elif o == btc.OP_1NEGATE:
                payload.append(b"\x81")
                pushnum = True
            elif btc.OP_1 <= o <= btc.OP_16:
                payload.append(bytes([o - btc.OP_1 + 1]))
                pushnum = True
            else:
                break                                     # non-push opcode: not an envelope, consumed
        if ok:
            out.append((payload, pushnum, stuttered))
        else:
            stuttered = False
    return out


def parse_payload(payload):
    body_at = next((k for k, x in enumerate(payload) if k % 2 == 0 and x == b""), None)
    head = payload[:body_at] if body_at is not None else payload
    fields, incomplete = {}, False
    for k in range(0, len(head), 2):
        if k + 1 >= len(head):
            incomplete = True
            break
        fields.setdefault(head[k], []).append(head[k + 1])
    # every tag except metadata (0x05) may appear at most once, parent (0x03) included (SPEC §3.3)
    duplicate = any(len(v) > 1 for t, v in fields.items() if t != bytes([TAG_METADATA]))

    def take(tag):
        v = fields.get(bytes([tag]))
        if not v:
            return None
        x = v.pop(0)
        if not v:
            del fields[bytes([tag])]
        return x

    meta_chunks = fields.pop(bytes([TAG_METADATA]), None)
    env = {
        "content_type": take(TAG_CONTENT_TYPE),
        "pointer": take(TAG_POINTER),
        "content_encoding": take(TAG_CONTENT_ENCODING),
        "metaprotocol": take(TAG_METAPROTOCOL),
        "delegate": take(TAG_DELEGATE),
        "metadata": b"".join(meta_chunks) if meta_chunks else None,
        "parents": [x for x in fields.pop(bytes([TAG_PARENT]), [])],
        "body": b"".join(payload[body_at + 1:]) if body_at is not None else None,
        "incomplete_field": incomplete,
        "duplicate_field": duplicate,
    }
    # tags are whole push contents; a tag is even or odd by its first byte. The only recognised even tag is
    # 0x02 (pointer, taken above); any other remaining even tag is unrecognised (SPEC §3.3).
    env["unrecognized_even_field"] = any(t[:1] and t[0] % 2 == 0 for t in fields)
    env["unknown_odd_tags"] = sorted(t.hex() for t in fields if t[:1] and t[0] % 2 == 1)
    return env


def inscriptions_in_tx(tx):
    """All envelopes of a parsed transaction, in id order: list of dicts with id, input, fields."""
    out, n = [], 0
    for vi, inp in enumerate(tx["vin"]):
        ts = btc.tapscript_of(inp["witness"])
        if ts is None or PROTOCOL_ID not in ts:      # an envelope needs a push of exactly "ord"
            continue
        for k, (payload, pushnum, stutter) in enumerate(raw_envelopes(ts)):
            env = parse_payload(payload)
            env.update(id=insc_id(tx["txid"], n), input=vi, offset=k, pushnum=pushnum, stutter=stutter)
            out.append(env)
            n += 1
    return out


def curses(env):
    """Informational only (UCO ignores curses)."""
    c = []
    for flag in ("duplicate_field", "incomplete_field", "unrecognized_even_field", "pushnum", "stutter"):
        if env.get(flag):
            c.append(flag)
    if env["input"] != 0:
        c.append("not_in_first_input")
    if env["offset"] != 0:
        c.append("not_at_offset_zero")
    if env["pointer"] is not None:
        c.append("pointer")
    return c
