# Copied unchanged from an unpublished demo by the same author (MIT, BruceLanLan); self-contained, standard library only. Only this line was added.
"""Minimal pure-Python taproot helpers (BIP-340/341/342): secp256k1 arithmetic, tagged hashes,
single-leaf output key + control block, witness splicing into a raw tx, and (optional) a
BIP-340 Schnorr signer with the BIP-341 script-path sighash so a leaf may begin with
<pubkey> OP_CHECKSIGVERIFY. Regtest/testing use only. MIT."""
import hashlib, struct

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
# BIP-341 "nothing up my sleeve" internal key (H = lift_x(sha256(G_x)))
NUMS_X = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

def sha256(b): return hashlib.sha256(b).digest()
def tagged(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode()); return sha256(t + t + msg)

def pt_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)

def pt_mul(k, pt):
    r = None
    while k:
        if k & 1: r = pt_add(r, pt)
        pt = pt_add(pt, pt); k >>= 1
    return r

def lift_x(x: int):
    if x >= P: return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if pow(y, 2, P) != y2: return None
    return (x, y if y % 2 == 0 else P - y)

def has_even_y(pt): return pt[1] % 2 == 0
def xbytes(pt): return pt[0].to_bytes(32, "big")

def compact_size(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

LEAF_VERSION = 0xc0

def tapleaf_hash(script: bytes) -> bytes:
    return tagged("TapLeaf", bytes([LEAF_VERSION]) + compact_size(len(script)) + script)

def taproot_output(internal_x: bytes, script: bytes):
    """Single-leaf tree. Returns (output_xonly, parity, control_block, leaf_hash, scriptPubKey)."""
    leaf = tapleaf_hash(script)
    t = int.from_bytes(tagged("TapTweak", internal_x + leaf), "big")
    assert t < N
    Pi = lift_x(int.from_bytes(internal_x, "big"))
    Q = pt_add(Pi, pt_mul(t, G))
    parity = 0 if has_even_y(Q) else 1
    control = bytes([LEAF_VERSION | parity]) + internal_x
    spk = b"\x51\x20" + xbytes(Q)
    return xbytes(Q), parity, control, leaf, spk

# ---- transaction helpers -----------------------------------------------------------------------
def read_varint(b, p):
    v = b[p]; p += 1
    if v == 0xfd: return struct.unpack_from("<H", b, p)[0], p + 2
    if v == 0xfe: return struct.unpack_from("<I", b, p)[0], p + 4
    if v == 0xff: return struct.unpack_from("<Q", b, p)[0], p + 8
    return v, p

def parse_tx(raw: bytes):
    """Parse a non-witness serialized tx into dict."""
    p = 0
    version = raw[p:p + 4]; p += 4
    assert raw[p] != 0 or raw[p + 1] != 1, "expected non-witness serialization"
    nin, p = read_varint(raw, p)
    vins = []
    for _ in range(nin):
        txid = raw[p:p + 32]; p += 32
        vout = raw[p:p + 4]; p += 4
        sl, p = read_varint(raw, p); ss = raw[p:p + sl]; p += sl
        seq = raw[p:p + 4]; p += 4
        vins.append((txid, vout, ss, seq))
    nout, p = read_varint(raw, p)
    vouts = []
    for _ in range(nout):
        val = raw[p:p + 8]; p += 8
        sl, p = read_varint(raw, p); spk = raw[p:p + sl]; p += sl
        vouts.append((val, spk))
    locktime = raw[p:p + 4]; p += 4
    assert p == len(raw)
    return dict(version=version, vins=vins, vouts=vouts, locktime=locktime)

def serialize_tx(tx, witnesses=None):
    out = bytearray(tx["version"])
    if witnesses is not None: out += b"\x00\x01"
    out += compact_size(len(tx["vins"]))
    for txid, vout, ss, seq in tx["vins"]:
        out += txid + vout + compact_size(len(ss)) + ss + seq
    out += compact_size(len(tx["vouts"]))
    for val, spk in tx["vouts"]:
        out += val + compact_size(len(spk)) + spk
    if witnesses is not None:
        for w in witnesses:
            out += compact_size(len(w))
            for item in w:
                out += compact_size(len(item)) + item
    out += tx["locktime"]
    return bytes(out)

def witness_serialized_size(items) -> int:
    return len(compact_size(len(items))) + sum(len(compact_size(len(i))) + len(i) for i in items)

# ---- BIP-341 script-path sighash (SIGHASH_DEFAULT) + BIP-340 signing ---------------------------
def sighash_scriptpath(tx, input_index, prevouts, leaf_hash):
    """prevouts: list of (value_int, scriptPubKey_bytes) for all inputs. SIGHASH_DEFAULT (0x00)."""
    def dsha(b): return sha256(b)
    sha_prevouts = sha256(b"".join(t + v for t, v, _, _ in tx["vins"]))
    sha_amounts = sha256(b"".join(struct.pack("<q", v) for v, _ in prevouts))
    sha_spks = sha256(b"".join(compact_size(len(s)) + s for _, s in prevouts))
    sha_seqs = sha256(b"".join(s for _, _, _, s in tx["vins"]))
    sha_outputs = sha256(b"".join(val + compact_size(len(spk)) + spk for val, spk in tx["vouts"]))
    msg = b"\x00"                     # sighash epoch
    msg += b"\x00"                    # hash_type SIGHASH_DEFAULT
    msg += tx["version"] + tx["locktime"] + sha_prevouts + sha_amounts + sha_spks + sha_seqs + sha_outputs
    spend_type = 2 * 1 + 0            # ext_flag=1 (script path), no annex
    msg += bytes([spend_type])
    msg += struct.pack("<I", input_index)
    # extension for script path
    msg += leaf_hash + b"\x00" + b"\xff\xff\xff\xff"   # key_version 0, codesep_pos
    return tagged("TapSighash", msg)

def schnorr_sign(msg32: bytes, seckey: int, aux: bytes = b"\x00" * 32) -> bytes:
    Pp = pt_mul(seckey, G)
    d = seckey if has_even_y(Pp) else N - seckey
    t = (d ^ int.from_bytes(tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged("BIP0340/nonce", t + xbytes(Pp) + msg32), "big") % N
    assert k0
    R = pt_mul(k0, G)
    k = k0 if has_even_y(R) else N - k0
    e = int.from_bytes(tagged("BIP0340/challenge", xbytes(R) + xbytes(Pp) + msg32), "big") % N
    s = (k + e * d) % N
    return xbytes(R) + s.to_bytes(32, "big")

def pubkey_xonly(seckey: int) -> bytes:
    return xbytes(pt_mul(seckey, G))

if __name__ == "__main__":
    # self-check: BIP-340 test vector 0
    sk = 3
    assert pubkey_xonly(sk).hex() == "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    sig = schnorr_sign(b"\x00" * 32, sk, b"\x00" * 32)
    assert sig.hex().upper() == "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", sig.hex()
    # NUMS point lifts
    assert lift_x(int.from_bytes(NUMS_X, "big")) is not None
    print("taproot.py self-check OK")
