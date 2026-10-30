import copy
import math
import struct
from uco import btc, envelope, taproot


def verify_schnorr(sig, msg, public_key):
    if len(sig) != 64 or len(public_key) != 32:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    point = taproot.lift_x(int.from_bytes(public_key, "big"))
    if point is None or r >= taproot.P or s >= taproot.N:
        return False
    e = int.from_bytes(btc.tagged("BIP0340/challenge", sig[:32] + public_key + msg), "big") % taproot.N
    R = taproot.pt_add(taproot.pt_mul(s, taproot.G), taproot.pt_mul(taproot.N - e, point))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def wallet_script(public_key):
    key = bytes.fromhex(public_key)
    if len(key) == 33 and key[0] in (2, 3):
        key = key[1:]
    if len(key) != 32:
        raise ValueError("A Taproot wallet public key is required")
    point = taproot.lift_x(int.from_bytes(key, "big"))
    tweak = int.from_bytes(btc.tagged("TapTweak", key), "big")
    if point is None or tweak >= taproot.N:
        raise ValueError("Invalid public key")
    output = taproot.pt_add(point, taproot.pt_mul(tweak, taproot.G))
    if output is None:
        raise ValueError("Invalid Taproot output")
    return key, b"\x51\x20" + taproot.xbytes(output)


def address_script(address, network):
    if not isinstance(address, str) or len(address) > 90 or (address != address.lower() and address != address.upper()):
        raise ValueError("Invalid address")
    address = address.lower()
    hrp, sep, tail = address.rpartition("1")
    expected = {"mainnet": "bc", "testnet": "tb", "testnet4": "tb", "signet": "tb", "regtest": "bcrt"}
    if hrp != expected.get(network) or not sep or len(tail) < 7:
        raise ValueError("Address belongs to another network")
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    try:
        data = [alphabet.index(c) for c in tail]
    except ValueError:
        raise ValueError("Invalid address alphabet") from None
    chk = 1
    for v in [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data:
        top, chk = chk >> 25, ((chk & 0x1ffffff) << 5) ^ v
        for i, gen in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            if top >> i & 1:
                chk ^= gen
    version = data[0]
    if version > 16 or chk != (1 if version == 0 else 0x2bc830a3):
        raise ValueError("Invalid address checksum")
    acc = bits = 0
    program = bytearray()
    for v in data[1:-6]:
        acc = ((acc << 5) | v) & 0xfff
        bits += 5
        if bits >= 8:
            bits -= 8
            program.append(acc >> bits & 255)
    if bits >= 5 or (acc << (8 - bits)) & 255 or not 2 <= len(program) <= 40:
        raise ValueError("Invalid witness program")
    if version == 0 and len(program) not in (20, 32):
        raise ValueError("Invalid v0 witness program")
    return bytes([0 if version == 0 else 0x50 + version, len(program)]) + program


def _tx(inputs, outputs):
    return {"version": 2, "vin": [{"txid": i["txid"], "vout": i["vout"],
            "script_sig": b"", "sequence": 0xfffffffe, "witness": []} for i in inputs],
            "vout": outputs, "locktime": 0}


def parse(raw_hex):
    raw = bytes.fromhex(raw_hex)
    if not 10 <= len(raw) <= 100000:
        raise ValueError("Invalid transaction size")
    tx, end = btc.parse_tx(raw)
    if end != len(raw) or btc.serialize_tx(tx) != raw:
        raise ValueError("Noncanonical or trailing transaction data")
    return tx


def _vsize(tx, witnesses):
    tx = copy.deepcopy(tx)
    for vin, witness in zip(tx["vin"], witnesses):
        vin["witness"] = witness
    return parse(btc.serialize_tx(tx).hex())["vsize"]


def _kv(key, value):
    return btc.compact_size(len(key)) + key + btc.compact_size(len(value)) + value


def psbt(tx, prevouts, input_fields):
    raw = b"psbt\xff" + _kv(b"\x00", btc.serialize_tx(tx, witness=False)) + b"\x00"
    for prevout, fields in zip(prevouts, input_fields):
        value, spk = prevout
        raw += _kv(b"\x01", struct.pack("<Q", value) + btc.compact_size(len(spk)) + spk)
        raw += _kv(b"\x03", b"\x00\x00\x00\x00")
        raw += b"".join(_kv(k, v) for k, v in fields) + b"\x00"
    return (raw + b"\x00" * len(tx["vout"])).hex()


def prepare(entry, public_key, utxos, recipient_spk, fee_spk, protocol_fee, rate=1, postage=330, btap_script=None):
    if type(rate) is not int or not 1 <= rate <= 500:
        raise ValueError("Fee rate must be an integer in 1..500 sat/vB")
    if postage < 330:
        raise ValueError("Postage is below P2TR dust")
    if btap_script is not None:
        btap_script = bytes(btap_script)
        if not btap_script.startswith(b"\x6a") or not 2 <= len(btap_script) <= 83:
            raise ValueError("BTAP OP_RETURN script is invalid")
    key, funding_spk = wallet_script(public_key)
    if recipient_spk != funding_spk:
        raise ValueError("First version requires the connected UniSat Taproot recipient")
    if protocol_fee and fee_spk is None:
        raise ValueError("Protocol fee receiver is not configured")
    leaf = btc.push(key) + bytes([btc.OP_CHECKSIG]) + envelope.build_envelope(
        entry["body"].encode(), "application/json", "uco/0", bytes.fromhex(entry["metadata_hex"]))
    _, _, control, leaf_hash, commit_spk = taproot.taproot_output(taproot.NUMS_X, leaf)
    outputs = [{"value": postage, "spk": recipient_spk}]
    if protocol_fee:
        outputs.append({"value": protocol_fee, "spk": fee_spk})
    if btap_script is not None:
        outputs.append({"value": 0, "spk": btap_script})
    reveal = _tx([{"txid": "00" * 32, "vout": 0}], outputs)
    reveal_fee = _vsize(reveal, [[bytes(64), leaf, control]]) * rate
    commit_value = postage + protocol_fee + reveal_fee
    chosen, total = [], 0
    for u in sorted(utxos, key=lambda u: (-u["value"], u["txid"], u["vout"])):
        if len(chosen) >= 20:
            break
        if u.get("script") != funding_spk.hex() or u.get("safe") is not True or not u.get("confirmed"):
            continue
        chosen.append(u)
        total += u["value"]
        commit = _tx(chosen, [{"value": commit_value, "spk": commit_spk}, {"value": 330, "spk": funding_spk}])
        commit_fee = _vsize(commit, [[bytes(64)]] * len(chosen)) * rate
        change = total - commit_value - commit_fee
        if change >= 330:
            commit["vout"][1]["value"] = change
            break
    else:
        raise ValueError("Insufficient confirmed asset-safe Taproot funds (including change)")
    if change < 330:
        raise ValueError("Insufficient funds within the 20-input limit")
    commit_id = parse(btc.serialize_tx(commit).hex())["txid"]
    reveal["vin"][0]["txid"] = commit_id
    commit_psbt = psbt(commit, [(u["value"], funding_spk) for u in chosen], [[(b"\x17", key)]] * len(chosen))
    reveal_psbt = psbt(reveal, [(commit_value, commit_spk)], [[(b"\x15" + control, leaf + b"\xc0"), (b"\x17", taproot.NUMS_X)]])
    return {"commit_psbt": commit_psbt, "reveal_psbt": reveal_psbt,
            "commit_unsigned": btc.serialize_tx(commit).hex(), "reveal_unsigned": btc.serialize_tx(reveal).hex(),
            "commit_txid": commit_id, "reveal_txid": parse(btc.serialize_tx(reveal).hex())["txid"],
            "utxos": chosen, "leaf": leaf.hex(), "control": control.hex(), "public_key": key.hex(),
            "commit_value": commit_value, "commit_script": commit_spk.hex(),
            "review": {"protocol_fee": protocol_fee, "postage": postage, "commit_fee": commit_fee,
                       "reveal_fee": reveal_fee, "fee_rate": rate, "change": change,
                       "btap_bytes": len(btap_script) if btap_script is not None else 0,
                       "total_required": postage + protocol_fee + commit_fee + reveal_fee}}


def estimate(entry, protocol_fee, postage=330, btap_bytes=75):
    key, p2tr = bytes(32), b"\x51\x20" + bytes(32)
    leaf = btc.push(key) + bytes([btc.OP_CHECKSIG]) + envelope.build_envelope(
        entry["body"].encode(), "application/json", "uco/0", bytes.fromhex(entry["metadata_hex"]))
    _, _, control, _, commit_spk = taproot.taproot_output(taproot.NUMS_X, leaf)
    outputs = [{"value": postage, "spk": p2tr}]
    if protocol_fee:
        outputs.append({"value": protocol_fee, "spk": p2tr})
    if btap_bytes:
        outputs.append({"value": 0, "spk": b"\x6a" + bytes([btap_bytes]) + bytes(btap_bytes)})
    reveal = _tx([{"txid": "00" * 32, "vout": 0}], outputs)
    commit = _tx([{"txid": "11" * 32, "vout": 0}], [{"value": postage, "spk": commit_spk}, {"value": 330, "spk": p2tr}])
    return {"reveal_vsize": _vsize(reveal, [[bytes(64), leaf, control]]),
            "commit_vsize": _vsize(commit, [[bytes(64)]])}


def verify_signed(plan, kind, raw_hex):
    tx = parse(raw_hex)
    expected = bytes.fromhex(plan[kind + "_unsigned"])
    if btc.serialize_tx(tx, witness=False) != expected:
        raise ValueError("Wallet changed transaction inputs, outputs or ordering")
    if kind == "commit":
        prevouts = [(u["value"], bytes.fromhex(u["script"])) for u in plan["utxos"]]
        for i, vin in enumerate(tx["vin"]):
            if len(vin["witness"]) != 1 or not verify_schnorr(vin["witness"][0], btc.sighash_taproot(tx, i, prevouts), prevouts[i][1][2:]):
                raise ValueError("Invalid funding signature or sighash mode")
    elif kind == "reveal":
        leaf, control = bytes.fromhex(plan["leaf"]), bytes.fromhex(plan["control"])
        w = tx["vin"][0]["witness"]
        prevouts = [(plan["commit_value"], bytes.fromhex(plan["commit_script"]))]
        if len(w) != 3 or w[1:] != [leaf, control] or not verify_schnorr(w[0], btc.sighash_taproot(tx, 0, prevouts, taproot.tapleaf_hash(leaf)), bytes.fromhex(plan["public_key"])):
            raise ValueError("Invalid reveal script/signature or sighash mode")
    else:
        raise ValueError("Invalid transaction kind")
    quoted = plan["review"][kind + "_fee"]
    if quoted < tx["vsize"] * plan["review"]["fee_rate"]:
        raise ValueError("Actual transaction exceeds quoted fee rate")
    return tx


def signed_psbt_to_raw(plan, kind, text):
    data = bytes.fromhex(text)
    if len(data) > 200000 or data[:5] != b"psbt\xff":
        raise ValueError("Invalid PSBT")
    pos = 5

    def read_map():
        nonlocal pos
        fields = {}
        while True:
            size, pos = btc.read_compact(data, pos)
            if size == 0:
                return fields
            key, pos = data[pos:pos + size], pos + size
            size, pos = btc.read_compact(data, pos)
            value, pos = data[pos:pos + size], pos + size
            if pos > len(data) or key in fields:
                raise ValueError("Truncated PSBT or duplicate key")
            fields[key] = value

    glob = read_map()
    if glob.get(b"\x00", b"").hex() != plan[kind + "_unsigned"]:
        raise ValueError("PSBT unsigned transaction changed")
    tx = parse(plan[kind + "_unsigned"])
    for vin in tx["vin"]:
        fields = read_map()
        final = fields.get(b"\x08")
        if final is not None:
            count, at = btc.read_compact(final, 0)
            if count > 10:
                raise ValueError("Unexpected witness count")
            witness = []
            for _ in range(count):
                size, at = btc.read_compact(final, at)
                witness.append(final[at:at + size])
                at += size
            if at != len(final):
                raise ValueError("Invalid final witness")
        elif kind == "commit":
            witness = [fields.get(b"\x13", b"")]
        else:
            leaf = bytes.fromhex(plan["leaf"])
            key = b"\x14" + bytes.fromhex(plan["public_key"]) + taproot.tapleaf_hash(leaf)
            witness = [fields.get(key, b""), leaf, bytes.fromhex(plan["control"])]
        vin["witness"] = witness
    for _ in tx["vout"]:
        read_map()
    if pos != len(data):
        raise ValueError("Trailing PSBT bytes")
    raw = btc.serialize_tx(tx).hex()
    verify_signed(plan, kind, raw)
    return raw
