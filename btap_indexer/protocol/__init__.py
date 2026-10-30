import hashlib
import re
from uco import btc, envelope, objects, taproot
from btap_indexer.circuit import MAX_BODY_BYTES, check_flat_result, precheck_design
from btap_indexer.transactions import verify_schnorr

TAG = b"BTAP"
VERSION = 2
COLLECTION_ID = 1
RECORD_PAID = 0x00
RECORD_FREE = 0x01
RECORD_CHECKPOINT = 0x02
MINT_LEN = 75
CHECKPOINT_LEN = 39
MAX_SCRIPT_SIZE = 83
PAID_TICKET_LIMIT = 0x7fffffff
FREE_TICKET_START = 0x80000000
FREE_TICKET_LIMIT = 0xffffffff

POOLS = {RECORD_PAID: "paid", RECORD_FREE: "free"}
RECORD_TYPES = {name: record for record, name in POOLS.items()}


def _sha256(value):
    if isinstance(value, str):
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("body_sha256 must be 32-byte hex")
        return bytes.fromhex(value)
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise ValueError("body_sha256 must be 32 bytes")
    return bytes(value)


def secret_key(text):
    if not isinstance(text, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", text):
        raise ValueError("Ticket private key must be 32-byte hex")
    value = int(text, 16)
    if not 1 <= value < taproot.N:
        raise ValueError("Ticket private key is outside the curve order")
    return value


def public_key(text):
    return taproot.pubkey_xonly(secret_key(text)).hex()


def ticket_message(ticket_id, body_sha256, record_type, recipient_script, genesis, policy=None):
    ticket_id = bytes(ticket_id)
    if len(ticket_id) != 4:
        raise ValueError("ticket_id must be 4 bytes")
    if record_type not in POOLS:
        raise ValueError("Invalid BTAP ticket record type")
    number = int.from_bytes(ticket_id, 'big')
    if policy is None:
        if record_type != RECORD_FREE or not 1 <= number <= 10000:
            raise ValueError("Only free tickets 1..10000 are valid in collection v2")
    elif not (1 <= number <= PAID_TICKET_LIMIT if record_type == RECORD_PAID
              else FREE_TICKET_START <= number <= FREE_TICKET_LIMIT):
        raise ValueError('Ticket ID is outside its pool namespace')
    if policy is not None and genesis != policy.genesis:
        raise ValueError('Policy network mismatch')
    if not isinstance(recipient_script, bytes) or len(recipient_script) != 34 or recipient_script[:2] != b'\x51\x20':
        raise ValueError("Ticket requires a Taproot recipient")
    return hashlib.sha256(TAG + bytes([policy.version if policy else VERSION, COLLECTION_ID, record_type]) + ticket_id
                          + _sha256(body_sha256) + recipient_script + _sha256(genesis)
                          + (policy.digest if policy else b'')).digest()


def sign_ticket(private_key, ticket_id, body_sha256, pool, recipient_script, genesis, policy=None):
    if pool not in RECORD_TYPES:
        raise ValueError("Invalid pool")
    message = ticket_message(ticket_id, body_sha256, RECORD_TYPES[pool], recipient_script, genesis, policy)
    return taproot.schnorr_sign(message, secret_key(private_key))


def ticket_record(pool, ticket_id, signature, version=VERSION):
    if pool not in RECORD_TYPES:
        raise ValueError("Invalid pool")
    ticket_id, signature = bytes(ticket_id), bytes(signature)
    if len(ticket_id) != 4 or len(signature) != 64:
        raise ValueError("Invalid ticket fields")
    if version not in (2, 3):
        raise ValueError('Unsupported ticket version')
    return (TAG + bytes([version, COLLECTION_ID, RECORD_TYPES[pool]]) + ticket_id + signature)


def checkpoint_record(root):
    root = _sha256(root)
    return TAG + bytes([VERSION, COLLECTION_ID, RECORD_CHECKPOINT]) + root


def record_script(record):
    record = bytes(record)
    if not 1 <= len(record) <= 75:
        raise ValueError("BTAP record must be 1..75 bytes")
    script = b"\x6a" + bytes([len(record)]) + record
    if len(script) > MAX_SCRIPT_SIZE:
        raise ValueError("BTAP record exceeds the standard OP_RETURN size")
    return script


def decode_script(spk):
    if not isinstance(spk, (bytes, bytearray)) or len(spk) < 2 or spk[0] != 0x6a:
        return None
    size = spk[1]
    if size >= 0x4c or len(spk) != size + 2:
        return None
    data = bytes(spk[2:])
    if not data.startswith(TAG):
        return None
    return parse_record(data)


def parse_record(data):
    data = bytes(data)
    if not data.startswith(TAG) or len(data) < 7:
        raise ValueError("Not a BTAP record")
    version, collection, record_type = data[4], data[5], data[6]
    if version not in (2, 3) or collection != COLLECTION_ID:
        raise ValueError("Unsupported BTAP version or collection")
    if record_type in POOLS:
        if len(data) != MINT_LEN:
            raise ValueError("Invalid BTAP mint record length")
        return {"type": "mint", "version": version, "record_type": record_type, "pool": POOLS[record_type],
                "ticket_id": data[7:11], "signature": data[11:75]}
    if record_type == RECORD_CHECKPOINT:
        if len(data) != CHECKPOINT_LEN:
            raise ValueError("Invalid BTAP checkpoint length")
        return {"type": "checkpoint", "record_type": record_type, "merkle_root": data[7:39]}
    raise ValueError("Unknown BTAP record type")


def verify_ticket(record, body_sha256, ticket_public_key, recipient_script, genesis, policy=None):
    if record.get("type") != "mint":
        return False
    if not isinstance(ticket_public_key, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", ticket_public_key):
        return False
    if record.get("version", 2) != (policy.version if policy else VERSION):
        return False
    try:
        message = ticket_message(record["ticket_id"], body_sha256, record["record_type"], recipient_script, genesis, policy)
    except ValueError:
        return False
    return verify_schnorr(record["signature"], message, bytes.fromhex(ticket_public_key))


def merkle_root(identifiers):
    if not identifiers:
        raise ValueError("At least one identifier is required")
    leaves = [hashlib.sha256(bytes.fromhex(value)).digest() for value in identifiers]
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [hashlib.sha256(leaves[i] + leaves[i + 1]).digest() for i in range(0, len(leaves), 2)]
    return leaves[0].hex()


def replay(items, ticket_public_key, fee_script, protocol_fee, used_tickets=None, serial_start=0, genesis=None, policy=None, pool_counts=None):
    if not isinstance(fee_script, (bytes, bytearray)) or not fee_script:
        raise ValueError("Official fee script is required")
    if type(protocol_fee) is not int or protocol_fee <= 0:
        raise ValueError("Protocol fee must be positive")
    if type(serial_start) is not int or serial_start < 0:
        raise ValueError("serial_start must be a non-negative integer")
    if used_tickets is None:
        used = set()
    elif isinstance(used_tickets, set):
        used = used_tickets
    else:
        used = set(used_tickets)
    counts = dict(pool_counts or {'free': 0, 'paid': 0})
    if policy and (bytes(fee_script) != policy.fee_script or protocol_fee != policy.protocol_fee):
        raise ValueError('Replay fee configuration does not match policy')
    ordered = sorted(items, key=lambda item: (item.get("height") if type(item.get("height")) is int else -1,
                                              item.get("position", 0), item.get("txid") or ""))
    accepted, rejected = [], []
    for item in ordered:
        try:
            entry = _replay_one(item, ticket_public_key, bytes(fee_script), protocol_fee, genesis, policy)
            if entry["ticket_id"] in used:
                raise ValueError("Ticket has already been used")
            if policy:
                cap = policy.free_supply if entry["pool"] == "free" else policy.paid_supply
                if counts.get(entry["pool"], 0) >= cap:
                    raise ValueError(entry["pool"].title() + " pool full: confirmed but not selected")
            counts[entry["pool"]] = counts.get(entry["pool"], 0) + 1
            used.add(entry["ticket_id"])
            entry["serial"] = serial_start + len(accepted) + 1
            accepted.append(entry)
        except ValueError as exc:
            rejected.append({"inscription_id": item.get("inscription_id"), "height": item.get("height"),
                             "txid": item.get("txid"), "reason": str(exc)})
    return {"accepted": accepted, "rejected": rejected}


def _replay_one(item, ticket_public_key, fee_script, protocol_fee, genesis, policy=None):
    tx = item["tx"]
    if not isinstance(tx, dict) or "vout" not in tx or "vin" not in tx:
        raise ValueError("Missing parsed reveal transaction")
    if type(item.get("height")) is not int:
        raise ValueError("Missing block height")
    if policy:
        if type(policy.activation_height) is not int or item['height'] < policy.activation_height:
            raise ValueError('Reveal precedes policy activation height')
        if type(item.get('position')) is not int or item['position'] < 0:
            raise ValueError('Confirmed chain position is required')
    all_envelopes = envelope.inscriptions_in_tx(tx)
    designs = [env for env in all_envelopes if env.get("metaprotocol") == b"uco/0"]
    if len(designs) != 1 or len(all_envelopes) != 1 or len(tx['vin']) != 1:
        raise ValueError("Expected exactly one uco/0 Design")
    env = designs[0]
    if env.get('pointer') is not None or env.get('input') != 0 or env.get('offset') != 0:
        raise ValueError('Official mint requires the default inscription pointer in the first input')
    if len(tx['vout']) not in ((2, 3) if policy else (2,)) or tx['vout'][0]['value'] < 330 or tx['vout'][-1]['value'] != 0:
        raise ValueError('Official reveal requires postage, optional protocol fee and one zero-value BTAP output')
    if not isinstance(env.get("body"), (bytes, bytearray)):
        raise ValueError("UCO Design has no body")
    if len(env["body"]) > MAX_BODY_BYTES:
        raise ValueError("UCO Design body exceeds the product limit")
    try:
        doc = objects.parse_canonical_json(bytes(env["body"]))
    except objects.Invalid as exc:
        raise ValueError(str(exc)) from None
    precheck_design(doc)
    try:
        result = objects.classify(env, {}, {})
    finally:
        objects._flatnets.clear()
    check_flat_result(result)
    body_sha256 = hashlib.sha256(env["body"]).hexdigest()

    records, checkpoints = [], 0
    for output in tx["vout"]:
        record = decode_script(output.get("spk", b""))
        if record is None:
            continue
        if record["type"] == "checkpoint":
            checkpoints += 1
        else:
            records.append(record)
    if checkpoints:
        raise ValueError("Checkpoint record cannot be inside a reveal")
    if len(records) != 1:
        raise ValueError("Expected exactly one BTAP mint record")
    record = records[0]
    if not verify_ticket(record, body_sha256, ticket_public_key, bytes(tx["vout"][0]["spk"]), genesis, policy):
        raise ValueError("Invalid ticket signature")
    definition = None
    if policy:
        expected_outputs = 3 if record['pool'] == 'paid' else 2
        if len(tx['vout']) != expected_outputs or decode_script(tx['vout'][-1]['spk']) != record:
            raise ValueError('Noncanonical pool output layout')
        if record['pool'] == 'paid' and (tx['vout'][1]['spk'] != fee_script or tx['vout'][1]['value'] != protocol_fee):
            raise ValueError('Paid mint needs exact protocol fee at output 1')
        from btap_indexer.circuit import compile_design
        definition = compile_design(doc)
    fee_outputs = [output for output in tx["vout"]
                   if bytes(output.get("spk", b"")) == fee_script and output.get("value") == protocol_fee]
    if record["pool"] == "paid" and not policy:
        if len(fee_outputs) != 1:
            raise ValueError("Paid mint needs exactly one protocol-fee output")
    elif fee_outputs and not policy:
        raise ValueError("Free mint must not carry a protocol-fee output")
    txid = tx["txid"] if "txid" in tx else btc.serialize_tx(tx).hex()
    return {"serial": 0, "inscription_id": env["id"], "txid": txid,
            "ticket_id": record["ticket_id"].hex(), "pool": record["pool"],
            "body": bytes(env["body"]), "body_sha256": body_sha256, "definition": definition, "nState": result["nState"],
            "state_capable": result["nState"] > 0, "instantiable": result["nState"] > 0,
            "height": item["height"]}
