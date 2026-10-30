import hashlib
import json
from uco import cbor, objects

RULE = "uco/0@19260366f1807109cfa3c40e35ce3b79eaaf268e"

MAX_PARTS = 512
MAX_PINS = 32
MAX_STATE = 64
MAX_BODY_BYTES = 32768
MAX_FLAT_RECORDS = 512
MAX_FLAT_BYTES = 4096


def precheck_design(design):
    if not isinstance(design, dict):
        raise ValueError("Design must be an object")
    parts = design.get("parts")
    if not isinstance(parts, list) or len(parts) > MAX_PARTS:
        raise ValueError(f"At most {MAX_PARTS} primitive parts are allowed")
    for key, low, high in (("nIn", 0, MAX_PINS), ("nOut", 1, MAX_PINS)):
        value = design.get(key)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{key} must be an integer in {low}..{high}")
    if any(not isinstance(p, dict) or p.get("g") not in ("NAND", "LATCH") for p in parts):
        raise ValueError("Only self-contained NAND and LATCH parts are supported")
    return parts


def check_flat_result(result):
    if not result or not result.get("valid"):
        raise ValueError((result or {}).get("reason", "Invalid UCO Design"))
    if result["nState"] > MAX_STATE or result["gates"] > MAX_FLAT_RECORDS:
        raise ValueError("Definition exceeds state/flattened record limit")
    if len(result["flat"]) // 2 > MAX_FLAT_BYTES:
        raise ValueError("Definition exceeds flattened byte limit")


def compile_design(design):
    precheck_design(design)
    body = objects.canonical_json(design)
    metadata = cbor.encode({"kind": "design"})
    if len(body) + len(metadata) > MAX_BODY_BYTES:
        raise ValueError("Definition exceeds 32 KiB")
    env = dict(metaprotocol=b"uco/0", body=body, metadata=metadata,
               duplicate_field=False, incomplete_field=False, unrecognized_even_field=False,
               content_encoding=None, delegate=None)
    result = objects.classify(env, {}, {})
    check_flat_result(result)
    objects._flatnets.clear()
    state_capable = result["nState"] > 0
    return {**result, "body": body.decode(), "body_sha256": hashlib.sha256(body).hexdigest(),
            "metadata_hex": metadata.hex(), "rule": RULE,
            "capabilities": {"definition": True, "chain_state": False,
                             "state_capable": state_capable, "instantiable": state_capable},
            "instances": []}


def simulate(design, inputs, state=None):
    entry = compile_design(design)
    state = [0] * entry["nState"] if state is None else state
    for bits, size in ((inputs, entry["nIn"]), (state, entry["nState"])):
        if not isinstance(bits, list) or len(bits) != size or any(type(b) is not int or b not in (0, 1) for b in bits):
            raise ValueError(f"Expected exactly {size} bits (0 or 1)")
    next_state, outputs = objects.flat_beat(entry, state, inputs)
    objects._flatnets.clear()
    return {"outputs": outputs, "state": next_state, "rule": RULE}


def load_design(text):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("Duplicate JSON key")
            out[key] = value
        return out
    return json.loads(text, object_pairs_hook=unique)
