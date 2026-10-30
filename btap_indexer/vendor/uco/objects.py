"""UCO v0.1 definition objects: Module, Design, Machine (docs/SPEC.md §4-§6), the FLAT-1 flattener (§5.3),
and a hierarchical evaluator used as an independent check of flattening.

A registry maps inscription id -> entry (a JSON-able dict). Valid circuit entries (module, design) carry
`flat` (hex of the FLAT-1 netlist), `nIn`, `nOut`, `nState`, `gates`, `flatHash`. Entries are created in
chain order; an object may reference only entries that already exist when it is validated."""
import hashlib
import json
import re
from array import array

from . import cbor, envelope, tap02

METAPROTOCOL = b"uco/0"
_flatnets = {}                       # flat hash -> FlatNet (content-addressed, so never stale)
MAX_FLAT_ELEMENTS = 1 << 20          # records of the final FLAT-1 netlist, F4 inverters included (SPEC §5.3, §12)
MAX_PINS = 1 << 16
MAX_PARTS = 4096
MAX_CELLS = 64
MAX_CELL_WIDTH = 256
MAX_OPS = 64
MAX_OP_INPUTS = 512
NAME_MAX = 64


class Invalid(ValueError):
    pass


# ---- flat circuits ---------------------------------------------------------------------------------

class Flat:
    """A NAND/LATCH-only circuit in local signal ids: 0, 1 constants; 2..2+nIn-1 inputs; then one id per
    element in order. `out` lists the ids of the outputs (they need not be the last signals)."""

    def __init__(self, n_in, n_out):
        self.n_in, self.n_out = n_in, n_out
        self.elems = []          # [op, a, b] for NAND, [op, d] for LATCH
        self.out = []

    @property
    def next_id(self):
        return 2 + self.n_in + len(self.elems)

    def emit(self, op, *ins):
        if len(self.elems) >= MAX_FLAT_ELEMENTS:
            raise Invalid("flattened circuit exceeds the element bound")
        self.elems.append([op, *ins])
        return self.next_id - 1


class FlatNet:
    """A finished FLAT-1 netlist (F4 applied) in compact arrays: ops[i] is 0 (NAND) or 1 (LATCH) for the
    element with id 2 + n_in + i; a[i], b[i] are a NAND's operands, a[i] a LATCH's d. Outputs are the last
    n_out ids. Built once per object and cached by flat hash, so a REF or module part never re-decodes it."""
    __slots__ = ("n_in", "n_out", "ops", "a", "b", "n_state", "gates")

    def __init__(self, n_in, n_out, ops, a, b):
        self.n_in, self.n_out, self.ops, self.a, self.b = n_in, n_out, bytes(ops), a, b
        self.gates = len(self.ops)
        self.n_state = self.ops.count(1)

    def check(self):
        """Appendix A.3 for a NAND/LATCH-only netlist, in one pass."""
        n_in, n_out, k = self.n_in, self.n_out, len(self.ops)
        S = 2 + n_in + k
        if S > tap02.MAX_SIGNALS or not (0 <= n_in <= MAX_PINS and 1 <= n_out <= MAX_PINS) or 2 + n_in + n_out > S:
            raise tap02.IllFormed("flat netlist: size, pins or too few signals for outputs")
        first = 2 + n_in
        for i, (op, x, y) in enumerate(zip(self.ops, self.a, self.b)):
            if (op == 0 and (x >= first + i or y >= first + i)) or (op == 1 and x >= S):
                raise tap02.IllFormed(f"flat netlist: bad reference in element {i}")
        return self

    def encode(self) -> bytes:
        out = bytearray()
        for op, x, y in zip(self.ops, self.a, self.b):
            out += (x << 24 | y).to_bytes(7, "big") if op == 0 else (0x01000000 | x).to_bytes(4, "big")
        return bytes(out)

    @classmethod
    def decode(cls, nl: bytes, n_in: int, n_out: int):
        """Inverse of encode, for a netlist that holds only NAND and LATCH records."""
        ops, A, B, p, n = bytearray(), array("l"), array("l"), 0, len(nl)
        while p < n:
            op = nl[p]
            if op == 0 and p + 7 <= n:
                v = int.from_bytes(nl[p + 1:p + 7], "big")
                A.append(v >> 24)
                B.append(v & 0xffffff)
                p += 7
            elif op == 1 and p + 4 <= n:
                A.append(int.from_bytes(nl[p + 1:p + 4], "big"))
                B.append(0)
                p += 4
            else:
                raise tap02.IllFormed("not a complete NAND/LATCH-only netlist")
            ops.append(op)
        return cls(n_in, n_out, ops, A, B).check()


def inline(sub: FlatNet, in_ids, dst: Flat):
    """F1: copies `sub` into `dst` with its inputs bound to in_ids; returns the dst ids of sub's outputs."""
    m = [0, 1] + list(in_ids)
    patches = []
    for op, x, y in zip(sub.ops, sub.a, sub.b):
        if op == 0:
            m.append(dst.emit(tap02.NAND, m[x], m[y]))
        else:
            g = dst.emit(tap02.LATCH, -1)
            patches.append((g, x))
            m.append(g)
    for g, d in patches:
        dst.elems[g - 2 - dst.n_in][1] = m[d]
    return m[len(m) - sub.n_out:]


def flat_from_netlist(data: bytes, n_in: int, n_out: int, resolve_flat) -> Flat:
    """F2: FLAT-1 walk of a TAP-02 netlist; REF records are replaced by the inlined FlatNet of the target."""
    els = tap02.decode(data, n_in)
    f = Flat(n_in, n_out)
    m = list(range(2 + n_in))
    patches = []
    for e in els:
        if e.op == tap02.NAND:
            m.append(f.emit(tap02.NAND, m[e.ins[0]], m[e.ins[1]]))
        elif e.op == tap02.LATCH:
            g = f.emit(tap02.LATCH, -1)
            patches.append((g, e.ins[0]))
            m.append(g)
        else:
            sub = resolve_flat(e.cpu, e.cid)
            m.extend(inline(sub, [m[s] for s in e.ins], f))
    for g, d in patches:
        f.elems[g - 2 - n_in][1] = m[d]
    s = len(m)
    f.out = [m[k] for k in range(s - n_out, s)]
    return f


def finalize(f: Flat) -> FlatNet:
    """F4 (outputs last) and F5 (well-formed, at most 2^20 records)."""
    ops = bytearray(e[0] for e in f.elems)
    A = array("l", (e[1] for e in f.elems))
    B = array("l", (e[2] if e[0] == 0 else 0 for e in f.elems))
    n = 2 + f.n_in + len(ops)
    if f.out != list(range(n - f.n_out, n)):
        for o in f.out:
            ops.append(0); A.append(o); B.append(o)
        for k in range(f.n_out):
            ops.append(0); A.append(n + k); B.append(n + k)
    if len(ops) > MAX_FLAT_ELEMENTS:                 # the bound counts the F4 inverters too
        raise Invalid("flattened circuit exceeds the element bound")
    return FlatNet(f.n_in, f.n_out, ops, A, B).check()


def to_netlist(f: Flat) -> bytes:
    """Encodes a Flat as a TAP-02 netlist whose last nOut signals are the outputs (FLAT-1 rules F4, F5)."""
    return finalize(f).encode()


def flat_hash(netlist: bytes, n_in: int, n_out: int) -> str:
    return hashlib.sha256(b"UCO-FLAT-1" + n_in.to_bytes(4, "big") + n_out.to_bytes(4, "big") + netlist).hexdigest()


def flatnet_of(entry) -> FlatNet:
    """The FlatNet of a valid circuit entry, from the cache filled at validation, else decoded once."""
    fn = _flatnets.get(entry["flatHash"])
    if fn is None:
        fn = _flatnets[entry["flatHash"]] = FlatNet.decode(bytes.fromhex(entry["flat"]), entry["nIn"], entry["nOut"])
    return fn


# ---- canonical JSON --------------------------------------------------------------------------------

def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _str_ok(x):
    """SPEC §3.6/§5.1: only bytes 0x20-0x7E other than '"' and '\\', so no escape can occur."""
    return all(0x20 <= ord(ch) <= 0x7e and ch not in '"\\' for ch in x)


MAX_JSON_DEPTH = 16     # SPEC §5.1: arrays and objects nested at most 16 deep (valid documents need 4)
MAX_DIGITS = 9          # SPEC §5.1/§12: every decimal number has at most 9 digits


def parse_canonical_json(body: bytes):
    """Parses and checks the canonical JSON grammar of SPEC §5.1 in one left-to-right pass with an explicit
    stack: no recursion, no interpreter-dependent integer conversion (at most 9 digits are converted), and
    only `Invalid` can be raised. Returns dicts, lists, str and int."""
    b, n = bytes(body), len(body)
    p, stack, root, mode = 0, [], None, "value"

    def bad(why):
        raise Invalid(f"body is not canonical JSON: {why} at byte {p}")

    def string():
        nonlocal p
        q = p + 1
        while q < n and b[q] != 0x22:
            if not 0x20 <= b[q] <= 0x7e or b[q] == 0x5c:
                p = q
                bad("byte outside 0x20-0x7E or a backslash in a string")
            q += 1
        if q >= n:
            bad("unterminated string")
        v = b[p + 1:q].decode("ascii")
        p = q + 1
        return v

    def integer():
        nonlocal p
        q = p
        while q < n and 0x30 <= b[q] <= 0x39 and q - p <= MAX_DIGITS:
            q += 1
        if q - p > MAX_DIGITS:
            bad(f"integer of more than {MAX_DIGITS} digits")
        if q - p > 1 and b[p] == 0x30:
            bad("leading zero")
        v = int(b[p:q])
        p = q
        return v

    def attach(v):
        nonlocal root
        if not stack:
            root = v
        elif isinstance(stack[-1][0], dict):
            stack[-1][0][stack[-1][1]] = v
        else:
            stack[-1][0].append(v)

    while True:
        if mode == "value":
            if p >= n:
                bad("value expected")
            c = b[p]
            if c in (0x7b, 0x5b):                                   # { or [
                if len(stack) >= MAX_JSON_DEPTH:
                    bad(f"nested more than {MAX_JSON_DEPTH} deep")
                cont = {} if c == 0x7b else []
                attach(cont)
                stack.append([cont, None])                          # [container, last key]
                p += 1
                close = 0x7d if c == 0x7b else 0x5d
                if p < n and b[p] == close:
                    p += 1
                    stack.pop()
                    mode = "after"
                else:
                    mode = "key" if c == 0x7b else "value"
            elif c == 0x22:
                attach(string())
                mode = "after"
            elif 0x30 <= c <= 0x39:
                attach(integer())
                mode = "after"
            else:
                bad("not a value")
        elif mode == "key":
            if p >= n or b[p] != 0x22:
                bad("key expected")
            k = string()
            if stack[-1][1] is not None and k <= stack[-1][1]:      # ASCII: str order = byte order
                bad("keys not strictly ascending")
            stack[-1][1] = k
            if p >= n or b[p] != 0x3a:
                bad("':' expected")
            p += 1
            mode = "value"
        else:                                                       # after a complete value
            if not stack:
                if p != n:
                    bad("bytes after the document")
                return root
            is_obj = isinstance(stack[-1][0], dict)
            if p >= n:
                bad("unterminated container")
            c = b[p]
            p += 1
            if c == 0x2c:
                mode = "key" if is_obj else "value"
            elif c == (0x7d if is_obj else 0x5d):
                stack.pop()
            else:
                bad("',' or end of container expected")


def _uint(x, lo, hi, what):
    if not isinstance(x, int) or isinstance(x, bool) or not lo <= x <= hi:
        raise Invalid(f"{what} must be an integer in [{lo}, {hi}]")
    return x


def _name(x):
    if not isinstance(x, str) or not 1 <= len(x) <= NAME_MAX or not _str_ok(x):
        raise Invalid("name must be 1..64 printable ASCII characters other than '\"' and '\\'")
    return x


def _cbor_value_ok(x):
    """SPEC §3.5: metadata values are unsigned integers, byte strings, text strings, arrays and maps with
    text keys only (no negative integers, floats, tags or simple values such as true/false/null)."""
    if type(x) is int:
        return x >= 0
    if isinstance(x, (bytes, str)):
        return True
    if isinstance(x, list):
        return all(_cbor_value_ok(y) for y in x)
    if isinstance(x, dict):
        return all(isinstance(k, str) and _cbor_value_ok(y) for k, y in x.items())
    return False


def _keys(d, required, optional=()):
    if not isinstance(d, dict):
        raise Invalid("expected an object")
    ks = set(d)
    if not set(required) <= ks or not ks <= set(required) | set(optional):
        raise Invalid(f"keys must be {sorted(required)} (+ optional {sorted(optional)}), got {sorted(ks)}")


def _circuit(reg, iid):
    if not isinstance(iid, str):
        raise Invalid("reference must be an inscription id string")
    try:
        envelope.split_id(iid)
    except ValueError:
        raise Invalid(f"bad inscription id {iid!r}")
    e = reg.get(iid)
    if e is None:
        raise Invalid(f"reference {iid} is not an earlier inscription")
    if not e.get("valid") or e.get("kind") not in ("module", "design"):
        raise Invalid(f"reference {iid} is not a valid module or design")
    return e


# ---- validation of inscriptions --------------------------------------------------------------------

def classify(env, reg, flat_cache):
    """Returns a registry entry for an inscription, or None if it is not a UCO object."""
    if env.get("metaprotocol") != METAPROTOCOL:
        return None
    entry = {"kind": None, "valid": False}
    try:
        for flag in ("duplicate_field", "incomplete_field", "unrecognized_even_field"):
            if env[flag]:
                raise Invalid(f"envelope has {flag}")
        if env["content_encoding"] is not None or env["delegate"] is not None:
            raise Invalid("content encoding and delegation are not allowed in UCO objects")
        if env["metadata"] is None or not cbor.canonical(env["metadata"]):
            raise Invalid("metadata must be deterministic CBOR")
        meta = cbor.decode(env["metadata"])
        if not isinstance(meta, dict) or not isinstance(meta.get("kind"), str):
            raise Invalid("metadata must be a map with a text 'kind'")
        if not _cbor_value_ok(meta):
            raise Invalid("metadata may hold only unsigned integers, byte and text strings, arrays and maps")
        entry["kind"] = meta["kind"]
        body = env["body"] if env["body"] is not None else b""
        if meta["kind"] == "module":
            entry.update(_module(meta, body, reg, flat_cache))
        elif meta["kind"] == "design":
            _keys(meta, ["kind"])
            entry.update(_design(parse_canonical_json(body), reg, flat_cache))
        elif meta["kind"] == "machine":
            _keys(meta, ["kind"])
            entry.update(_machine(parse_canonical_json(body), reg))
        else:
            raise Invalid(f"unknown kind {meta['kind']!r}")
        entry["valid"] = True
    except (Invalid, tap02.IllFormed, cbor.CBORError) as e:
        entry["reason"] = str(e)
    except Exception as e:  # noqa: BLE001
        # Totality (SPEC §14): no input may stop the indexer. Every path above is meant to raise only the
        # three errors caught before; reaching this line is a bug in this implementation, recorded as such.
        entry["reason"] = f"internal error ({type(e).__name__}); treated as invalid"
    return entry


def get_flat(reg, flat_cache, iid) -> FlatNet:
    return flatnet_of(reg[iid])


def _presize(count, targets):
    """SPEC §5.4 F0: own NAND/LATCH records plus the records of every inlined target's flat netlist, checked
    before any target is inlined (FLAT(X) has at least this many records)."""
    total = count + sum(t["gates"] for t in targets)
    if total > MAX_FLAT_ELEMENTS:
        raise Invalid(f"flattened circuit would have at least {total} records (> 2^20)")


def _finish(f: Flat):
    fn = finalize(f)
    nl = fn.encode()
    fh = flat_hash(nl, f.n_in, f.n_out)
    _flatnets[fh] = fn
    return {"flat": nl.hex(), "nIn": f.n_in, "nOut": f.n_out, "nState": fn.n_state, "gates": fn.gates,
            "flatHash": fh}


def _module(meta, body, reg, flat_cache):
    _keys(meta, ["kind", "nIn", "nOut", "nState"], ["name", "refs", "origin"])
    n_in = _uint(meta["nIn"], 0, MAX_PINS, "nIn")
    n_out = _uint(meta["nOut"], 1, MAX_PINS, "nOut")
    if "name" in meta:
        _name(meta["name"])
    refs = {}                                      # (cpu, id) -> target inscription id
    if "refs" in meta and (not isinstance(meta["refs"], list) or not meta["refs"]):
        raise Invalid("refs, when present, must be a non-empty array")
    for r in meta.get("refs", []):
        if not (isinstance(r, list) and len(r) == 3 and isinstance(r[0], bytes) and len(r[0]) == 20):
            raise Invalid("refs entries must be [cpu:bytes20, id:uint, inscription id]")
        key = (r[0], _uint(r[1], 0, (1 << 64) - 1, "ref id"))
        if key in refs:
            raise Invalid("duplicate refs entry")
        _circuit(reg, r[2])
        refs[key] = r[2]
    if "origin" in meta:
        o = meta["origin"]
        _keys(o, ["chain", "cpu", "id"])
        if not isinstance(o["cpu"], bytes) or len(o["cpu"]) != 20:
            raise Invalid("origin.cpu must be 20 bytes")
        _uint(o["chain"], 0, (1 << 64) - 1, "origin.chain")
        _uint(o["id"], 0, (1 << 64) - 1, "origin.id")
    used = set()
    els = tap02.decode(body, n_in)                 # A.3 condition 1; linear in the body
    _presize(sum(1 for e in els if e.op != tap02.REF),
             [reg[refs[(e.cpu, e.cid)]] for e in els if e.op == tap02.REF and (e.cpu, e.cid) in refs])
    stubs = {}

    def resolve(cpu, cid):
        """A stub with the target's validated nIn/nOut/nState/gates: REF arity and state size need nothing else,
        so no target netlist is decoded here (SPEC A.6)."""
        iid = refs.get((cpu, cid))
        if iid is None:
            return None
        used.add((cpu, cid))
        if iid not in stubs:
            t = reg[iid]
            stubs[iid] = tap02.Circuit(t["nIn"], t["nOut"], [], n_state=t["nState"], n_gates=t["gates"])
        return stubs[iid]

    c = tap02.load(body, n_in, n_out, resolve)     # §3 including REF arity, with refs as the resolver
    if used != set(refs):
        raise Invalid("refs lists a target that the netlist does not use")
    if c.n_state != meta["nState"]:
        raise Invalid(f"metadata nState {meta['nState']} != computed {c.n_state}")
    f = flat_from_netlist(body, n_in, n_out, lambda cpu, cid: get_flat(reg, flat_cache, refs[(cpu, cid)]))
    out = _finish(f)
    out["name"] = meta.get("name")
    out["refs"] = {f"0x{k[0].hex()}:{k[1]}": v for k, v in refs.items()}
    if "origin" in meta:
        o = meta["origin"]
        out["origin"] = {"chain": o["chain"], "cpu": "0x" + o["cpu"].hex(), "id": o["id"]}
    return out


SIG_RE = re.compile(r"^(c[01]|i(0|[1-9][0-9]{0,8})|p(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8}))$")   # ≤ 9 digits


def _design(doc, reg, flat_cache):
    _keys(doc, ["name", "nIn", "nOut", "parts", "out"])
    _name(doc["name"])
    n_in = _uint(doc["nIn"], 0, MAX_PINS, "nIn")
    n_out = _uint(doc["nOut"], 1, MAX_PINS, "nOut")
    parts = doc["parts"]
    if not isinstance(parts, list) or len(parts) > MAX_PARTS:
        raise Invalid("parts must be a list of at most 4096 parts")
    if not isinstance(doc["out"], list) or len(doc["out"]) != n_out:
        raise Invalid("out must list exactly nOut signals")
    arity = []          # outputs per part
    targets = []
    for j, p in enumerate(parts):
        if isinstance(p, dict) and "g" in p:
            _keys(p, ["g", "in"])
            if p["g"] not in ("NAND", "LATCH"):
                raise Invalid(f"part {j}: unknown primitive {p['g']!r}")
            need = 2 if p["g"] == "NAND" else 1
            targets.append(None)
        else:
            _keys(p, ["m", "in"])
            t = _circuit(reg, p["m"])
            need = t["nIn"]
            targets.append(t)
        if not isinstance(p["in"], list) or len(p["in"]) != need:
            raise Invalid(f"part {j}: expected {need} inputs")
        arity.append(1 if targets[-1] is None else targets[-1]["nOut"])

    def check_ref(r, j, forward_ok):
        if not isinstance(r, str) or not SIG_RE.match(r):
            raise Invalid(f"bad signal reference {r!r}")
        if r[0] == "i" and int(r[1:]) >= n_in:
            raise Invalid(f"input {r} out of range")
        if r[0] == "p":
            pj, k = map(int, r[1:].split("."))
            if pj >= len(parts) or (not forward_ok and pj >= j):
                raise Invalid(f"part {j}: reference {r} is not to an earlier part")
            if k >= arity[pj]:
                raise Invalid(f"reference {r}: part {pj} has {arity[pj]} outputs")

    for j, p in enumerate(parts):
        for r in p["in"]:
            check_ref(r, j, p.get("g") == "LATCH")
    for r in doc["out"]:
        check_ref(r, len(parts), True)

    _presize(sum(1 for t in targets if t is None), [t for t in targets if t is not None])
    f = Flat(n_in, n_out)
    sig = {}

    def val(r):
        if r[0] == "c":
            return int(r[1])
        if r[0] == "i":
            return 2 + int(r[1:])
        pj, k = map(int, r[1:].split("."))
        return sig[(pj, k)]

    patches = []
    for j, p in enumerate(parts):
        if p.get("g") == "NAND":
            sig[(j, 0)] = f.emit(tap02.NAND, val(p["in"][0]), val(p["in"][1]))
        elif p.get("g") == "LATCH":
            sig[(j, 0)] = f.emit(tap02.LATCH, -1)
            patches.append((sig[(j, 0)], p["in"][0]))
        else:
            outs = inline(get_flat(reg, flat_cache, p["m"]), [val(r) for r in p["in"]], f)
            for k, o in enumerate(outs):
                sig[(j, k)] = o
    for g, r in patches:
        f.elems[g - 2 - n_in][1] = val(r)
    f.out = [val(r) for r in doc["out"]]
    out = _finish(f)
    out["name"] = doc["name"]
    return out


def _machine(doc, reg):
    _keys(doc, ["name", "cells", "ops"])
    _name(doc["name"])
    cells = doc["cells"]
    if not isinstance(cells, list) or not 1 <= len(cells) <= MAX_CELLS:
        raise Invalid("cells must be a list of 1..64 widths")
    for w in cells:
        _uint(w, 1, MAX_CELL_WIDTH, "cell width")
    ops = doc["ops"]
    if not isinstance(ops, list) or not 1 <= len(ops) <= MAX_OPS:
        raise Invalid("ops must be a list of 1..64 operations")
    out_ops = []
    for k, op in enumerate(ops):
        _keys(op, ["name", "c", "slots"])
        _name(op["name"])
        t = _circuit(reg, op["c"])
        slots = op["slots"]
        if not isinstance(slots, list) or not 1 <= len(slots) <= len(cells):
            raise Invalid(f"op {k}: slots must list 1..len(cells) widths")
        for w in slots:
            _uint(w, 1, MAX_CELL_WIDTH, "slot width")
        if sum(slots) != t["nState"]:
            raise Invalid(f"op {k}: slot widths sum to {sum(slots)} but the circuit has nState {t['nState']}")
        if t["nIn"] > MAX_OP_INPUTS:
            raise Invalid(f"op {k}: more than {MAX_OP_INPUTS} inputs")
        out_ops.append({"name": op["name"], "c": op["c"], "slots": slots, "nIn": t["nIn"], "nOut": t["nOut"]})
    return {"name": doc["name"], "cells": cells, "ops": out_ops}


# ---- evaluation --------------------------------------------------------------------------------------

def flat_beat(entry, state, inputs):
    """One beat (Appendix A.4) of the entry's FLAT-1 netlist. Returns (new state, outputs)."""
    fn = flatnet_of(entry)
    s = [0, 1] + list(inputs)
    latches, k = [], 0
    for op, x, y in zip(fn.ops, fn.a, fn.b):
        if op == 0:
            s.append(1 - (s[x] & s[y]))
        else:
            s.append(state[k])
            latches.append(x)
            k += 1
    return [s[d] for d in latches], s[len(s) - fn.n_out:]


class Hier:
    """Hierarchical evaluator over the original objects (module netlists with TAP-02 REF semantics,
    design documents part by part). Independent of FLAT-1; used by tests and the demo to check it."""

    def __init__(self, sources):
        # sources: inscription id -> ("module", netlist bytes, meta) or ("design", doc)
        self.src = sources
        self.cache = {}

    def circuit(self, iid):
        if iid in self.cache:
            return self.cache[iid]
        kind = self.src[iid][0]
        if kind == "module":
            _, nl, meta = self.src[iid]
            refs = {(r[0], r[1]): r[2] for r in meta.get("refs", [])}

            def resolve(cpu, cid):
                return self._as_tap02(refs[(cpu, cid)])
            c = ("module", tap02.load(nl, meta["nIn"], meta["nOut"], resolve))
        else:
            doc = self.src[iid][1]
            n_state = 0
            for p in doc["parts"]:
                if p.get("g") == "LATCH":
                    n_state += 1
                elif "m" in p:
                    n_state += self.n_state(p["m"])
            c = ("design", doc, n_state)
        self.cache[iid] = c
        return c

    def _as_tap02(self, iid):
        c = self.circuit(iid)
        if c[0] != "module":
            raise NotImplementedError("REF to a design is evaluated through FLAT-1 only")
        return c[1]

    def n_state(self, iid):
        c = self.circuit(iid)
        return c[1].n_state if c[0] == "module" else c[2]

    def beat(self, iid, state, inputs):
        c = self.circuit(iid)
        if c[0] == "module":
            return tap02.beat(c[1], list(state), list(inputs))
        doc = c[1]
        sig, base, latches, new_state = {}, 0, [], list(state)

        def val(r):
            if r[0] == "c":
                return int(r[1])
            if r[0] == "i":
                return inputs[int(r[1:])]
            pj, k = map(int, r[1:].split("."))
            return sig[(pj, k)]
        for j, p in enumerate(doc["parts"]):
            if p.get("g") == "NAND":
                sig[(j, 0)] = 1 - (val(p["in"][0]) & val(p["in"][1]))
            elif p.get("g") == "LATCH":
                sig[(j, 0)] = state[base]
                latches.append((base, p["in"][0]))
                base += 1
            else:
                n = self.n_state(p["m"])
                ns, outs = self.beat(p["m"], state[base:base + n], [val(r) for r in p["in"]])
                new_state[base:base + n] = ns
                for k, o in enumerate(outs):
                    sig[(j, k)] = o
                base += n
        for b, r in latches:
            new_state[b] = val(r)
        return new_state, [val(r) for r in doc["out"]]
