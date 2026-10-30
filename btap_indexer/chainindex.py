import contextlib
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from btap_indexer import protocol
from btap_indexer.circuit import compile_design
from btap_indexer.providers import ProviderUnavailable
from btap_indexer.transactions import parse
from uco import btc
from btap_indexer import constants
from btap_indexer.chain_validation import validate_block

DEFAULT_MAX_BLOCKS = 50
MAX_BLOCKS_PER_SYNC = 1000
REPLAY_BATCH_ITEMS = 32
MAX_REJECT_ITEMS = 1000


class ChainStore:

    def __init__(self, path):
        self.path = str(path)
        with contextlib.closing(self.connect()) as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS chain_meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
              );
              CREATE TABLE IF NOT EXISTS chain_blocks (
                height INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE,
                prev TEXT NOT NULL, candidates INTEGER NOT NULL
              );
              CREATE TABLE IF NOT EXISTS chain_candidates (
                height INTEGER NOT NULL, position INTEGER NOT NULL,
                txid TEXT NOT NULL UNIQUE, block_hash TEXT NOT NULL,
                raw TEXT NOT NULL,
                PRIMARY KEY (height, position)
              );
              CREATE TABLE IF NOT EXISTS chain_replay (
                txid TEXT PRIMARY KEY,
                height INTEGER NOT NULL,
                position INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                serial INTEGER,
                ticket_id TEXT,
                entry TEXT,
                reason TEXT
              );
              CREATE INDEX IF NOT EXISTS chain_replay_serial
                ON chain_replay(status, serial);
              CREATE INDEX IF NOT EXISTS chain_replay_position
                ON chain_replay(height,position,txid);
              CREATE TABLE IF NOT EXISTS chain_used_tickets (
                ticket_id TEXT PRIMARY KEY,
                txid TEXT NOT NULL
              );
              CREATE INDEX IF NOT EXISTS chain_used_ticket_txid ON chain_used_tickets(txid);
            """)
            columns = {row[1] for row in db.execute('PRAGMA table_info(chain_replay)')}
            if 'pool' not in columns:
                db.execute('ALTER TABLE chain_replay ADD COLUMN pool TEXT')
            db.execute("UPDATE chain_replay SET pool=json_extract(entry,'$.pool') WHERE status='accepted' AND pool IS NULL")
            db.execute('CREATE INDEX IF NOT EXISTS chain_replay_pool ON chain_replay(status,pool)')
            if 'recipient' not in columns:
                db.execute('ALTER TABLE chain_replay ADD COLUMN recipient TEXT')
            for row in db.execute("SELECT r.txid,c.raw FROM chain_replay r JOIN chain_candidates c ON c.txid=r.txid "
                                  "WHERE r.status='accepted' AND r.recipient IS NULL").fetchall():
                db.execute('UPDATE chain_replay SET recipient=? WHERE txid=?',
                           (_recipient(parse(row['raw'])), row['txid']))
            db.execute('CREATE INDEX IF NOT EXISTS chain_replay_recipient ON chain_replay(recipient,status,serial)')
            tracked = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chain_spends'").fetchone()
            db.execute('CREATE TABLE IF NOT EXISTS chain_spends ('
                       'txid TEXT PRIMARY KEY, spent_by TEXT NOT NULL, height INTEGER NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS chain_spends_height ON chain_spends(height)')
            if tracked is None:
                applied = db.execute('SELECT MIN(height),MAX(height) FROM chain_blocks').fetchone()
                if applied[0] is not None:
                    self._set(db, 'spend_gap', [applied[0], applied[1]])
            db.execute('PRAGMA journal_mode=WAL')

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute('PRAGMA cache_size=-4096')
        db.execute('PRAGMA temp_store=FILE')
        return db

    @contextlib.contextmanager
    def transaction(self):
        with contextlib.closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise

    @staticmethod
    def _set(db, key, value):
        db.execute("INSERT INTO chain_meta(key,value) VALUES(?,?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (key, json.dumps(value)))

    def meta(self):
        with contextlib.closing(self.connect()) as db:
            rows = db.execute("SELECT key,value FROM chain_meta").fetchall()
        result = {}
        for row in rows:
            try:
                result[row["key"]] = json.loads(row["value"])
            except ValueError:
                raise ValueError("Chain index metadata is corrupt") from None
        return result

    def reset(self, network, genesis, activation_height, deep_reorgs=0):
        with self.transaction() as db:
            db.execute("DELETE FROM chain_candidates")
            db.execute("DELETE FROM chain_blocks")
            db.execute("DELETE FROM chain_replay")
            db.execute("DELETE FROM chain_used_tickets")
            db.execute("DELETE FROM chain_spends")
            db.execute("DELETE FROM chain_meta")
            for key, value in (("network", network), ("genesis", genesis),
                               ("activation_height", activation_height),
                               ("tip_height", activation_height - 1), ("tip_hash", ""),
                               ("caught_up", False), ("last_sync", 0),
                               ("reorgs", 0), ("deep_reorgs", deep_reorgs)):
                self._set(db, key, value)

    def block(self, height):
        with contextlib.closing(self.connect()) as db:
            row = db.execute("SELECT * FROM chain_blocks WHERE height=?", (height,)).fetchone()
        return dict(row) if row else None

    def block_hash(self, height):
        row = self.block(height)
        return row["hash"] if row else None

    def apply(self, height, block_hash, prev, candidates, spends=()):
        try:
            with self.transaction() as db:
                existing = db.execute("SELECT hash FROM chain_blocks WHERE height=?",
                                      (height,)).fetchone()
                if existing is not None:
                    if existing["hash"] != block_hash:
                        raise ValueError("Chain index conflict at height %d" % height)
                    return False
                db.execute("INSERT INTO chain_blocks(height,hash,prev,candidates) VALUES(?,?,?,?)",
                           (height, block_hash, prev, len(candidates)))
                for item in candidates:
                    db.execute("INSERT INTO chain_candidates(height,position,txid,block_hash,raw) "
                               "VALUES(?,?,?,?,?)",
                               (height, item["position"], item["txid"], block_hash, item["raw"]))
                for txid, spent_by in spends:
                    db.execute("INSERT OR IGNORE INTO chain_spends(txid,spent_by,height) VALUES(?,?,?)",
                               (txid, spent_by, height))
                self._set(db, "tip_height", height)
                self._set(db, "tip_hash", block_hash)
                self._set(db, "caught_up", False)
                return True
        except sqlite3.IntegrityError:
            with contextlib.closing(self.connect()) as db:
                row = db.execute("SELECT hash FROM chain_blocks WHERE height=?",
                                 (height,)).fetchone()
            if row is not None and row["hash"] == block_hash:
                return False
            raise

    def rollback(self, height):
        with self.transaction() as db:
            row = db.execute("SELECT prev FROM chain_blocks WHERE height=?", (height,)).fetchone()
            if row is None:
                raise ValueError("Cannot roll back a block that is not indexed")
            db.execute("DELETE FROM chain_candidates WHERE height=?", (height,))
            db.execute("DELETE FROM chain_spends WHERE height>=?", (height,))
            db.execute("DELETE FROM chain_blocks WHERE height=?", (height,))
            self._invalidate_suffix(db, height)
            self._set(db, "tip_height", height - 1)
            self._set(db, "tip_hash", row["prev"])
            self._set(db, "caught_up", False)
            reorgs = db.execute("SELECT value FROM chain_meta WHERE key='reorgs'").fetchone()
            count = json.loads(reorgs["value"]) if reorgs else 0
            self._set(db, "reorgs", count + 1)
        return height - 1

    @classmethod
    def _invalidate_suffix(cls, db, height):
        db.execute('DELETE FROM chain_used_tickets WHERE txid IN '
                   '(SELECT txid FROM chain_replay WHERE height>=?)', (height,))
        db.execute('DELETE FROM chain_replay WHERE height>=?', (height,))
        serial = db.execute("SELECT COALESCE(MAX(serial),0) FROM chain_replay WHERE status='accepted'").fetchone()[0]
        cls._set(db, 'replay_serial', serial)

    def pending_candidates(self, limit=REPLAY_BATCH_ITEMS):
        with contextlib.closing(self.connect()) as db:
            tail = db.execute('SELECT height,position FROM chain_replay ORDER BY height DESC,position DESC LIMIT 1').fetchone()
            after = tuple(tail) if tail else (-1, -1)
            rows = db.execute('SELECT height,position,txid,block_hash,length(raw) AS raw_length, '
                              'CASE WHEN length(raw)<=? THEN raw ELSE NULL END AS raw '
                              'FROM chain_candidates WHERE (height,position)>(?,?) '
                              'ORDER BY height,position LIMIT ?',
                              (constants.MAX_RAW_BYTES*2, *after, limit)).fetchall()
        return [dict(row) for row in rows]

    def replay_pending_count(self):
        with contextlib.closing(self.connect()) as db:
            tail = db.execute('SELECT height,position FROM chain_replay ORDER BY height DESC,position DESC LIMIT 1').fetchone()
            after = tuple(tail) if tail else (-1, -1)
            return db.execute('SELECT COUNT(*) FROM chain_candidates WHERE (height,position)>(?,?)', after).fetchone()[0]

    def finish_sync(self, tip_height, tip_hash, caught_up):
        with self.transaction() as db:
            current = db.execute("SELECT value FROM chain_meta WHERE key='tip_height'").fetchone()
            try:
                current_height = json.loads(current["value"]) if current else None
            except ValueError:
                current_height = None
            if type(current_height) is int and current_height > tip_height:
                tip_height = current_height
                row = db.execute("SELECT hash FROM chain_blocks WHERE height=?",
                                 (current_height,)).fetchone()
                tip_hash = row["hash"] if row else ""
                caught_up = False
            self._set(db, "tip_height", tip_height)
            self._set(db, "tip_hash", tip_hash or "")
            self._set(db, "caught_up", bool(caught_up))
            self._set(db, "last_sync", int(time.time()))

    def replay_config(self):
        meta = self.meta()
        return (meta.get("replay_fee_script"), meta.get("replay_ticket_public_key"),
                meta.get("replay_protocol_fee"), meta.get("replay_policy_hash"))

    def set_replay_config(self, fee_script, ticket_public_key, protocol_fee, policy_hash=None):
        with self.transaction() as db:
            self._set(db, "replay_fee_script", fee_script)
            self._set(db, "replay_ticket_public_key", ticket_public_key)
            self._set(db, "replay_protocol_fee", protocol_fee)
            self._set(db, "replay_policy_hash", policy_hash)
            self._set(db, "replay_serial", 0)

    def clear_replay(self):
        with self.transaction() as db:
            db.execute("DELETE FROM chain_replay")
            db.execute("DELETE FROM chain_used_tickets")
            db.execute("DELETE FROM chain_meta WHERE key='replay_serial'")

    def replay_serial(self):
        value = self.meta().get("replay_serial", 0)
        if type(value) is not int or value < 0:
            raise ValueError("Chain replay serial metadata is corrupt")
        return value

    def replay_used_tickets(self):
        with contextlib.closing(self.connect()) as db:
            rows = db.execute("SELECT ticket_id FROM chain_used_tickets").fetchall()
        return {row["ticket_id"] for row in rows}

    def used_ticket_subset(self, ticket_ids):
        if not ticket_ids:
            return set()
        marks = ','.join('?' for _ in ticket_ids)
        with contextlib.closing(self.connect()) as db:
            return {row[0] for row in db.execute(f'SELECT ticket_id FROM chain_used_tickets WHERE ticket_id IN ({marks})', list(ticket_ids))}

    def pool_counts(self):
        with contextlib.closing(self.connect()) as db:
            return dict(db.execute("SELECT pool,COUNT(*) FROM chain_replay WHERE status='accepted' GROUP BY pool"))

    def replay_accepted_page(self, offset, limit):
        with contextlib.closing(self.connect()) as db:
            rows = db.execute("SELECT entry FROM chain_replay WHERE status='accepted' "
                              "ORDER BY serial LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [json.loads(row["entry"]) for row in rows]

    def replay_accepted_count(self):
        with contextlib.closing(self.connect()) as db:
            return db.execute("SELECT COUNT(*) FROM chain_replay WHERE status='accepted'").fetchone()[0]

    def replay_rejected(self, limit=MAX_REJECT_ITEMS):
        with contextlib.closing(self.connect()) as db:
            rows = db.execute("SELECT txid,height,reason FROM chain_replay WHERE status='rejected' "
                              "ORDER BY height,position LIMIT ?", (limit,)).fetchall()
        return [{"txid": row["txid"], "height": row["height"], "reason": row["reason"]} for row in rows]

    def replay_rejected_count(self):
        with contextlib.closing(self.connect()) as db:
            return db.execute("SELECT COUNT(*) FROM chain_replay WHERE status='rejected'").fetchone()[0]

    def append_replay(self, accepted, rejected, used_tickets, next_serial):
        with self.transaction() as db:
            for row in accepted:
                db.execute("""INSERT INTO chain_replay
                              (txid,height,position,block_hash,status,serial,ticket_id,entry,reason)
                              VALUES(?,?,?,?,'accepted',?,?,?,NULL)
                              ON CONFLICT(txid) DO UPDATE SET
                                height=excluded.height, position=excluded.position,
                                block_hash=excluded.block_hash, status='accepted',
                                serial=excluded.serial, ticket_id=excluded.ticket_id,
                                entry=excluded.entry, reason=NULL""",
                           (row["txid"], row["height"], row["position"], row["block_hash"],
                            row["serial"], row["ticket_id"], row["entry"]))
                db.execute("UPDATE chain_replay SET pool=?,recipient=? WHERE txid=?",
                           (row.get("pool") or json.loads(row["entry"]).get("pool"),
                            row.get("recipient"), row["txid"]))
            for row in rejected:
                db.execute("""INSERT INTO chain_replay
                              (txid,height,position,block_hash,status,serial,ticket_id,entry,reason)
                              VALUES(?,?,?,?,'rejected',NULL,NULL,NULL,?)
                              ON CONFLICT(txid) DO UPDATE SET
                                height=excluded.height, position=excluded.position,
                                block_hash=excluded.block_hash, status='rejected',
                                serial=NULL, ticket_id=NULL, entry=NULL, pool=NULL, recipient=NULL,
                                reason=excluded.reason""",
                           (row["txid"], row["height"], row["position"], row["block_hash"],
                            row["reason"]))
            for ticket_id, txid in used_tickets:
                db.execute("INSERT OR IGNORE INTO chain_used_tickets(ticket_id,txid) VALUES(?,?)",
                           (ticket_id, txid))
            self._set(db, "replay_serial", next_serial)

    def candidate_txids(self):
        with contextlib.closing(self.connect()) as db:
            return {row[0] for row in db.execute("SELECT txid FROM chain_candidates")}

    def add_spends(self, height, block_hash, spends):
        with self.transaction() as db:
            if db.execute("SELECT 1 FROM chain_blocks WHERE height=? AND hash=?",
                          (height, block_hash)).fetchone() is None:
                return
            for txid, spent_by in spends:
                db.execute("INSERT OR IGNORE INTO chain_spends(txid,spent_by,height) VALUES(?,?,?)",
                           (txid, spent_by, height))

    def set_spend_gap(self, gap):
        with self.transaction() as db:
            if gap is None:
                db.execute("DELETE FROM chain_meta WHERE key='spend_gap'")
            else:
                self._set(db, "spend_gap", gap)

    def locate(self, txid):
        with contextlib.closing(self.connect()) as db:
            row = db.execute("SELECT c.height,c.position,c.block_hash,c.raw FROM chain_candidates c "
                             "JOIN chain_blocks b ON b.height=c.height AND b.hash=c.block_hash "
                             "WHERE c.txid=?", (txid,)).fetchone()
            tip = db.execute("SELECT value FROM chain_meta WHERE key='tip_height'").fetchone()
        if row is None:
            return None
        return {**dict(row), "tip_height": json.loads(tip["value"]) if tip else row["height"]}

    def counts(self):
        with contextlib.closing(self.connect()) as db:
            blocks = db.execute("SELECT COUNT(*) FROM chain_blocks").fetchone()[0]
            candidates = db.execute("SELECT COUNT(*) FROM chain_candidates").fetchone()[0]
        return {"blocks": blocks, "candidates": candidates}

    def status(self):
        meta = self.meta()
        return {**meta, **self.counts(), "initialized": bool(meta),
                "ready": bool(meta) and meta.get("last_sync", 0) > 0}


def _recipient(tx):
    return bytes(tx["vout"][0]["spk"]).hex() if tx["vout"] else None


def _spends(txs, tracked):
    found = []
    for tx in txs:
        for vin in tx["vin"]:
            if vin["vout"] == 0 and vin["txid"] in tracked:
                found.append((vin["txid"], tx["txid"]))
        if any(_is_btap_output(output.get("spk", b"")) for output in tx["vout"]):
            tracked.add(tx["txid"])
    return found


def _is_btap_output(spk):
    if not isinstance(spk, (bytes, bytearray)) or len(spk) < 7 or spk[0] != 0x6a:
        return False
    size = spk[1]
    if size >= 0x4c or len(spk) != size + 2:
        return False
    return bytes(spk[2:]).startswith(protocol.TAG)


class ChainIndexer:
    def __init__(self, path, provider, network, genesis, activation_height,
                 max_blocks_per_sync=DEFAULT_MAX_BLOCKS):
        if type(activation_height) is not int or activation_height < 0:
            raise ValueError("A non-negative activation height is required for chain indexing")
        if type(max_blocks_per_sync) is not int or not 1 <= max_blocks_per_sync <= MAX_BLOCKS_PER_SYNC:
            raise ValueError(f"max_blocks_per_sync must be in 1..{MAX_BLOCKS_PER_SYNC}")
        self.store = ChainStore(path)
        self.provider = provider
        self.network, self.genesis = network, genesis
        self.activation_height = activation_height
        self.max_blocks_per_sync = max_blocks_per_sync
        self._replay_lock = threading.RLock()

    def status(self):
        stored = self.store.status()
        return {**stored, "configured_network": self.network,
                "configured_genesis": self.genesis,
                "configured_activation_height": self.activation_height,
                "max_blocks_per_sync": self.max_blocks_per_sync,
                "identity_ok": self._identity_ok(stored)}

    def ready(self):
        meta = self.store.meta()
        return self._identity_ok(meta) and meta.get("last_sync", 0) > 0

    def _identity_ok(self, meta):
        return (bool(meta) and meta.get("network") == self.network
                and meta.get("genesis") == self.genesis
                and meta.get("activation_height") == self.activation_height)

    def _reset(self, meta=None):
        deep = (meta or {}).get("deep_reorgs", 0)
        if meta:
            deep += 1
        self.store.reset(self.network, self.genesis, self.activation_height, deep_reorgs=deep)

    def _rollback_to_tip(self, cursor, tip):
        while cursor > tip:
            if self.store.block(cursor) is None:
                self._reset(self.store.meta())
                return self.activation_height - 1
            cursor = self.store.rollback(cursor)
        return cursor

    def _verify_cursor(self, cursor):
        while cursor >= self.activation_height:
            stored = self.store.block(cursor)
            if stored is None:
                self._reset(self.store.meta())
                return self.activation_height - 1, None
            current = self.provider.block_hash(cursor)
            if current == stored["hash"]:
                return cursor, current
            cursor = self.store.rollback(cursor)
        return self.activation_height - 1, None

    def _download(self, height):
        node_hash = self.provider.block_hash(height)
        return height, node_hash, self.provider.raw_block(node_hash)

    def sync(self, max_blocks=None):
        with self._replay_lock:
            return self._sync(max_blocks)

    def _sync(self, max_blocks=None):
        maximum = self.max_blocks_per_sync if max_blocks is None else max_blocks
        if type(maximum) is not int or not 1 <= maximum <= MAX_BLOCKS_PER_SYNC:
            raise ValueError(f"max_blocks must be in 1..{MAX_BLOCKS_PER_SYNC}")
        self.provider.check_network()
        tip = self.provider.tip_height()
        meta = self.store.meta()
        if not meta or not self._identity_ok(meta):
            self._reset(meta)
            meta = self.store.meta()
        cursor = meta["tip_height"]
        if type(cursor) is not int:
            raise ValueError("Chain index metadata is corrupt")
        applied = 0
        verified = None
        if cursor > tip:
            cursor = self._rollback_to_tip(cursor, tip)
        else:
            cursor, verified = self._verify_cursor(cursor)
        if cursor < self.activation_height - 1:
            self._reset(meta)
            cursor = self.activation_height - 1
            verified = None
        target = min(tip, cursor + maximum)
        expected_prev = None
        if target > cursor:
            if cursor >= self.activation_height:
                expected_prev = verified or self.provider.block_hash(cursor)
            elif self.activation_height:
                expected_prev = self.provider.block_hash(self.activation_height - 1)
        heights = list(range(cursor + 1, target + 1))
        tracked = self.store.candidate_txids() if heights else set()
        if heights:
            with ThreadPoolExecutor(max_workers=min(4, len(heights))) as pool:
                for start in range(0, len(heights), 4):
                    for height, node_hash, raw in pool.map(self._download, heights[start:start + 4]):
                        try:
                            if len(raw) > 4000000:
                                raise ValueError('Block exceeds the serialized consensus-size ceiling')
                            count, _ = btc.read_compact(raw, 80)
                            if not 1 <= count <= 100000:
                                raise ValueError('Invalid block transaction count')
                            block = btc.parse_block(raw)
                            validate_block(raw, block)
                        except (ValueError, IndexError) as exc:
                            raise ProviderUnavailable("Invalid raw block") from exc
                        if block["hash"] != node_hash:
                            raise ProviderUnavailable("Raw block hash does not match the active chain")
                        if expected_prev and block["prev"] != expected_prev:
                            raise ProviderUnavailable("Block chain changed during sync; retry")
                        candidates = []
                        for position, tx in enumerate(block["txs"]):
                            if not any(_is_btap_output(output.get("spk", b"")) for output in tx["vout"]):
                                continue
                            candidates.append({"position": position, "txid": tx["txid"],
                                               "raw": btc.serialize_tx(tx).hex()})
                        spends = _spends(block["txs"], tracked)
                        self.store.apply(height, node_hash, block["prev"], candidates, spends)
                        expected_prev = node_hash
                        cursor, applied = height, applied + 1
        caught_up = cursor >= tip
        if applied and cursor >= self.activation_height:
            if self.provider.block_hash(cursor) != self.store.block_hash(cursor):
                caught_up = False
        self.store.finish_sync(cursor, self.store.block_hash(cursor) or "", caught_up)
        return {**self.status(), "applied": applied, "caught_up": caught_up, "tip": tip}

    def backfill_spends(self, max_blocks=None):
        maximum = self.max_blocks_per_sync if max_blocks is None else max_blocks
        with self._replay_lock:
            gap = self.store.meta().get("spend_gap")
            if not gap:
                return {"backfilled": 0, "remaining": 0}
            start, end = gap
            stop = min(end, start + maximum - 1)
            tracked = self.store.candidate_txids()
            for height in range(start, stop + 1):
                stored = self.store.block(height)
                if stored is None:
                    continue
                try:
                    block = btc.parse_block(self.provider.raw_block(stored["hash"]))
                except (ValueError, IndexError) as exc:
                    raise ProviderUnavailable("Invalid raw block") from exc
                if block["hash"] != stored["hash"]:
                    raise ProviderUnavailable("Raw block hash does not match the index")
                self.store.add_spends(height, stored["hash"], _spends(block["txs"], tracked))
            self.store.set_spend_gap([stop + 1, end] if stop < end else None)
            return {"backfilled": stop - start + 1, "remaining": max(0, end - stop)}

    def rebuild(self, max_blocks=None):
        with self._replay_lock:
            self._reset(self.store.meta())
            return self._sync(max_blocks)

    def _ensure_replay(self, fee_script, ticket_public_key, protocol_fee, max_candidates=None, policy=None):
        config = (bytes(fee_script).hex(), str(ticket_public_key), int(protocol_fee), policy.digest.hex() if policy else None)
        if self.store.replay_config() != config:
            self.store.clear_replay()
            self.store.set_replay_config(*config)
        next_serial = self.store.replay_serial()
        pool_counts = self.store.pool_counts()
        processed = 0
        while max_candidates is None or processed < max_candidates:
            amount = REPLAY_BATCH_ITEMS if max_candidates is None else min(REPLAY_BATCH_ITEMS, max_candidates-processed)
            chunk = self.store.pending_candidates(amount)
            if not chunk:
                break
            processed += len(chunk)
            by_txid = {key["txid"]: key for key in chunk}
            items, rejected = [], []
            for key in chunk:
                raw = key.get("raw")
                if raw is None:
                    rejected.append({**key, "reason": "Candidate transaction is missing or too large"})
                    continue
                try:
                    if len(raw) // 2 > constants.MAX_RAW_BYTES:
                        raise ValueError("Candidate transaction is too large")
                    tx = parse(raw)
                    if tx["txid"] != key["txid"]:
                        raise ValueError("Candidate transaction ID mismatch")
                    items.append({"tx": tx, "height": key["height"],
                                  "position": key["position"], "txid": key["txid"]})
                except ValueError as exc:
                    rejected.append({**key, "reason": str(exc)})
            ticket_ids = set()
            for item in items:
                outputs = item['tx']['vout']
                if len(outputs) not in (2, 3):
                    continue
                try:
                    record = protocol.decode_script(outputs[-1].get('spk', b''))
                except ValueError:
                    continue
                if record and record['type'] == 'mint':
                    ticket_ids.add(record['ticket_id'].hex())
            used = self.store.used_ticket_subset(ticket_ids)
            replayed = protocol.replay(items, ticket_public_key, fee_script, protocol_fee,
                                    used_tickets=used, serial_start=next_serial, genesis=self.genesis, policy=policy, pool_counts=pool_counts)
            txs = {item["txid"]: item["tx"] for item in items}
            accepted, used_tickets = [], []
            for entry in replayed["accepted"]:
                key = by_txid[entry["txid"]]
                used_tickets.append((entry["ticket_id"], entry["txid"]))
                try:
                    definition = entry.get("definition") or compile_design(json.loads(entry["body"].decode()))
                except (ValueError, TypeError, KeyError, UnicodeDecodeError) as exc:
                    rejected.append({**key, "reason": "Invalid Bitcointapes definition: " + str(exc)})
                    continue
                next_serial += 1
                pool_counts[entry["pool"]] = pool_counts.get(entry["pool"], 0) + 1
                accepted.append({
                    "txid": entry["txid"], "height": key["height"],
                    "position": key["position"], "block_hash": key["block_hash"],
                    "serial": next_serial, "ticket_id": entry["ticket_id"], "pool": entry["pool"],
                    "recipient": _recipient(txs[entry["txid"]]),
                    "entry": json.dumps({
                        "serial": next_serial,
                        "inscription_id": entry["inscription_id"],
                        "pool": entry["pool"], "ticket_id": entry["ticket_id"],
                        "definition": definition,
                        "confirmation": {"block_height": key["height"],
                                         "block_hash": key["block_hash"],
                                         "chain_position": key["position"]}})})
            for item in replayed["rejected"]:
                key = by_txid.get(item.get("txid"))
                if key is not None:
                    rejected.append({**key, "reason": item["reason"]})
            self.store.append_replay(accepted, rejected, used_tickets, next_serial)
        return processed

    def advance_replay(self, fee_script, ticket_public_key, protocol_fee, max_candidates=REPLAY_BATCH_ITEMS, *, policy=None):
        if type(max_candidates) is not int or not 1 <= max_candidates <= REPLAY_BATCH_ITEMS:
            raise ValueError(f'Replay task must contain 1..{REPLAY_BATCH_ITEMS} candidates')
        with self._replay_lock:
            processed = self._ensure_replay(fee_script, ticket_public_key, protocol_fee, max_candidates, policy)
            return {'processed': processed, 'pending': self.store.replay_pending_count()}

    def collection(self, fee_script, ticket_public_key, protocol_fee, offset=0,
                   limit=constants.MAX_PAGE_ITEMS, *, advance=True, policy=None):
        if type(offset) is not int or offset < 0:
            raise ValueError('Invalid collection offset')
        if type(limit) is not int or not 1 <= limit <= constants.MAX_PAGE_ITEMS:
            raise ValueError(f'Collection limit must be between 1 and {constants.MAX_PAGE_ITEMS}')
        if advance:
            with self._replay_lock:
                self._ensure_replay(fee_script, ticket_public_key, protocol_fee, policy=policy)
        with contextlib.closing(self.store.connect()) as db:
            db.execute('BEGIN')
            meta = {row['key']: json.loads(row['value']) for row in db.execute('SELECT key,value FROM chain_meta')}
            if (meta.get('replay_fee_script'), meta.get('replay_ticket_public_key'),
                    meta.get('replay_protocol_fee'), meta.get('replay_policy_hash')) != (
                    bytes(fee_script).hex(), str(ticket_public_key), int(protocol_fee), policy.digest.hex() if policy else None):
                return {'items': [], 'total': 0, 'next_offset': None, 'verified': False,
                        'caught_up': False, 'reason': 'Index is awaiting replay for this public policy'}
            total = db.execute("SELECT COUNT(*) FROM chain_replay WHERE status='accepted'").fetchone()[0]
            pool_counts = dict(db.execute("SELECT pool,COUNT(*) FROM chain_replay WHERE status='accepted' GROUP BY pool"))
            items = [json.loads(row[0]) for row in db.execute("SELECT entry FROM chain_replay WHERE status='accepted' ORDER BY serial LIMIT ? OFFSET ?", (limit, offset))]
            rejected = [dict(row) for row in db.execute("SELECT txid,height,reason FROM chain_replay WHERE status='rejected' ORDER BY height,position LIMIT ?", (MAX_REJECT_ITEMS,))]
            rejected_total = db.execute("SELECT COUNT(*) FROM chain_replay WHERE status='rejected'").fetchone()[0]
            scanned = db.execute('SELECT COUNT(*) FROM chain_candidates').fetchone()[0]
            tail = db.execute('SELECT height,position FROM chain_replay ORDER BY height DESC,position DESC LIMIT 1').fetchone()
            pending = db.execute('SELECT COUNT(*) FROM chain_candidates WHERE (height,position)>(?,?)', tuple(tail) if tail else (-1,-1)).fetchone()[0]
        return {'items': items, 'rejected': rejected,
                'scanned': scanned, 'network_requests': 0,
                'max_items': constants.MAX_PAGE_ITEMS,
                'rejected_total': rejected_total, 'rejected_truncated': rejected_total > len(rejected),
                'ordered_by': 'block-height,chain-position,txid',
                'pool_counts': pool_counts, 'policy_hash': meta.get('replay_policy_hash'),
                'total': total, 'offset': offset, 'limit': limit,
                'next_offset': offset+limit if offset+limit < total else None,
                'source': 'chain-rebuild', 'verified': True,
                'caught_up': bool(meta.get('caught_up')) and pending == 0,
                'chain_caught_up': bool(meta.get('caught_up')), 'replay_pending': pending,
                'tip_height': meta.get('tip_height')}
