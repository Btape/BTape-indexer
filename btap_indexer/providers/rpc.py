import http.client
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from btap_indexer.transactions import parse

from . import ProviderRateLimited, ProviderUnavailable, RequestBudget

HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_BLOCKS = 10000000


class ProviderRejection(ValueError):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class RPCError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def _error_message(raw, limit):
    try:
        payload = json.loads(raw[:limit].decode())
    except (UnicodeDecodeError, ValueError):
        return None
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict) and type(error.get("code")) is int:
        return RPCError(error["code"], str(error.get("message") or "rejected")[:240])
    return None


class BitcoinRPC:

    def __init__(self, url, genesis, confirmations=1, budget_per_hour=None, burst=15,
                 check_ttl=600, rest_after=900, failure_rest=60, timeout=30):
        self.url = url.rstrip("/") + "/"
        self.genesis, self.confirmations = genesis, confirmations
        self.budget = RequestBudget(budget_per_hour, burst) if budget_per_hour else None
        self.check_ttl = max(0, check_ttl)
        self.rest_after, self.failure_rest, self.timeout = rest_after, failure_rest, timeout
        self._network_lock = threading.Lock()
        self._network_ok_until = 0.0
        self._txids = {}

    def _rpc(self, method, params=(), limit=4000000, priority=False):
        if self.budget:
            self.budget.take(bypass=priority)
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": list(params)}).encode()
        request = urllib.request.Request(self.url, data=body, headers={
            "Content-Type": "application/json", "Accept": "application/json",
            "User-Agent": "Bitcointapes/0.1"})
        local = urllib.parse.urlsplit(self.url).hostname in ("127.0.0.1", "localhost", "::1")
        try:
            opener = (urllib.request.build_opener(urllib.request.ProxyHandler({}))
                      if local else urllib.request.build_opener())
            with opener.open(request, timeout=self.timeout) as response:
                raw = response.read(limit + 1)
                if len(raw) > limit:
                    raise ProviderUnavailable("RPC response too large")
        except urllib.error.HTTPError as exc:
            retry_after = None
            try:
                retry_after = float(exc.headers.get("Retry-After") or 0) or None
            except (AttributeError, TypeError, ValueError):
                pass
            if exc.code == 429:
                raise ProviderRateLimited("Bitcoin RPC rate limited",
                                          retry_after=retry_after or self.rest_after) from exc
            raw = b""
            try:
                raw = exc.read(limit + 1)
            except OSError:
                pass
            error = None if exc.code in (401, 403, 404, 405) else _error_message(raw, limit)
            if error is not None:
                raise error from exc
            raise ProviderUnavailable("Bitcoin RPC unavailable",
                                      retry_after=self.failure_rest) from exc
        except OSError as exc:
            raise ProviderUnavailable("Bitcoin RPC unavailable",
                                      retry_after=self.failure_rest) from exc
        except http.client.HTTPException as exc:
            raise ProviderUnavailable("Bitcoin RPC response was truncated",
                                      retry_after=self.failure_rest) from exc
        except ValueError as exc:
            raise ProviderUnavailable("Bitcoin RPC unavailable",
                                      retry_after=self.failure_rest) from exc
        try:
            payload = json.loads(raw.decode())
        except (UnicodeDecodeError, ValueError) as exc:
            raise ProviderUnavailable("Bitcoin RPC sent an invalid response",
                                      retry_after=self.failure_rest) from exc
        if not isinstance(payload, dict):
            raise ProviderUnavailable("Bitcoin RPC sent an invalid response")
        error = payload.get("error")
        if isinstance(error, dict) and type(error.get("code")) is int:
            raise RPCError(error["code"], str(error.get("message") or "rejected")[:240])
        if "result" not in payload:
            raise ProviderUnavailable("Bitcoin RPC response is missing its result")
        return payload["result"]

    def _read_error(self, error, message="Bitcoin RPC rejected the request"):
        if error.code == -5:
            raise ProviderUnavailable("Transaction not found") from None
        if error.code == -28:
            raise ProviderUnavailable("Bitcoin node is warming up",
                                      retry_after=self.failure_rest) from None
        raise ProviderUnavailable(message) from None

    def check_network(self):
        with self._network_lock:
            if time.monotonic() < self._network_ok_until:
                return
            if not HEX64.fullmatch(self.genesis or ""):
                raise ProviderUnavailable("Expected genesis hash is not configured")
            try:
                genesis = self._rpc("getblockhash", [0])
            except RPCError as exc:
                self._read_error(exc, "Bitcoin RPC network probe failed")
            if genesis != self.genesis:
                raise ProviderUnavailable("Bitcoin RPC network mismatch",
                                          retry_after=self.rest_after)
            self._network_ok_until = time.monotonic() + self.check_ttl

    def fees(self):
        def rate(target):
            try:
                result = self._rpc("estimatesmartfee", [target])
            except RPCError as exc:
                self._read_error(exc, "Bitcoin RPC fee estimate failed")
            feerate = result.get("feerate") if isinstance(result, dict) else None
            if type(feerate) not in (int, float) or feerate <= 0:
                raise ProviderUnavailable("Invalid fee estimate")
            return max(1, min(500, round(feerate * 1e8 / 1000)))
        return {"hourFee": rate(6), "halfHourFee": rate(3), "fastestFee": rate(1)}

    def raw(self, txid):
        if not HEX64.fullmatch(txid or ""):
            raise ValueError("Invalid transaction ID")
        try:
            raw = self._rpc("getrawtransaction", [txid])
        except RPCError as exc:
            self._read_error(exc)
        if not isinstance(raw, str) or not raw:
            raise ProviderUnavailable("Invalid transaction bytes")
        if parse(raw)["txid"] != txid:
            raise ProviderUnavailable("Raw transaction ID mismatch")
        return raw

    def status(self, txid):
        if not HEX64.fullmatch(txid or ""):
            raise ValueError("Invalid transaction ID")
        try:
            tx = self._rpc("getrawtransaction", [txid, True])
        except RPCError as exc:
            self._read_error(exc)
        if not isinstance(tx, dict) or tx.get("txid") != txid:
            raise ProviderUnavailable("Invalid transaction status")
        if type(tx.get("confirmations")) is not int or tx["confirmations"] < 1:
            return {"txid": txid, "confirmed": False, "confirmations": 0}
        block_hash = tx.get("blockhash")
        if not HEX64.fullmatch(block_hash or ""):
            raise ProviderUnavailable("Invalid block identity")
        try:
            header = self._rpc("getblockheader", [block_hash])
        except RPCError as exc:
            self._read_error(exc, "Bitcoin RPC block header failed")
        if not isinstance(header, dict):
            raise ProviderUnavailable("Invalid block header")
        height, confirmations = header.get("height"), header.get("confirmations")
        if type(height) is not int or height < 0 or type(confirmations) is not int or confirmations < 1:
            return {"txid": txid, "confirmed": False, "confirmations": 0}
        return {"txid": txid, "confirmed": True, "block_hash": block_hash,
                "block_height": height, "block_time": tx.get("blocktime"),
                "confirmations": confirmations}

    def tx_position(self, txid, block_hash):
        if not HEX64.fullmatch(txid or "") or not HEX64.fullmatch(block_hash or ""):
            raise ValueError("Invalid transaction or block hash")
        if block_hash not in self._txids:
            try:
                block = self._rpc("getblock", [block_hash, 1], limit=8000000)
            except RPCError as exc:
                self._read_error(exc, "Bitcoin RPC block lookup failed")
            txids = block.get("tx") if isinstance(block, dict) else None
            if not isinstance(txids, list) or len(txids) > 100000:
                raise ProviderUnavailable("Invalid block transaction list")
            if any(not isinstance(item, str) or not HEX64.fullmatch(item) for item in txids):
                raise ProviderUnavailable("Invalid block transaction list")
            if len(self._txids) >= 8:
                self._txids.clear()
            self._txids[block_hash] = txids
        try:
            return self._txids[block_hash].index(txid)
        except ValueError:
            raise ProviderUnavailable("Reveal transaction is not in the confirmed block") from None

    def broadcast(self, raw):
        self.check_network()
        expected = parse(raw)["txid"]
        try:
            txid = self._rpc("sendrawtransaction", [raw], priority=True)
        except RPCError as exc:
            message = exc.message.lower()
            if exc.code == -27 or "already in block chain" in message:
                return expected
            if exc.code == -26 and re.search(r"already[- ]in[- ]mempool", message):
                return expected
            if exc.code == -28 or "work queue depth" in message or "loading block index" in message:
                raise ProviderUnavailable("Bitcoin node is warming up",
                                          retry_after=self.failure_rest) from None
            raise ProviderRejection(f"Bitcoin node rejected the transaction: {exc.message}",
                                    exc.code) from None
        if txid != expected:
            raise ProviderUnavailable("Broadcast response mismatch; query before retrying")
        return txid

    def unspent(self, txid, vout):
        if not HEX64.fullmatch(txid or "") or type(vout) is not int or vout < 0:
            raise ValueError("Invalid transaction output")
        try:
            result = self._rpc("gettxout", [txid, vout, True])
        except RPCError as exc:
            self._read_error(exc, "Bitcoin RPC UTXO lookup failed")
        return result is not None

    def tip_height(self):
        try:
            value = self._rpc("getblockcount")
        except RPCError as exc:
            self._read_error(exc, "Bitcoin RPC tip lookup failed")
        if type(value) is not int or not 0 <= value <= MAX_BLOCKS:
            raise ProviderUnavailable("Invalid chain tip height")
        return max(-1, value - self.confirmations + 1)

    def tip_hash(self):
        try:
            value = self._rpc("getbestblockhash")
        except RPCError as exc:
            self._read_error(exc, "Bitcoin RPC tip lookup failed")
        if not HEX64.fullmatch(value or ""):
            raise ProviderUnavailable("Invalid chain tip hash")
        return value

    def block_hash(self, height):
        if type(height) is not int or not 0 <= height <= MAX_BLOCKS:
            raise ValueError("Invalid block height")
        try:
            value = self._rpc("getblockhash", [height])
        except RPCError as exc:
            self._read_error(exc, "Block height is not available")
        if not HEX64.fullmatch(value or ""):
            raise ProviderUnavailable("Invalid block hash")
        return value

    def raw_block(self, block_hash):
        if not HEX64.fullmatch(block_hash or ""):
            raise ValueError("Invalid block hash")
        try:
            value = self._rpc("getblock", [block_hash, 0], limit=8000001)
        except RPCError as exc:
            self._read_error(exc, "Bitcoin RPC block download failed")
        if not isinstance(value, str):
            raise ProviderUnavailable("Invalid raw block")
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            raise ProviderUnavailable("Invalid raw block") from None
        if len(raw) < 81:
            raise ProviderUnavailable("Raw block is too short")
        return raw

    def source_status(self):
        return {"active": 0, "sources": [{"index": 0, "base": "bitcoin-rpc", "resting_for": 0}]}


class ChainPool:

    raw_cache_ttl = 300.0
    unspent_cache_ttl = 20.0

    def __init__(self, primary, fallback=None, minimum_cooldown=30, maximum_cooldown=3600):
        self.primary, self.fallback = primary, fallback
        self.minimum_cooldown, self.maximum_cooldown = minimum_cooldown, maximum_cooldown
        self._resting_until = 0.0
        self._active = 0
        self._lock = threading.Lock()
        self._raw_cache = {}
        self._unspent_cache = {}

    def _cached(self, cache, key, ttl, fetch):
        entry = cache.get(key)
        if entry and entry[0] > time.monotonic():
            return entry[1]
        value = fetch()
        if len(cache) > 4096:
            cache.clear()
        cache[key] = (time.monotonic() + ttl, value)
        return value

    @property
    def active(self):
        return self._active

    def _rest(self, error):
        delay = max(self.minimum_cooldown, min(float(error.retry_after), self.maximum_cooldown))
        with self._lock:
            self._resting_until = time.monotonic() + delay

    def _call(self, name, *args, **kwargs):
        error = None
        if self.primary is not None:
            with self._lock:
                resting = self._resting_until > time.monotonic()
            if not resting:
                try:
                    result = getattr(self.primary, name)(*args, **kwargs)
                    with self._lock:
                        self._resting_until = 0.0
                        self._active = 0
                    return result
                except ProviderUnavailable as exc:
                    if exc.retry_after is not None:
                        self._rest(exc)
                    error = exc
        if self.fallback is not None:
            try:
                result = getattr(self.fallback, name)(*args, **kwargs)
                with self._lock:
                    self._active = 1
                return result
            except ProviderUnavailable as exc:
                error = exc
        raise error or ProviderUnavailable("No chain source is configured")

    def check_network(self):
        return self._call("check_network")

    def fees(self):
        return self._call("fees")

    def raw(self, txid):
        return self._cached(self._raw_cache, txid, self.raw_cache_ttl,
                            lambda: self._call("raw", txid))

    def status(self, txid):
        return self._call("status", txid)

    def tx_position(self, txid, block_hash):
        return self._call("tx_position", txid, block_hash)

    def broadcast(self, raw):
        return self._call("broadcast", raw)

    def unspent(self, txid, vout):
        return self._cached(self._unspent_cache, (txid, vout), self.unspent_cache_ttl,
                            lambda: self._call("unspent", txid, vout))

    def tip_height(self):
        return self._call("tip_height")

    def tip_hash(self):
        return self._call("tip_hash")

    def block_hash(self, height):
        return self._call("block_hash", height)

    def raw_block(self, block_hash):
        return self._call("raw_block", block_hash)

    def source_status(self):
        now = time.monotonic()
        sources = [{"index": 0, "base": "bitcoin-rpc",
                    "resting_for": max(0, round(self._resting_until - now))}]
        active = self._active
        if self.fallback is not None and hasattr(self.fallback, "source_status"):
            fallback = self.fallback.source_status()
            for source in fallback["sources"]:
                sources.append({**source, "index": len(sources)})
            if self._active == 1:
                active = 1 + fallback.get("active", 0)
        return {"active": active, "sources": sources}
