import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from btap_indexer.transactions import parse

HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ProviderUnavailable(RuntimeError):
    def __init__(self, message, retry_after=None, status=None):
        super().__init__(message)
        self.retry_after = retry_after
        self.status = status


class ProviderRateLimited(ProviderUnavailable):
    pass


class ProviderNotFound(ProviderUnavailable):
    def __init__(self, message="External API reports the object is not found", status=404):
        super().__init__(message, status=status)


class RequestBudget:
    def __init__(self, per_hour, burst=20, max_wait=30.0, max_waiters=8):
        if type(per_hour) is not int or not 1 <= per_hour <= 100000:
            raise ValueError("per_hour must be a positive integer")
        if type(burst) is not int or not 1 <= burst <= 10000:
            raise ValueError("burst must be a positive integer")
        if max_wait is not None and (type(max_wait) not in (int, float) or max_wait <= 0):
            raise ValueError("max_wait must be a positive number or None")
        if type(max_waiters) is not int or max_waiters < 1:
            raise ValueError("max_waiters must be a positive integer")
        self.rate = per_hour / 3600.0
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self.lock = threading.Lock()
        self.max_wait = max_wait
        self.max_waiters = max_waiters
        self.waiters = 0

    def take(self, bypass=False):
        if bypass:
            return
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            if self.waiters >= self.max_waiters:
                raise ProviderRateLimited("Provider is busy; retry shortly", retry_after=1)
            self.waiters += 1
        deadline = time.monotonic() + self.max_wait if self.max_wait else None
        try:
            while True:
                with self.lock:
                    now = time.monotonic()
                    self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                    self.updated = now
                    if self.tokens >= 1.0:
                        self.tokens -= 1.0
                        return
                    wait = (1.0 - self.tokens) / self.rate
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProviderRateLimited("Request budget unavailable; retry shortly",
                                                  retry_after=max(1, int(wait) + 1))
                    wait = min(wait, remaining)
                time.sleep(min(wait, 5.0))
        finally:
            with self.lock:
                self.waiters -= 1


class HTTP:
    token_header = 'Authorization'
    token_prefix = 'Bearer '
    def __init__(self, base, token=None, budget=None, rest_after=900, failure_rest=60,
                 rate_limit_pause=5.0):
        self.base, self.token, self.budget = base.rstrip("/"), token, budget
        self.rest_after, self.failure_rest = rest_after, failure_rest
        self.rate_limit_pause = rate_limit_pause
        self._blocked_until = 0.0

    def request(self, path, body=None, text=False, priority=False):
        raw = self.request_bytes(path, body, limit=2000000, priority=priority)
        try:
            value = raw.decode()
            return value.strip() if text else json.loads(value)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ProviderUnavailable("External API unavailable or invalid response",
                                      retry_after=self.failure_rest) from exc

    def request_bytes(self, path, body=None, limit=2000000, priority=False):
        if not self.base:
            raise ProviderUnavailable("External API is not configured")
        headers = {"Accept": "application/json", "User-Agent": "Bitcointapes/0.1"}
        if self.token:
            headers[self.token_header] = self.token_prefix + self.token
        if body is not None:
            headers["Content-Type"] = "text/plain"
        req = urllib.request.Request(self.base + path, data=body.encode() if body is not None else None, headers=headers)
        local = urllib.parse.urlsplit(self.base).hostname in ("127.0.0.1", "localhost", "::1")
        for attempt in (0, 1):
            pause = self._blocked_until - time.monotonic()
            if pause > 0:
                time.sleep(min(pause, self.rate_limit_pause))
            if self.budget:
                self.budget.take(bypass=priority)
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({})) if local else urllib.request.build_opener()
                with opener.open(req, timeout=30) as response:
                    raw = response.read(limit + 1)
                    if len(raw) > limit:
                        raise ProviderUnavailable("API response too large")
                    return raw
            except urllib.error.HTTPError as exc:
                retry_after = None
                try:
                    retry_after = float(exc.headers.get("Retry-After") or 0) or None
                except (AttributeError, TypeError, ValueError):
                    pass
                if exc.code == 429:
                    self._blocked_until = max(self._blocked_until,
                                              time.monotonic() + self.rate_limit_pause)
                    if body is None and attempt == 0:
                        continue
                    raise ProviderRateLimited("External API rate limited",
                                              retry_after=retry_after or self.rest_after, status=429) from exc
                if exc.code == 404:
                    raise ProviderNotFound(status=404) from exc
                raise ProviderUnavailable("External API unavailable or invalid response",
                                          retry_after=self.failure_rest, status=exc.code) from exc
            except OSError as exc:
                if body is None and attempt == 0:
                    continue
                raise ProviderUnavailable("External API unavailable or invalid response",
                                          retry_after=self.failure_rest) from exc
            except ValueError as exc:
                raise ProviderUnavailable("External API unavailable or invalid response",
                                          retry_after=self.failure_rest) from exc


class Mempool(HTTP):
    def __init__(self, base, genesis, budget_per_hour=None, burst=20, check_ttl=600, rest_after=900):
        super().__init__(base, budget=RequestBudget(budget_per_hour, burst) if budget_per_hour else None,
                         rest_after=rest_after)
        self.genesis, self._txids = genesis, {}
        self.check_ttl = max(0, check_ttl)
        self._network_lock = threading.Lock()
        self._network_ok_until = 0.0

    def check_network(self):
        with self._network_lock:
            if time.monotonic() < self._network_ok_until:
                return
            if not HEX64.fullmatch(self.genesis or ""):
                raise ProviderUnavailable("Expected genesis hash is not configured")
            if self.request("/block-height/0", text=True) != self.genesis:
                raise ProviderUnavailable("Bitcoin API network mismatch")
            self._network_ok_until = time.monotonic() + self.check_ttl

    def fees(self):
        self.check_network()
        fees = self.request("/v1/fees/recommended")
        if type(fees.get("hourFee")) is not int or not 1 <= fees["hourFee"] <= 500:
            raise ProviderUnavailable("Invalid fee estimate")
        return fees

    def raw(self, txid):
        if not HEX64.fullmatch(txid):
            raise ValueError("Invalid transaction ID")
        raw = self.request("/tx/" + txid + "/hex", text=True)
        if parse(raw)["txid"] != txid:
            raise ProviderUnavailable("Raw transaction ID mismatch")
        return raw

    def status(self, txid):
        if not HEX64.fullmatch(txid):
            raise ValueError("Invalid transaction ID")
        self.check_network()
        status = self.request("/tx/" + txid + "/status")
        if not status.get("confirmed"):
            return {"confirmed": False, "confirmations": 0}
        block_hash, height = status.get("block_hash"), status.get("block_height")
        if not HEX64.fullmatch(block_hash or "") or type(height) is not int or height < 0:
            raise ProviderUnavailable("Invalid block identity")
        tip = int(self.request("/blocks/tip/height", text=True))
        if self.request("/block-height/" + str(height), text=True) != block_hash:
            raise ProviderUnavailable("Transaction is not on the active chain")
        return {**status, "confirmations": max(0, tip - height + 1)}

    def tx_position(self, txid, block_hash):
        if not HEX64.fullmatch(txid or "") or not HEX64.fullmatch(block_hash or ""):
            raise ValueError("Invalid transaction or block hash")
        if block_hash not in self._txids:
            self.check_network()
            try:
                txids = json.loads(self.request_bytes("/block/" + block_hash + "/txids", limit=8000000))
            except ValueError:
                raise ProviderUnavailable("Invalid block transaction list") from None
            if not isinstance(txids, list) or len(txids) > 100000:
                raise ProviderUnavailable("Invalid block transaction list")
            if any(not isinstance(t, str) or not HEX64.fullmatch(t) for t in txids):
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
        txid = self.request("/tx", body=raw, text=True, priority=True)
        if txid != expected:
            raise ProviderUnavailable("Broadcast response mismatch; query before retrying")
        return txid

    def unspent(self, txid, vout):
        if not HEX64.fullmatch(txid or "") or type(vout) is not int or vout < 0:
            raise ValueError("Invalid transaction output")
        result = self.request(f"/tx/{txid}/outspend/{vout}")
        if not isinstance(result, dict) or type(result.get("spent")) is not bool:
            raise ProviderUnavailable("Invalid outspend response")
        return result["spent"] is False

    def tip_hash(self):
        value = self.request("/blocks/tip/hash", text=True)
        if not HEX64.fullmatch(value or ""):
            raise ProviderUnavailable("Invalid chain tip hash")
        return value

    def tip_height(self):
        value = self.request("/blocks/tip/height", text=True)
        try:
            height = int(value)
        except ValueError:
            raise ProviderUnavailable("Invalid chain tip height") from None
        if not 0 <= height <= 10000000:
            raise ProviderUnavailable("Invalid chain tip height")
        return height

    def block_hash(self, height):
        if type(height) is not int or height < 0:
            raise ValueError("Invalid block height")
        value = self.request("/block-height/" + str(height), text=True)
        if not HEX64.fullmatch(value):
            raise ProviderUnavailable("Invalid block hash")
        return value

    def raw_block(self, block_hash):
        if not HEX64.fullmatch(block_hash or ""):
            raise ValueError("Invalid block hash")
        raw = self.request_bytes("/block/" + block_hash + "/raw", limit=8000000)
        if len(raw) < 81:
            raise ProviderUnavailable("Raw block is too short")
        return raw


class EsploraPool:
    def __init__(self, providers, minimum_cooldown=30, maximum_cooldown=3600):
        if not providers:
            raise ValueError("At least one Bitcoin API is required")
        self.providers = list(providers)
        self.minimum_cooldown, self.maximum_cooldown = minimum_cooldown, maximum_cooldown
        self._resting_until = {}
        self._active = 0
        self._lock = threading.Lock()

    @property
    def active(self):
        return self._active

    def source_status(self):
        now = time.monotonic()
        with self._lock:
            return {'active': self._active,
                    'sources': [{'index': index, 'base': getattr(provider, 'base', None),
                                 'resting_for': max(0, round(self._resting_until.get(index, 0.0) - now))}
                                for index, provider in enumerate(self.providers)]}

    def _rest(self, index, retry_after):
        delay = max(self.minimum_cooldown, min(float(retry_after), self.maximum_cooldown))
        with self._lock:
            self._resting_until[index] = time.monotonic() + delay

    def _call(self, name, *args, **kwargs):
        last = None
        for index, provider in enumerate(self.providers):
            with self._lock:
                resting = self._resting_until.get(index, 0.0) > time.monotonic()
            if resting:
                continue
            try:
                result = getattr(provider, name)(*args, **kwargs)
            except ProviderUnavailable as exc:
                if exc.retry_after is not None:
                    self._rest(index, exc.retry_after)
                last = exc
                continue
            with self._lock:
                self._resting_until.pop(index, None)
                self._active = index
            return result
        raise last or ProviderUnavailable("All Bitcoin APIs are resting; retry shortly")

    def check_network(self):
        return self._call("check_network")

    def fees(self):
        return self._call("fees")

    def raw(self, txid):
        return self._call("raw", txid)

    def status(self, txid):
        return self._call("status", txid)

    def tx_position(self, txid, block_hash):
        return self._call("tx_position", txid, block_hash)

    def broadcast(self, raw):
        return self._call("broadcast", raw)

    def unspent(self, txid, vout):
        return self._call("unspent", txid, vout)

    def tip_hash(self):
        return self._call("tip_hash")

    def tip_height(self):
        return self._call("tip_height")

    def block_hash(self, height):
        return self._call("block_hash", height)

    def raw_block(self, block_hash):
        return self._call("raw_block", block_hash)

    def request(self, path, body=None, text=False):
        return self._call("request", path, body, text)

    def request_bytes(self, path, body=None, limit=2000000):
        return self._call("request_bytes", path, body, limit)
