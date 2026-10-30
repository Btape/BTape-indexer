import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from btap_indexer.policy import from_settings as collection_policy
from btap_indexer.providers import EsploraPool, Mempool
from btap_indexer.providers.networks import MAINNET, SIGNET
from btap_indexer.providers.rpc import BitcoinRPC, ChainPool

HEX64 = re.compile(r"^[0-9a-f]{64}$")
POLICY_V2 = {"supply": 10000, "wallet_limit": 5, "ip_limit": 5}
POLICY_V3 = {"supply": 5000, "free_supply": 1000, "paid_supply": 4000,
             "protocol_fee": 3250, "wallet_limit": 1, "ip_limit": 1}


class ConfirmedMempool(Mempool):
    def __init__(self, base, genesis, confirmations, budget_per_hour=None, burst=20,
                 check_ttl=600, rest_after=900):
        super().__init__(base, genesis, budget_per_hour, burst, check_ttl, rest_after)
        self.confirmations = confirmations

    def tip_height(self):
        return max(-1, super().tip_height() - self.confirmations + 1)


def _check_url(key, url):
    parts = urlsplit(url)
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")):
        raise ValueError(key + " must use HTTPS (HTTP allowed on loopback only)")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(key + " must not embed credentials, query or fragment")


def _env_int(name, fallback):
    raw = os.getenv(name)
    if raw is None:
        return fallback
    try:
        return int(raw)
    except ValueError:
        raise ValueError(name + " must be an integer") from None


def read_settings(path):
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError("Configuration must be a JSON object")
    network = value.get("network")
    if network not in ("mainnet", "signet"):
        raise ValueError("network must be mainnet or signet")
    base = MAINNET if network == "mainnet" else SIGNET
    value["network"] = network
    value["genesis"] = base["genesis"]
    value.setdefault("mempool_url", base["mempool_url"])
    version = value.get("protocol_version", 2)
    if type(version) is not int or version not in (2, 3):
        raise ValueError("protocol_version must be 2 or 3")
    expected = POLICY_V2 if version == 2 else POLICY_V3
    if any(type(value.get(k)) is not int or value[k] != v for k, v in expected.items()):
        raise ValueError("Collection policy mismatch: " + json.dumps(expected, sort_keys=True))
    if version == 3 and (type(value.get("postage", 330)) is not int or value.get("postage", 330) != 330):
        raise ValueError("v3 postage must be exactly 330 sats")
    if type(value.get("postage", 330)) is not int or value.get("postage", 330) < 330:
        raise ValueError("postage must be at least 330 sats")
    _check_url("mempool_url", value["mempool_url"])
    backups = value.get("mempool_backup_urls")
    if backups is None:
        backups = [url for url in base.get("mempool_backup_urls", [])
                   if url and url != value["mempool_url"]]
    if not isinstance(backups, list) or len(backups) > 4:
        raise ValueError("mempool_backup_urls must be a list of at most 4 URLs")
    for url in backups:
        if not isinstance(url, str) or not url:
            raise ValueError("mempool_backup_urls must be a list of URLs")
        _check_url("mempool_backup_urls", url)
    value["mempool_backup_urls"] = [url for url in dict.fromkeys(backups)
                                    if url != value["mempool_url"]]
    activation = value.get("activation_height")
    if type(activation) is not int or activation < 0:
        raise ValueError("activation_height must be a non-negative integer")
    confirmations = value.get("confirmations", 1)
    if type(confirmations) is not int or confirmations != 1:
        raise ValueError("confirmations must be 1")
    value["confirmations"] = confirmations
    interval = value.get("sync_interval_seconds", 30)
    if type(interval) is not int or not 1 <= interval <= 60:
        raise ValueError("sync_interval_seconds must be in 1..60")
    value["sync_interval_seconds"] = interval
    maximum = value.get("max_blocks_per_sync", 10)
    if type(maximum) is not int or not 1 <= maximum <= 1000:
        raise ValueError("max_blocks_per_sync must be in 1..1000")
    value["max_blocks_per_sync"] = maximum
    budget = value.get("provider_budget_per_hour", 650)
    if type(budget) is not int or not 100 <= budget <= 680:
        raise ValueError("provider_budget_per_hour must be in 100..680")
    value["provider_budget_per_hour"] = budget
    burst = value.get("provider_burst", 20)
    if type(burst) is not int or not 1 <= burst <= 100:
        raise ValueError("provider_burst must be in 1..100")
    value["provider_burst"] = burst
    ttl = value.get("provider_check_ttl_seconds", 600)
    if type(ttl) is not int or not 0 <= ttl <= 3600:
        raise ValueError("provider_check_ttl_seconds must be in 0..3600")
    value["provider_check_ttl_seconds"] = ttl
    cooldown = value.get("provider_cooldown_seconds", 900)
    if type(cooldown) is not int or not 60 <= cooldown <= 3600:
        raise ValueError("provider_cooldown_seconds must be in 60..3600")
    value["provider_cooldown_seconds"] = cooldown
    rpc_url = os.getenv("BITCOINTAPES_MEMPOOL_RPC_URL") or value.get("mempool_rpc_url", "")
    if not isinstance(rpc_url, str):
        raise ValueError("mempool_rpc_url must be a string")
    if rpc_url:
        _check_url("mempool_rpc_url", rpc_url)
    value["mempool_rpc_url"] = rpc_url
    rpc_budget = _env_int("BITCOINTAPES_MEMPOOL_RPC_BUDGET_PER_HOUR",
                          value.get("mempool_rpc_budget_per_hour", 1500))
    if type(rpc_budget) is not int or not 1 <= rpc_budget <= 100000:
        raise ValueError("mempool_rpc_budget_per_hour must be in 1..100000")
    value["mempool_rpc_budget_per_hour"] = rpc_budget
    rpc_burst = _env_int("BITCOINTAPES_MEMPOOL_RPC_BURST", value.get("mempool_rpc_burst", 15))
    if type(rpc_burst) is not int or not 1 <= rpc_burst <= 1000:
        raise ValueError("mempool_rpc_burst must be in 1..1000")
    value["mempool_rpc_burst"] = rpc_burst
    database = value.get("database")
    if database is not None:
        if not isinstance(database, str) or not database:
            raise ValueError("database must be a non-empty string")
        target = Path(database)
        if not target.is_absolute():
            target = Path(path).resolve().parent / target
        value["database"] = str(target.resolve())
    key = value.get("ticket_public_key", "")
    if not isinstance(key, str) or not HEX64.fullmatch(key):
        raise ValueError("ticket_public_key must be a 32-byte hex public key")
    policy = collection_policy(value)
    if policy is not None and not policy.fee_script:
        raise ValueError("v3 policy requires a valid fee_address")
    return value


def esplora_provider(settings):
    urls = [settings["mempool_url"], *settings.get("mempool_backup_urls", [])]
    return EsploraPool(
        [ConfirmedMempool(url, settings["genesis"], settings["confirmations"],
                          budget_per_hour=settings.get("provider_budget_per_hour", 650),
                          burst=settings.get("provider_burst", 20),
                          check_ttl=settings.get("provider_check_ttl_seconds", 600),
                          rest_after=settings.get("provider_cooldown_seconds", 900))
         for url in urls])


def bitcoin_provider(settings, esplora=None):
    esplora = esplora or esplora_provider(settings)
    url = settings.get("mempool_rpc_url", "")
    if not url:
        return esplora
    return ChainPool(BitcoinRPC(
        url, settings["genesis"], settings["confirmations"],
        budget_per_hour=settings.get("mempool_rpc_budget_per_hour", 1500),
        burst=settings.get("mempool_rpc_burst", 15),
        check_ttl=settings.get("provider_check_ttl_seconds", 600)), esplora)
