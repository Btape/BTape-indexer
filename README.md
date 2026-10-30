# BTAP Indexer

A standalone Bitcoin indexer for the BTAP (Bitcointapes) collection. It follows the active chain from a configured activation height, stores candidate transactions from raw blocks, and replays the public BTAP rules into a local SQLite index.

The indexer does not require a local bitcoind, ord, wallet private keys, the mint service, or a user order database.

## Requirements

- Python 3.9 or newer
- No third-party Python packages

## Layout

```text
chain_index.py              command-line entry point
btap_indexer/
  chainindex.py             block sync, reorg handling, replay, pagination
  settings.py               configuration validation and provider construction
  chain_validation.py       merkle root and witness commitment checks
  protocol/                 BTAP record decoding and replay
  circuit/                  circuit definition compilation
  transactions/             transaction and address helpers
  policy.py                 public collection policy and digest
  providers/                Esplora and Bitcoin Core JSON-RPC adapters
  vendor/                   vendored UCO code and its MIT license
config/
  indexer.example.json      mainnet template
  signet.example.json       signet template
  uco.lock.json             vendored file hashes
tests/                      smoke tests
verify_lock.py              verify vendored UCO files
```

## Configuration

Copy a template and fill in the required values:

- `network`: `mainnet` or `signet`
- `activation_height`: first block that belongs to the collection
- `ticket_public_key`: 32-byte hex BIP340 public key published by the collection
- `fee_address`: treasury address that receives the protocol fee
- `mempool_url`: Esplora-compatible API base URL
- `mempool_backup_urls`: optional failover endpoints, at most four
- `mempool_rpc_url`: optional Bitcoin Core JSON-RPC endpoint; read from the environment with `BITCOINTAPES_MEMPOOL_RPC_URL` when possible
- `database`: index database path used when `--db` is not supplied

The templates leave `activation_height`, `ticket_public_key` and `fee_address` empty on purpose. The indexer refuses to start until they are set.

Protocol values are fixed for each `protocol_version`. Version 2 uses the legacy 10,000 free supply and 5 per wallet or IP. Version 3 uses 5,000 total, 1,000 free, 4,000 paid, a 3,250 sat protocol fee, and 1 per wallet or IP. A mismatch is rejected before any network request.

## Run

```sh
python3 chain_index.py --config config/indexer.example.json --db public-index.sqlite3
```

Follow the chain continuously:

```sh
python3 chain_index.py --config config/indexer.example.json --db public-index.sqlite3 --loop
```

Rebuild derived state from the activation height:

```sh
python3 chain_index.py --config config/indexer.example.json --db public-index.sqlite3 --rebuild
```

Print the first 100 accepted definitions after each round:

```sh
python3 chain_index.py --config config/indexer.example.json --db public-index.sqlite3 --collection
```

Each round prints one JSON object with `applied`, `caught_up`, `tip_height`, `tip_hash`, `replayed`, `pending`, and the index counters.

## Data model

SQLite tables:

- `chain_meta`: network identity, activation height, tip, reorg counters, replay configuration
- `chain_blocks`: active-chain hash and parent at each applied height
- `chain_candidates`: raw transactions that carry a BTAP-tagged output
- `chain_replay`: accepted and rejected replay results with serial numbers
- `chain_used_tickets`: ticket identifiers already consumed
- `chain_spends`: first spend of each candidate's inscription output

The index is a function of raw blocks. `--rebuild` deletes derived state and replays from the activation height. A shallow reorg rolls back the affected suffix, restores ticket claims, and keeps the unchanged prefix. A missing block or an identity change triggers a full rebuild.

## External APIs

A chain read source is required. A Bitcoin Core JSON-RPC node is used first when configured, then Esplora-compatible endpoints.

### Bitcoin Core JSON-RPC

| Method | Purpose |
| --- | --- |
| `getblockhash(0)` | network identity |
| `getblockcount` | chain tip |
| `getblockhash(height)` | height to hash |
| `getblock(hash, 0)` | raw block bytes |

The node must have `txindex=1`. No address index is required.

### Esplora-compatible REST

| Endpoint | Purpose |
| --- | --- |
| `GET /block-height/0` | network identity |
| `GET /blocks/tip/height` | chain tip |
| `GET /block-height/{height}` | height to hash |
| `GET /block/{hash}/raw` | raw block bytes |

Requests are paced by `provider_budget_per_hour` for each Esplora endpoint and by `mempool_rpc_budget_per_hour` for the RPC node. A source that answers 429 or fails at the transport level is rested and traffic moves to the next source.

Steady-state load is about two requests every 30 seconds, plus two requests per new block. Initial rebuilds are limited by `max_blocks_per_sync` and the configured budget.

No UniSat, Xverse, Turnstile or wallet API is needed by this indexer.

## Trust model

The remote chain source selects the active chain and is trusted for proof-of-work and script validity. The indexer independently verifies block hashes, parent links, transaction merkle roots, and witness commitments. It is not a full node and does not perform independent consensus validation.

Only blocks at or after `activation_height` are downloaded. Addresses and mempools are never scanned.

## Tests

```sh
python3 -m unittest discover -s tests -v
python3 verify_lock.py
```

## License

MIT. The vendored code under `btap_indexer/vendor/uco` is MIT-licensed and is kept unchanged; see `btap_indexer/vendor/LICENSE-UCO` and `THIRD_PARTY_NOTICES.md`.
