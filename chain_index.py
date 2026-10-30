import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from btap_indexer.chainindex import ChainIndexer
from btap_indexer.policy import from_settings
from btap_indexer.settings import bitcoin_provider, read_settings


def main():
    parser = argparse.ArgumentParser(
        description="Follow a Bitcoin chain and replay BTAP records into a local index.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--db", help="Independent derived index database")
    parser.add_argument("--rebuild", action="store_true",
                        help="Drop derived chain state and replay from activation height")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--collection", action="store_true",
                        help="Print the first 100 accepted definitions")
    args = parser.parse_args()
    settings = read_settings(args.config)
    database = Path(args.db or settings.get("database") or "public-index.sqlite3")
    database.parent.mkdir(parents=True, exist_ok=True)
    provider = bitcoin_provider(settings)
    index = ChainIndexer(database, provider, settings["network"], settings["genesis"],
                         settings["activation_height"], settings["max_blocks_per_sync"])
    policy = from_settings(settings)
    fee_script, fee = (policy.fee_script, policy.protocol_fee) if policy else (b"\x6a", 1)
    first = True
    while True:
        result = index.rebuild() if first and args.rebuild else index.sync()
        first = False
        print(json.dumps(result, sort_keys=True), flush=True)
        progress = index.advance_replay(fee_script, settings["ticket_public_key"], fee, policy=policy)
        while progress["pending"]:
            progress = index.advance_replay(fee_script, settings["ticket_public_key"], fee, policy=policy)
        if args.collection:
            print(json.dumps(index.collection(fee_script, settings["ticket_public_key"], fee,
                                              0, 100, advance=False, policy=policy),
                             sort_keys=True), flush=True)
        if not args.loop:
            break
        time.sleep(settings["sync_interval_seconds"])


if __name__ == "__main__":
    main()
