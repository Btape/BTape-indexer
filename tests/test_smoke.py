import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from btap_indexer.chain_validation import merkle
from btap_indexer.chainindex import ChainIndexer
from uco import btc


def raw_block(height, previous):
    coinbase = {
        "version": 2,
        "vin": [{"txid": "00" * 32, "vout": 0xffffffff, "sequence": 0xffffffff,
                 "script_sig": bytes([height % 256]), "witness": [bytes(32)]}],
        "vout": [{"value": 0, "spk": b"\x51"}],
        "locktime": 0,
    }
    root = merkle([bytes(32)])
    coinbase["vout"].append({"value": 0, "spk": bytes.fromhex("6a24aa21a9ed") + btc.dsha(root + bytes(32))})
    txs = [coinbase]
    root = merkle([btc.dsha(btc.serialize_tx(tx, witness=False)) for tx in txs])
    header = (struct.pack("<I", 4) + bytes.fromhex(previous)[::-1] + root
              + struct.pack("<III", 1700000000 + height, 0x207fffff, height))
    return header + btc.compact_size(len(txs)) + b"".join(btc.serialize_tx(tx) for tx in txs)


class FakeProvider:
    def __init__(self, blocks):
        self.blocks = blocks

    def check_network(self):
        return None

    def tip_height(self):
        return max(self.blocks)

    def block_hash(self, height):
        return self.blocks[height][0]

    def raw_block(self, block_hash):
        for hash_, raw in self.blocks.values():
            if hash_ == block_hash:
                return raw
        raise AssertionError("unknown block")


class SmokeTests(unittest.TestCase):
    def test_sync_and_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            genesis = "00" * 32
            raw = raw_block(100, genesis)
            blocks = {
                99: (genesis, None),
                100: (btc.parse_block(raw)["hash"], raw),
            }
            provider = FakeProvider(blocks)
            chain = ChainIndexer(Path(tmp) / "index.sqlite3", provider, "mainnet", genesis, 100, 10)
            result = chain.sync()
            self.assertTrue(result["caught_up"])
            self.assertEqual(result["applied"], 1)
            self.assertEqual(chain.status()["tip_height"], 100)
            chain.rebuild()
            self.assertEqual(chain.status()["tip_height"], 100)


if __name__ == "__main__":
    unittest.main()
