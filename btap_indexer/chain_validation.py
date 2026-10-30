from btap_indexer import protocol
from uco import btc


def merkle(leaves):
    if not leaves:
        raise ValueError('Empty block')
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves = leaves + [leaves[-1]]
        leaves = [btc.dsha(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
    return leaves[0]


def validate_block(raw, block):
    txs = block['txs']
    if not txs or merkle([bytes.fromhex(tx['txid'])[::-1] for tx in txs]) != raw[36:68]:
        raise ValueError('Block transaction merkle root mismatch')
    coinbase = txs[0]
    commitments = [out['spk'][6:38] for out in coinbase['vout']
                   if len(out['spk']) >= 38 and out['spk'][:6] == bytes.fromhex('6a24aa21a9ed')]
    has_witness = any(vin.get('witness') for tx in txs for vin in tx['vin'])
    if not commitments and has_witness:
        raise ValueError('Missing witness commitment')
    if commitments:
        witness = coinbase['vin'][0]['witness']
        if len(witness) != 1 or len(witness[0]) != 32:
            raise ValueError('Invalid coinbase witness reserved value')
        root = merkle([bytes(32)] + [btc.dsha(btc.serialize_tx(tx)) for tx in txs[1:]])
        if btc.dsha(root + witness[0]) != commitments[-1]:
            raise ValueError('Block witness commitment mismatch')
