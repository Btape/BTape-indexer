import hashlib
import json
from dataclasses import dataclass

from btap_indexer.transactions import address_script


@dataclass(frozen=True)
class CollectionPolicy:
    genesis: str
    activation_height: object
    fee_script: bytes
    version: int = 3
    supply: int = 5000
    free_supply: int = 1000
    paid_supply: int = 4000
    protocol_fee: int = 3250
    wallet_limit: int = 1
    ip_limit: int = 1

    def public(self):
        return {**self.__dict__, 'fee_script': self.fee_script.hex(),
                'admission': 'one-confirmation,block-height,chain-position,txid',
                'free_quota': 'permanent-issued-tickets', 'paid_seats': 'confirmed-block-order'}

    @property
    def digest(self):
        return hashlib.sha256(json.dumps(self.public(), sort_keys=True, separators=(',', ':')).encode()).digest()


def from_settings(settings):
    if settings.get('protocol_version', 2) == 2:
        return None
    address = settings.get('fee_address', '')
    return CollectionPolicy(settings['genesis'], settings.get('activation_height'),
                            address_script(address, settings['network']) if address else b'',
                            protocol_fee=settings.get('protocol_fee', 3250))
