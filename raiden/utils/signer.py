from abc import ABC, abstractmethod
from typing import Callable, Union

from coincurve import PrivateKey
from eth_keys import keys
from eth_keys.exceptions import BadSignature
from eth_utils import keccak, to_checksum_address

from raiden.exceptions import InvalidSignature
from raiden.utils.typing import Address, AddressHex


def eth_sign_sha3(data: bytes) -> bytes:
    """
    eth_sign/recover compatible hasher
    Prefixes data with "\x19Ethereum Signed Message:\n<len(data)>"
    """
    prefix = b'\x19Ethereum Signed Message:\n'
    if not data.startswith(prefix):
        data = prefix + b'%d%s' % (len(data), data)
    return keccak(data)


def recover(
        data: bytes,
        signature: bytes,
        hasher: Callable[[bytes], bytes] = eth_sign_sha3,
) -> Address:
    """ eth_recover address from data hash and signature """
    _hash = hasher(data)

    if signature[-1] >= 27:  # support (0,1,27,28) v values
        signature = signature[:-1] + bytes([signature[-1] - 27])

    try:
        sig = keys.Signature(signature_bytes=signature)
        public_key = keys.ecdsa_recover(message_hash=_hash, signature=sig)
    except BadSignature as e:
        raise InvalidSignature from e
    return public_key.to_canonical_address()


class Signer(ABC):
    """ ABC for Signer interface """
    # attribute or cached property which represents the address of the account of this Signer
    address: Address

    # hasher used for this Signer to sign and recover hash
    # must be kept in sync with sign implementation, which may or may not allow changing it
    # (e.g. privatekey local signing may use it, but eth_sign rpc always use \x19-prefixed-hasher)
    # default hasher is eth_sign/personal_sign/eip191 compatible
    hasher: Callable[[bytes], bytes] = staticmethod(eth_sign_sha3)

    @abstractmethod
    def sign(self, data: bytes, v: int = 27) -> bytes:
        """ Sign data hash (from hasher) with this Signer's account """
        pass

    # TODO: signTransaction (replace privkey on JSONRPCClient)
    # @abstractmethod
    # def signTransaction(self, transaction: dict) -> bytes:
    #     """ Allows Signers to sign transactions with account """
    #     pass

    # TODO: signTypedData (one can dream)
    # @abstractmethod
    # def signTypedData(self, data: dict) -> bytes:
    #     """ Allows Signers to sign typed/structured data from EIP-712 with account """
    #     pass

    @property
    def address_hex(self) -> AddressHex:
        return to_checksum_address(self.address)

    def recover(self, data: bytes, signature: bytes) -> Address:
        """ Use instance hasher to recover address from data hash and signature """
        return recover(data=data, signature=signature, hasher=self.hasher)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} for {self.address_hex}>'


class LocalSigner(Signer):
    """ Concrete Signer implementation using a local raw or coincurve private key """
    private_key: keys.PrivateKey

    def __init__(self, private_key: Union[bytes, PrivateKey]) -> None:
        if isinstance(private_key, PrivateKey):
            private_key = private_key.secret
        self.private_key = keys.PrivateKey(private_key)
        self.address = self.private_key.public_key.to_canonical_address()

    def sign(self, data: bytes, v: int = 27) -> bytes:
        assert v in (0, 27), 'Raiden is only signing messages with v in (0, 27)'
        _hash = self.hasher(data)
        signature = self.private_key.sign_msg_hash(message_hash=_hash)
        sig_bytes = signature.to_bytes()
        # adjust last byte to v
        return sig_bytes[:-1] + bytes([sig_bytes[-1] + v])