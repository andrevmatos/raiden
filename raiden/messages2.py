from dataclasses import dataclass, field, Field, fields, asdict, replace
import struct

from raiden.encoding import signing
from raiden.utils.typing import (
    ClassVar,
    Dict,
    List,
    Any,
    Union,
    Optional,
    Address
)
from raiden.utils import (
    sha3
)


@dataclass(frozen=True)
class Message:
    # Needs to be set by a subclass. Don't change typehint
    cmdid: ClassVar[int] = field(default=None, metadata={'format': 'B'})

    def to_dict(self) -> Dict[str, Any]:
        """Returns a dict representing the object, ready to be dumped"""
        return dict(asdict(self), type=type(self).__name__)

    @classmethod
    def from_dict(cls, data: dict) -> 'cls':
        """Gets a dict representing the object, do some validation and
        constructs an object of this class based on it"""
        assert data['type'] == cls.__name__,\
            f'Wrong type: {data["type"]!r} != {cls.__name__!r}'
        _fields = fields(cls)
        names = set(_field.name for _field in _fields)
        assert data.keys() <= names,\
            f'Dict contains keys not present in type: {data.keys()-names!r}'
        assert all(
            isinstance(data.get(_field.name), (type(None), _field.type))
            for _field in _fields
        ), f'Some dict values are of the wrong type in {data!r}'
        return cls(**{k: v for k, v in data.items() if k != 'type'})

    def to_bytes(self, _fields: List[Union[str, Field]]=None) -> bytes:
        """Serializes this object into bytes

        The serialization is made based on a 'format' key on field.metadata dict
        @param _fields: list of ordered fields or field names to be serialized
        """
        # if _fields parameter is set, use list of names in given order
        if _fields:
            _fields = [
                self.__dataclass_fields__[field_or_name]
                if isinstance(field_or_name, str)
                else field_or_name
                for field_or_name in _fields
            ]
        else:  # by default, use all fields, including cmdid
            _fields = (self.__dataclass_fields__['cmdid'],) + fields(self)
        _fields = [  # filter for valid metadata
            _field
            for _field in _fields
            if getattr(_field, 'metadata', {}).get('format')
        ]

        fmt = '!'  # network byte-alignment=big-endian. first byte is the cmdid
        values = []

        for _field in _fields:
            _fmt = _field.metadata['format']
            value = getattr(self, _field.name)
            if _fmt.endswith('s'):
                if _field.type is int:  # accept '(\d+)s' formats for integers
                    value = value.to_bytes(struct.calcsize(_fmt), byteorder='big')
                if not isinstance(value, bytes) or len(value) != struct.calcsize(_fmt):
                    raise struct.error('Invalid bytes type or size')
            fmt += _fmt
            values.append(value)

        # use struct.pack to format values
        return struct.pack(fmt, *values)

    @classmethod
    def from_bytes(cls, data: bytes, _fields: List[Union[str, Field]]=None) -> 'cls':
        """Constructs an object based on binary packed data"""
        # if _fields parameter is set, use list of names in given order
        if _fields:
            _fields = [
                cls.__dataclass_fields__[field_or_name]
                if isinstance(field_or_name, str)
                else field_or_name
                for field_or_name in _fields
            ]
        else:  # by default, use all fields, including cmdid
            _fields = (cls.__dataclass_fields__['cmdid'],) + fields(cls)

        _fields = [  # filter for valid metadata
            _field
            for _field in _fields
            if getattr(_field, 'metadata', {}).get('format')
        ]

        fmt = '!'  # network byte-alignment=big-endian
        for _field in _fields:
            fmt += _field.metadata['format']

        # use struct.unpack to get values
        values = struct.unpack(fmt, data)
        assert len(_fields) == len(values), 'Names and values of different size'

        for i, _field in enumerate(_fields):
            # accept '(\d+)s' formats for integers (decode bytes)
            if _field.type is int and _field.metadata['format'].endswith('s'):
                values[i] = int.from_bytes(values[i], byteorder='big')

        params = dict(zip([_field.name for _field in _fields], values))
        cmdid = params.pop('cmdid', None)
        assert cmdid is None or cmdid == cls.cmdid, 'Invalid data for klass'

        return cls(**params)

    @property
    def hash(self):
        return sha3(self.to_bytes())


@dataclass(frozen=True)
class SignedMessage(Message):
    # signature field without 'format' metadata -> won't be included in super().to_bytes()
    signature: bytes = field(metadata={'format': '65s'})

    def to_bytes(self, _fields: List[Union[str, Field]]=None) -> bytes:
        """Like Message.to_bytes, but ensure signature is last field"""
        if not _fields:
            # if _fields not explicitly set, signature goes last
            _fields = ['cmdid'] + sorted(
                fields(self),
                key=lambda _field: _field.name == 'signature'
            )
        return super().to_bytes(_fields=_fields)

    @classmethod
    def from_bytes(cls, data: bytes, _fields: List[Union[str, Field]]=None) -> 'cls':
        """Like Message.from_bytes, but ensure signature is last field"""
        if not _fields:
            # if _fields not explicitly set, signature goes last
            _fields = ['cmdid'] + sorted(
                fields(cls),
                key=lambda _field: _field.name == 'signature'
            )
        return super().from_bytes(data, _fields=_fields)

    def data_to_sign(self) -> bytes:
        """Return a binary-encoded representation to be signed

        By default, it just packs all fields, except 'signature' (of course),
        in reverse MRO order
        @return: to_bytes() only of fields to be signed
        """
        _fields = ['cmdid'] + [
            _field
            for _field in fields(self)
            if _field.name != 'signature'
        ]
        return self.to_bytes(_fields=_fields)

    def signed(self, private_key: 'PrivateKey') -> 'SignedMessage':
        """Returns [possibly a copy] of this object, signed"""
        if self.signature:
            return self
        data = self.data_to_sign()
        signature = signing.sign(data, private_key)
        return replace(self, signature=signature)

    @property
    def sender(self) -> Optional[Address]:
        """Returns the address which signed this object

        May by cached after
        """
        if not self.signature:
            return None
        data = self.data_to_sign()
        return signing.recover_address(data, self.signature)

    @property
    def hash(self):
        """Exclude 'signature' from SignedMessage.hash calculation"""
        _fields = ['cmdid'] + [
            _field
            for _field in fields(self)
            if _field.name != 'signature'
        ]
        return sha3(self.to_bytes(_fields=_fields))


@dataclass(frozen=True)
class Processed(SignedMessage):
    cmdid = 0
    message_identifier: int = field(metadata={'format': 'Q'})


@dataclass(frozen=True)
class Delivered(SignedMessage):
    cmdid = 12
    delivered_message_identifier: int = field(metadata={'format': 'Q'})


@dataclass(frozen=True)
class Ping(SignedMessage):
    cmdid = 1
    nonce: int = field(metadata={'format': 'Q'})


@dataclass(frozen=True)
class Pong(SignedMessage):
    cmdid = 2
    nonce: int = field(metadata={'format': 'Q'})


@dataclass(frozen=True)
class SecretRequest(SignedMessage):
    cmdid = 3
    message_identifier: int = field(metadata={'format': 'Q'})
    payment_identifier: int = field(metadata={'format': 'Q'})
    secrethash: bytes = field(metadata={'format': '32s'})
    amount: bytes = field(metadata={'format': '32s'})


@dataclass(frozen=True)
class RevealSecret(SignedMessage):
    cmdid = 11
    message_identifier: int = field(metadata={'format': 'Q'})
    secret: bytes = field(metadata={'format': '32s'})


@dataclass(frozen=True)
class EnvelopeMessage(SignedMessage):
    """Like SignedMessage, but dat_to_sign return only a subset of the fields

    Also, define some common properties
    """
    nonce: int = field(metadata={'format': 'Q'})
    transferred_amount: int = field(metadata={'format': '32s'})
    locked_amount: int = field(metadata={'format': '32s'})
    locksroot: bytes = field(metadata={'format': '32s'})
    channel: Address = field(metadata={'format': '20s'})

    def data_to_sign(self) -> bytes:
        """Return only a fields subset for signing"""
        # Locked amount should get signed when smart contracts change to include it
        # klass.get_bytes_from(data, 'locked_amount'),
        _fields = ['nonce', 'transferred_amount', 'locksroot', 'channel']
        data_from_fields = self.to_bytes(_fields=_fields)
        # append message_hash (i.e. self.to_bytes() without 'signature') as extra_hash
        data = data_from_fields + self.hash
        return data


@dataclass(frozen=True)
class Secret(EnvelopeMessage):
    cmdid = 4
    message_identifier: int = field(metadata={'format': 'Q'})
    payment_identifier: int = field(metadata={'format': 'Q'})
    secret: bytes = field(metadata={'format': '32s'})


@dataclass(frozen=True)
class DirectTransfer(EnvelopeMessage):
    cmdid = 5
    message_identifier: int = field(metadata={'format': 'Q'})
    payment_identifier: int = field(metadata={'format': 'Q'})
    registry_address: Address = field(metadata={'format': '20s'})
    token: Address = field(metadata={'format': '20s'})
    recipient: Address = field(metadata={'format': '20s'})
