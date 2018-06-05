from dataclasses import dataclass, field, Field, fields, asdict, replace
from cachetools import LRUCache, cachedmethod
import struct

from raiden.encoding import signing
from raiden.utils.typing import (
    ClassVar,
    Dict,
    Tuple,
    List,
    Iterable,
    Any,
    Optional,
    Address
)
from raiden.utils import (
    sha3
)


def _reveal_type(_type: type) -> type:
    """Return the actual type, even if type is a ClassVar, InitVar or NewType"""
    return (
        getattr(_type, '__type__', None) or
        getattr(_type, '__supertype__', None) or
        _type
    )


def _internal_cache(cls_or_obj):
    """Used with cachetools.cachedmethod, stores and returns a cache in the object

    As this function keeps the cache inside the object, it doesn't affect garbage
    collection, allowing both the object and cache to be deleted when no further
    reference is found.
    """
    cache = cls_or_obj.__dict__.get('__cache')
    if not cache:
        cache = cls_or_obj.__dict__['__cache'] = LRUCache(32)
    return cache


@dataclass(frozen=True)
class BytesEncodableFieldsMixin:
    """Provides the base for a dataclass that can be [de]serializable to/from bytes

    Thix mixin provides (to|from)_bytes methods. These methods may take an optional
    list of fields (attributes) to be used for (en|de)coding. These fields need
    to have a 'format' metadata describing the `struct` format string to use.
    Typehint for all fields is also adivised.
    A 'cmdid' ClassVar[int] special attribute should also be set as a first byte.
    Without giving a specific
    """
    magic_number: ClassVar[bytes] = field(default=b'\x96\xf7', metadata={'format': '2s'})
    # Needs to be set by a subclass. Don't change typehint
    cmdid: ClassVar[int] = field(default=None, metadata={'format': 'H'})

    @classmethod
    def _prefix_fields(cls) -> Tuple[Field]:
        """Return a tuple of fields to be used as standard prefix for to|from_bytes"""
        return (
            cls.__dataclass_fields__['magic_number'],
            cls.__dataclass_fields__['cmdid']
        )

    @classmethod
    @cachedmethod(_internal_cache)
    def _calc_binary_fields(cls, _fields: Iterable[Field]=None) -> List[Field]:
        """Calculate the valid _fields iterable to be serialized"""
        # if _fields parameter is set, use list of names in given order,
        # not including self._prefix_fields()
        if _fields:
            _fields = [
                cls.__dataclass_fields__[_field.name]
                for _field in _fields
            ]
        else:  # by default, use all fields, including self._prefix_fields()
            _fields = list(cls._prefix_fields() + fields(cls))

        for _field in _fields:
            _type = _reveal_type(_field.type)
            if issubclass(_type, BytesEncodableFieldsMixin):
                _field.metadata['format'] = f'{_type.calcsize()}s'

        _fields = [  # filter for valid metadata
            _field
            for _field in _fields
            if getattr(_field, 'metadata', {}).get('format')
        ]
        return _fields

    @classmethod
    @cachedmethod(_internal_cache)
    def _calc_format(cls, _fields: Iterable[Field]) -> str:
        """Calculate the struct format string to be (en|de)coded"""
        # '!' => network byte-alignment=big-endian
        return '!' + ''.join(_field.metadata['format'] for _field in _fields)

    @classmethod
    def calcsize(cls, _fields: Iterable[Field]=None) -> int:
        """Caculate the size of the serialized bytes for the given _fields"""
        _fields = cls._calc_binary_fields(_fields=_fields)
        fmt = cls._calc_format(_fields)
        return struct.calcsize(fmt)

    def to_bytes(self, _fields: Iterable[Field]=None) -> bytes:
        """Serializes this object into bytes

        The serialization is made based on a 'format' key on field.metadata dict
        @param _fields: list of ordered fields or field names to be serialized
        """
        _fields = self._calc_binary_fields(_fields=_fields)
        fmt = self._calc_format(_fields=_fields)
        values = []

        for _field in _fields:
            _fmt = _field.metadata['format']
            value = getattr(self, _field.name)
            if _fmt.endswith('s'):
                # accept '(\d+)s' formats for integers, including in ClassVar's
                _type = _reveal_type(_field.type)
                # encode big integers
                if _type is int:
                    value = value.to_bytes(struct.calcsize(_fmt), byteorder='big')
                # support recursively messages as fields
                elif issubclass(_type, BytesEncodableFieldsMixin):
                    value = value.to_bytes()
                # test bytes for exact size
                if not isinstance(value, bytes) or len(value) != struct.calcsize(_fmt):
                    raise struct.error('Invalid bytes type or size')
            values.append(value)

        # use struct.pack to format values
        return struct.pack(fmt, *values)

    @classmethod
    def from_bytes(cls, data: bytes, _fields: Iterable[Field]=None) -> 'cls':
        """Constructs an object based on binary packed data"""
        _fields = cls._calc_binary_fields(_fields=_fields)
        fmt = cls._calc_format(_fields=_fields)

        # use struct.unpack to get values
        values = struct.unpack(fmt, data)
        assert len(_fields) == len(values), 'Names and values of different size'

        for i, (_field, value) in enumerate(zip(_fields, values)):
            _type = _reveal_type(_field.type)
            # accept '(\d+)s' formats for integers (decode bytes)
            if _type is int and _field.metadata['format'].endswith('s'):
                values[i] = int.from_bytes(value, byteorder='big')
            # support recursively messages as fields (decode bytes)
            elif issubclass(_type, BytesEncodableFieldsMixin):
                values[i] = _type.from_bytes(value)

        params = dict(zip([_field.name for _field in _fields], values))
        if 'magic_number' in params:
            assert params['magic_number'] == cls.magic_number, 'Invalid data for klass'
        if 'cmdid' in params:
            assert params['cmdid'] == cls.cmdid, 'Invalid data for klass'

        return cls(**params)


@dataclass(frozen=True)
class DictEncodableFieldsMixin:
    def to_dict(self) -> Dict[str, Any]:
        """Returns a dict representing the object, ready to be dumped"""
        return dict(asdict(self), type=type(self).__name__)

    @classmethod
    def from_dict(cls, data: dict) -> 'cls':
        """Gets a dict representing the object, do some validation and
        constructs an object of this class based on it"""
        assert data.get('type') == cls.__name__,\
            f'Wrong type: {data.get("type")!r} != {cls.__name__!r}'
        _fields = fields(cls)
        names = set(_field.name for _field in _fields)
        assert data.keys() <= names,\
            f'Dict contains keys not present in type: {data.keys()-names!r}'
        for _field in _fields:
            _type = _reveal_type(_field.type)
            # support recursively messages as fields
            if _field.name in data and issubclass(_type, DictEncodableFieldsMixin):
                data[_field.name] = _type.from_dict(data[_field.name])

        assert all(
            isinstance(
                data.get(_field.name),
                (type(None), _reveal_type(_field.type))
            )
            for _field in _fields
        ), f'Some dict values are of the wrong type in {data!r}'
        return cls(**{k: v for k, v in data.items() if k != 'type'})


@dataclass(frozen=True)
class Message(DictEncodableFieldsMixin, BytesEncodableFieldsMixin):
    """Base for all messages. Includes serialization mixins"""
    @property
    @cachedmethod(_internal_cache)
    def hash(self):
        return sha3(self.to_bytes())

    @classmethod
    def message_from_bytes(cls, data: bytes) -> 'Message':
        """Classmethod as entrypoint to decode a message from full bytes array"""
        prefix_fields = cls._prefix_fields()
        cmdid_index = [_field.name for _field in prefix_fields].index('cmdid')
        fmt = cls._calc_format(_fields=prefix_fields)
        size = cls.calcsize(_fields=prefix_fields)
        values = struct.unpack(fmt, data[:size])
        cmdid = values[cmdid_index]
        return _CMDID_TO_CLASS[cmdid].from_bytes(data)

    @classmethod
    def message_from_dict(cls, data: dict) -> 'Message':
        """Classmethod as entrypoint to decode a message from dict"""
        return _CLASSNAME_TO_CLASS[data['type']].from_dict(data)


@dataclass(frozen=True)
class SignedMessage(Message):
    """Base for messages which may be signed"""
    # signature field without 'format' metadata -> won't be included in super().to_bytes()
    signature: bytes = field(metadata={'format': '65s'})

    @classmethod
    @cachedmethod(_internal_cache)
    def _calc_binary_fields(cls, _fields: Iterable[Field]=None) -> Tuple[Field]:
        """Like Message._calc_binary_fields, but ensure 'signature' goes last"""
        _fields = super()._calc_binary_fields(_fields=_fields)
        return tuple(sorted(_fields, key=lambda _field: _field.name == 'signature'))

    @property
    @cachedmethod(_internal_cache)
    def hash(self):
        """Exclude 'signature' from SignedMessage.hash calculation"""
        *_fields, sig_field = self._calc_binary_fields()
        assert sig_field.name == 'signature'
        return sha3(self.to_bytes(_fields=_fields))

    @cachedmethod(_internal_cache)
    def data_to_sign(self) -> bytes:
        """Return a binary-encoded representation to be signed

        By default, it just packs all fields, except 'signature', in reverse MRO order
        @return: to_bytes() only of fields to be signed
        """
        *_fields, sig_field = self._calc_binary_fields()
        assert sig_field.name == 'signature'
        return self.to_bytes(_fields=_fields)

    def signed(self, private_key: 'PrivateKey') -> 'SignedMessage':
        """Returns [possibly a copy] of this object, signed"""
        if self.signature:
            return self
        data = self.data_to_sign()
        signature = signing.sign(data, private_key)
        return replace(self, signature=signature)

    @property
    @cachedmethod(_internal_cache)
    def sender(self) -> Optional[Address]:
        """Returns the address which signed this object
        """
        # TODO: cache it, dataclass is frozen/immutable
        if not self.signature:
            return None
        data = self.data_to_sign()
        return signing.recover_address(data, self.signature)


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
    amount: int = field(metadata={'format': '32s'})


@dataclass(frozen=True)
class RevealSecret(SignedMessage):
    cmdid = 11
    message_identifier: int = field(metadata={'format': 'Q'})
    secret: bytes = field(metadata={'format': '32s'})

    @property
    @cachedmethod(_internal_cache)
    def secrethash(self):
        return sha3(self.secret)


@dataclass(frozen=True)
class EnvelopeMessage(SignedMessage):
    """Like SignedMessage, but data_to_sign returns only a subset of the fields

    Also, define some common properties
    """
    nonce: int = field(metadata={'format': 'Q'})
    transferred_amount: int = field(metadata={'format': '32s'})
    locked_amount: int = field(metadata={'format': '32s'})
    locksroot: bytes = field(metadata={'format': '32s'})
    channel: Address = field(metadata={'format': '20s'})
    message_identifier: int = field(metadata={'format': 'Q'})
    payment_identifier: int = field(metadata={'format': 'Q'})

    @cachedmethod(_internal_cache)
    def data_to_sign(self) -> bytes:
        """Return only a fields subset for signing"""
        _fields = self._calc_binary_fields(
            self.__dataclass_fields__[name]
            for name in [
                'nonce',
                'transferred_amount',
                # Locked amount should get signed when smart contracts change to include it
                # 'locked_amount',
                'locksroot',
                'channel'
            ]
        )
        data_from_fields = self.to_bytes(_fields=_fields)
        # append message_hash (i.e. self.to_bytes() without 'signature') as extra_hash
        data = data_from_fields + self.hash
        return data


@dataclass(frozen=True)
class Secret(EnvelopeMessage):
    cmdid = 4
    secret: bytes = field(metadata={'format': '32s'})

    @property
    @cachedmethod(_internal_cache)
    def secrethash(self):
        return sha3(self.secret)


@dataclass(frozen=True)
class DirectTransfer(EnvelopeMessage):
    cmdid = 5
    registry_address: Address = field(metadata={'format': '20s'})
    token: Address = field(metadata={'format': '20s'})
    recipient: Address = field(metadata={'format': '20s'})


@dataclass(frozen=True)
class Lock(Message):
    expiration: int = field(metadata={'format': 'Q'})
    amount: int = field(metadata={'format': '32s'})
    secrethash: bytes = field(metadata={'format': '32s'})

    @classmethod
    def _prefix_fields(cls) -> Tuple[Field]:
        # Lock is an internal structure, it doesn't need the prefixes
        return tuple()

    @property
    @cachedmethod(_internal_cache)
    def lockhash(self):
        return self.hash


@dataclass(frozen=True)
class LockedTransfer(EnvelopeMessage):
    cmdid = 7
    registry_address: Address = field(metadata={'format': '20s'})
    token: Address = field(metadata={'format': '20s'})
    recipient: Address = field(metadata={'format': '20s'})
    lock: Lock = field(metadata={'format': 'from_calcsize'})
    target: Address = field(metadata={'format': '20s'})
    initiator: Address = field(metadata={'format': '20s'})
    fee: int = field(metadata={'format': '32s'})


@dataclass(frozen=True)
class RefundTransfer(LockedTransfer):
    cmdid = 8


def _get_subclasses(cls: type) -> Iterable[type]:
    for subclass in cls.__subclasses__():
        yield from _get_subclasses(subclass)
        yield subclass


_CMDID_TO_CLASS = {
    cls.cmdid: cls
    for cls in _get_subclasses(Message)
    if cls.cmdid is not None
}

_CLASSNAME_TO_CLASS = {
    cls.__name__: cls
    for cls in _get_subclasses(Message)
}
