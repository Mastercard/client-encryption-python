import base64
from enum import Enum

from client_encryption.encryption_exception import EncodingError


def encode_bytes(_bytes, encoding):
    """Encode byte sequence to Hex or Base64."""

    if type(_bytes) is bytes:
        if encoding == ClientEncoding.HEX:
            encoded = _bytes.hex()
        elif encoding == ClientEncoding.BASE64:
            encoded = base64.b64encode(_bytes).decode('utf-8')
        else:
            raise EncodingError("Encode: Invalid encoding.")

        return encoded
    else:
        raise ValueError("Encode: Invalid or missing input bytes.")


def url_encode_bytes(_bytes):
    encoded = base64.urlsafe_b64encode(_bytes).decode().replace("=", "")
    return encoded


def decode_jwe(value):
    return base64.urlsafe_b64decode(value + "==")


def decode_value(value, encoding):
    """Decode Hex or Base64 string to byte sequence."""

    if type(value) is str:
        if encoding == ClientEncoding.HEX:
            decoded = bytes.fromhex(value)
        elif encoding == ClientEncoding.BASE64:
            decoded = base64.b64decode(value)
        else:
            raise EncodingError("Decode: Invalid encoding.")

        return decoded
    else:
        raise ValueError("Decode: Invalid or missing input string.")


class ClientEncoding(Enum):
    BASE64 = 'BASE64'
    HEX = 'HEX'
