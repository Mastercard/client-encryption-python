from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from binascii import Error
from cryptography.hazmat.primitives.serialization import PublicFormat

from client_encryption.encoding_utils import encode_bytes, decode_value, url_encode_bytes
from client_encryption.encryption_exception import KeyWrappingError
from client_encryption.encryption_utils import load_hash_algorithm
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig


class SessionKeyParams(object):
    """Class implementing private session key and its params. Provide key and iv random generation functionality"""

    _JWE_KEY_SIZE = 256 // 8
    _MASTERCARD_KEY_SIZE = 128 // 8
    _BLOCK_SIZE = AES.block_size

    def __init__(self, config, encrypted_key, iv_value, padding_digest_algorithm=None):
        self._config = config
        self._encrypted_key_value = encrypted_key
        self._iv_value = iv_value
        self._oaep_padding_digest_algorithm_value = \
            config.oaep_padding_digest_algorithm if padding_digest_algorithm is None else padding_digest_algorithm

        self._key = None
        self._iv = None

    @property
    def config(self):
        return self._config

    @property
    def key(self):
        if not self._key:
            self._key = SessionKeyParams.__unwrap_secret_key(self._encrypted_key_value,
                                                             self._config,
                                                             self._oaep_padding_digest_algorithm_value)

        return self._key

    @property
    def iv_spec(self):
        if not self._iv:
            self._iv = decode_value(self._iv_value, self._config.data_encoding)

        return self._iv

    @property
    def encrypted_key_value(self):
        return self._encrypted_key_value

    @property
    def iv_value(self):
        return self._iv_value

    @property
    def oaep_padding_digest_algorithm_value(self):
        return self._oaep_padding_digest_algorithm_value

    @staticmethod
    def generate(config):
        """Generate encryption parameters."""
        # Generate an AES secret key
        if type(config) is FieldLevelEncryptionConfig:
            secret_key = get_random_bytes(SessionKeyParams._MASTERCARD_KEY_SIZE)
        else:
            secret_key = get_random_bytes(SessionKeyParams._JWE_KEY_SIZE)

        encoding = config.data_encoding

        # Generate a random IV
        iv = get_random_bytes(SessionKeyParams._BLOCK_SIZE)
        iv_encoded = encode_bytes(iv, encoding)

        # Encrypt the secret key
        secret_key_encrypted = SessionKeyParams.__wrap_secret_key(secret_key, config)

        key_params = SessionKeyParams(config, secret_key_encrypted, iv_encoded)
        key_params._key = secret_key
        key_params._iv = iv

        return key_params

    @staticmethod
    def __wrap_secret_key(plain_key, config):
        try:
            hash_algo = load_hash_algorithm(config.oaep_padding_digest_algorithm)
            _cipher = PKCS1_OAEP.new(key=RSA.import_key(
                config.encryption_certificate.public_key().public_bytes(config.encryption_certificate_type,
                                                                        PublicFormat.SubjectPublicKeyInfo)),
                                     hashAlgo=hash_algo)

            encrypted_secret_key = _cipher.encrypt(plain_key)
            if type(config) is FieldLevelEncryptionConfig:
                return encode_bytes(encrypted_secret_key, config.data_encoding)
            else:
                return url_encode_bytes(encrypted_secret_key)

        except (IOError, TypeError):
            raise KeyWrappingError("Unable to encrypt session secret key.")

    @staticmethod
    def __unwrap_secret_key(encrypted_key, config, _hash):
        try:
            hash_algo = load_hash_algorithm(_hash)

            if type(config) is FieldLevelEncryptionConfig:
                encrypted_key = decode_value(encrypted_key, config.data_encoding)

            _cipher = PKCS1_OAEP.new(key=config.decryption_key,
                                     hashAlgo=hash_algo)

            secret_key = _cipher.decrypt(encrypted_key)
            return secret_key

        except (IOError, TypeError, Error):
            raise KeyWrappingError("Unable to decrypt session secret key.")
