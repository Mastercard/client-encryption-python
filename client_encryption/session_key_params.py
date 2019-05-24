from binascii import Error
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.PublicKey import RSA
from client_encryption.encoding_utils import encode_bytes, decode_value
from client_encryption.encryption_utils import load_hash_algorithm
from client_encryption.encryption_exception import KeyWrappingError


class SessionKeyParams(object):
    """Class implementing private session key and its params. Provide key and iv random generation functionality"""

    _KEY_SIZE = 128//8
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

        encoding = config.data_encoding

        # Generate a random IV
        iv = Random.new().read(SessionKeyParams._BLOCK_SIZE)
        iv_encoded = encode_bytes(iv, encoding)

        # Generate an AES secret key
        secret_key = Random.new().read(SessionKeyParams._KEY_SIZE)

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
            _cipher = PKCS1_OAEP.new(key=RSA.import_key(config.encryption_certificate),
                                     hashAlgo=hash_algo)

            encrypted_secret_key = _cipher.encrypt(plain_key)
            return encode_bytes(encrypted_secret_key, config.data_encoding)

        except (IOError, TypeError):
            raise KeyWrappingError("Unable to encrypt session secret key.")

    @staticmethod
    def __unwrap_secret_key(encrypted_key, config, _hash):
        try:
            hash_algo = load_hash_algorithm(_hash)

            encrypted_key = decode_value(encrypted_key, config.data_encoding)
            _cipher = PKCS1_OAEP.new(key=config.decryption_key,
                                     hashAlgo=hash_algo)

            secret_key = _cipher.decrypt(encrypted_key)
            return secret_key

        except (IOError, TypeError, Error):
            raise KeyWrappingError("Unable to decrypt session secret key.")
