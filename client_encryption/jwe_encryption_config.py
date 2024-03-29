import json
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

from client_encryption.encoding_utils import ClientEncoding
from client_encryption.encryption_utils import load_encryption_certificate, load_decryption_key


class JweEncryptionConfig(object):
    """Class implementing a full configuration for field level encryption."""

    def __init__(self, conf):
        if type(conf) is str:
            json_config = json.loads(conf)
        elif type(conf) is dict:
            json_config = conf
        else:
            raise ValueError("Invalid configuration format. Must be valid json string or dict.")

        if not json_config["paths"]:
            raise KeyError("Invalid configuration. Must provide at least one service path.")

        self._paths = dict()
        for path, opt in json_config["paths"].items():
            self._paths[path] = EncryptionPathConfig(opt)

        if "encryptionCertificate" in json_config:
            x509_cert, cert_type = load_encryption_certificate(json_config["encryptionCertificate"])
            self._encryption_certificate = x509_cert
            # Fixed encoding is required, regardless of initial certificate encoding to ensure correct calculation of fingerprint value
            self._encryption_certificate_type = Encoding.DER
            self._encryption_key_fingerprint = \
                json_config.get("encryptionKeyFingerprint", self.__compute_fingerprint(
                    x509_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)))
        else:
            self._encryption_certificate = None
            self._encryption_key_fingerprint = None
            self._encryption_certificate_type = None

        if "decryptionKey" in json_config:
            decryption_key_password = json_config.get("decryptionKeyPassword", None)
            self._decryption_key = load_decryption_key(json_config["decryptionKey"], decryption_key_password)
        else:
            self._decryption_key = None

        self._encrypted_value_field_name = json_config["encryptedValueFieldName"]

        # Fixed properties
        self._data_encoding = ClientEncoding.BASE64
        self._oaep_padding_digest_algorithm = "SHA256"

    @property
    def paths(self):
        return self._paths

    @property
    def data_encoding(self):
        return self._data_encoding

    @property
    def oaep_padding_digest_algorithm(self):
        return self._oaep_padding_digest_algorithm

    @property
    def encryption_certificate(self):
        return self._encryption_certificate

    @property
    def encryption_certificate_type(self):
        return self._encryption_certificate_type

    @property
    def encryption_key_fingerprint(self):
        return self._encryption_key_fingerprint

    @property
    def decryption_key(self):
        return self._decryption_key

    @property
    def encrypted_value_field_name(self):
        return self._encrypted_value_field_name

    @staticmethod
    def __compute_fingerprint(asn1):
        return SHA256.new(asn1).hexdigest()


class EncryptionPathConfig(object):

    def __init__(self, conf):
        self._to_encrypt = conf["toEncrypt"]
        self._to_decrypt = conf["toDecrypt"]

    @property
    def to_encrypt(self):
        return self._to_encrypt

    @property
    def to_decrypt(self):
        return self._to_decrypt
