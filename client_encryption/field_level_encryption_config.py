import json
from OpenSSL.crypto import dump_certificate, FILETYPE_ASN1, dump_publickey
from Crypto.Hash import SHA256
from client_encryption.encoding_utils import Encoding
from client_encryption.encryption_utils import load_encryption_certificate, load_decryption_key, load_hash_algorithm


class FieldLevelEncryptionConfig(object):
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
            x509_cert = load_encryption_certificate(json_config["encryptionCertificate"])
            self._encryption_certificate = dump_certificate(FILETYPE_ASN1, x509_cert)
            self._encryption_key_fingerprint = \
                json_config.get("encryptionKeyFingerprint",
                                self.__compute_fingerprint(
                                    dump_publickey(FILETYPE_ASN1, x509_cert.get_pubkey())))
            self._encryption_certificate_fingerprint = \
                json_config.get("encryptionCertificateFingerprint",
                                self.__compute_fingerprint(self._encryption_certificate))
        else:
            self._encryption_certificate = None
            self._encryption_key_fingerprint = None
            self._encryption_certificate_fingerprint = None

        if "decryptionKey" in json_config:
            decryption_key_password = json_config.get("decryptionKeyPassword", None)
            self._decryption_key = load_decryption_key(json_config["decryptionKey"], decryption_key_password)
        else:
            self._decryption_key = None

        digest_algo = json_config["oaepPaddingDigestAlgorithm"]
        if load_hash_algorithm(digest_algo) is not None:
            self._oaep_padding_digest_algorithm = digest_algo

        data_enc = Encoding(json_config["dataEncoding"].upper())
        self._data_encoding = data_enc
        self._iv_field_name = json_config["ivFieldName"]
        self._encrypted_key_field_name = json_config["encryptedKeyFieldName"]
        self._encrypted_value_field_name = json_config["encryptedValueFieldName"]

        self._encryption_certificate_fingerprint_field_name =\
            json_config.get("encryptionCertificateFingerprintFieldName", None)
        self._encryption_key_fingerprint_field_name =\
            json_config.get("encryptionKeyFingerprintFieldName", None)
        self._oaep_padding_digest_algorithm_field_name =\
            json_config.get("oaepPaddingDigestAlgorithmFieldName", None)

        self._use_http_headers = json_config.get("useHttpHeaders", False)

    @property
    def paths(self):
        return self._paths

    @property
    def encryption_certificate(self):
        return self._encryption_certificate

    @property
    def encryption_key_fingerprint(self):
        return self._encryption_key_fingerprint

    @property
    def encryption_certificate_fingerprint(self):
        return self._encryption_certificate_fingerprint

    @property
    def decryption_key(self):
        return self._decryption_key

    @property
    def oaep_padding_digest_algorithm(self):
        return self._oaep_padding_digest_algorithm

    @property
    def data_encoding(self):
        return self._data_encoding

    @property
    def iv_field_name(self):
        return self._iv_field_name

    @property
    def encrypted_key_field_name(self):
        return self._encrypted_key_field_name

    @property
    def encrypted_value_field_name(self):
        return self._encrypted_value_field_name

    @property
    def encryption_certificate_fingerprint_field_name(self):
        return self._encryption_certificate_fingerprint_field_name

    @property
    def encryption_key_fingerprint_field_name(self):
        return self._encryption_key_fingerprint_field_name

    @property
    def oaep_padding_digest_algorithm_field_name(self):
        return self._oaep_padding_digest_algorithm_field_name

    @property
    def use_http_headers(self):
        return self._use_http_headers

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
