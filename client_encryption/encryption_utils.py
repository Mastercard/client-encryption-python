from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs12
from enum import IntEnum

from client_encryption.encryption_exception import CertificateError, PrivateKeyError, HashAlgorithmError

_SUPPORTED_HASH = {"SHA1": SHA1, "SHA224": SHA224, "SHA256": SHA256, "SHA384": SHA384, "SHA512": SHA512}


class FileType(IntEnum):
    FILETYPE_PEM = 0
    FILETYPE_ASN1 = 1
    FILETYPE_INVALID = -1


def load_encryption_certificate(certificate_path):
    """Load X509 encryption certificate data at the given file path."""

    try:
        with open(certificate_path, "rb") as cert_content:
            certificate = cert_content.read()
    except IOError:
        raise CertificateError("Unable to load certificate.")

    try:
        cert_type = __get_crypto_file_type(certificate)

        if cert_type == FileType.FILETYPE_PEM:
            cert = x509.load_pem_x509_certificate(certificate)
            return cert, Encoding.PEM
        if cert_type == FileType.FILETYPE_ASN1:
            cert = x509.load_der_x509_certificate(certificate)
            return cert, Encoding.DER
        if cert_type == FileType.FILETYPE_INVALID:
            raise CertificateError("Wrong certificate format.")
    except ValueError:
        raise CertificateError("Invalid  certificate format.")


def write_encryption_certificate(certificate_path, certificate, cert_type):
    with open(certificate_path, "wb") as f:
        f.write(certificate.public_bytes(cert_type))


def load_decryption_key(key_file_path, decryption_key_password=None):
    """Load a RSA decryption key."""

    try:
        with open(key_file_path, "rb") as key_content:
            private_key = key_content.read()
            # if key format is p12 (decryption_key_password is populated) then we have to retrieve the private key
            if decryption_key_password is not None:
                private_key = __load_pkcs12_private_key(private_key, decryption_key_password)
        return RSA.importKey(private_key)
    except ValueError:
        raise PrivateKeyError("Wrong decryption key format.")
    except (Exception):
        raise PrivateKeyError("Unable to load key file.")


def __load_pkcs12_private_key(pkcs_file, password):
    private_key, certs, addcerts = pkcs12.load_key_and_certificates(pkcs_file, password.encode("utf-8"))
    return private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption())


def __get_crypto_file_type(file_content):
    if file_content.startswith(b"-----BEGIN "):
        return FileType.FILETYPE_PEM
    else:
        return FileType.FILETYPE_ASN1


def validate_hash_algorithm(algo_str):
    """Validate a hash algorithm against a list of supported ones."""

    if algo_str:
        algo_key = algo_str.replace("-", "").upper()

        if algo_key in _SUPPORTED_HASH:
            return algo_key
        else:
            raise HashAlgorithmError("Hash algorithm invalid or not supported.")
    else:
        raise HashAlgorithmError("No hash algorithm provided.")


def load_hash_algorithm(algo_str):
    """Load a hash algorithm object of Crypto.Hash from a list of supported ones."""

    return _SUPPORTED_HASH[validate_hash_algorithm(algo_str)]
