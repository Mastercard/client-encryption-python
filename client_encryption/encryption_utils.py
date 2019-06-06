from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
from OpenSSL.crypto import load_certificate, load_pkcs12, dump_privatekey, FILETYPE_PEM, FILETYPE_ASN1, Error
from client_encryption.encryption_exception import CertificateError, PrivateKeyError, HashAlgorithmError


_SUPPORTED_HASH = {"SHA1": SHA1, "SHA224": SHA224, "SHA256": SHA256, "SHA384": SHA384, "SHA512": SHA512}


def load_encryption_certificate(certificate_path):
    """Load X509 encryption certificate data at the given file path."""

    try:
        with open(certificate_path, "rb") as cert_content:
            certificate = cert_content.read()
            x509 = load_certificate(__get_crypto_file_type(certificate), certificate)

        return x509
    except IOError:
        raise CertificateError("Unable to load certificate.")
    except (ValueError, Error):
        raise CertificateError("Wrong encryption certificate format.")


def load_decryption_key(key_file_path, decryption_key_password=None):
    """Load a RSA decryption key."""

    try:
        with open(key_file_path, "rb") as key_content:
            private_key = key_content.read()

            # if key format is p12 (decryption_key_password is populated) then we have to retrieve the private key
            if decryption_key_password is not None:
                private_key = __load_pkcs12_private_key(private_key, decryption_key_password)

        return RSA.importKey(private_key)
    except (Error, IOError):
        raise PrivateKeyError("Unable to load key file.")
    except ValueError:
        raise PrivateKeyError("Wrong decryption key format.")


def __load_pkcs12_private_key(pkcs12_key, password):
    """Load a private key in ASN1 format out of a PKCS#12 container."""

    pkcs12 = load_pkcs12(pkcs12_key, password.encode("utf-8")).get_privatekey()
    return dump_privatekey(FILETYPE_ASN1, pkcs12)


def __get_crypto_file_type(file_content):
    if file_content.startswith(b"-----BEGIN "):
        return FILETYPE_PEM
    else:
        return FILETYPE_ASN1


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
