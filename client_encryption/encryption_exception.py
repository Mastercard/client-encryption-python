class EncryptionError(Exception):
    """Encryption related exception for client-encryption module."""
    pass


class EncodingError(Exception):
    """Encoding not supported or invalid."""
    pass


class CertificateError(Exception):
    """Certificate exception for client-encryption module."""
    pass


class PrivateKeyError(Exception):
    """Private key exception for client-encryption module."""
    pass


class HashAlgorithmError(Exception):
    """Hash algorithm exception for client-encryption module."""
    pass


class KeyWrappingError(Exception):
    """Encryption exception on wrapping/unwrapping session key for client-encryption module."""
    pass
