import unittest
from tests import get_mastercard_config_for_test
from binascii import Error
import client_encryption.session_key_params as to_test
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
from client_encryption.encryption_exception import KeyWrappingError


class SessionKeyParamsTest(unittest.TestCase):

    _expected_iv = b"\x14\x19iI|\xfa7\xc2\xac6\xb7\x84\xd6\xc8\x92\x15"
    _expected_private_key = b"\xd4\xd2\xfe\x88\xbe\xa2t\xc5\x9d\xc0\x10\xf0m\xbc7\xff"
    _iv_encoded = "FBlpSXz6N8KsNreE1siSFQ=="
    _wrapped_key = "VAJccUUNnqGU1aerzKahl/qLMd0BGWo7QC0sn5v9c5TL+9vMt5q/7h6Ae83mlovgjCmaDxBCkVwrLdB/fUMxhjYAEMTMT8Y8Z/RsVQq7osiLotO+UBycIDFJaKanRxCDnrDOrbBPMY+v/STFl99SR1dJOQx9udSkI+QOw2g7UayvM83Huw3ESH8GIKSo9PR0rPAS/vLRaDjeaJlDCFe/hwGWqdEa85JCJ6B0itkGjWag6bNdspYbmMruEPZ4J5/+LLCA5dNLiVObyBlGRAJDXbC3/nR1Tzg/5wzpRxFSGo1qcBPEIB9nSgJNIf2WDGEJTcINTEs181jKUQKvu2Kqeg=="

    def setUp(self):
        self._config = FieldLevelEncryptionConfig(get_mastercard_config_for_test())

    def test_generate(self):
        key_params = to_test.SessionKeyParams.generate(self._config)

        self.assertIsNotNone(key_params)
        self.assertEqual(self._config, key_params.config)
        self.assertIsNotNone(key_params.iv_spec)
        self.assertIsNotNone(key_params.iv_value)
        self.assertIsNotNone(key_params.key)
        self.assertIsNotNone(key_params.encrypted_key_value)
        self.assertIsNotNone(key_params.oaep_padding_digest_algorithm_value)

        expected = to_test.SessionKeyParams._SessionKeyParams__unwrap_secret_key(key_params.encrypted_key_value,
                                                                                 self._config, "SHA-256")
        self.assertEqual(expected, key_params.key)
        self.assertEqual(self._config.oaep_padding_digest_algorithm, key_params.oaep_padding_digest_algorithm_value)

    def test_get_key(self):
        key_params = to_test.SessionKeyParams(self._config, self._wrapped_key, self._iv_encoded)

        self.assertEqual(self._expected_private_key, key_params.key)

    def test_get_key_not_wrapped_key(self):
        key_params = to_test.SessionKeyParams(self._config, "this is not a private key!", self._iv_encoded)

        with self.assertRaises(ValueError):
            key_params.key

    def test_get_key_invalid_wrapped_key(self):
        wrong_wrapped_key = self._wrapped_key[0:-15]+"c29tZSBkYXRh=="
        key_params = to_test.SessionKeyParams(self._config, wrong_wrapped_key, self._iv_encoded)

        with self.assertRaises(KeyWrappingError):
            key_params.key

    def test_get_iv(self):
        key_params = to_test.SessionKeyParams(self._config, self._wrapped_key, self._iv_encoded)

        self.assertEqual(self._expected_iv, key_params.iv_spec)

    def test_get_iv_invalid_encoding(self):
        key_params = to_test.SessionKeyParams(self._config, self._wrapped_key, "df(sag")

        with self.assertRaises(Error):
            key_params.iv_spec

    def test_wrap_secret_key(self):
        prev_wrpd_key = ""
        for i in range(1, 4):
            wrpd_key = to_test.SessionKeyParams._SessionKeyParams__wrap_secret_key(self._expected_private_key, self._config)
            self.assertIsNotNone(wrpd_key)
            self.assertNotEqual(prev_wrpd_key, wrpd_key)

            prev_wrpd_key = wrpd_key  # check 2 wraps for same key do not match (MGF1)

            plain_key = to_test.SessionKeyParams._SessionKeyParams__unwrap_secret_key(wrpd_key, self._config, "SHA-256")
            self.assertEqual(self._expected_private_key, plain_key)

    def test_wrap_secret_key_fail(self):
        self.assertRaises(KeyWrappingError, to_test.SessionKeyParams._SessionKeyParams__wrap_secret_key,
                          None, self._config)

    def test_unwrap_secret_key(self):
        key = to_test.SessionKeyParams._SessionKeyParams__unwrap_secret_key(self._wrapped_key, self._config, "SHA-256")

        self.assertEqual(self._expected_private_key, key)

    def test_unwrap_secret_key_fail(self):
        self.assertRaises(KeyWrappingError, to_test.SessionKeyParams._SessionKeyParams__unwrap_secret_key,
                          self._wrapped_key[0:-15]+"c29tZSBkYXRh==", self._config, "SHA-256")
