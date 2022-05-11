import unittest
import client_encryption.jwe_encryption as to_test
from client_encryption.jwe_encryption_config import JweEncryptionConfig
from tests import get_mastercard_config_for_test


class JweEncryptionTest(unittest.TestCase):

    def setUp(self):
        self._config = JweEncryptionConfig(get_mastercard_config_for_test())
        self._config._paths["$"]._to_encrypt = {"$": "$"}
        self._config._paths["$"]._to_decrypt = {"encryptedValue": "$"}

    def test_encrypt_payload_should_be_able_to_be_decrypted(self):
        payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            }
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        decrypted_payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertDictEqual(payload, decrypted_payload)

    def test_encrypt_payload_should_be_able_to_decrypt_empty_json(self):
        payload = {}

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        decrypted_payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertDictEqual(payload, decrypted_payload)

    def test_encrypt_payload_should_be_able_to_decrypt_root_arrays(self):
        payload = [
            {
                'field1': 'field2'
            }
        ]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        decrypted_payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertListEqual(payload, decrypted_payload)

    def test_encrypt_payload_with_multiple_encryption_paths(self):
        self._config._paths["$"]._to_encrypt = {"data1": "encryptedData1", "data2": "encryptedData2"}
        self._config._paths["$"]._to_decrypt = {"encryptedData1": "data1", "encryptedData2": "data2"}

        payload = {
            "data1": {
                "field1": "value1",
                "field2": "value2"
            },
            "data2": {
                "field3": "value3",
                "field4": "value4"
            }
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("data1", encrypted_payload)
        self.assertNotIn("data2", encrypted_payload)

        decrypted_payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertDictEqual(payload, decrypted_payload)

    def test_decrypt_payload_should_decrypt_gcm_payload(self):
        encrypted_payload = {
            "encryptedValue": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiNzYxYjAwM2MxZWFkZTNhNTQ5MGU1MDAwZDM3ODg3YmFhNWU2ZWMwZTIyNmMwNzcwNmU1OTk0NTFmYzAzMmE3OSIsImN0eSI6ImFwcGxpY2F0aW9uL2pzb24ifQ.BSaTAccaFe1S2KyhuIyiQTvbonrKSDTzyKruStdl1Ym9Qu_lTjhfvqZ0-PzqquY8S4WcN55YhNZHY4gYdA6gZj4Jemgt31YpnwcewehoDi2xFV8mtlA7ILgUpJtEEfVGXRxiHt1S1AfrrbplcHrwrSemnnaPD4xA6uVlpXtImq8_GtrF5u6A-dPKdHr5gEhVUtfNj_MTvOR3UsnpVWv6vKbXDvNQci44pRVnaXKdyORA_Dv2ogBDDf2wtBZDyki5yyjdMAFkzBBeNkEaepJUvK71nNVd4HrZrulEOR1mvebGP1cYbEEtPGp6rZByB68Ktm3afyYS6f2rrLJlLUmNxQ.gnqed-xAvu4IVQUQ_JhxIA.tLw_NKkvBvzO0ZLxtI9_lXYnnBAo0c4SiI7s1cUhUST5d7nc6SVd48a6FE10QLjE2tmulq_cuB44iB5Q6ttynQXl5FjvTBs.lSfPmu-dvcIhHxnkIzPxBQ"
        }

        decrypted_payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedData": {}
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedValue", payload)
        self.assertDictEqual(decrypted_payload, payload)

    def test_decrypt_payload_should_decrypt_cbc_payload(self):
        encrypted_payload = {
            "encryptedValue": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.2GzZlB3scifhqlzIV2Rxk1TwiWL35e0AtcI9MFusG9jv9zGrJ8BapJx73PlFu69S0IAR7hXpqwzD7-UzmHUdrxB7izbMm9TNDpznHIuTaJWSRngD5Zui_rUXETL0GJG8dERx7IngqTltfzZanhDnjDNfKaowD6pFSEVN-Ff-pTeJqLMPs5504DtnYGD_uhQjvFmREIBgQTGEINzT88PXwLTAVBbWbAad_I-4Q12YwW_Y4yqmARCMTRWP-ixMrlSWCJlh6hz-biEotWNwGvp2pdhdiEP2VSvvUKHd7IngMWcMozOcoZQ1n18kWiFvt90fzNXSmzTjyGYSWUsa_mVouA.aX5mOSiXtilwYPFeTUFN_A.ZyAY79BAjG-QMQIhesj9bQ.TPZ2VYWdTLopCNkvMqUyuQ"
        }

        decrypted_payload = {"foo": "bar"}

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedValue", payload)
        self.assertDictEqual(decrypted_payload, payload)
