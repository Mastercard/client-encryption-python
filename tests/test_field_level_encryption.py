import unittest
from unittest.mock import Mock, patch
import json
import base64
from tests import get_mastercard_config_for_test
from client_encryption.encoding_utils import ClientEncoding
from client_encryption.encryption_exception import EncryptionError
import client_encryption.field_level_encryption as to_test
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
from client_encryption.session_key_params import SessionKeyParams


class FieldLevelEncryptionTest(unittest.TestCase):

    def setUp(self):
        self._config = FieldLevelEncryptionConfig(get_mastercard_config_for_test())
        self._config._paths["$"]._to_encrypt = {"data": "encryptedData"}
        self._config._paths["$"]._to_decrypt = {"encryptedData": "data"}

    def test_encrypt_bytes(self):
        iv_value = base64.b64decode("VNm/scgd1jhWF0z4+Qh6MA==")
        key_kalue = base64.b64decode("mZzmzoURXI3Vk0vdsPkcFw==")
        data_value = "some data ù€@"
        encrypted_value = to_test._encrypt_value(key_kalue, iv_value, data_value)

        self.assertEqual(base64.b64decode("Y6X9YneTS4VuPETceBmvclrDoCqYyBgZgJUdnlZ8/0g="), encrypted_value)

    def test_decrypt_bytes(self):
        iv_value = base64.b64decode("VNm/scgd1jhWF0z4+Qh6MA==")
        key_kalue = base64.b64decode("mZzmzoURXI3Vk0vdsPkcFw==")
        encrypted_value = base64.b64decode("Y6X9YneTS4VuPETceBmvclrDoCqYyBgZgJUdnlZ8/0g=")
        data_value = to_test._decrypt_bytes(key_kalue, iv_value, encrypted_value)

        self.assertEqual("some data ù€@", data_value)

    def test_populate_node_with_key_params(self):
        params = SessionKeyParams.generate(self._config)
        payload = {"key_params": {}}
        node = payload["key_params"]
        to_test._populate_node_with_key_params(node, self._config, params)

        self.assertEqual(5, len(payload["key_params"].keys()))
        self.assertIsNotNone(payload["key_params"][self._config.iv_field_name])
        self.assertIsNotNone(payload["key_params"][self._config.encrypted_key_field_name])
        self.assertEqual("SHA256", payload["key_params"][self._config.oaep_padding_digest_algorithm_field_name])
        self.assertEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79",
                         payload["key_params"][self._config.encryption_key_fingerprint_field_name])
        self.assertEqual("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
                         payload["key_params"][self._config.encryption_certificate_fingerprint_field_name])

    def test_remove_fingerprint_from_node(self):
        encrypted_payload = {
            "encryptedData": {
                self._config.encryption_certificate_fingerprint_field_name:
                    "gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=",
                self._config.encryption_key_fingerprint_field_name:
                    "dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=",
                "oaepHashingAlgo": "SHA256"
            }
        }

        to_test._remove_fingerprint_from_node(encrypted_payload["encryptedData"], self._config)

        self.assertEqual(1, len(encrypted_payload["encryptedData"].keys()))
        self.assertEqual({"encryptedData": {"oaepHashingAlgo": "SHA256"}}, encrypted_payload)

    def __assert_payload_encrypted(self, payload, encrypted, config):
        self.assertNotIn("data", encrypted)
        self.assertIn("encryptedData", encrypted)
        enc_data = encrypted["encryptedData"]
        self.assertEqual(6, len(enc_data.keys()))
        self.assertIsNotNone(enc_data["iv"])
        self.assertIsNotNone(enc_data["encryptedKey"])
        self.assertIsNotNone(enc_data["encryptedValue"])
        self.assertEqual("SHA256", enc_data["oaepHashingAlgo"])
        self.assertEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", enc_data["keyFingerprint"])
        self.assertEqual("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", enc_data["certFingerprint"])
        del payload["encryptedData"]
        self.assertEqual(payload, to_test.decrypt_payload(encrypted, config))

    def __assert_array_payload_encrypted(self, payload, encrypted, config):
        self.assertNotIn("data", encrypted[0])
        self.assertIn("encryptedData", encrypted[0])
        enc_data = encrypted[0]["encryptedData"]
        self.assertEqual(6, len(enc_data.keys()))
        self.assertIsNotNone(enc_data["iv"])
        self.assertIsNotNone(enc_data["encryptedKey"])
        self.assertIsNotNone(enc_data["encryptedValue"])
        self.assertEqual("SHA256", enc_data["oaepHashingAlgo"])
        self.assertEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", enc_data["keyFingerprint"])
        self.assertEqual("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", enc_data["certFingerprint"])
        del payload[0]["encryptedData"]
        self.assertEqual(payload, to_test.decrypt_payload(encrypted, config))

    def test_encrypt_payload_base64_field_encoding(self):
        payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedData": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_payload_hex_field_encoding(self):
        self._config._data_encoding = ClientEncoding.HEX

        payload = {
                    "data": {
                        "field1": "value1",
                        "field2": "value2"
                    },
                    "encryptedData": {}
                  }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_payload_as_string(self):
        payload = '{"data": {"field1": "value1","field2": "value2"},"encryptedData": {}}'

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_payload_encrypted(json.loads(payload), encrypted_payload, self._config)

    def test_encrypt_payload_with_type_string(self):
        payload = {
            "data": "string",
            "encryptedData": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_payload_with_type_integer(self):
        payload = {
            "data": 12345,
            "encryptedData": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_payload_with_type_float(self):
        payload = {
            "data": 123.34,
            "encryptedData": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_payload_with_type_boolean(self):
        payload = {
            "data": False,
            "encryptedData": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_payload_with_type_list(self):
        payload = {
            "data": ["item1", "item2", "item3"],
            "encryptedData": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_array_payload_with_type_string(self):
        payload = [{
            "data": "item1",
            "encryptedData": {}
        }]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_array_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_array_payload_with_type_list(self):
        payload = [{
            "data": ["item1", "item2", "item3"],
            "encryptedData": {}
        }]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_array_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_array_payload_with_type_object(self):

        payload = [{
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedData": {}
        }]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_array_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_array_payload_with_type_multiple_object(self):

        payload = [{
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedData": {}
            },
            {
                "data": {
                    "field1": "value1",
                    "field2": "value2"
                },
                "encryptedData": {}
            }
        ]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)
        self.__assert_array_payload_encrypted(payload, encrypted_payload, self._config)

    def test_encrypt_array_payload_skip_when_in_path_does_not_exist(self):
        payload = [{
            "dataNotToEncrypt": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedData": {}
        }]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertEqual(payload, encrypted_payload)

    def test_encrypt_array_payload_create_node_when_out_path_parent_exists(self):
        self._config._paths["$"]._to_encrypt = {"data": "encryptedDataParent.encryptedData"}

        payload = [{
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedDataParent": {}
        }]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("data", encrypted_payload[0])
        self.assertIn("encryptedDataParent", encrypted_payload[0])
        self.assertIn("encryptedData", encrypted_payload[0]["encryptedDataParent"])

    def test_encrypt_array_payload_with_multiple_encryption_paths(self):
        self._config._paths["$"]._to_encrypt = {"data1": "encryptedData1", "data2": "encryptedData2"}

        payload = [{
            "data1": {
                "field1": "value1",
                "field2": "value2"
            },
            "data2": {
                "field3": "value3",
                "field4": "value4"
            },
            "encryptedData1": {},
            "encryptedData2": {}
        }]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("data1", encrypted_payload[0])
        self.assertNotIn("data2", encrypted_payload[0])
        enc_data1 = encrypted_payload[0]["encryptedData1"]
        enc_data2 = encrypted_payload[0]["encryptedData2"]
        self.assertIsNotNone(enc_data1["iv"])
        self.assertIsNotNone(enc_data1["encryptedKey"])
        self.assertIsNotNone(enc_data1["encryptedValue"])
        self.assertIsNotNone(enc_data2["iv"])
        self.assertIsNotNone(enc_data2["encryptedKey"])
        self.assertIsNotNone(enc_data2["encryptedValue"])
        self.assertNotEqual(enc_data1["iv"], enc_data2["iv"], "using same set of params")

    def test_encrypt_array_payload_when_root_as_in_path(self):
        self._config._paths["$"]._to_encrypt = {"$": "encryptedData"}

        payload = [{
            "field1": "value1",
            "field2": "value2"
        }]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("field1", encrypted_payload[0])
        self.assertNotIn("field2", encrypted_payload[0])
        self.assertIn("encryptedData", encrypted_payload[0])
        self.assertEqual(6, len(encrypted_payload[0]["encryptedData"].keys()))

    def test_encrypt_array_payload_when_out_path_same_as_in_path(self):
        self._config._paths["$"]._to_encrypt = {"data": "data"}

        payload = [{
            "data": {
                "field1": "value1",
                "field2": "value2"
            }
        }]

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertIn("data", encrypted_payload[0])
        self.assertNotIn("field1", encrypted_payload[0]["data"])
        self.assertNotIn("field2", encrypted_payload[0]["data"])
        self.assertIn("iv", encrypted_payload[0]["data"])
        self.assertIn("encryptedKey", encrypted_payload[0]["data"])
        self.assertIn("encryptedValue", encrypted_payload[0]["data"])
        self.assertIn("certFingerprint", encrypted_payload[0]["data"])
        self.assertIn("keyFingerprint", encrypted_payload[0]["data"])
        self.assertIn("oaepHashingAlgo", encrypted_payload[0]["data"])

    def test_encrypt_payload_skip_when_in_path_does_not_exist(self):
        payload = {
            "dataNotToEncrypt": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedData": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertEqual(payload, encrypted_payload)

    def test_encrypt_payload_create_node_when_out_path_parent_exists(self):
        self._config._paths["$"]._to_encrypt = {"data": "encryptedDataParent.encryptedData"}

        payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedDataParent": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("data", encrypted_payload)
        self.assertIn("encryptedDataParent", encrypted_payload)
        self.assertIn("encryptedData", encrypted_payload["encryptedDataParent"])

    def test_encrypt_payload_fail_when_out_path_parent_does_not_exist(self):
        self._config._paths["$"]._to_encrypt = {"data": "notExistingEncryptedDataParent.encryptedData"}

        payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedDataParent": {}
        }

        self.assertRaises(EncryptionError, to_test.encrypt_payload, payload, self._config)

    def test_encrypt_payload_when_out_path_same_as_in_path(self):
        self._config._paths["$"]._to_encrypt = {"data": "data"}

        payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            }
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertIn("data", encrypted_payload)
        self.assertNotIn("field1", encrypted_payload["data"])
        self.assertNotIn("field2", encrypted_payload["data"])
        self.assertIn("iv", encrypted_payload["data"])
        self.assertIn("encryptedKey", encrypted_payload["data"])
        self.assertIn("encryptedValue", encrypted_payload["data"])
        self.assertIn("certFingerprint", encrypted_payload["data"])
        self.assertIn("keyFingerprint", encrypted_payload["data"])
        self.assertIn("oaepHashingAlgo", encrypted_payload["data"])

    def test_encrypt_payload_when_out_path_already_contains_data(self):
        payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedData": {
                "field1": "fieldValue",
                "iv": "previousIv"
            }
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("data", encrypted_payload)
        self.assertIn("encryptedData", encrypted_payload)
        self.assertIn("field1", encrypted_payload["encryptedData"])
        self.assertIn("iv", encrypted_payload["encryptedData"])
        self.assertEqual("fieldValue", encrypted_payload["encryptedData"]["field1"])
        self.assertNotEqual("previousIv", encrypted_payload["encryptedData"]["iv"])

    def test_encrypt_payload_with_multiple_encryption_paths(self):
        self._config._paths["$"]._to_encrypt = {"data1": "encryptedData1", "data2": "encryptedData2"}

        payload = {
            "data1": {
                "field1": "value1",
                "field2": "value2"
            },
            "data2": {
                "field3": "value3",
                "field4": "value4"
            },
            "encryptedData1": {},
            "encryptedData2": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("data1", encrypted_payload)
        self.assertNotIn("data2", encrypted_payload)
        enc_data1 = encrypted_payload["encryptedData1"]
        enc_data2 = encrypted_payload["encryptedData2"]
        self.assertIsNotNone(enc_data1["iv"])
        self.assertIsNotNone(enc_data1["encryptedKey"])
        self.assertIsNotNone(enc_data1["encryptedValue"])
        self.assertIsNotNone(enc_data2["iv"])
        self.assertIsNotNone(enc_data2["encryptedKey"])
        self.assertIsNotNone(enc_data2["encryptedValue"])
        self.assertNotEqual(enc_data1["iv"], enc_data2["iv"], "using same set of params")

    def test_encrypt_payload_when_oaep_padding_digest_algorithm_field_not_set(self):
        self._config._oaep_padding_digest_algorithm_field_name = None

        payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedData": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("data", encrypted_payload)
        self.assertIn("encryptedData", encrypted_payload)
        self.assertEqual(5, len(encrypted_payload["encryptedData"].keys()))

    def test_encrypt_payload_when_root_as_in_path(self):
        self._config._paths["$"]._to_encrypt = {"$": "encryptedData"}

        payload = {
            "field1": "value1",
            "field2": "value2"
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("field1", encrypted_payload)
        self.assertNotIn("field2", encrypted_payload)
        self.assertIn("encryptedData", encrypted_payload)
        self.assertEqual(6, len(encrypted_payload["encryptedData"].keys()))

    def test_encrypt_payload_when_root_as_in_and_out_path(self):
        self._config._paths["$"]._to_encrypt = {"$": "$"}

        payload = {
            "field1": "value1",
            "field2": "value2"
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config)

        self.assertNotIn("field1", encrypted_payload)
        self.assertNotIn("field2", encrypted_payload)
        self.assertIn("iv", encrypted_payload)
        self.assertIn("encryptedKey", encrypted_payload)
        self.assertIn("encryptedValue", encrypted_payload)
        self.assertIn("certFingerprint", encrypted_payload)
        self.assertIn("keyFingerprint", encrypted_payload)
        self.assertIn("oaepHashingAlgo", encrypted_payload)

    def test_encrypt_payload_when_encryption_error_occurs(self):
        payload = {
            "data": {},
            "encryptedData": {}
        }

        encrypt_mock = Mock(side_effect=ValueError("Data must be aligned to block boundary in ECB mode"))

        with patch('client_encryption.field_level_encryption._encrypt_value', encrypt_mock):
            self.assertRaises(EncryptionError, to_test.encrypt_payload, payload, self._config)

    def test_encrypt_payload_when_session_key_params_is_provided(self):
        payload = {
            "data": {},
            "encryptedData": {}
        }

        params = SessionKeyParams.generate(self._config)
        encrypted_payload = to_test.encrypt_payload(payload, self._config, params)

        self.assertNotIn("data", encrypted_payload)
        self.assertIn("encryptedData", encrypted_payload)
        self.assertIn("encryptedValue", encrypted_payload["encryptedData"])
        self.assertEqual(1, len(encrypted_payload["encryptedData"].keys()))
        del payload["encryptedData"]
        self.assertEqual(payload, to_test.decrypt_payload(encrypted_payload, self._config, params))

    def test_encrypt_payload_when_session_key_params_is_None(self):
        payload = {
            "data": {
                "field1": "value1",
                "field2": "value2"
            },
            "encryptedData": {}
        }

        encrypted_payload = to_test.encrypt_payload(payload, self._config, None)

        self.assertNotIn("field1", encrypted_payload)
        self.assertNotIn("field2", encrypted_payload)
        self.assertIn("encryptedData", encrypted_payload)
        self.assertEqual(6, len(encrypted_payload["encryptedData"].keys()))

    def test_decrypt_payload_base64_field_encoding(self):
        self._config._data_encoding = ClientEncoding.BASE64
        self._config._encryption_certificate_fingerprint_field_name = "encryptionCertificateFingerprint"
        self._config._encryption_key_fingerprint_field_name = "encryptionKeyFingerprint"
        self._config._oaep_padding_digest_algorithm_field_name = "oaepHashingAlgorithm"

        encrypted_payload = {
            "encryptedData": {
                "iv": "uldLBySPY3VrznePihFYGQ==",
                "encryptedKey": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==",
                "encryptedValue": "KGfmdUWy89BwhQChzqZJ4w==",
                "encryptionCertificateFingerprint": "gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=",
                "encryptionKeyFingerprint": "dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=",
                "oaepHashingAlgorithm": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertNotIn("encryptedData", payload)
        self.assertDictEqual({"data": {}}, payload)

    def test_decrypt_payload_hex_field_encoding(self):
        self._config._data_encoding = ClientEncoding.HEX
        self._config._encryption_certificate_fingerprint_field_name = "encryptionCertificateFingerprint"
        self._config._encryption_key_fingerprint_field_name = "encryptionKeyFingerprint"
        self._config._oaep_padding_digest_algorithm_field_name = "oaepHashingAlgorithm"

        encrypted_payload = {
            "encryptedData": {
                "iv": "ba574b07248f63756bce778f8a115819",
                "encryptedKey": "26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24",
                "encryptedValue": "2867e67545b2f3d0708500a1cea649e3",
                "encryptionCertificateFingerprint": "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
                "encryptionKeyFingerprint": "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79",
                "oaepHashingAlgorithm": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertNotIn("encryptedData", payload)
        self.assertDictEqual({"data": {}}, payload)

    def test_decrypt_payload_as_string(self):
        encrypted_payload_string = '{' \
                                '"encryptedData": {' \
                                    '"iv": "uldLBySPY3VrznePihFYGQ==",' \
                                    '"encryptedKey": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==","encryptedValue": "KGfmdUWy89BwhQChzqZJ4w==",' \
                                    '"oaepHashingAlgo": "SHA256"' \
                                '}' \
                            '}'

        payload = to_test.decrypt_payload(encrypted_payload_string, self._config)
        self.assertNotIn("encryptedData", payload)
        self.assertDictEqual({"data": {}}, payload)

    def test_decrypt_payload_with_type_string(self):
        encrypted_payload = {
            "encryptedData": {
                "iv": "O3Q2ImjdBmKxWRUk7mQVFg==",
                "encryptedKey": "kibOZUXsipx2qZxEJ3+Aociuvg8h3mFSm+7DM/AkLKvxPpqzm2l7IyERhGRVf/amEuIeCkoNvDE+LgxDPPFWPTEXg7warFtZCnEPlzuD/uES67QYMp9HUAtK240VwM8hJ+KFS8C4Scc3Eb1GZkIRXbgziyTD3HClQA/iMUNlwiVsMrLAiSucyteR17fKEbJqKOtn2kAZFz6jFVQKvxZdsqF+Xwcz+uNpzRCsLMZqqnqAXqqOjK0sfOTjn47JfUW/46O4stsHL392Nt4N1X3YDuab2ikve1wdk+NRV6QLjcaS2bsFC31T0vWMJdsjnAn5Pnbu0AdYaOrJxvRyBjCFxg==",
                "encryptedValue": "SG7XYn5kKlsbSXhpDW/kUQ==",
                "oaepHashingAlgo": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedData", payload)
        self.assertDictEqual({"data": "string"}, payload)

    def test_decrypt_payload_with_type_integer(self):
        encrypted_payload = {
            "encryptedData": {
                "iv": "EmYzzlZKAVbaSF/Y4syvJA==",
                "encryptedKey": "gDQtozERUlMJddjoX5oW7dYzS0DYt1+HG3wtniMfeoG+5jQfT8zUC6jN/2/itO8oX3EeoU8/a77NGy8OUSjfFUibuy4rvP6ojbtakBn3BnYNi8KEVK25Yk5uJqfBj2g7T+zWDcOwJE9vFBwf8Sj2D5hjoxxGlRXhFNJoF0sOzE6qqUIzjnIHk6xigk3zfhUOiCyFa7OdsuLRAfAXETRTk/qnI/0MYd7E3fyT0fDqbwijNw1L8nosfiSuK3bbTwU6cLKDbZW5gp3AGgZAdlBRPrH/iLi+ctDyYw8ebktcPpXk/4OmV/ZQv4C6/dR20RuK4Cp1INRVS2nrS8Xbin0flg==",
                "encryptedValue": "wReq0oQGo5QjRYGUPlIVHg==",
                "oaepHashingAlgo": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedData", payload)
        self.assertDictEqual({"data": 12345}, payload)

    def test_decrypt_payload_with_type_boolean(self):
        encrypted_payload = {
            "encryptedData": {
                "iv": "F1A4qvOslYRmvzWfwcKbTw==",
                "encryptedKey": "Hdg0V/zckF54UHGmOz3ETQYg9RKqvdc0P2dK3ftIf1sMgQO4TpPGUwghHFVN9t/UMdovcqPexSrLMo3r1GrL1lMDGXKGOhS+lCkU571JdPHgNGP372ZuaeBvGkk0LEnM79jS4lQG3NIC0mlQ5NDwMXqRDwV2xVG6knSGq6WqRMyWfMY7GzrAbtUxyfci1JGideFyBDGqXkCFPh1P2Sn2VJO3ZVdSVHj2C2Xxi5p9/LD2UfAZCckZSw/H6GR+WzOdITbwhYNnsGBZbl+Ft0hnYBmLcqHfFEKocPdDDHXkaoEENzWppIME1yRqUptigv+D2/o74+w4uZiqVl3LH10qJg==",
                "encryptedValue": "1vyqJ7nIbb0amo4wV8OdKQ==",
                "oaepHashingAlgo": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedData", payload)
        self.assertDictEqual({"data": False}, payload)

    def test_decrypt_payload_with_type_list(self):
        encrypted_payload = {
            "encryptedData": {
                "iv": "unaCJ1/6/wH2X4WgNAjGsQ==",
                "encryptedKey": "Y85zA4Ss/c9DGs3FvT9kv4XXdWSWfcvKeYOOuD9S61XuUhpN9ICu6KXuRVACgApo2E2Y0hLC1YQf9KwXTVm1X3dLY0zxSOB8n1TpDl4TgB2wtMsiuSotUE4YqsinLZI6F+utJ1ufnQx6LFjwdPgZYb6JOjHxoitBQbQif9LhooEN0Zbbc8GQH17Dpf2dsmUvA9NnoSmYji1HUzkrajgJWM1Fn47jpSmaKZ85/F1gBXcZ0D5KGfT83D5VywU+MTbNEudu2cQcEHFe1l9TIjrqB5M7d+VklpFlLZ+UZVAUK4xb8lz9Q0ohZte3ohws94XbaQyMsvQFkEPH7JdofcGtAQ==",
                "encryptedValue": "kyGB3cPNP+tUdEqOYbJcmFjwMxD/DK9kubzjonsDdEU=",
                "oaepHashingAlgo": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)
        self.assertNotIn("encryptedData", payload)
        self.assertDictEqual({"data": ["item1", "item2", "item3"]}, payload)

    def test_decrypt_payload_skip_when_in_path_does_not_exist(self):
        encrypted_payload = {"data": {}}

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertDictEqual({"data": {}}, payload)

    def test_decrypt_payload_skip_when_encrypted_value_does_not_exist(self):
        encrypted_payload = {
            "encryptedData": {
                "iv": "ba574b07248f63756bce778f8a115819",
                "encryptedKey": "26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24",
                "oaepHashingAlgorithm": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertDictEqual(encrypted_payload, payload)

    def test_decrypt_payload_create_node_when_out_path_parent_exists(self):
        self._config._paths["$"]._to_decrypt = {"encryptedData": "dataParent.data"}
        self._config._encryption_certificate_fingerprint_field_name = "encryptionCertificateFingerprint"
        self._config._encryption_key_fingerprint_field_name = "encryptionKeyFingerprint"
        self._config._oaep_padding_digest_algorithm_field_name = "oaepHashingAlgorithm"

        encrypted_payload = {
            "encryptedData": {
                "iv": "uldLBySPY3VrznePihFYGQ==",
                "encryptedKey": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==",
                "encryptedValue": "KGfmdUWy89BwhQChzqZJ4w==",
                "encryptionCertificateFingerprint": "gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=",
                "encryptionKeyFingerprint": "dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=",
                "oaepHashingAlgorithm": "SHA256"
            },
            "dataParent": {}
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertNotIn("encryptedData", payload)
        self.assertIn("dataParent", payload)
        self.assertIn("data", payload["dataParent"])

    def test_decrypt_payload_fail_when_out_path_parent_does_not_exist(self):
        self._config._paths["$"]._to_decrypt = {"encryptedData": "notExistingDataParent.data"}
        self._config._encryption_certificate_fingerprint_field_name = "encryptionCertificateFingerprint"
        self._config._encryption_key_fingerprint_field_name = "encryptionKeyFingerprint"
        self._config._oaep_padding_digest_algorithm_field_name = "oaepHashingAlgorithm"

        encrypted_payload = {
            "encryptedData": {
                "iv": "uldLBySPY3VrznePihFYGQ==",
                "encryptedKey": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==",
                "encryptedValue": "KGfmdUWy89BwhQChzqZJ4w==",
                "encryptionCertificateFingerprint": "gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=",
                "encryptionKeyFingerprint": "dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=",
                "oaepHashingAlgorithm": "SHA256"
            },
            "dataParent": {}
        }

        self.assertRaises(EncryptionError, to_test.decrypt_payload, encrypted_payload, self._config)

    def test_decrypt_payload_when_out_path_same_as_in_path(self):
        self._config._paths["$"]._to_decrypt = {"data": "data"}
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "data": {
                "iv": "17492f69d92d2008ee9289cf3e07bd36",
                "encryptedKey": "22b3df5e70777cef394c39ac74bacfcdbfc8cef4a4da771f1d07611f18b4dc9eacde7297870acb421abe77b8b974f53b2e5b834a68e11a4ddab53ece2d37ae7dee5646dc3f4c5c17166906258615b9c7c52f7242a1afa6edf24815c3dbec4b2092a027de11bcdab4c47de0159ce76d2449394f962a07196a5a5b41678a085d77730baee0d3d0e486eb4719aae8f1f1c0fd7026aea7b0872c049e8df1e7eed088fa84fc613602e989fa4e7a7b77ac40da212a462ae5d3df5078be96fcf3d0fe612e0ec401d27a243c0df1feb8241d49248697db5ec79571b9d52386064ee3db11d200156bfd3af03a289ea37ec2c8f315840e7804669a855bf9e34190e3b14d28",
                "encryptedValue": "9cad34c0d7b2443f07bb7b7e19817ade132ba3f312b1176c09a312e5b5f908198e1e0cfac0fd8c9f66c70a9b05b1a701",
                "oaepHashingAlgo": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertIn("data", payload)
        self.assertIn("field1", payload["data"])
        self.assertIn("field2", payload["data"])
        self.assertNotIn("iv", payload["data"])
        self.assertNotIn("encryptedKey", payload["data"])
        self.assertNotIn("encryptedValue", payload["data"])
        self.assertNotIn("oaepHashingAlgo", payload["data"])

    def test_decrypt_payload_when_out_path_already_contains_data(self):
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "encryptedData": {
                "iv": "17492f69d92d2008ee9289cf3e07bd36",
                "encryptedKey": "22b3df5e70777cef394c39ac74bacfcdbfc8cef4a4da771f1d07611f18b4dc9eacde7297870acb421abe77b8b974f53b2e5b834a68e11a4ddab53ece2d37ae7dee5646dc3f4c5c17166906258615b9c7c52f7242a1afa6edf24815c3dbec4b2092a027de11bcdab4c47de0159ce76d2449394f962a07196a5a5b41678a085d77730baee0d3d0e486eb4719aae8f1f1c0fd7026aea7b0872c049e8df1e7eed088fa84fc613602e989fa4e7a7b77ac40da212a462ae5d3df5078be96fcf3d0fe612e0ec401d27a243c0df1feb8241d49248697db5ec79571b9d52386064ee3db11d200156bfd3af03a289ea37ec2c8f315840e7804669a855bf9e34190e3b14d28",
                "encryptedValue": "9cad34c0d7b2443f07bb7b7e19817ade132ba3f312b1176c09a312e5b5f908198e1e0cfac0fd8c9f66c70a9b05b1a701",
                "oaepHashingAlgo": "SHA256"
            },
            "data": {
                "field1": "previousField1Value",
                "field3": "field3Value"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertNotIn("encryptedData", payload)
        self.assertIn("data", payload)
        self.assertIn("field1", payload["data"])
        self.assertIn("field2", payload["data"])
        self.assertIn("field3", payload["data"])
        self.assertEqual("field1Value", payload["data"]["field1"])
        self.assertEqual("field2Value", payload["data"]["field2"])
        self.assertEqual("field3Value", payload["data"]["field3"])

    def test_decrypt_payload_when_out_path_already_contains_string_data(self):
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "encryptedData": {
                "iv": "17492f69d92d2008ee9289cf3e07bd36",
                "encryptedKey": "22b3df5e70777cef394c39ac74bacfcdbfc8cef4a4da771f1d07611f18b4dc9eacde7297870acb421abe77b8b974f53b2e5b834a68e11a4ddab53ece2d37ae7dee5646dc3f4c5c17166906258615b9c7c52f7242a1afa6edf24815c3dbec4b2092a027de11bcdab4c47de0159ce76d2449394f962a07196a5a5b41678a085d77730baee0d3d0e486eb4719aae8f1f1c0fd7026aea7b0872c049e8df1e7eed088fa84fc613602e989fa4e7a7b77ac40da212a462ae5d3df5078be96fcf3d0fe612e0ec401d27a243c0df1feb8241d49248697db5ec79571b9d52386064ee3db11d200156bfd3af03a289ea37ec2c8f315840e7804669a855bf9e34190e3b14d28",
                "encryptedValue": "9cad34c0d7b2443f07bb7b7e19817ade132ba3f312b1176c09a312e5b5f908198e1e0cfac0fd8c9f66c70a9b05b1a701",
                "oaepHashingAlgo": "SHA256"
            },
            "data": "toBeReplaced"
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertNotIn("encryptedData", payload)
        self.assertIn("data", payload)
        self.assertIn("field1", payload["data"])
        self.assertIn("field2", payload["data"])
        self.assertEqual("field1Value", payload["data"]["field1"])
        self.assertEqual("field2Value", payload["data"]["field2"])

    def test_decrypt_payload_when_in_path_contains_additional_fields(self):
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "encryptedData": {
                "iv": "17492f69d92d2008ee9289cf3e07bd36",
                "encryptedKey": "22b3df5e70777cef394c39ac74bacfcdbfc8cef4a4da771f1d07611f18b4dc9eacde7297870acb421abe77b8b974f53b2e5b834a68e11a4ddab53ece2d37ae7dee5646dc3f4c5c17166906258615b9c7c52f7242a1afa6edf24815c3dbec4b2092a027de11bcdab4c47de0159ce76d2449394f962a07196a5a5b41678a085d77730baee0d3d0e486eb4719aae8f1f1c0fd7026aea7b0872c049e8df1e7eed088fa84fc613602e989fa4e7a7b77ac40da212a462ae5d3df5078be96fcf3d0fe612e0ec401d27a243c0df1feb8241d49248697db5ec79571b9d52386064ee3db11d200156bfd3af03a289ea37ec2c8f315840e7804669a855bf9e34190e3b14d28",
                "encryptedValue": "9cad34c0d7b2443f07bb7b7e19817ade132ba3f312b1176c09a312e5b5f908198e1e0cfac0fd8c9f66c70a9b05b1a701",
                "oaepHashingAlgo": "SHA256",
                "field": "fieldValue"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertIn("encryptedData", payload)
        self.assertIn("data", payload)
        self.assertIn("field", payload["encryptedData"])
        self.assertEqual("fieldValue", payload["encryptedData"]["field"])

    def test_decrypt_payload_with_multiple_decryption_paths(self):
        self._config._paths["$"]._to_decrypt = {"encryptedData1": "data1", "encryptedData2": "data2"}
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "encryptedData2": {
                "iv": "c1ffb457798714b679e5b59e5b8fb62c",
                "encryptedKey": "f16425f1550c28515bc83e25f7f63ca8102a2cbbadd6452c610f03d920563856f1a7318d98bc0939a3a6a84922caebc3691b34aa96ed4d2d016727a30d3622966dec3cb13f9da9d149106afc2b81846e624aa6134551bca169fa539df4034b48e47923cb4f2636b993c805b851cc046a7e98a70ff1c6b43207ac8dcbfbf6132a070860040093d4399af70b0d45cf44854390df9c24f2eb17aa6e745da1a2b7a765f8b4970f6764731d6a7d51af85be669e35ad433ff0942710764265253c956797cd1e3c8ba705ee8578373a14bbab368426d3797bd68076f6ec9c4ef8d43c2959f4fd4c17897a9d6d0622ffc662d5f5c304fb6d5ca84de63f7cf9b9dfe700d2",
                "encryptedValue": "a49dff0a6f9ca58bdd3e991f13eb8e53"
            },
            "encryptedData1": {
                "iv": "4c278e7b0c0890973077960f682181b6",
                "encryptedKey": "c2c4a40433e91d1175ba933ddb7eb014e9839e3bf639c6c4e2ea532373f146ee6a88515103cb7aeb9df328c67b747c231bfdf4a6b3d366792b6e9ec0f106447f28518a864cc9dd59ed6e1a9ed017229166f23389b4c141b4492981e51ad6863ed48e8c93394378a8e8ab922b8c96dfdf6c683c334eef4c668d9f059b6ac6c26a7d623032ef0bac0e3d4fde5a735d4c09879364efb723c2f2bd3288f8619f9f1a63ed1e283ae7cb40726632fe271fea08252991a158bce3aeca90a4ce7b6895f7b94516ada042de80942ddbc3462baeee49c4169c18c0024fec48743610281cec0333906953da783b3bcd246226efccff4cdefa62c26753db228e0120feff2bdc",
                "encryptedValue": "1ea73031bc0cf9c67b61bc1684d78f2b"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertNotIn("encryptedData1", payload)
        self.assertNotIn("encryptedData2", payload)
        self.assertIn("data1", payload)
        self.assertIn("data1", payload)

    def test_decrypt_payload_when_oaep_padding_digest_algorithm_field_not_returned(self):
        encrypted_payload = {
            "encryptedData": {
                "iv": "uldLBySPY3VrznePihFYGQ==",
                "encryptedKey": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==",
                "encryptedValue": "KGfmdUWy89BwhQChzqZJ4w=="
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertDictEqual({"data": {}}, payload)

    def test_decrypt_payload_when_root_as_in_path(self):
        self._config._paths["$"]._to_decrypt = {"$": "data"}
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "iv": "6fef040c8fe8ad9ec56b74efa194b5f7",
            "encryptedKey": "b04c69e1ca944fd7641ea79f03e5cd540144759212fa50d07c8a97ab30ca8bded324e2d4b8cd2613b25cd6bceac35b76c2fa1b521ff205b5f33eafaf4102efbefd35cae6707f985953d6dac366cca36295b29d8af3d94d5d5d1532158066b9fecfc2cc000f10e4757967e84c043d7db164d7488f5bef28f59c989c4cd316c870da7b7c1d10cfd73b6d285cd43447e9e96702e3e818011b45b0ecda21b02286db04b7c77ab193dcc4a9036beff065a404689b7cea40b6a348554900ae3eb819af9cb53ab800e158051aac8d8075045a06808e3730cd8cbc1b5334dcdc922d0227f6da1518442914ac5f3abf6751dfb5721074459d0626b62e934f6a6e6fd96020",
            "encryptedValue": "386cdb354a33a5b5ae44fa73622297d0372857d1f7634b45010f691964958e2afca0f7391742dc1243768ccf0b4fce8b",
            "certFingerprint": "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
            "keyFingerprint": "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79",
            "oaepHashingAlgo": "SHA256"
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertDictEqual({"data": {"field1": "value1", "field2": "value2"}}, payload)

    def test_decrypt_payload_when_root_as_in_and_out_path(self):
        self._config._paths["$"]._to_decrypt = {"$": "$"}
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "iv": "6fef040c8fe8ad9ec56b74efa194b5f7",
            "encryptedKey": "b04c69e1ca944fd7641ea79f03e5cd540144759212fa50d07c8a97ab30ca8bded324e2d4b8cd2613b25cd6bceac35b76c2fa1b521ff205b5f33eafaf4102efbefd35cae6707f985953d6dac366cca36295b29d8af3d94d5d5d1532158066b9fecfc2cc000f10e4757967e84c043d7db164d7488f5bef28f59c989c4cd316c870da7b7c1d10cfd73b6d285cd43447e9e96702e3e818011b45b0ecda21b02286db04b7c77ab193dcc4a9036beff065a404689b7cea40b6a348554900ae3eb819af9cb53ab800e158051aac8d8075045a06808e3730cd8cbc1b5334dcdc922d0227f6da1518442914ac5f3abf6751dfb5721074459d0626b62e934f6a6e6fd96020",
            "encryptedValue": "386cdb354a33a5b5ae44fa73622297d0372857d1f7634b45010f691964958e2afca0f7391742dc1243768ccf0b4fce8b",
            "certFingerprint": "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
            "keyFingerprint": "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79",
            "oaepHashingAlgo": "SHA256"
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertDictEqual({"field1": "value1", "field2": "value2"}, payload)

    def test_DecryptPayload_ShouldOverwriteInputObject_WhenOutPathSameAsInPath_PrimitiveTypeData(self):
        self._config._paths["$"]._to_decrypt = {"data": "data"}
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "data": {
                "encryptedValue": "741a932b1ed546072384eef82f42c781",
                "encryptedKey": "0069fd96179b119cda77ec56be29b184d25c639af27c1f59b6b5e4de4e9bcba883d7933dda5cb6bb8888ea402cbd0f2cddf572b2baee2dd57c94081e4db318a0ded28ae96a80eff1ed421ca7bae6418fae3a1ce9744c02d4aa4dc53efa69b483a2e030919df30a87f95bb18595b4beb15b65eff3c1332c2d54100bd39ccb3ab7eeea648e0ccc473586002063a380dddd940aaa075b998047bd75a5cdb79142c150fa87e9ec2706569a5f7f06bc36c959f144cd22fbf5e690388902eca06d3cc4492d50b72ed5e96f66e6f03087931d3147401720fb512c0c3d5b89fa029fba157fbb1571a4712377b68bac4344dbf75535a1b40197a293eadc563ea035b62591",
                "iv": "f84e565520f5b75cbb6a13c97fdaea2b",
                "oaepHashingAlgo": "SHA256",
                "certFingerprint": "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
                "keyFingerprint": "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertEqual("string", payload['data'])

    def test_decrypt_payload_when_decryption_error_occurs(self):
        encrypted_payload = {
            "encryptedData": {
                "iv": "uldLBySPY3VrznePihFYGQ==",
                "encryptedKey": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==",
                "encryptedValue": "KGfmdUWy89BwhQChzqZJ4w=="
            }
        }

        decrypt_mock = Mock(side_effect=ValueError("Data must be aligned to block boundary in ECB mode"))

        with patch('client_encryption.field_level_encryption._decrypt_bytes', decrypt_mock):
            self.assertRaises(EncryptionError, to_test.decrypt_payload, encrypted_payload, self._config)

    def test_decrypt_payload_when_certificate_and_key_fingerprint_field_name_not_set(self):
        self._config._encryption_certificate_fingerprint_field_name = None
        self._config._encryption_key_fingerprint_field_name = None

        encrypted_payload = {
            "encryptedData": {
                "iv": "uldLBySPY3VrznePihFYGQ==",
                "encryptedKey": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==",
                "encryptedValue": "KGfmdUWy89BwhQChzqZJ4w==",
                "encryptionCertificateFingerprint": "gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=",
                "encryptionKeyFingerprint": "dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=",
                "oaepHashingAlgo": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config)

        self.assertIn("encryptedData", payload)
        self.assertNotIn("iv", payload["encryptedData"])
        self.assertNotIn("encryptedKey", payload["encryptedData"])
        self.assertNotIn("encryptedValue", payload["encryptedData"])
        self.assertNotIn("oaepHashingAlgo", payload["encryptedData"])
        self.assertIn("encryptionCertificateFingerprint", payload["encryptedData"])
        self.assertIn("encryptionKeyFingerprint", payload["encryptedData"])

    def test_decrypt_payload_when_session_key_params_is_provided(self):
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "encryptedData": {
                "encryptedValue": "2867e67545b2f3d0708500a1cea649e3"
            }
        }

        iv_value = "ba574b07248f63756bce778f8a115819"
        encrypted_key = "26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24"
        oaep_hashing_algo = "SHA256"

        params = SessionKeyParams(self._config, encrypted_key, iv_value, oaep_hashing_algo)
        payload = to_test.decrypt_payload(encrypted_payload, self._config, params)

        self.assertNotIn("encryptedData", payload)
        self.assertDictEqual({"data": {}}, payload)

    def test_decrypt_payload_when_session_key_params_is_None(self):
        self._config._data_encoding = ClientEncoding.HEX

        encrypted_payload = {
            "encryptedData": {
                "iv": "ba574b07248f63756bce778f8a115819",
                "encryptedKey": "26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24",
                "encryptedValue": "2867e67545b2f3d0708500a1cea649e3",
                "oaepHashingAlgo": "SHA256"
            }
        }

        payload = to_test.decrypt_payload(encrypted_payload, self._config, None)

        self.assertNotIn("encryptedData", payload)
        self.assertDictEqual({"data": {}}, payload)

    def test_decrypt_payload_when_encryption_params_are_missing(self):
        encrypted_payload = {
            "encryptedData": {
                "encryptedValue": "KGfmdUWy89BwhQChzqZJ4w=="
            }
        }

        self.assertRaises(EncryptionError, to_test.decrypt_payload, encrypted_payload, self._config)
