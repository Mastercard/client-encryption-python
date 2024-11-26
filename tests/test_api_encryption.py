import unittest
from unittest.mock import patch, Mock
import json
from tests.utils.api_encryption_test_utils import MockApiClient, MockService, MockRestApiClient
from tests import get_mastercard_config_for_test, MASTERCARD_TEST_CONFIG, get_jwe_config_for_test
import client_encryption.api_encryption as to_test


class ApiEncryptionTest(unittest.TestCase):

    def setUp(self):
        self._json_config = json.loads(get_mastercard_config_for_test())
        self._jwe_json_config = json.loads(get_jwe_config_for_test())
        self._json_config["paths"]["$"]["toEncrypt"] = {"data": "encryptedData"}
        self._json_config["paths"]["$"]["toDecrypt"] = {"encryptedData": "data"}

    def _set_header_params_config(self):
        self._json_config.update({
            "useHttpHeaders": True,
             "ivFieldName": "x-iv",
             "encryptedKeyFieldName": "x-key",
             "encryptionCertificateFingerprintFieldName": "x-cert-fingerprint",
             "encryptionKeyFingerprintFieldName": "x-key-fingerprint",
             "oaepPaddingDigestAlgorithmFieldName": "x-oaep-digest"
        })

    @patch('client_encryption.api_encryption.FieldLevelEncryptionConfig')
    def test_ApiEncryption_with_config_as_file_name(self, FieldLevelEncryptionConfig):
        to_test.ApiEncryption(MASTERCARD_TEST_CONFIG)

        assert FieldLevelEncryptionConfig.called

    @patch('client_encryption.api_encryption.FieldLevelEncryptionConfig')
    def test_ApiEncryption_with_config_as_dict(self, FieldLevelEncryptionConfig):
        to_test.ApiEncryption(self._json_config)

        assert FieldLevelEncryptionConfig.called

    def test_ApiEncryption_fail_with_config_as_string(self):
        self.assertRaises(FileNotFoundError, to_test.ApiEncryption, "this is not accepted")

    def test_encrypt_payload_returns_same_data_type_as_input(self):
        api_encryption = to_test.ApiEncryption(self._json_config)

        test_headers = {"Content-Type": "application/json"}

        body = {
            "data": {
                "secret1": "test",
                "secret2": "secret"
            },
            "encryptedData": {}
        }

        encrypted = api_encryption._encrypt_payload(body=body, headers=test_headers)
        self.assertIsInstance(encrypted, dict)

        encrypted = api_encryption._encrypt_payload(body=json.dumps(body), headers=test_headers)
        self.assertIsInstance(encrypted, str)

        encrypted = api_encryption._encrypt_payload(body=json.dumps(body).encode("utf-8"), headers=test_headers)
        self.assertIsInstance(encrypted, bytes)

    def test_encrypt_payload_with_params_in_body(self):
        api_encryption = to_test.ApiEncryption(self._json_config)

        test_headers = {"Content-Type": "application/json"}

        encrypted = api_encryption._encrypt_payload(body={
            "data": {
                "secret1": "test",
                "secret2": "secret"
            },
            "encryptedData": {}
        }, headers=test_headers)

        self.assertNotIn("data", encrypted)
        self.assertIn("encryptedData", encrypted)
        self.assertIn("encryptedValue", encrypted["encryptedData"])
        self.assertEqual(6, len(encrypted["encryptedData"].keys()))
        self.assertDictEqual({"Content-Type": "application/json"}, test_headers)

    def test_decrypt_payload_with_params_in_body(self):
        api_encryption = to_test.ApiEncryption(self._json_config)

        test_headers = {"Content-Type": "application/json"}

        decrypted = json.loads(api_encryption._decrypt_payload(body={
            "encryptedData": {
                "iv": "uldLBySPY3VrznePihFYGQ==",
                "encryptedKey": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==",
                "encryptedValue": "KGfmdUWy89BwhQChzqZJ4w==",
                "oaepHashingAlgo": "SHA256"
            }
        }, headers=test_headers))

        self.assertNotIn("encryptedData", decrypted)
        self.assertDictEqual({"data": {}}, decrypted)
        self.assertDictEqual({"Content-Type": "application/json"}, test_headers)

    def test_encrypt_payload_with_params_in_headers(self):
        self._set_header_params_config()

        test_headers = {"Content-Type": "application/json"}

        api_encryption = to_test.ApiEncryption(self._json_config)
        encrypted = api_encryption._encrypt_payload(body={
            "data": {
                "secret1": "test",
                "secret2": "secret"
            },
            "encryptedData": {}
        }, headers=test_headers)

        self.assertNotIn("data", encrypted)
        self.assertIn("encryptedData", encrypted)
        self.assertIn("encryptedValue", encrypted["encryptedData"])
        self.assertEqual(1, len(encrypted["encryptedData"].keys()))
        self.assertIn("x-iv", test_headers)
        self.assertIn("x-key", test_headers)
        self.assertIn("x-cert-fingerprint", test_headers)
        self.assertIn("x-key-fingerprint", test_headers)
        self.assertIn("x-oaep-digest", test_headers)
        self.assertEqual(6, len(test_headers.keys()))

    def test_decrypt_payload_with_params_in_headers(self):
        self._set_header_params_config()

        test_headers = {"Content-Type": "application/json",
                        "x-iv": "uldLBySPY3VrznePihFYGQ==",
                        "x-key": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==",
                        "x-cert-fingerprint": "gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=",
                        "x-key-fingerprint": "dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=",
                        "x-oaep-digest": "SHA256"
                        }

        api_encryption = to_test.ApiEncryption(self._json_config)
        decrypted = json.loads(api_encryption._decrypt_payload(body={
            "encryptedData": {
                "encryptedValue": "KGfmdUWy89BwhQChzqZJ4w=="
            }
        }, headers=test_headers))

        self.assertNotIn("encryptedData", decrypted)
        self.assertDictEqual({"data": {}}, decrypted)
        self.assertDictEqual({"Content-Type": "application/json"}, test_headers)

    def test_decrypt_payload_with_params_in_headers_skip_decrypt(self):
        self._set_header_params_config()

        test_headers = {"Content-Type": "application/json",
                        "x-key": "Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==",
                        "x-cert-fingerprint": "gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=",
                        "x-key-fingerprint": "dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=",
                        "x-oaep-digest": "SHA256"
                        }

        api_encryption = to_test.ApiEncryption(self._json_config)
        decrypted = api_encryption._decrypt_payload(body={
            "data": {
                "key1": "notSecret",
                "key2": "anotherValue"
            },
        }, headers=test_headers)

        self.assertDictEqual({"data": {"key1": "notSecret", "key2": "anotherValue"}}, decrypted)
        self.assertEqual(5, len(test_headers.keys()))

    @patch('client_encryption.api_encryption.FieldLevelEncryptionConfig')
    def test_add_header_encryption_layer_with_config_as_file_name(self, FieldLevelEncryptionConfig):
        to_test.add_encryption_layer(MockApiClient(), MASTERCARD_TEST_CONFIG)

        assert FieldLevelEncryptionConfig.called

    @patch('client_encryption.api_encryption.FieldLevelEncryptionConfig')
    def test_add_header_encryption_layer_with_config_as_dict(self, FieldLevelEncryptionConfig):
        to_test.add_encryption_layer(MockApiClient(), self._json_config)

        assert FieldLevelEncryptionConfig.called

    def test_add_header_encryption_layer_fail_with_config_as_string(self):
        self.assertRaises(FileNotFoundError, to_test.add_encryption_layer, MockApiClient(), "this is not accepted")

    def test_add_encryption_layer_post(self):
        secret1 = 435
        secret2 = 746
        test_client = MockApiClient()
        to_test.add_encryption_layer(test_client, self._json_config)
        response = MockService(test_client).do_something_post(body={
            "data": {
                "secret1": secret1,
                "secret2": secret2
            }
        }, headers={"Content-Type": "application/json"})

        self.assertIn("data", json.loads(response.data))
        self.assertIn("secret", json.loads(response.data)["data"])
        self.assertEqual(secret2-secret1, json.loads(response.data)["data"]["secret"])
        self.assertDictEqual({"Content-Type": "application/json"}, response.getheaders())

    def test_add_encryption_layer_delete(self):
        secret1 = 394
        secret2 = 394
        test_client = MockApiClient()
        to_test.add_encryption_layer(test_client, self._json_config)
        response = MockService(test_client).do_something_delete(body={
            "data": {
                "secret1": secret1,
                "secret2": secret2
            }
        }, headers={"Content-Type": "application/json"})

        self.assertEqual("OK", json.loads(response.data))
        self.assertDictEqual({"Content-Type": "application/json"}, response.getheaders())

    def test_add_encryption_layer_get(self):
        test_client = MockApiClient()
        to_test.add_encryption_layer(test_client, self._json_config)
        response = MockService(test_client).do_something_get(headers={"Content-Type": "application/json"})
        json_res = json.loads(response.data)

        self.assertIn("data", json_res)
        self.assertIn("secret", json_res['data'])
        self.assertEqual([53, 84, 75], json_res["data"]["secret"])
        self.assertDictEqual({"Content-Type": "application/json"}, response.getheaders())

    def test_add_header_encryption_layer_post_no_oaep_algo(self):
        self._set_header_params_config()
        del self._json_config["oaepPaddingDigestAlgorithmFieldName"]

        secret1 = 435
        secret2 = 746
        test_client = MockApiClient()
        to_test.add_encryption_layer(test_client, self._json_config)
        response = MockService(test_client).do_something_post_use_headers(body={
            "data": {
                "secret1": secret1,
                "secret2": secret2
            },
            "encryptedData": {}
        }, headers={"Content-Type": "application/json"})

        self.assertIn("data", json.loads(response.data))
        self.assertIn("secret", json.loads(response.data)["data"])
        self.assertEqual(secret2-secret1, json.loads(response.data)["data"]["secret"])
        self.assertDictEqual({"Content-Type": "application/json", "x-oaep-digest": "SHA256"}, response.getheaders())

    def test_add_header_encryption_layer_post_no_cert_fingerprint(self):
        self._set_header_params_config()
        del self._json_config["encryptionCertificateFingerprintFieldName"]

        secret1 = 164
        secret2 = 573
        test_client = MockApiClient()
        to_test.add_encryption_layer(test_client, self._json_config)
        response = MockService(test_client).do_something_post_use_headers(body={
            "data": {
                "secret1": secret1,
                "secret2": secret2
            },
            "encryptedData": {}
        }, headers={"Content-Type": "application/json"})

        self.assertIn("data", json.loads(response.data))
        self.assertIn("secret", json.loads(response.data)["data"])
        self.assertEqual(secret2-secret1, json.loads(response.data)["data"]["secret"])
        self.assertDictEqual({"Content-Type": "application/json"}, response.getheaders())

    def test_add_header_encryption_layer_post_no_pubkey_fingerprint(self):
        self._set_header_params_config()
        del self._json_config["encryptionKeyFingerprintFieldName"]

        secret1 = 245
        secret2 = 854
        test_client = MockApiClient()
        to_test.add_encryption_layer(test_client, self._json_config)
        response = MockService(test_client).do_something_post_use_headers(body={
            "data": {
                "secret1": secret1,
                "secret2": secret2
            },
            "encryptedData": {}
        }, headers={"Content-Type": "application/json"})

        self.assertIn("data", json.loads(response.data))
        self.assertIn("secret", json.loads(response.data)["data"])
        self.assertEqual(secret2-secret1, json.loads(response.data)["data"]["secret"])
        self.assertDictEqual({"Content-Type": "application/json"}, response.getheaders())

    def test_add_header_encryption_layer_no_iv(self):
        self._set_header_params_config()
        del self._json_config["ivFieldName"]

        test_client = MockApiClient()

        self.assertRaises(KeyError, to_test.add_encryption_layer, test_client, self._json_config)

    def test_add_header_encryption_layer_no_secret_key(self):
        self._set_header_params_config()
        del self._json_config["encryptedKeyFieldName"]

        test_client = MockApiClient()

        self.assertRaises(KeyError, to_test.add_encryption_layer, test_client, self._json_config)

    def test_add_header_encryption_layer_post(self):
        self._set_header_params_config()

        secret1 = 445
        secret2 = 497
        test_client = MockApiClient()
        to_test.add_encryption_layer(test_client, self._json_config)
        response = MockService(test_client).do_something_post_use_headers(body={
            "data": {
                "secret1": secret1,
                "secret2": secret2
            },
            "encryptedData": {}
        }, headers={"Content-Type": "application/json"})

        self.assertIn("data", json.loads(response.data))
        self.assertIn("secret", json.loads(response.data)["data"])
        self.assertEqual(secret2-secret1, json.loads(response.data)["data"]["secret"])
        self.assertDictEqual({"Content-Type": "application/json"}, response.getheaders())

    def test_add_header_encryption_layer_delete(self):
        self._set_header_params_config()

        secret1 = 783
        secret2 = 783
        test_client = MockApiClient()
        to_test.add_encryption_layer(test_client, self._json_config)
        response = MockService(test_client).do_something_delete_use_headers(body={
            "data": {
                "secret1": secret1,
                "secret2": secret2
            },
            "encryptedData": {}
        }, headers={"Content-Type": "application/json"})

        self.assertEqual("OK", response.data)
        self.assertDictEqual({"Content-Type": "application/json"}, response.getheaders())

    def test_add_header_encryption_layer_get(self):
        self._set_header_params_config()

        test_client = MockApiClient()
        to_test.add_encryption_layer(test_client, self._json_config)
        response = MockService(test_client).do_something_get_use_headers(headers={"Content-Type": "application/json"})

        self.assertIn("data", json.loads(response.data))
        self.assertIn("secret", json.loads(response.data)["data"])
        self.assertEqual([53, 84, 75], json.loads(response.data)["data"]["secret"])
        self.assertDictEqual({"Content-Type": "application/json"}, response.getheaders())

    @patch('client_encryption.api_encryption.__oauth_warn')
    def test_add_encryption_layer_oauth_set(self, __oauth_warn):
        test_client = MockApiClient()
        test_rest_client = MockRestApiClient(test_client)
        to_test.add_encryption_layer(test_rest_client, self._json_config)

        assert not __oauth_warn.called

    def test_add_encryption_layer_missing_oauth_layer_warning(self):
        test_client = Mock()
        test_client.rest_client.request = None

        # no __oauth__ flag
        with self.assertWarns(UserWarning):
            to_test.add_encryption_layer(test_client, self._json_config)