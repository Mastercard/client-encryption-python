import unittest
from tests import resource_path, get_mastercard_config_for_test
import json
import client_encryption.field_level_encryption_config as to_test
from client_encryption.encryption_utils import load_encryption_certificate
from client_encryption.encoding_utils import ClientEncoding
from client_encryption.encryption_exception import HashAlgorithmError, PrivateKeyError, CertificateError
from Crypto.PublicKey import RSA


class FieldLevelEncryptionConfigTest(unittest.TestCase):

    def setUp(self):
        self._test_config_file = get_mastercard_config_for_test()
        self._expected_cert, cert_type = load_encryption_certificate(resource_path("certificates/test_certificate-2048.der"))
        self._expected_key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD0ynqAQWn0T7/VJLletTJgoxsTt5TR3IkJ+Yk/Pxg6Q5hXuiGrBdC+OVo/9hrNnptuZh9rZYKto6lbSjYFiKMeBDvPZrYDPzusp0C0KllIoVbzYiOezD76XHsQAEje0UXbzZlXstPXef2bi2HkqV26ST167L5O4moK8+7jHMT80T6XgsUyvyt8PjsQ9CSu6fnD9NfCSYmt2cb16OXcEtA7To2zoGznXqB6JhntFjG0jxee7RkLR+moOqMI9kFM5GSIV4uhwQ9FtOCjUf7TFAU12wwfX/QXUEj6G93GVtzf6QdkVkWh4EyRHeMLyMNc5c0Iw1ZvXdOKfoeo9F47QpbzAgMBAAECggEAK3dMmzuCSdxjTsCPnc6E3H35z914Mm97ceb6RN26OpZIFcO6OLj2oOBkMxlLFxnDta2yhIpo0tZNuyUJRKBHfov35tLxHNB8kyK7rYIbincDjoHtm0PfJuuG+odiaRY11lrCkLzzOr6xlo4AWu7r8qkQnqQtAqrXc4xu7artG4rfMIunGnjjWQGzovtey1JgZctO97MU4Wvw18vgYBI6JM4eHJkZxgEhVQblBTKZs4OfiWk6MRHchgvqnWugwl213FgCzwy9cnyxTP13i9QKaFzL29TYmmN6bRWBH95z41M8IAa0CGahrSJjudZCFwsFh413YWv/pdqdkKHg1sqseQKBgQD641RYQkMn4G9vOiwB/is5M0OAhhUdWH1QtB8vvhY5ISTjFMqgIIVQvGmqDDk8QqFMOfFFqLtnArGn8HrKmBXMpRigS4ae/QgHEz34/RFjNDQ9zxIf/yoCRH5PmnPPU6x8j3bj/vJMRQA6/yngoca+9qvi3R32AtC5DUELnwyzNwKBgQD5x1iEV+albyCNNyLoT/f6LSH1NVcO+0IOvIaAVMtfy+hEEXz7izv3/AgcogVZzRARSK0qsQ+4WQN6Q2WG5cQYSyB92PR+VgwhnagVvA+QHNDL988xoMhB5r2D2IVSRuTB2EOg7LiWHUHIExaxVkbADODDj7YV2aQCJVv0gbDQJQKBgQCaABix5Fqci6NbPvXsczvM7K6uoZ8sWDjz5NyPzbqObs3ZpdWK3Ot4V270tnQbjTq9M4PqIlyGKp0qXO7ClQAskdq/6hxEU0UuMp2DzLNzlYPLvON/SH1czvZJnqEfzli+TMHJyaCpOGGf1Si7fhIk/f0cUGYnsCq2rHAU1hhRmQKBgE/BJTRs1MqyJxSwLEc9cZLCYntnYrr342nNLK1BZgbalvlVFDFFjgpqwTRTT54S6jR6nkBpdPmKAqBBcOOX7ftL0b4dTkQguZLqQkdeWyHK8aiPIetYyVixkoXM1xUkadqzcTSrIW1dPiniXnaVc9XSxtnqw1tKuSGuSCRUXN65AoGBAN/AmT1S4PAQpSWufC8NUJey8S0bURUNNjd52MQ7pWzGq2QC00+dBLkTPj3KOGYpXw9ScZPbxOthBFzHOxERWo16AFw3OeRtn4VB1QJ9XvoA/oz4lEhJKbwUfuFGGvSpYvg3vZcOHF2zlvcUu7C0ub/WhOjV9jZvU5B2Ev8x1neb"

    def test_load_config_as_string(self):
        conf = to_test.FieldLevelEncryptionConfig(self._test_config_file)
        self.__check_configuration(conf)

    def test_load_config_as_json(self):
        json_conf = json.loads(self._test_config_file)

        conf = to_test.FieldLevelEncryptionConfig(json_conf)
        self.__check_configuration(conf)

    def test_load_config_wrong_format(self):
        self.assertRaises(ValueError, to_test.FieldLevelEncryptionConfig, b"not a valid config format")

    def test_load_config_with_key_password(self):
        json_conf = json.loads(self._test_config_file)
        json_conf["decryptionKey"] = resource_path("keys/test_key.p12")
        json_conf["decryptionKeyPassword"] = "Password1"

        conf = to_test.FieldLevelEncryptionConfig(json_conf)
        self.assertIsNotNone(conf.decryption_key, "No key password set")

    def test_load_config_with_wrong_key_password(self):
        json_conf = json.loads(self._test_config_file)
        json_conf["decryptionKey"] = resource_path("keys/test_key.p12")
        json_conf["decryptionKeyPassword"] = "wrong_passwd"

        self.assertRaises(PrivateKeyError, to_test.FieldLevelEncryptionConfig, json_conf)

    def test_load_config_with_missing_required_key_password(self):
        json_conf = json.loads(self._test_config_file)
        json_conf["decryptionKey"] = resource_path("keys/test_key.p12")

        self.assertRaises(PrivateKeyError, to_test.FieldLevelEncryptionConfig, json_conf)

    def test_load_config_missing_paths(self):
        wrong_json = json.loads(self._test_config_file)
        del wrong_json["paths"]["$"]

        self.assertRaises(KeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

        del wrong_json["paths"]

        self.assertRaises(KeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_path_to_encrypt(self):
        wrong_json = json.loads(self._test_config_file)
        del wrong_json["paths"]["$"]["toEncrypt"]

        self.assertRaises(KeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_path_to_decrypt(self):
        wrong_json = json.loads(self._test_config_file)
        del wrong_json["paths"]["$"]["toDecrypt"]

        self.assertRaises(KeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_iv_field_name(self):
        wrong_json = json.loads(self._test_config_file)
        del wrong_json["ivFieldName"]

        self.assertRaises(KeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_encrypted_key_field_name(self):
        wrong_json = json.loads(self._test_config_file)
        del wrong_json["encryptedKeyFieldName"]

        self.assertRaises(KeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_encrypted_value_field_name(self):
        wrong_json = json.loads(self._test_config_file)
        del wrong_json["encryptedValueFieldName"]

        self.assertRaises(KeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_data_encoding(self):
        wrong_json = json.loads(self._test_config_file)
        del wrong_json["dataEncoding"]

        self.assertRaises(KeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_hex_data_encoding(self):
        json_conf = json.loads(self._test_config_file)
        json_conf["dataEncoding"] = "hex"

        conf = to_test.FieldLevelEncryptionConfig(json_conf)
        self.__check_configuration(conf, encoding=ClientEncoding.HEX)

    def test_load_config_wrong_data_encoding(self):
        wrong_json = json.loads(self._test_config_file)
        wrong_json["dataEncoding"] = "WRONG"

        self.assertRaises(ValueError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_encryption_certificate(self):
        json_conf = json.loads(self._test_config_file)
        del json_conf["encryptionCertificate"]

        conf = to_test.FieldLevelEncryptionConfig(json_conf)
        self.assertIsNone(conf.encryption_certificate)
        self.assertIsNone(conf.encryption_certificate_fingerprint)
        self.assertIsNone(conf.encryption_key_fingerprint)

    def test_load_config_encryption_certificate_file_not_found(self):
        wrong_json = json.loads(self._test_config_file)
        wrong_json["encryptionCertificate"] = resource_path("certificates/wrong_certificate_name.pem")

        self.assertRaises(CertificateError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_decryption_key(self):
        json_conf = json.loads(self._test_config_file)
        del json_conf["decryptionKey"]

        conf = to_test.FieldLevelEncryptionConfig(json_conf)
        self.assertIsNone(conf.decryption_key)

    def test_load_config_decryption_key_file_not_found(self):
        wrong_json = json.loads(self._test_config_file)
        wrong_json["decryptionKey"] = resource_path("keys/wrong_private_key_name.pem")

        self.assertRaises(PrivateKeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_oaep_padding_algorithm(self):
        wrong_json = json.loads(self._test_config_file)
        del wrong_json["oaepPaddingDigestAlgorithm"]

        self.assertRaises(KeyError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_SHA512_oaep_padding_algorithm(self):
        oaep_algo_test = "sha-512"
        json_conf = json.loads(self._test_config_file)
        json_conf["oaepPaddingDigestAlgorithm"] = oaep_algo_test

        conf = to_test.FieldLevelEncryptionConfig(json_conf)
        self.__check_configuration(conf, oaep_algo="SHA512")

    def test_load_config_wrong_oaep_padding_algorithm(self):
        oaep_algo_test = "sha_512"
        wrong_json = json.loads(self._test_config_file)
        wrong_json["oaepPaddingDigestAlgorithm"] = oaep_algo_test

        self.assertRaises(HashAlgorithmError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_unsupported_oaep_padding_algorithm(self):
        wrong_json = json.loads(self._test_config_file)
        wrong_json["oaepPaddingDigestAlgorithm"] = "MD5"

        self.assertRaises(HashAlgorithmError, to_test.FieldLevelEncryptionConfig, wrong_json)

    def test_load_config_missing_optional_param(self):
        json_conf = json.loads(self._test_config_file)
        del json_conf["encryptionCertificateFingerprintFieldName"]

        conf = to_test.FieldLevelEncryptionConfig(json_conf)

        self.assertIsNotNone(conf.encryption_certificate_fingerprint)  # fingerprint is always calculated
        self.assertIsNone(conf.encryption_certificate_fingerprint_field_name)

    def __check_configuration(self, conf, encoding=ClientEncoding.BASE64, oaep_algo="SHA256"):
        self.assertIsNotNone(conf.paths["$"], "No resource to encrypt/decrypt fields of is set")
        resource = conf.paths["$"]
        self.assertIsInstance(resource, to_test.EncryptionPathConfig, "Must be EncryptionPathConfig")
        self.assertDictEqual({"node1.node2.colour": "node1.node2.enc"}, resource.to_encrypt,
                             "Fields to be encrypted not set properly")
        self.assertDictEqual({"node1.node2.enc": "node1.node2.plainColour"}, resource.to_decrypt,
                             "Fields to be decrypted not set properly")

        self.assertEqual("iv", conf.iv_field_name, "IV field name not set")
        self.assertEqual("encryptedKey", conf.encrypted_key_field_name, "Encrypted key field name not set")
        self.assertEqual("encryptedValue", conf.encrypted_value_field_name, "Encrypted value field name not set")
        self.assertEqual(encoding, conf.data_encoding, "Data encoding value not set")

        self.assertEqual(self._expected_cert, conf.encryption_certificate, "Wrong encryption certificate")
        self.assertIsInstance(conf.decryption_key, RSA.RsaKey, "Must be RSA key")
        self.assertEqual(self._expected_key,
                         conf.decryption_key.export_key(pkcs=8).decode('utf-8').replace("\n", "")[27:-25],
                         "Wrong decryption key")
        self.assertEqual("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279",
                         conf.encryption_certificate_fingerprint, "Wrong certificate fingerprint")
        self.assertEqual("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79",
                         conf.encryption_key_fingerprint, "Wrong public key fingerprint")

        self.assertEqual(oaep_algo, conf.oaep_padding_digest_algorithm, "Oaep padding algorithm not set")
        self.assertEqual("certFingerprint", conf.encryption_certificate_fingerprint_field_name,
                         "Certificate fingerprint field name not set")
        self.assertEqual("keyFingerprint", conf.encryption_key_fingerprint_field_name,
                         "Public key fingerprint field name not set")
        self.assertEqual("oaepHashingAlgo", conf.oaep_padding_digest_algorithm_field_name,
                         "Oaep padding algorithm field name not set")
