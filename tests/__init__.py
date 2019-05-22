import os
import json

TEST_CONFIG = os.path.join(os.path.dirname(__file__), "resources/test_config.json")
TEST_RESOURCES_FOLDER = os.path.join(os.path.dirname(__file__), "resources/")


def resource_path(file_name): return TEST_RESOURCES_FOLDER + file_name


def get_config_for_test():
    with open(TEST_CONFIG, encoding='utf-8') as json_file:
        config = json.loads(json_file.read())

        """
        We need to update the certificate and key path in configuration in order to make it work with absolute path
        """
        config["encryptionCertificate"] = resource_path(config["encryptionCertificate"])
        config["decryptionKey"] = resource_path(config["decryptionKey"])

        return json.dumps(config)
