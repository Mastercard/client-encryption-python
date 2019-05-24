from unittest.mock import Mock
import json
from tests import get_config_for_test
import client_encryption.field_level_encryption as encryption
import client_encryption.field_level_encryption_config as encryption_config
from client_encryption.session_key_params import SessionKeyParams


class MockService(object):

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = MockApiClient()
        self.api_client = api_client

    def do_something_get(self, **kwargs):
        return self.api_client.request("GET", "localhost/testservice", headers=kwargs["headers"])

    def do_something_post(self, **kwargs):
        return self.api_client.request("POST", "localhost/testservice", headers=kwargs["headers"], body=kwargs["body"])

    def do_something_delete(self, **kwargs):
        return self.api_client.request("DELETE", "localhost/testservice", headers=kwargs["headers"], body=kwargs["body"])

    def do_something_get_use_headers(self, **kwargs):
        return self.api_client.request("GET", "localhost/testservice/headers", headers=kwargs["headers"])

    def do_something_post_use_headers(self, **kwargs):
        return self.api_client.request("POST", "localhost/testservice/headers", headers=kwargs["headers"], body=kwargs["body"])

    def do_something_delete_use_headers(self, **kwargs):
        return self.api_client.request("DELETE", "localhost/testservice/headers", headers=kwargs["headers"], body=kwargs["body"])


class MockApiClient(object):

    def __init__(self, configuration=None, header_name=None, header_value=None,
                 cookie=None):
        json_config = json.loads(get_config_for_test())
        json_config["paths"]["$"]["toEncrypt"] = {"data": "encryptedData"}
        json_config["paths"]["$"]["toDecrypt"] = {"encryptedData": "data"}
        self._config = encryption_config.FieldLevelEncryptionConfig(json_config)

    def request(self, method, url, query_params=None, headers=None,
                post_params=None, body=None, _preload_content=True,
                _request_timeout=None):
        check = -1

        if body:
            if url == "localhost/testservice/headers":
                iv = headers["x-iv"]
                encrypted_key = headers["x-key"]
                oaep_digest_algo = headers["x-oaep-digest"] if "x-oaep-digest" in headers else None

                params = SessionKeyParams(self._config, encrypted_key, iv, oaep_digest_algo)
            else:
                params = None

            plain = encryption.decrypt_payload(body, self._config, params)
            check = plain["data"]["secret2"]-plain["data"]["secret1"]
            res = {"data": {"secret": check}}
        else:
            res = {"data": {"secret": [53, 84, 75]}}

        if url == "localhost/testservice/headers" and method in ["GET", "POST", "PUT"]:
            params = SessionKeyParams.generate(self._config)
            json_resp = encryption.encrypt_payload(res, self._config, params)

            response_headers = {"Content-Type": "application/json",
                                "x-iv": params.iv_value,
                                "x-key": params.encrypted_key_value,
                                "x-oaep-digest": self._config.oaep_padding_digest_algorithm
                                }
            mock_headers = Mock(return_value=response_headers)
        else:
            json_resp = encryption.encrypt_payload(res, self._config)
            mock_headers = Mock(return_value={"Content-Type": "application/json"})

        response = Mock()
        response.status = 200
        response.getheaders = mock_headers

        if method in ["GET", "POST", "PUT"]:
            response.data = json_resp
            response.json = Mock(return_value=json_resp)
        else:
            response.data = "OK" if check == 0 else "KO"

        return response
