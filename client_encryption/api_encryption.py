import json
from functools import wraps
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
from client_encryption.session_key_params import SessionKeyParams
from client_encryption.field_level_encryption import encrypt_payload, decrypt_payload


class ApiEncryption(object):

    def __init__(self, encryption_conf_file):
        """Load and initialize FieldLevelEncryptionConfig object."""

        if type(encryption_conf_file) is dict:
            self._encryption_conf = FieldLevelEncryptionConfig(encryption_conf_file)
        else:
            with open(encryption_conf_file, encoding='utf-8') as json_file:
                self._encryption_conf = FieldLevelEncryptionConfig(json_file.read())

    def field_encryption(self, func):
        """Decorator for API request. func is APIClient.request"""

        @wraps(func)
        def request_function(*args, **kwargs):
            """Wrap request and add field encryption layer to it."""

            in_body = kwargs.get("body", None)
            kwargs["body"] = self._encrypt_payload(kwargs.get("headers", None), in_body) if in_body else in_body

            response = func(*args, **kwargs)

            if type(response.data) is not str:
                response_body = self._decrypt_payload(response.getheaders(), response.json())
                response._content = json.dumps(response_body, indent=4).encode('utf-8')

            return response

        return request_function

    def _encrypt_payload(self, headers, body):
        """Encryption enforcement based on configuration - encrypt and add session key params to header or body"""

        conf = self._encryption_conf

        if conf.use_http_headers:
            params = SessionKeyParams.generate(conf)

            headers[conf.iv_field_name] = params.iv_value
            headers[conf.encrypted_key_field_name] = params.encrypted_key_value
            headers[conf.encryption_certificate_fingerprint_field_name] = conf.encryption_certificate_fingerprint
            headers[conf.encryption_key_fingerprint_field_name] = conf.encryption_key_fingerprint
            headers[conf.oaep_padding_digest_algorithm_field_name] = conf.oaep_padding_digest_algorithm

            encrypted_payload = encrypt_payload(body, conf, params)
        else:
            encrypted_payload = encrypt_payload(body, conf)

        return encrypted_payload

    def _decrypt_payload(self, headers, body):
        """Encryption enforcement based on configuration - decrypt using session key params from header or body"""

        conf = self._encryption_conf

        if conf.use_http_headers:
            if conf.iv_field_name in headers and conf.encrypted_key_field_name in headers:
                iv = headers.pop(conf.iv_field_name)
                encrypted_key = headers.pop(conf.encrypted_key_field_name)
                oaep_digest_algo = headers.pop(conf.oaep_padding_digest_algorithm_field_name) \
                    if conf.oaep_padding_digest_algorithm_field_name in headers else None
                if conf.encryption_certificate_fingerprint_field_name in headers:
                    del headers[conf.encryption_certificate_fingerprint_field_name]
                if conf.encryption_key_fingerprint_field_name in headers:
                    del headers[conf.encryption_key_fingerprint_field_name]

                params = SessionKeyParams(conf, encrypted_key, iv, oaep_digest_algo)
                payload = decrypt_payload(body, conf, params)
            else:
                # skip decryption if not iv nor key is in headers
                payload = body
        else:
            payload = decrypt_payload(body, conf)

        return payload


def add_encryption_layer(api_client, encryption_conf_file):
    """Decorate APIClient.request with field level encryption"""

    api_encryption = ApiEncryption(encryption_conf_file)
    api_client.request = api_encryption.field_encryption(api_client.request)
