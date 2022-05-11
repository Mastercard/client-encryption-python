import json
import inspect
from enum import Enum
from functools import wraps
from warnings import warn
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
from client_encryption.jwe_encryption_config import JweEncryptionConfig
from client_encryption.session_key_params import SessionKeyParams
from client_encryption.field_level_encryption import encrypt_payload as encrypt_field_level, \
    decrypt_payload as decrypt_field_level
from client_encryption.jwe_encryption import encrypt_payload as encrypt_jwe, decrypt_payload as decrypt_jwe


class ApiEncryption(object):

    def __init__(self, encryption_conf_file, encryption_type='Mastercard'):
        """Load and initialize FieldLevelEncryptionConfig object."""

        if type(encryption_conf_file) is dict:
            if encryption_type == EncryptionType.MASTERCARD.value:
                self._encryption_conf = FieldLevelEncryptionConfig(encryption_conf_file)
            else:
                self._encryption_conf = JweEncryptionConfig(encryption_conf_file)
        else:
            if encryption_type == EncryptionType.MASTERCARD.value:
                with open(encryption_conf_file, encoding='utf-8') as json_file:
                    self._encryption_conf = FieldLevelEncryptionConfig(json_file.read())
            else:
                with open(encryption_conf_file, encoding='utf-8') as json_file:
                    self._encryption_conf = JweEncryptionConfig(json_file.read())

    def field_encryption_call_api(self, func):
        """Decorator for API call_api. func is APIClient.call_api"""

        @wraps(func)
        def call_api_function(*args, **kwargs):
            check_type = inspect.signature(func.__self__.call_api).parameters.get("_check_type") is None
            if check_type:
                kwargs["_preload_content"] = False  # version 4.3.1
            return func(*args, **kwargs)

        call_api_function.__fle__ = True

        return call_api_function

    def field_encryption(self, func):
        """Decorator for API call_api. func is APIClient.call_api"""

        @wraps(func)
        def call_api_function(*args, **kwargs):
            """Wrap call_api and add field encryption layer to it."""

            check_type = inspect.signature(func.__self__.call_api).parameters.get("_check_type") is not None

            in_body = kwargs.get("body", None)

            in_headers = kwargs.get("headers", None)

            kwargs["body"] = self._encrypt_payload(in_headers, in_body) if in_body else in_body

            response = func(*args, **kwargs)

            if check_type:
                response.data = self._decrypt_payload(response.getheaders(), response.data)
            else:
                response._body = self._decrypt_payload(response.getheaders(), response.data)

            return response

        call_api_function.__fle__ = True
        return call_api_function

    def _encrypt_payload(self, headers, body):
        """Encryption enforcement based on configuration - encrypt and add session key params to header or body"""

        conf = self._encryption_conf

        if type(conf) is FieldLevelEncryptionConfig:
            return self.encrypt_field_level_payload(headers, conf, body)
        else:
            return self.encrypt_jwe_payload(conf, body)

    def _decrypt_payload(self, headers, body):
        """Encryption enforcement based on configuration - decrypt using session key params from header or body"""

        conf = self._encryption_conf

        if type(conf) is FieldLevelEncryptionConfig:
            return self.decrypt_field_level_payload(headers, conf, body)
        else:
            return self.decrypt_jwe_payload(conf, body)

    @staticmethod
    def encrypt_jwe_payload(conf, body):
        return encrypt_jwe(body, conf)

    @staticmethod
    def decrypt_jwe_payload(conf, body):
        decrypted_body = decrypt_jwe(body, conf)
        payload = json.dumps(decrypted_body).encode('utf-8')

        return payload

    @staticmethod
    def decrypt_field_level_payload(headers, conf, body):
        """Encryption enforcement based on configuration - decrypt using session key params from header or body"""
        params = None

        if conf.use_http_headers:
            if conf.iv_field_name in headers and conf.encrypted_key_field_name in headers:
                iv = headers.pop(conf.iv_field_name)
                encrypted_key = headers.pop(conf.encrypted_key_field_name)
                oaep_digest_algo = headers.pop(conf.oaep_padding_digest_algorithm_field_name) \
                    if _contains_param(conf.oaep_padding_digest_algorithm_field_name, headers) else None
                if _contains_param(conf.encryption_certificate_fingerprint_field_name, headers):
                    del headers[conf.encryption_certificate_fingerprint_field_name]
                if _contains_param(conf.encryption_key_fingerprint_field_name, headers):
                    del headers[conf.encryption_key_fingerprint_field_name]

                params = SessionKeyParams(conf, encrypted_key, iv, oaep_digest_algo)
            else:
                # skip decryption and return original body if not iv nor key is in headers
                return body

        decrypted_body = decrypt_field_level(body, conf, params)
        payload = json.dumps(decrypted_body).encode('utf-8')

        return payload

    @staticmethod
    def encrypt_field_level_payload(headers, conf, body):
        if conf.use_http_headers:
            params = SessionKeyParams.generate(conf)

            encryption_params = {
                conf.iv_field_name: params.iv_value,
                conf.encrypted_key_field_name: params.encrypted_key_value
            }
            if conf.encryption_certificate_fingerprint_field_name:
                encryption_params[conf.encryption_certificate_fingerprint_field_name] = \
                    conf.encryption_certificate_fingerprint
            if conf.encryption_key_fingerprint_field_name:
                encryption_params[conf.encryption_key_fingerprint_field_name] = conf.encryption_key_fingerprint
            if conf.oaep_padding_digest_algorithm_field_name:
                encryption_params[conf.oaep_padding_digest_algorithm_field_name] = conf.oaep_padding_digest_algorithm

            encrypted_payload = encrypt_field_level(body, conf, params)
            headers.update(encryption_params)
        else:
            encrypted_payload = encrypt_field_level(body, conf)

        return encrypted_payload

def _contains_param(param_name, headers): return param_name and param_name in headers


def add_encryption_layer(api_client, encryption_conf_file, encryption_type='Mastercard'):
    """Decorate APIClient.call_api with encryption"""
    api_encryption = ApiEncryption(encryption_conf_file, encryption_type)
    api_client.request = api_encryption.field_encryption(api_client.request)
    api_client.call_api = api_encryption.field_encryption_call_api(api_client.call_api)

    __check_oauth(api_client)  # warn the user if authentication layer is missing/not set


def __check_oauth(api_client):
    try:
        api_client.rest_client.request.__wrapped__
    except AttributeError:
        __oauth_warn()


def __oauth_warn():
    warn("No signing layer detected. Request will be only encrypted without being signed. "
         "Please refer to "
         "https://github.com/Mastercard/client-encryption-python#integrating-with-mastercard-oauth1-signer-module")


class EncryptionType(Enum):
    MASTERCARD = 'Mastercard'
    JWE = 'JWE'
