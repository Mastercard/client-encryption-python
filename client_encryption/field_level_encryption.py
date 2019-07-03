import json
import copy
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from client_encryption.session_key_params import SessionKeyParams
from client_encryption.encoding_utils import encode_bytes, decode_value
from client_encryption.json_path_utils import get_node, pop_node, update_node, cleanup_node
from client_encryption.encryption_exception import EncryptionError


def encrypt_payload(payload, config, _params=None):
    """Encrypt some fields of a JSON payload using the given configuration."""

    try:
        json_payload = copy.deepcopy(payload) if type(payload) is dict else json.loads(payload)

        for elem, target in config.paths["$"].to_encrypt.items():
            if not _params:
                params = SessionKeyParams.generate(config)
            else:
                params = _params

            try:
                value = pop_node(json_payload, elem)

                try:
                    encrypted_value = _encrypt_value(params.key, params.iv_spec, value)
                    crypto_node = get_node(json_payload, target, create=True)
                    crypto_node[config.encrypted_value_field_name] = encode_bytes(encrypted_value, config.data_encoding)

                    if not _params:
                        _populate_node_with_key_params(crypto_node, config, params)

                except KeyError:
                    raise EncryptionError("Field " + target + " not found!")

            except KeyError:
                pass  # data-to-encrypt node not found, nothing to encrypt

        return json_payload

    except (IOError, ValueError, TypeError) as e:
        raise EncryptionError("Payload encryption failed!", e)


def decrypt_payload(payload, config, _params=None):
    """Decrypt some fields of a JSON payload using the given configuration."""

    try:
        json_payload = payload if type(payload) is dict else json.loads(payload)

        for elem, target in config.paths["$"].to_decrypt.items():
            try:
                node = get_node(json_payload, elem)

                cipher_text = decode_value(node.pop(config.encrypted_value_field_name), config.data_encoding)

                if not _params:
                    try:
                        encrypted_key = node.pop(config.encrypted_key_field_name)
                        iv = node.pop(config.iv_field_name)
                    except KeyError:
                        raise EncryptionError("Encryption field(s) missing in payload.")

                    oaep_digest_algo = node.pop(config.oaep_padding_digest_algorithm_field_name,
                                                config.oaep_padding_digest_algorithm)

                    _remove_fingerprint_from_node(node, config)

                    params = SessionKeyParams(config, encrypted_key, iv, oaep_digest_algo)
                else:
                    params = _params

                cleanup_node(json_payload, elem, target)

                try:
                    update_node(json_payload, target, _decrypt_bytes(params.key, params.iv_spec, cipher_text))
                except KeyError:
                    raise EncryptionError("Field '" + target + "' not found!")

            except KeyError:
                pass  # encrypted data node not found, nothing to decrypt

        return json_payload

    except json.JSONDecodeError:  # not a json response - return it as is
        return payload
    except (IOError, ValueError, TypeError) as e:
        raise EncryptionError("Payload decryption failed!", e)


def _encrypt_value(_key, iv, node_str):
    padded_node = pad(node_str.encode('utf-8'), AES.block_size)

    aes = AES.new(_key, AES.MODE_CBC, iv)
    return aes.encrypt(padded_node)


def _decrypt_bytes(_key, iv, _bytes):
    aes = AES.new(_key, AES.MODE_CBC, iv)
    plain_bytes = aes.decrypt(_bytes)

    return unpad(plain_bytes, AES.block_size).decode('utf-8')


def _populate_node_with_key_params(node, config, params):
    node[config.encrypted_key_field_name] = params.encrypted_key_value
    node[config.iv_field_name] = params.iv_value
    if config.oaep_padding_digest_algorithm_field_name:
        node[config.oaep_padding_digest_algorithm_field_name] = params.oaep_padding_digest_algorithm_value
    if config.encryption_certificate_fingerprint_field_name:
        node[config.encryption_certificate_fingerprint_field_name] = config.encryption_certificate_fingerprint
    if config.encryption_key_fingerprint_field_name:
        node[config.encryption_key_fingerprint_field_name] = config.encryption_key_fingerprint


def _remove_fingerprint_from_node(node, config):
    if config.encryption_certificate_fingerprint_field_name in node:
        del node[config.encryption_certificate_fingerprint_field_name]
    if config.encryption_key_fingerprint_field_name in node:
        del node[config.encryption_key_fingerprint_field_name]

