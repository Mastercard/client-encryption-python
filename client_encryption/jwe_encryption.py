import copy
import json

from Crypto.Cipher import AES

from client_encryption.encoding_utils import url_encode_bytes, decode_jwe
from client_encryption.encryption_exception import EncryptionError
from client_encryption.json_path_utils import pop_node, update_node, get_node
from client_encryption.session_key_params import SessionKeyParams


def encrypt_payload(payload, config, _params=None):
    algorithm = "RSA-OAEP-256"
    cty = "application/json"
    enc = "A256GCM"

    try:
        json_payload = copy.deepcopy(payload) if type(payload) is dict or type(payload) is list else json.loads(payload)

        for elem, target in config.paths["$"].to_encrypt.items():
            if not _params:
                params = SessionKeyParams.generate(config)
            else:
                params = _params

            try:
                value = pop_node(json_payload, elem)

                try:
                    header = _build_header(algorithm, enc, cty, config.encryption_key_fingerprint)
                    encoded_header = url_encode_bytes(header.encode())
                    aad = encoded_header.encode('ascii')

                    encoded_payload = value.encode()
                    iv = params.iv_spec
                    cipher = AES.new(params.key, AES.MODE_GCM, iv)
                    cipher.update(aad)

                    encrypted_and_digest = cipher.encrypt_and_digest(encoded_payload)
                    full_cipher_text = encrypted_and_digest[0] + encrypted_and_digest[1]

                    cipher_text = full_cipher_text[: len(full_cipher_text) - 16]
                    tag = full_cipher_text[-16:]

                    jwe_payload = _jwe_compact_serialize(encoded_header, params.encrypted_key_value, iv, cipher_text,
                                                         tag)

                    if isinstance(json_payload, list):
                        json_payload = {config.encrypted_value_field_name: jwe_payload}
                    else:
                        crypto_node = get_node(json_payload, target, create=True)
                        crypto_node[config.encrypted_value_field_name] = jwe_payload

                except KeyError:
                    raise EncryptionError("Field " + target + " not found!")

            except KeyError:
                pass  # data-to-encrypt node not found, nothing to encrypt

        return json_payload

    except (IOError, ValueError, TypeError) as e:
        raise EncryptionError("Payload encryption failed!", e)


def decrypt_payload(payload, config, _params=None):
    try:
        json_payload = payload if type(payload) is dict else json.loads(payload)

        for elem, target in config.paths["$"].to_decrypt.items():
            try:
                node = get_node(json_payload, elem)

                # If entire payload isn't encrypted
                if isinstance(node, dict):
                    node = get_node(node, config.encrypted_value_field_name)

                encrypted_value = node.split(".")

                encrypted_key = decode_jwe(encrypted_value[1])
                iv = decode_jwe(encrypted_value[2])
                params = SessionKeyParams(config, encrypted_key, iv, 'SHA256')
                key = params.key

                header = json.loads(decode_jwe(encrypted_value[0]))
                cipher_text = decode_jwe(encrypted_value[3])

                if header['enc'] == 'A128CBC-HS256':
                    aes = AES.new(key[16:], AES.MODE_CBC, iv)  # NOSONAR
                else:
                    aad = json.dumps(header).encode("ascii")
                    aes = AES.new(key, AES.MODE_GCM, iv)
                    aes.update(aad)

                decrypted = aes.decrypt(cipher_text)
                decoded_payload = ''.join(c for c in decrypted.decode() if c.isprintable())

                if isinstance(json.loads(decoded_payload), list):
                    json_payload = json.loads(decoded_payload)
                else:
                    update_node(json_payload, target, decoded_payload)
                    del json_payload[elem]
            except KeyError:
                pass  # encrypted data node not found, nothing to decrypt

        return json_payload

    except json.JSONDecodeError:  # not a json response - return it as is
        return payload
    except (IOError, ValueError, TypeError) as e:
        raise EncryptionError("Payload decryption failed!", e)


def _jwe_compact_serialize(encoded_header, encrypted_cek, iv, cipher_text, auth_tag):
    encoded_cipher_text = url_encode_bytes(cipher_text)
    encoded_auth_tag = url_encode_bytes(auth_tag)
    encoded_iv = url_encode_bytes(iv)
    return (
            encoded_header
            + "."
            + encrypted_cek
            + "."
            + encoded_iv
            + "."
            + encoded_cipher_text
            + "."
            + encoded_auth_tag
    )


def _build_header(alg, enc, cty, kid):
    header = {"alg": alg, "enc": enc, "kid": kid, "cty": cty}
    json_header = json.dumps(
        header,
        separators=(",", ":"),
        sort_keys=False
    )
    return json_header
