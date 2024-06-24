# client-encryption-python
[![](https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg)](https://developer.mastercard.com/)

[![](https://github.com/Mastercard/client-encryption-python/workflows/Build%20&%20Test/badge.svg)](https://github.com/Mastercard/client-encryption-python/actions?query=workflow%3A%22Build+%26+Test%22)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-python&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-python&metric=coverage)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-python&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-python)
[![](https://github.com/Mastercard/client-encryption-python/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/client-encryption-python/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/pypi/v/mastercard-client-encryption.svg?style=flat&color=blue)](https://pypi.org/project/mastercard-client-encryption)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/client-encryption-python/blob/master/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
  * [Versioning and Deprecation Policy](#versioning)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Library to Your Project](#adding-the-library-to-your-project)
  * [Performing Payload Encryption and Decryption](#performing-payload-encryption-and-decryption)
      * [JWE Encryption and Decryption](#jwe-encryption-and-decryption)
      * [Mastercard Encryption and Decryption](#mastercard-encryption-and-decryption)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)


## Overview <a name="overview"></a>
This is the Python version of the Mastercard compliant payload encryption/decryption.

### Compatibility <a name="compatibility"></a>
Python 3.8+

### References <a name="references"></a>
* [JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
* [Securing Sensitive Data Using Payload Encryption](https://developer.mastercard.com/platform/documentation/security-and-authentication/securing-sensitive-data-using-payload-encryption/)

### Versioning and Deprecation Policy <a name="versioning"></a>
* [Mastercard Versioning and Deprecation Policy](https://github.com/Mastercard/.github/blob/main/CLIENT_LIBRARY_DEPRECATION_POLICY.md)

## Usage <a name="usage"></a>
### Prerequisites <a name="prerequisites"></a>
Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com). 

As part of this set up, you'll receive:
- A public request encryption certificate (aka _Client Encryption Keys_)
- A private response decryption key (aka _Mastercard Encryption Keys_)

### Installation <a name="adding-the-libraries-to-your-project"></a>
If you want to use **mastercard-client-encryption** with [Python](https://www.python.org/), it is available through `PyPI`:
- [https://pypi.org/project/mastercard-client-encryption](https://pypi.org/project/mastercard-client-encryption)

**Adding the library to your project**
Install the library by pip:

```bash
pip install mastercard-client-encryption
```

Or clone it from git:

```bash
git clone https://github.com/Mastercard/client-encryption-python.git
```

and then execute from the repo folder:

```bash
python3 setup.py install
```

You can then use it as a regular module:

```python
# Mastercard Encryption/Decryption
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
from client_encryption.field_level_encryption import encrypt_payload, decrypt_payload
```

```python
# JWE Encryption/Decryption
from client_encryption.jwe_encryption_config import JweEncryptionConfig
from client_encryption.jwe_encryption import encrypt_payload, decrypt_payload
```

### Performing Payload Encryption and Decryption <a name="performing-payload-encryption-and-decryption"></a>

This library supports two types of encryption/decryption, both of which support field level and entire payload encryption: JWE encryption and what the library refers to as Field Level Encryption (Mastercard encryption), a scheme used by many services hosted on Mastercard Developers before the library added support for JWE.

+ [JWE Encryption and Decryption](#jwe-encryption-and-decryption)
+ [Mastercard Encryption and Decryption](#mastercard-encryption-and-decryption)

#### JWE Encryption and Decryption <a name="jwe-encryption-and-decryption"></a>

+ [Introduction](#jwe-introduction)
+ [Configuring the JWE Encryption](#configuring-the-jwe-encryption)
+ [Performing JWE Encryption](#performing-jwe-encryption)
+ [Performing JWE Decryption](#performing-jwe-decryption)

##### Introduction <a name="jwe-introduction"></a>

This library uses [JWE compact serialization](https://datatracker.ietf.org/doc/html/rfc7516#section-7.1) for the encryption of sensitive data.
The core methods responsible for payload encryption and decryption are `encrypt_payload` and `decrypt_payload` in the `jwe_encryption` module.

- `encrypt_payload()` usage:

```python
config = JweEncryptionConfig(config_dictionary)
encrypted_request_payload = encrypt_payload(body, config)
```

- `decrypt_payload()` usage:

```python
config = JweEncryptionConfig(config_dictionary)
decrypted_response_payload = decrypt_payload(body, config)
```

##### Configuring the JWE Encryption <a name="configuring-the-jwe-encryption"></a>

`jwe_encryption` needs a config dictionary to instruct how to decrypt/decrypt the payloads. Example:

```json
{
  "paths": {
    "$": {
      "toEncrypt": {
          "path.to.foo": "path.to.encryptedFoo"
      },
      "toDecrypt": {
          "path.to.encryptedFoo": "path.to.foo"
      }
    }
  },
  "encryptedValueFieldName": "encryptedData",
  "encryptionCertificate": "./path/to/public.cert",
  "decryptionKey": "./path/to/your/private.key",
}
```

The above can be either stored to a file or passed to 'JweEncryptionConfig' as dictionary:
```python
config_dictionary = {
                        "paths": {…},
                        …
                        "decryptionKey": "./path/to/your/private.key"
                    }
                    
config = JweEncryptionConfig(config_dictionary)

config_file_path = "./config.json"
config = JweEncryptionConfig(config_file_path)
```

##### Performing JWE Encryption <a name="performing-jwe-encryption"></a>

Call `jwe_encryption.encrypt_payload()` with a JSON (dict) request payload, and optional `params` object.

Example using the configuration [above](#configuring-the-jwe-encryption):

```python
from client_encryption.session_key_params import SessionKeyParams

payload = {
  "path": {
    "to": {
      "foo": {
        "sensitiveField1": "sensitiveValue1",
        "sensitiveField2": "sensitiveValue2"
      }
    }
  }
}

params = SessionKeyParams.generate(conf) # optional
request_payload = encrypt_payload(payload, config, params)
```

Output:

```json
{
  "path": {
    "to": {
      "encryptedFoo": {
        "encryptedValue": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM(...)==.Y+oPYKZEMTKyYcSIVEgtQw=="
      }
    }
  }
}
```

##### Performing JWE Decryption <a name="performing-jwe-decryption"></a>

Call `jwe_encryption.decrypt_payload()` with a JSON (dict) encrypted response payload.

Example using the configuration [above](#configuring-the-jwe-encryption):

```python
response = {
  "path": {
    "to": {
      "encryptedFoo": {
        "encryptedValue": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM(...)==.Y+oPYKZEMTKyYcSIVEgtQw=="
      }
    }
  }
}

response_payload = decrypt_payload(response, config)

```

Output:

```json
{
  "path": {
    "to": {
      "foo": {
        "sensitiveField1": "sensitiveValue1",
        "sensitiveField2": "sensitiveValue2"
      }
    }
  }
}
```

#### Mastercard Encryption and Decryption <a name="mastercard-encryption-and-decryption"></a>

+ [Introduction](#mastercard-introduction)
+ [Configuring the Mastercard Encryption](#configuring-the-mastercard-encryption)
+ [Performing Mastercard Encryption](#performing-mastercard-encryption)
+ [Performing Mastercard Decryption](#performing-mastercard-decryption)

##### Introduction <a name="introduction"></a>

The core methods responsible for payload encryption and decryption are `encrypt_payload` and `decrypt_payload` in the `field_level_encryption` module.

- `encrypt_payload()` usage:

```python
config = FieldLevelEncryptionConfig(config_dictionary)
encrypted_request_payload = encrypt_payload(body, config)
```

- `decrypt_payload()` usage:

```python
config = FieldLevelEncryptionConfig(config_dictionary)
decrypted_response_payload = decrypt_payload(body, config)
```

##### Configuring the Mastercard Encryption <a name="configuring-the-mastercard-encryption"></a>

`field_level_encryption` needs a config dictionary to instruct how to decrypt/decrypt the payloads. Example:

```json
{
  "paths": {
    "$": {
      "toEncrypt": {
          "path.to.foo": "path.to.encryptedFoo"
      },
      "toDecrypt": {
          "path.to.encryptedFoo": "path.to.foo"
      }
    }
  },
  "ivFieldName": "iv",
  "encryptedKeyFieldName": "encryptedKey",
  "encryptedValueFieldName": "encryptedData",
  "dataEncoding": "hex",
  "encryptionCertificate": "./path/to/public.cert",
  "decryptionKey": "./path/to/your/private.key",
  "oaepPaddingDigestAlgorithm": "SHA256"
}
```

The above can be either stored to a file or passed to 'FieldLevelEncryptionConfig' as dictionary:
```python
config_dictionary = {
                        "paths": {…},
                        …
                        "decryptionKey": "./path/to/your/private.key",
                        "oaepPaddingDigestAlgorithm": "SHA256"
                    }
                    
config = FieldLevelEncryptionConfig(config_dictionary)

config_file_path = "./config.json"
config = FieldLevelEncryptionConfig(config_file_path)
```

For all config options, please see:

- [Configuration object](https://github.com/Mastercard/client-encryption-python/wiki/Configuration-Object) for all config options

We have a predefined set of configurations to use with Mastercard services:

- [Service configurations](https://github.com/Mastercard/client-encryption-python/wiki/Service-Configurations-for-Client-Encryption-Python)



##### Performing Mastercard Encryption <a name="performing-mastercard-encryption"></a>

Call `field_level_encryption.encrypt_payload()` with a JSON (dict) request payload, and optional `params` object.

Example using the configuration [above](#configuring-the-field-level-encryption):

```python
from client_encryption.session_key_params import SessionKeyParams

payload = {
  "path": {
    "to": {
      "foo": {
        "sensitiveField1": "sensitiveValue1",
        "sensitiveField2": "sensitiveValue2"
      }
    }
  }
}

params = SessionKeyParams.generate(conf) # optional
request_payload = encrypt_payload(payload, config, params)
```

Output:

```json
{
    "path": {
        "to": {
            "encryptedFoo": {
                "iv": "7f1105fb0c684864a189fb3709ce3d28",
                "encryptedKey": "67f467d1b653d98411a0c6d3c…ffd4c09dd42f713a51bff2b48f937c8",
                "encryptedData": "b73aabd267517fc09ed72455c2…dffb5fa04bf6e6ce9ade1ff514ed6141",
                "publicKeyFingerprint": "80810fc13a8319fcf0e2e…82cc3ce671176343cfe8160c2279",
                "oaepHashingAlgorithm": "SHA256"
            }
        }
    }
}
```

##### Performing Mastercard Decryption <a name="performing-mastercard-decryption"></a>

Call `field_level_encryption.decrypt_payload()` with a JSON (dict) encrypted response payload.

Example using the configuration [above](#configuring-the-field-level-encryption):

```python
response = {
  "path": {
    "to": {
      "encryptedFoo": {
        "iv": "e5d313c056c411170bf07ac82ede78c9",
        "encryptedKey": "e3a56746c0f9109d18b3a2652b76…f16d8afeff36b2479652f5c24ae7bd",
        "encryptedData": "809a09d78257af5379df0c454dcdf…353ed59fe72fd4a7735c69da4080e74f",
        "oaepHashingAlgorithm": "SHA256",
        "publicKeyFingerprint": "80810fc13a8319fcf0e2e…3ce671176343cfe8160c2279"
      }
    }
  }
}

response_payload = decrypt_payload(response, config)

```

Output:

```json
{
  "path": {
    "to": {
      "foo": {
        "sensitiveField1": "sensitiveValue1",
        "sensitiveField2": "sensitiveValue2"
      }
    }
  }
}
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification). 
It provides generators and library templates for supporting multiple languages and frameworks.

The **client-encryption-python** library provides a method you can use to integrate the OpenAPI generated client with this library:
```python
from client_encryption.api_encryption import add_encryption_layer

config = {
  "paths": {
    "$": {
      …
    }
  },
  "encryptionCertificate": "path/to/cert.pem",
  …
  "decryptionKey": "path/to/to/key.pem"
}

add_encryption_layer(api_client, config)
```

Alternatively you can pass the configuration by a json file:
```python
from client_encryption.api_encryption import add_encryption_layer

add_encryption_layer(api_client, "path/to/my/config.json")
```

This method will add the Mastercard/JWE encryption in the generated OpenApi client, taking care of encrypting request and decrypting response payloads, but also of updating HTTP headers when needed, automatically, without manually calling `encrypt_payload()`/`decrypt_payload()` functions for each API request or response.

##### OpenAPI Generator <a name="openapi-generator"></a>

OpenAPI client can be generated, starting from your OpenAPI Spec using the following command:

```shell
openapi-generator-cli generate -i openapi-spec.yaml -l python -o out
```

The client library will be generated in the `out` folder.

See also: 

- [OpenAPI Generator CLI Installation](https://openapi-generator.tech/docs/installation/)

##### Usage of the `api_encryption.add_encryption_layer`:

To use it:

1. Generate the [OpenAPI client](#openapi-generator)

2. Import the **mastercard-client-encryption** module and the generated OpenAPI client

   ```python
   from client_encryption.api_encryption import add_encryption_layer
   from openapi_client.api_client import ApiClient # import generated OpenAPI client
   ```

3. Add the encryption layer to the generated client:

   ```python
   # Create a new instance of the generated client
   api_client = ApiClient()
   # Enable encryption
   add_encryption_layer(api_client, "path/to/my/config.json")
   ```

4. Use the `ApiClient` instance with Encryption enabled:

   Example:

   ```python
   request_body = {…}
   response = MyServiceApi(api_client).do_some_action_post(body=request_body)
   # requests and responses will be automatically encrypted and decrypted
   # accordingly with the configuration object used
   
   # … use the (decrypted) response object here …
   decrypted = response.json()

   ```

##### Integrating with `mastercard-client-encryption` module:

In order to use both signing and encryption layers, a defined order is required as signing library should calculate the hash of the encrypted payload.
According to the above the signing layer must be applied first in order to work as inner layer. The outer layer - encryption - will be executed first, providing the signing layer the encrypted payload to sign.

1. Generate the [OpenAPI client](#openapi-generator)

2. Import both **mastercard-client-encryption** and **mastercard-client-encryption** modules and the generated OpenAPI client

   ```python
   from oauth1.signer_interceptor import add_signing_layer
   from client_encryption.api_encryption import add_encryption_layer
   from openapi_client.api_client import ApiClient # import generated OpenAPI client
   ```

3. Add the authentication layer to the generated client:
   ```python
   # Create a new instance of the generated client
   api_client = ApiClient()

   # Enable authentication
   add_signing_layer(api_client, key_file, key_password, consumer_key)
   ```
     
4. Then add the encryption layer:
   ```python
   add_encryption_layer(api_client, "path/to/my/config.json")
   ```

5. Use the `ApiClient` instance with Authentication and Encryption both enabled:
   ```python
   response = MyServiceApi(api_client).do_some_action_post(body=request_body)
   decrypted = response.json()
   ```
