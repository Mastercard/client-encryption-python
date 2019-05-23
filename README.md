# client-encryption-python

[![](https://travis-ci.org/Mastercard/client-encryption-python.svg?branch=master)](https://travis-ci.org/Mastercard/client-encryption-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-python&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-python&metric=coverage)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-python)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-python&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-python)
[![](https://img.shields.io/pypi/v/mastercard-client-encryption.svg?style=flat&color=blue)](https://pypi.org/project/mastercard-client-encryption)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/client-encryption-python/blob/master/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Library to Your Project](#adding-the-library-to-your-project)
  * [Performing Field Level Encryption and Decryption](#performing-field-level-encryption-and-decryption)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)


## Overview <a name="overview"></a>
This is the Python version of the Mastercard compliant payload encryption/decryption.

### Compatibility <a name="compatibility"></a>
Python 3.6, 3.7

### References <a name="references"></a>

<img src="https://user-images.githubusercontent.com/3964455/55345820-c520a280-54a8-11e9-8235-407199fa1d97.png" alt="Encryption of sensitive data" width="75%" height="75%"/>

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
$ pip install mastercard-client-encryption
```

Or clone it from git:

```bash
$ git clone https://github.com/Mastercard/client-encryption-python.git
```

and then execute from the repo folder:

```bash
$ python3 setup.py install
```

You can then use it as a regular module:

```python
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
from client_encryption.field_level_encryption import encrypt_payload, decrypt_payload
```

### Performing Field Level Encryption and Decryption <a name="performing-field-level-encryption-and-decryption"></a>

- [Introduction](#introduction)
- [Configuring the Field Level Encryption](#configuring-the-field-level-encryption)
- [Performing Encryption](#performing-encryption)
- [Performing Decryption](#performing-decryption)

#### Introduction <a name="introduction"></a>

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

#### Configuring the Field Level Encryption <a name="configuring-the-field-level-encryption"></a>

`field_level_encryption` needs a config dictionary to instruct how to decrypt/decrypt the payloads. Example:

```json
{
  "paths": {
    "$": {
      "toEncrypt": {
          "element": "path.to.foo",
          "obj": "path.to.encryptedFoo"
      },
      "toDecrypt": {
          "element": "path.to.encryptedFoo",
          "obj": "path.to.foo"
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
config_dictionary = {"paths": {...},
                    (...)
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

- [Service configurations](https://github.com/Mastercard/client-encryption-python/wiki/Mastercard-Services-Configuration) wiki page



#### Performing Encryption <a name="performing-encryption"></a>

Call `field_level_encryption.encrypt_payload()` with a JSON (dict) request payload, and optional `params` object.

Example using the configuration [above](#configuring-the-field-level-encryption):

```python
from client_encryption.session_key_params import SessionKeyParams

payload = {
  path: {
    to: {
      foo: {
        sensitiveField1: 'sensitiveValue1',
        sensitiveField2: 'sensitiveValue2'
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
                "encryptedKey": "67f467d1b653d98411a0c6d3c(...)ffd4c09dd42f713a51bff2b48f937c8",
                "encryptedData": "b73aabd267517fc09ed72455c2(...)dffb5fa04bf6e6ce9ade1ff514ed6141",
                "publicKeyFingerprint": "80810fc13a8319fcf0e2e(...)82cc3ce671176343cfe8160c2279",
                "oaepHashingAlgorithm": "SHA256"
            }
        }
    }
}
```

#### Performing Decryption <a name="performing-decryption"></a>

Call `field_level_encryption.decrypt_payload()` with a JSON (dict) encrypted response payload.

Example using the configuration [above](#configuring-the-field-level-encryption):

```python
response = {
  path: {
    to: {
      encryptedFoo: {
        iv: 'e5d313c056c411170bf07ac82ede78c9',
        encryptedKey: 'e3a56746c0f9109d18b3a2652b76(...)f16d8afeff36b2479652f5c24ae7bd',
        encryptedData: '809a09d78257af5379df0c454dcdf(...)353ed59fe72fd4a7735c69da4080e74f',
        oaepHashingAlgorithm: 'SHA256',
        publicKeyFingerprint: '80810fc13a8319fcf0e2e(...)3ce671176343cfe8160c2279'
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
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
from client_encryption.api_encryption import add_encryption_layer

api_encryption.add_encryption_layer(api_client, config)
```
This method will add the field level encryption in the generated OpenApi client, taking care of encrypting request and decrypting response payloads, but also of updating HTTP headers when needed, automatically, without manually calling `encrypt_payload()`/`decrypt_payload()` functions for each API request or response.

##### OpenAPI Generator <a name="openapi-generator"></a>

OpenAPI client can be generated, starting from your OpenAPI Spec / Swagger using the following command:

```shell
java -jar openapi-generator-cli.jar generate -i openapi-spec.yaml -l python -o out
```

Client library will be generated in the `out` folder.

See also: 

- [OpenAPI Generator (executable)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-cli)

##### Usage of the `api_encryption.add_encryption_layer`:

To use it:

1. Generate the OpenAPI client, as [above](#openapi-generator)

2. Import the **mastercard-client-encryption** module and the generated swagger ApiClient

   ```python
   from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
   from client_encryption.api_encryption import add_encryption_layer
   from swagger_client.api_client import ApiClient # import generated swagger ApiClient
   ```

3. Add the field level encryption layer to the generated client:

   ```python
   # Read the service configuration file
   config_file_path = "./config.json"
   config = FieldLevelEncryptionConfig(config_file_path) 
   # Create a new instance of the generated client
   api_client = ApiClient()
   # Enable field level encryption
   api_encryption.add_encryption_layer(api_client, config)
   ```

4. Use the `ApiClient` instance with the Field Level Encryption enabled:

   Example:

   ```python
   request_body = {...}
   response =MyServiceApi(api_client).do_some_action_post(body=request_body)
   # requests and responses will be automatically encrypted and decrypted
   # accordingly with the configuration object used
   
   # ... use the (decrypted) response object here ...
   decrypted = response.json()

   ```
