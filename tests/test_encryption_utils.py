import unittest
from tests import resource_path
import client_encryption.encryption_utils as to_test
from client_encryption.encryption_exception import CertificateError, PrivateKeyError, HashAlgorithmError
from cryptography import x509
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA224, SHA384, SHA512


class EncryptionUtilsTest(unittest.TestCase):

    _pkcs1_512 = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEA6Jj4PJOePIizjVn1J+ogRX7QFS4OoLiJx4Ehj3zJNMa2UiRvbswMmMEBbZ+GvHIbwJvvhKymZwPi7+bGubrjrQIDAQABAkBtvBWJRr+loXzMWD+ACEYXY1+6TlNaYhWmiPaTYnTur1b0l5jmwl8u8XDCwxz+9joU8cZI7Q/ixDcxAejXPIBFAiEA+KvX+Voe5qVZ3mywAmu/OgrsS1VKeNu5TW1UoFMvCe8CIQDvc9qrVTTA7XYPJ9FwT5RDU3C9E4tWfRdAD8wAYyP4IwIgOPAwDZpDBRDLWRCN5KADMykZHc6ztKSq8z2baPJjDOUCIGsEUlSEjkEzX7JCT35scozse9RlKb8LxRpidQAvTuIVAiAIsiF8nnE+JQPq07WOfQpq5/UM6XCENALXTOk6K0zzGg=="
    _pkcs1_2048 = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDMJPwAG210B9bznVVU0xKSmBxZnXIVODE275yg+kvxSDU5mBFg6CD59yP8DwxNiz/JeAgmEjWChdUX/01k9+vKsE/F4Ug4l74IZ48YyBe/cXuj25XTXTNzIiaAqe2/c2ssJXD22vMghoo2C/CCY8OF6AexalUyvsuTYMvlCY8Tbwnx6Qmdh8cnMZRKUlgmkKgJW07ts88MJxaCuU7OhqBO6O2nIFFYA9EmgDUnZvu6/Ouqa5QZ/xiqDwwh43tS7GziNKTeuwNcwITlwJUpr5t+hNXVdFAnY8AF026/Af/CqixGDdhOAV1YzjoBjgOAjPOpj/FJ4uJt3UfODbAdBMzrAgMBAAECggEBAMuaO2eT81cdFopEKb3/AfAJG4VZXVXChHspAYsf96v+e28ktnhzK6iCj3YuP/P65LR4LZBi6tFxzzUu4K7KAXZW4EkYReKDnPle574smlrKwSiMseJrewviTIpYcJFYeNQ/x2m8t22CIciDoe05uOENqNaOmciRuBIWIWUeYn9aoDsiMQ56EaKpOOt/Jekvyttwa35yElvbPSxF2UAGOXUxPaz1wIdkvDPrHV4NAMNjLDalFGYR10xnlVa0B3fsjxFaXY0esyyCBxonMgDkud12xGqYxXDv7WoUggrRkc5OSe++BDz5Ts/6vy/v7ea5+9fglqQ+KeCPnjeyVs4ZqkECgYEA7UXhER4p8KkYyjuRZmwABICQRv7kVy7iOsTNmR/aOTlYLjORaWZICprLVYsgQY/bksKjSjy9MR/HS0426QkyYQl7BWLnnU3HP5yVytuIlFxfo/xFMJ5wm1CNQ6rAcO8o02lwATzPPRg4ui0nGEIflJPdoTTuxzXn0r0QYzN52uECgYEA3EG9uCEzE3uVO5K/Ew7A1A5aAp9bNX59NctDtKAWEgKoRXrudgebSv+P2U3ZW3G6HouGpnavWSHMQ6HIfPtgEg0BhSqOOgUBVR+wdntq4zux1AFnHVXBLZdE+CWCmyj3ASFMTPvkLssfj/ae7UEhUB24TZxz3nAo8RR7Gmz8TUsCgYEAimnEVK8K+kg6nObI+D2yeO3ivHe/DpjcAjqCUXxCWjV4mmMcxaaUChOo4Dsr0vMvvNpsVUc/eqO2J9j1sVXbHL5iFI9Q2/Pect5Oh6svbpTAejIUzrrup7wC3GGEp5zsbP/KBf7KSjKSDRGAB+ey8oKbvInbbTymAsql/6iswiECgYEAuukzFZFe5banMpHaglKvwoSXT8hpv2Ci4samox6C/C+zGpsyx4i2+RMcwHy26kn9drRSxOrM7OeojvA40g8EPO06kAZIAeaDdfhZaIJdd44N32p9VcCTGZxYE/jI9+Dwk83tERtlTWxkUWgpAA+YNIO0BnCxR1+I7uTBfvBjvzcCgYBDrjptyo8peY0Jzaijg7hWBwLZp/M27GhR8uAV6FVESP+1uG06k3g3CECxCE3Pi6HVSaW6UpNMZnrtVaKQCJDyKnkdIExFVP8DhkJSHmid1TXJXEfpDT57JD4UX6NOCcB0ynSyYvDvJ6bodx6SSyB03CEMqJ8VMjXeYpZSHyAF7A=="
    _pkcs8_2048 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD0ynqAQWn0T7/VJLletTJgoxsTt5TR3IkJ+Yk/Pxg6Q5hXuiGrBdC+OVo/9hrNnptuZh9rZYKto6lbSjYFiKMeBDvPZrYDPzusp0C0KllIoVbzYiOezD76XHsQAEje0UXbzZlXstPXef2bi2HkqV26ST167L5O4moK8+7jHMT80T6XgsUyvyt8PjsQ9CSu6fnD9NfCSYmt2cb16OXcEtA7To2zoGznXqB6JhntFjG0jxee7RkLR+moOqMI9kFM5GSIV4uhwQ9FtOCjUf7TFAU12wwfX/QXUEj6G93GVtzf6QdkVkWh4EyRHeMLyMNc5c0Iw1ZvXdOKfoeo9F47QpbzAgMBAAECggEAK3dMmzuCSdxjTsCPnc6E3H35z914Mm97ceb6RN26OpZIFcO6OLj2oOBkMxlLFxnDta2yhIpo0tZNuyUJRKBHfov35tLxHNB8kyK7rYIbincDjoHtm0PfJuuG+odiaRY11lrCkLzzOr6xlo4AWu7r8qkQnqQtAqrXc4xu7artG4rfMIunGnjjWQGzovtey1JgZctO97MU4Wvw18vgYBI6JM4eHJkZxgEhVQblBTKZs4OfiWk6MRHchgvqnWugwl213FgCzwy9cnyxTP13i9QKaFzL29TYmmN6bRWBH95z41M8IAa0CGahrSJjudZCFwsFh413YWv/pdqdkKHg1sqseQKBgQD641RYQkMn4G9vOiwB/is5M0OAhhUdWH1QtB8vvhY5ISTjFMqgIIVQvGmqDDk8QqFMOfFFqLtnArGn8HrKmBXMpRigS4ae/QgHEz34/RFjNDQ9zxIf/yoCRH5PmnPPU6x8j3bj/vJMRQA6/yngoca+9qvi3R32AtC5DUELnwyzNwKBgQD5x1iEV+albyCNNyLoT/f6LSH1NVcO+0IOvIaAVMtfy+hEEXz7izv3/AgcogVZzRARSK0qsQ+4WQN6Q2WG5cQYSyB92PR+VgwhnagVvA+QHNDL988xoMhB5r2D2IVSRuTB2EOg7LiWHUHIExaxVkbADODDj7YV2aQCJVv0gbDQJQKBgQCaABix5Fqci6NbPvXsczvM7K6uoZ8sWDjz5NyPzbqObs3ZpdWK3Ot4V270tnQbjTq9M4PqIlyGKp0qXO7ClQAskdq/6hxEU0UuMp2DzLNzlYPLvON/SH1czvZJnqEfzli+TMHJyaCpOGGf1Si7fhIk/f0cUGYnsCq2rHAU1hhRmQKBgE/BJTRs1MqyJxSwLEc9cZLCYntnYrr342nNLK1BZgbalvlVFDFFjgpqwTRTT54S6jR6nkBpdPmKAqBBcOOX7ftL0b4dTkQguZLqQkdeWyHK8aiPIetYyVixkoXM1xUkadqzcTSrIW1dPiniXnaVc9XSxtnqw1tKuSGuSCRUXN65AoGBAN/AmT1S4PAQpSWufC8NUJey8S0bURUNNjd52MQ7pWzGq2QC00+dBLkTPj3KOGYpXw9ScZPbxOthBFzHOxERWo16AFw3OeRtn4VB1QJ9XvoA/oz4lEhJKbwUfuFGGvSpYvg3vZcOHF2zlvcUu7C0ub/WhOjV9jZvU5B2Ev8x1neb"
    _pkcs1_1024 = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMe6XwDswzfKfHVdHGYsJFnUuvrpCmlY/lloSi2xA+kW3KrfD/F0tZl3lddBwhv/BRBZxvEFZgk8yT8ZVDem+QgoSoL6HTxV1e19sGUz5ETw5hpBbk4WDtiMeAv9a8KRrpUn33RG5f1l2P1NS7wbKoRGWX9dQMAKzzlq1tJbo8FBAgMBAAECgYEAv1pyzQsJmfk4tqUHoWgnR52FqwD8xaPKxFQjxZTz3yzVLCxcNQSRPECTYdGRrIrvChRJgv+eG7mOQhL9WfhyW8ftdGRyHbZyMACzigZldRSVWtxcUOJHSjY6oAheHbgRIz+2kNaaf83fRp+ffVMEArGBjkSPZKuYrmCNJ4wYj3ECQQD6A8z8/6MuLDLC6JLhBFjF4MW2W5pp+XtQdH8jq8v1Vqo6m3BXV78mXK0o0wLCgypp13vf38EBf12o2CmeIcL1AkEAzIJkEBzw8iN8zWHix4QN5vabGXVjYOZwNRVYi34ThmzebUjn3B5WBj8HBfhQgSWGCxWM2jqpdg9taKqXj+3NnQJBAIsnpGfI7Y1cgmBjzKS7o6F3qvQF5ltHxfAQ91bmXx5Nv2/hZlTm/PigKq0HTYjwMqI4krUXuDhaKMo6jmd6iSUCQG0b3/Dsz+wP3OTipZBWtugTh9pEU9n9972KfuwlPpuId/8MV4+Lq8+3TrLzsVfFwkclnzlK9OBlCLU/1o7Wi80CQBXGAmr3gIoJmM6KSznFOujpXSlh2zHS264iXH+8ZUYfdtyalKb9LnidKi/NsQM3uAqvgJJKwBCoLqg/AlJA3qY="
    _pkcs1_4096 = "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"
    _pkcs12 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCYoc5Ue4MKxHIQeSESKQiIv341EFDtfAlAsXP74modJuwnSLOfSkFNgKH4y6vSKiUK7BxU2KFy7FkRJ9/vceJmP9MD6bWPgT2Wg4iSQxgPtAHEVps9MYvkhW0lt0hyhAcGLUR3kb4YjSkGfa8EzG/G2g+/VKdL0mnSgWhCnSBnR0xRwWccgdRTLm20/jzXkmHD92DBR7kDgiBUrPWTfLHDnsVoIUut6BAPI83TIjHjVG1Jn8K0prbGeQU9ALwaL36qvppYpmCqaAGHOM2fXsEPFNhEZxQpbyW2M4PtXHnjSqlNOKN2tmdF3jWwm9hKZ9xeaWJkBmBnLe3tNz0OdO0pAgMBAAECggEBAJHQGn5JFJJnw5SLM5XWz4lcb2SgNr/5/BjqriQXVEqPUZHh+X+Wf7ZbyeEWKgp4KrU5hYNlBS/2LMyf7GYixSfrl1qoncP/suektwcLw+PUks+P8XRPbhadhP1AEJ0eFlvHSR51hEaOLIA/98C80ZgF4H9njv93f5MT/5eL5lXipFX1dcxUB55q9QOtQ7uCg++NyG5F6u4FxbNtOtsjyNzWZSjYsjSyGHDip9ScDOPNsGQfznxo/oifdXvc25BgWvRflIIYEP08eeUSuGW2nUnx+Joc0oZTkC0wfU+aqKlaZp8zfOEIm0gUDgWtgnq5I5JHJMuW6BtA4K3E+nyP0lECgYEAzIbNx/lVxmFPbPp+AG9LD3JLycjdmTzwpHK44MsaUBOZ9PkLZs0NpR5z0/qcFb8YGGz3qN6E/TTydmfXCpZ3bxP3+x81gL9SVG/y2GP/ky/REA0jFycwVlONeVnd09xPNNLZLUgZhWyAQIA2pmVMh8W+pX6ojxGgOe+KIGutJCUCgYEAvwuNciTzkjBz9nFCjLONvP05WMdIAXo1uxd17iQ0lhRtmHbphojFAPcHYocm2oUXJo5nLvy+u8xnxbyXaZHmRqm98AzmBTtpphFtgfTtv/cSvOsBpdyyaJaN12IUs2XYACGBRa2DUkgxxvHtbmjFGFIU+5VgjOG8g0LfoPhLM7UCgYAmdRaOioihY7zOjg9RP5wKjIBJsfZREQ9irJus0SPieL0TPhzxuI7fRGmdK1tcD3GVbi/nVegFwIXy07WwrPhKL6QKWSTzT4ZIkEBGhg8RewVBkmbNvLWvFcjdT5ORebR/B0KE7DC4UN2Qw0sDYLrSMNGXRsilFjhdjHgZfoWw7QKBgAZrQvNk3nI5AoxzPcMwfUCuWXDsMTUrgAarQSEhQksQoKYQyMPmcIgZxLvAwsNw2VhITJs9jsMMmSgBsCyx5ETXizQ3mrruRhx4VW+aZSqgCJckZkfGZJAzDsz/1KY6c8l9VrSaoeDv4AxJMKsXBhhNGbtiR340T3sxkgX8kbpJAoGBAII2aFeQ4oE8DhSZZo2bpJxO072xy1P9PRlyasYBJ2sNiF0TTguXJB1Ncu0TM0+FLZXIFddalPgv1hY98vNX22dZWKvD3xJ7HRUx/Hyk+VEkH11lsLZ/8AhcwZAr76cE/HLz1XtkKKBCnnlOLPZN03j+WKU3p1fzeWqfW4nyCALQ"

    def test_load_encryption_certificate_pem(self):
        cert_path = resource_path("certificates/test_certificate-2048.pem")
        cert, type = to_test.load_encryption_certificate(cert_path)

        self.assertIsNotNone(cert)
        self.assertIsInstance(cert, x509.Certificate, "Must be X509 certificate")

    def test_load_encryption_certificate_der(self):
        cert_path = resource_path("certificates/test_certificate-2048.der")
        cert, type = to_test.load_encryption_certificate(cert_path)

        self.assertIsNotNone(cert)
        self.assertIsInstance(cert, x509.Certificate, "Must be X509 certificate")

    def test_load_encryption_certificate_invalid(self):
        cert_path = resource_path("keys/test_invalid_key.der")

        self.assertRaises(CertificateError, to_test.load_encryption_certificate, cert_path)

    def test_load_encryption_certificate_file_does_not_exist(self):
        cert_path = resource_path("certificates/non_existing_file.pem")

        self.assertRaises(CertificateError, to_test.load_encryption_certificate, cert_path)

    def test_load_decryption_key_pkcs8_pem(self):
        key_path = resource_path("keys/test_key_pkcs8-2048.pem")
        key = to_test.load_decryption_key(key_path)

        self.assertIsNotNone(key)
        self.assertIsInstance(key, RSA.RsaKey, "Must be RSA key")
        self.assertEqual(self._pkcs8_2048, self.__strip_key(key), "Decryption key does not match")

    def test_load_decryption_key_pkcs8_der(self):
        key_path = resource_path("keys/test_key_pkcs8-2048.der")
        key = to_test.load_decryption_key(key_path)

        self.assertIsNotNone(key)
        self.assertIsInstance(key, RSA.RsaKey, "Must be RSA key")
        self.assertEqual(self._pkcs8_2048, self.__strip_key(key), "Decryption key does not match")

    def test_load_decryption_key_pkcs1_pem(self):
        key_path = resource_path("keys/test_key_pkcs1-2048.pem")
        key = to_test.load_decryption_key(key_path)

        self.assertIsNotNone(key)
        self.assertIsInstance(key, RSA.RsaKey, "Must be RSA key")
        self.assertEqual(self._pkcs1_2048, self.__strip_key(key), "Decryption key does not match")

    def test_load_decryption_key_pkcs1_512bits_pem(self):
        key_path = resource_path("keys/test_key_pkcs1-512.pem")
        key = to_test.load_decryption_key(key_path)

        self.assertIsNotNone(key)
        self.assertIsInstance(key, RSA.RsaKey, "Must be RSA key")
        self.assertEqual(self._pkcs1_512, self.__strip_key(key), "Decryption key does not match")

    def test_load_decryption_key_pkcs1_1024bits_pem(self):
        key_path = resource_path("keys/test_key_pkcs1-1024.pem")
        key = to_test.load_decryption_key(key_path)

        self.assertIsNotNone(key)
        self.assertIsInstance(key, RSA.RsaKey, "Must be RSA key")
        self.assertEqual(self._pkcs1_1024, self.__strip_key(key), "Decryption key does not match")

    def test_load_decryption_key_pkcs1_4096bits_pem(self):
        key_path = resource_path("keys/test_key_pkcs1-4096.pem")
        key = to_test.load_decryption_key(key_path)

        self.assertIsNotNone(key)
        self.assertIsInstance(key, RSA.RsaKey, "Must be RSA key")
        self.assertEqual(self._pkcs1_4096, self.__strip_key(key), "Decryption key does not match")

    def test_load_decryption_key_pkcs12(self):
        key_path = resource_path("keys/test_key.p12")
        key_password = "Password1"
        p12_key = to_test.load_decryption_key(key_path, key_password)

        self.assertIsNotNone(p12_key)
        self.assertIsInstance(p12_key, RSA.RsaKey, "Must be RSA key")
        self.assertEqual(self._pkcs12, self.__strip_key(p12_key), "Decryption key does not match")

    def test_load_decryption_key_invalid_key(self):
        key_path = resource_path("keys/test_invalid_key.der")

        self.assertRaises(PrivateKeyError, to_test.load_decryption_key, key_path)

    def test_load_decryption_key_file_does_not_exist(self):
        key_path = resource_path("keys/non_existing_file.pem")

        self.assertRaises(PrivateKeyError, to_test.load_decryption_key, key_path)

    def test_load_hash_algorithm(self):
        hash_algo = to_test.load_hash_algorithm("SHA224")

        self.assertEqual(hash_algo, SHA224)

    def test_load_hash_algorithm_dash(self):
        hash_algo = to_test.load_hash_algorithm("SHA-512")

        self.assertEqual(hash_algo, SHA512)

    def test_load_hash_algorithm_lowercase(self):
        hash_algo = to_test.load_hash_algorithm("sha384")

        self.assertEqual(hash_algo, SHA384)

    def test_load_hash_algorithm_not_supported(self):
        self.assertRaises(HashAlgorithmError, to_test.load_hash_algorithm, "MD5")

    def test_load_hash_algorithm_underscore(self):
        self.assertRaises(HashAlgorithmError, to_test.load_hash_algorithm, "SHA_512")

    def test_load_hash_algorithm_none(self):
        self.assertRaises(HashAlgorithmError, to_test.load_hash_algorithm, None)

    def test_validate_hash_algorithm(self):
        hash_algo = to_test.validate_hash_algorithm("SHA224")

        self.assertEqual(hash_algo, "SHA224")

    def test_validate_hash_algorithm_dash(self):
        hash_algo = to_test.validate_hash_algorithm("SHA-512")

        self.assertEqual(hash_algo, "SHA512")

    def test_validate_hash_algorithm_lowercase(self):
        hash_algo = to_test.validate_hash_algorithm("sha384")

        self.assertEqual(hash_algo, "SHA384")

    def test_validate_hash_algorithm_not_supported(self):
        self.assertRaises(HashAlgorithmError, to_test.validate_hash_algorithm, "MD5")

    def test_validate_hash_algorithm_underscore(self):
        self.assertRaises(HashAlgorithmError, to_test.validate_hash_algorithm, "SHA_512")

    def test_validate_hash_algorithm_none(self):
        self.assertRaises(HashAlgorithmError, to_test.validate_hash_algorithm, None)

    @staticmethod
    def __strip_key(rsa_key):
        return rsa_key.export_key(pkcs=8).decode('utf-8').replace("\n", "")[27:-25]
