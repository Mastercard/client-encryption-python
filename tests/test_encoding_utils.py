import unittest
import client_encryption.encoding_utils as to_test
from client_encryption.encryption_exception import EncodingError


class EncodingUtilsTest(unittest.TestCase):

    def test_hex_encode(self):
        enc_one = to_test.encode_bytes(bytes(1), to_test.ClientEncoding.HEX)
        enc_string = to_test.encode_bytes(b"some data", to_test.ClientEncoding.HEX)
        enc_empty = to_test.encode_bytes(b"", to_test.ClientEncoding.HEX)

        self.assertEqual("00", enc_one, "Encoded bytes not matching")
        self.assertEqual("736f6d652064617461", enc_string, "Encoded bytes not matching")
        self.assertEqual("", enc_empty, "Encoded bytes not matching")

    def test_hex_decode(self):
        dec_one = to_test.decode_value("00", to_test.ClientEncoding.HEX)
        dec_string = to_test.decode_value("736f6d652064617461", to_test.ClientEncoding.HEX)
        dec_empty = to_test.decode_value("", to_test.ClientEncoding.HEX)

        self.assertEqual(bytes(1), dec_one, "Decoded value not matching")
        self.assertEqual(b"some data", dec_string, "Decoded value not matching")
        self.assertEqual(b"", dec_empty, "Decoded value not matching")

    def test_hex_decode_not_valid_hex(self):
        self.assertRaises(ValueError, to_test.decode_value, "736f6d65p064617461", to_test.ClientEncoding.HEX)

    def test_base64_encode(self):
        enc_one = to_test.encode_bytes(bytes(1), to_test.ClientEncoding.BASE64)
        enc_string = to_test.encode_bytes(b"some data", to_test.ClientEncoding.BASE64)
        enc_empty = to_test.encode_bytes(b"", to_test.ClientEncoding.BASE64)

        self.assertEqual("AA==", enc_one, "Encoded bytes not matching")
        self.assertEqual("c29tZSBkYXRh", enc_string, "Encoded bytes not matching")
        self.assertEqual("", enc_empty, "Encoded bytes not matching")

    def test_base64_decode(self):
        dec_one = to_test.decode_value("AA==", to_test.ClientEncoding.BASE64)
        dec_string = to_test.decode_value("c29tZSBkYXRh", to_test.ClientEncoding.BASE64)
        dec_empty = to_test.decode_value("", to_test.ClientEncoding.BASE64)

        self.assertEqual(bytes(1), dec_one, "Decoded value not matching")
        self.assertEqual(b"some data", dec_string, "Decoded value not matching")
        self.assertEqual(b"", dec_empty, "Decoded value not matching")

    def test_base64_decode_not_valid_base64(self):
        self.assertRaises(ValueError, to_test.decode_value, "c29tZS?kYXRh", to_test.ClientEncoding.BASE64)

    def test_encode_no_value(self):
        self.assertRaises(ValueError, to_test.encode_bytes, None, to_test.ClientEncoding.HEX)
        self.assertRaises(ValueError, to_test.encode_bytes, None, to_test.ClientEncoding.BASE64)

    def test_encode_not_a_byte_sequence(self):
        self.assertRaises(ValueError, to_test.encode_bytes, "not a byte sequence", to_test.ClientEncoding.HEX)
        self.assertRaises(ValueError, to_test.encode_bytes, "not a byte sequence", to_test.ClientEncoding.BASE64)

    def test_encode_invalid_encoding(self):
        self.assertRaises(EncodingError, to_test.encode_bytes, b"whatever", "ABC")

    def test_decode_no_value(self):
        self.assertRaises(ValueError, to_test.decode_value, None, to_test.ClientEncoding.HEX)
        self.assertRaises(ValueError, to_test.decode_value, None, to_test.ClientEncoding.BASE64)

    def test_decode_not_a_string(self):
        self.assertRaises(ValueError, to_test.decode_value, b"736f6d652064617461", to_test.ClientEncoding.HEX)
        self.assertRaises(ValueError, to_test.decode_value, b"736f6d652064617461", to_test.ClientEncoding.BASE64)

    def test_decode_invalid_encoding(self):
        self.assertRaises(EncodingError, to_test.decode_value, "whatever", "ABC")
