"""Hand-computable vectors isolate mode wiring from the cipher core."""
import unittest
from jav128.modes import encrypt_mode, decrypt_mode


def toy_cipher(block, keys):
    return bytes(value ^ 0xAA for value in block)


class ModeReferenceTests(unittest.TestCase):
    def test_three_block_vectors(self):
        plain = bytes(16) + bytes([0x11])*16 + bytes([0x22])*16
        vectors = {
            'ECB': bytes([0xAA])*16 + bytes([0xBB])*16 + bytes([0x88])*16,
            'CBC': bytes([0xAA])*16 + bytes([0x11])*16 + bytes([0x99])*16,
            'CFB': bytes([0xAA])*16 + bytes([0x11])*16 + bytes([0x99])*16,
            'OFB': bytes([0xAA])*16 + bytes([0x11])*16 + bytes([0x88])*16,
            'CTR': bytes([0xAA])*16 + bytes([0xBB])*15 + bytes([0xBA]) + bytes([0x88])*15 + bytes([0x8A]),
        }
        for mode, expected in vectors.items():
            with self.subTest(mode=mode):
                iv = None if mode == 'ECB' else bytes(16)
                actual,_ = encrypt_mode(plain, [], mode, iv, block_encryptor=toy_cipher)
                self.assertEqual(actual, expected)
                self.assertEqual(decrypt_mode(expected, [], mode, iv, block_encryptor=toy_cipher, block_decryptor=toy_cipher),plain)


if __name__=='__main__': unittest.main()
