import hashlib
import hmac
import unittest

from jav128.constants import BLOCK_SIZE, TAG_SIZE
from jav128.core import decrypt_block, encrypt_block
from jav128.decrypt import decrypt_bytes
from jav128.encrypt import encrypt_bytes
from jav128.key_schedule import expand_round_keys


MASTER_KEY = bytes(range(BLOCK_SIZE))
ROUND_KEYS = expand_round_keys(MASTER_KEY)


class DecryptionTests(unittest.TestCase):
    def test_block_and_container_round_trips(self):
        for block in (bytes(16), bytes([255]) * 16, bytes(range(16))):
            self.assertEqual(decrypt_block(encrypt_block(block, ROUND_KEYS), ROUND_KEYS), block)
        for mode in ("ECB", "CBC", "CFB", "OFB", "CTR"):
            nonce = None if mode == "ECB" else bytes(range(16))
            for plaintext in (b"", b"x", bytes(range(16)), bytes(range(256))):
                container = encrypt_bytes(plaintext, MASTER_KEY, ROUND_KEYS, mode, nonce)
                self.assertEqual(decrypt_bytes(container, MASTER_KEY, ROUND_KEYS), plaintext)

    def test_authentication_failure_does_not_expose_plaintext(self):
        container = bytearray(
            encrypt_bytes(b"secret", MASTER_KEY, ROUND_KEYS, "CBC", bytes(16))
        )
        container[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            decrypt_bytes(bytes(container), MASTER_KEY, ROUND_KEYS)

    def test_valid_tag_with_invalid_padding_is_rejected(self):
        container = bytearray(
            encrypt_bytes(b"secret", MASTER_KEY, ROUND_KEYS, "ECB")
        )
        ciphertext_end = len(container) - TAG_SIZE
        container[ciphertext_end - 1] ^= 1
        tag = hmac.new(
            hmac.new(MASTER_KEY, b"JAV-128/MAC/v1", hashlib.sha256).digest(),
            container[:-TAG_SIZE],
            hashlib.sha256,
        ).digest()
        container[-TAG_SIZE:] = tag
        with self.assertRaises(ValueError):
            decrypt_bytes(bytes(container), MASTER_KEY, ROUND_KEYS)

    def test_malformed_header_is_rejected(self):
        container = bytearray(
            encrypt_bytes(b"secret", MASTER_KEY, ROUND_KEYS, "CBC", bytes(16))
        )
        container[0:4] = b"NOPE"
        with self.assertRaisesRegex(ValueError, "header"):
            decrypt_bytes(bytes(container), MASTER_KEY, ROUND_KEYS)


if __name__ == "__main__":
    unittest.main()
