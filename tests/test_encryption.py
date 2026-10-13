import hashlib
import hmac
import unittest

from jav128.constants import BLOCK_SIZE, FORMAT_VERSION, MAGIC, MODE_IDS, TAG_SIZE
from jav128.container import derive_mac_key
from jav128.core import encrypt_block
from jav128.encrypt import encrypt_bytes
from jav128.modes import encrypt_mode
from jav128.padding import pad_pkcs7
from jav128.sbox import INV_SBOX, SBOX


ROUND_KEYS = [bytes([index]) * BLOCK_SIZE for index in range(17)]
MASTER_KEY = bytes(range(16))


class CipherCoreTests(unittest.TestCase):
    def test_sbox_and_inverse_are_byte_permutations(self):
        self.assertEqual(sorted(SBOX), list(range(256)))
        self.assertEqual(sorted(INV_SBOX), list(range(256)))
        for value in range(256):
            self.assertEqual(INV_SBOX[SBOX[value]], value)

    def test_encrypt_block_is_deterministic_and_validates_inputs(self):
        block = bytes(range(16))
        result = encrypt_block(block, ROUND_KEYS)
        self.assertEqual(len(result), BLOCK_SIZE)
        self.assertEqual(result.hex(), "42ca398c6d4f7cf04f1209dd9ef6a92f")
        self.assertEqual(result, encrypt_block(block, ROUND_KEYS))
        self.assertNotEqual(result, block)
        with self.assertRaises(ValueError):
            encrypt_block(b"short", ROUND_KEYS)
        with self.assertRaises(ValueError):
            encrypt_block(block, ROUND_KEYS[:-1])

    def test_pkcs7_always_adds_a_block_when_input_is_aligned(self):
        self.assertEqual(len(pad_pkcs7(b"")), BLOCK_SIZE)
        self.assertEqual(pad_pkcs7(bytes(range(16)))[-1], BLOCK_SIZE)
        self.assertEqual(len(pad_pkcs7(b"x" * 17)), 32)


class ModeEncryptionTests(unittest.TestCase):
    def test_each_mode_returns_block_aligned_ciphertext_and_expected_nonce(self):
        padded = pad_pkcs7(b"JAV-128 mode test")
        fixed_nonce = bytes(range(16))
        for mode in MODE_IDS:
            with self.subTest(mode=mode):
                ciphertext, nonce = encrypt_mode(
                    padded,
                    ROUND_KEYS,
                    mode,
                    None if mode == "ECB" else fixed_nonce,
                    block_encryptor=encrypt_block,
                )
                self.assertEqual(len(ciphertext), len(padded))
                self.assertEqual(len(ciphertext) % BLOCK_SIZE, 0)
                self.assertEqual(nonce, None if mode == "ECB" else fixed_nonce)

    def test_ctr_rejects_counter_wrap(self):
        maximum_counter = bytes([0xFF]) * 16
        with self.assertRaises(OverflowError):
            encrypt_mode(
                pad_pkcs7(bytes(16)),
                ROUND_KEYS,
                "CTR",
                maximum_counter,
                block_encryptor=encrypt_block,
            )

    def test_ctr_accepts_last_counter_for_one_block(self):
        maximum_counter = bytes([0xFF]) * 16
        ciphertext, _ = encrypt_mode(
            pad_pkcs7(b""),
            ROUND_KEYS,
            "CTR",
            maximum_counter,
            block_encryptor=encrypt_block,
        )
        self.assertEqual(len(ciphertext), BLOCK_SIZE)

    def test_authenticated_container_layout_and_tag(self):
        plaintext = b"binary\x00payload\xff"
        nonce = bytes(range(16))
        container = encrypt_bytes(plaintext, MASTER_KEY, ROUND_KEYS, "CBC", nonce)
        self.assertEqual(container[:4], MAGIC)
        self.assertEqual(container[4], FORMAT_VERSION)
        self.assertEqual(container[5], MODE_IDS["CBC"])
        self.assertEqual(container[6], BLOCK_SIZE)
        self.assertEqual(int.from_bytes(container[7:15], "big"), len(plaintext))
        self.assertEqual(container[15:31], nonce)

        padded_length = (len(plaintext) // BLOCK_SIZE + 1) * BLOCK_SIZE
        ciphertext = container[31 : 31 + padded_length]
        tag = container[-TAG_SIZE:]
        expected = hmac.new(
            derive_mac_key(MASTER_KEY), container[:-TAG_SIZE], hashlib.sha256
        ).digest()
        self.assertEqual(tag, expected)
        self.assertEqual(len(ciphertext), padded_length)

    def test_all_modes_support_empty_and_arbitrary_binary_input(self):
        for mode in MODE_IDS:
            with self.subTest(mode=mode):
                nonce = None if mode == "ECB" else bytes([MODE_IDS[mode]]) * 16
                empty_container = encrypt_bytes(b"", MASTER_KEY, ROUND_KEYS, mode, nonce)
                arbitrary = bytes(range(256)) * 3
                binary_container = encrypt_bytes(arbitrary, MASTER_KEY, ROUND_KEYS, mode, nonce)
                self.assertTrue(empty_container.startswith(MAGIC))
                self.assertTrue(binary_container.startswith(MAGIC))

    def test_invalid_iv_and_mode_are_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_bytes(b"x", MASTER_KEY, ROUND_KEYS, "CBC", b"short")
        with self.assertRaises(ValueError):
            encrypt_bytes(b"x", MASTER_KEY, ROUND_KEYS, "ECB", bytes(16))
        with self.assertRaises(ValueError):
            encrypt_bytes(b"x", MASTER_KEY, ROUND_KEYS, "GCM")

    def test_fixed_nonce_produces_repeatable_container(self):
        nonce = b"N" * BLOCK_SIZE
        first = encrypt_bytes(b"repeatable", MASTER_KEY, ROUND_KEYS, "CTR", nonce)
        second = encrypt_bytes(b"repeatable", MASTER_KEY, ROUND_KEYS, "CTR", nonce)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
