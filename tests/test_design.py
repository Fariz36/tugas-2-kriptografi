import unittest
from jav128.analysis import byte_statistics, bit_distance
from jav128.core import _inverse_permute_bytes, _permute_bytes, _rotl32, _rotr32
from jav128.key_schedule import expand_round_keys
from jav128.sbox import SBOX, INV_SBOX


class DesignTests(unittest.TestCase):
    def test_schedule_matches_independent_word_recurrence(self):
        key = bytes(range(16))
        words = [int.from_bytes(key[i:i+4], 'little') for i in range(0,16,4)]
        mask = 2**32-1
        for i in range(1,65):
            q = (0x3C6EF372 + i*0x9E3779B9) % 2**32
            x = words[i-1]
            value = (x+q) % 2**32
            value = int.from_bytes(bytes(SBOX[b] for b in value.to_bytes(4, "little")), "little")
            shift = (7*i+3) % 32
            rotated = ((value << shift) | (value >> (32-shift))) & mask
            words.append(words[i+2] ^ rotated ^ q)
        expected = b''.join(w.to_bytes(4,'little') for w in words)
        keys = expand_round_keys(key)
        self.assertEqual(len(keys),17)
        self.assertEqual(b''.join(keys),expected)
        self.assertEqual(keys[0],key)
        with self.assertRaises(ValueError):expand_round_keys(b'short')

    def test_every_key_bit_reaches_generated_round_keys(self):
        import random
        rng = random.Random(0x4A415633)
        for key in [bytes(16), bytes(range(16)), bytes([255])*16] + [rng.randbytes(16) for _ in range(29)]:
            baseline = expand_round_keys(key)
            for bit in range(128):
                changed = bytearray(key)
                changed[bit // 8] ^= 1 << (bit % 8)
                keys = expand_round_keys(bytes(changed))
                self.assertTrue(all(a != b for a, b in zip(baseline[1:], keys[1:])),
                                f"bit {bit}, key {key.hex()}")

    def test_mixing_layers_have_an_explicit_inverse(self):
        # Verify the fixed-i composition and its inverse, including zero rotation.
        for i in range(1, 65):
            q = (0x3C6EF372 + i * 0x9E3779B9) & 0xffffffff
            for x in (0, 1, 0x80000000, 0xffffffff, 0x12345678):
                t = (x + q) & 0xffffffff
                sub = int.from_bytes(bytes(SBOX[b] for b in t.to_bytes(4, 'little')), 'little')
                g = _rotl32(sub, (7*i+3) % 32) ^ q
                recovered_sub = _rotr32(g ^ q, (7*i+3) % 32)
                recovered_t = int.from_bytes(bytes(INV_SBOX[b] for b in recovered_sub.to_bytes(4, 'little')), 'little')
                self.assertEqual((recovered_t - q) & 0xffffffff, x)

    def test_rotation_and_permutation_inverses(self):
        for value in (0,1,0xffffffff,0x12345678):
            for shift in range(32):
                self.assertEqual(_rotr32(_rotl32(value,shift),shift),value)
        for i in range(16):
            block=bytes([1 if j==i else 0 for j in range(16)])
            self.assertEqual(_inverse_permute_bytes(_permute_bytes(block)),block)

    def test_statistics_and_distance(self):
        self.assertEqual(byte_statistics(bytes(range(256)))['entropy_bits_per_byte'],8)
        self.assertEqual(byte_statistics(b'a'*100)['entropy_bits_per_byte'],0)
        self.assertIsNone(byte_statistics(b'')['entropy_bits_per_byte'])
        self.assertEqual(bit_distance(bytes(16),bytes([255])*16),128)
        with self.assertRaises(ValueError):bit_distance(b'a',b'')


if __name__=='__main__':unittest.main()
