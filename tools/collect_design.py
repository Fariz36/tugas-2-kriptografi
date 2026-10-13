"""Collect round traces, key-schedule diffusion, and related-key evidence."""
import csv
import hashlib
import json
import random
from pathlib import Path
from jav128.analysis import bit_distance
from jav128.core import encrypt_block, decrypt_block
from jav128.key_schedule import expand_round_keys
from jav128.sbox import SBOX


def rot(x,n):
    n %= 32
    return ((x << n) | (x >> ((32-n)%32))) & 0xffffffff


def reference_encrypt(block,keys):
    """Independent literal round implementation, without core helpers."""
    state=list(block)
    trace=[]
    for r in range(1,17):
        state=[a^b for a,b in zip(state,keys[r-1])]
        substituted=[SBOX[b] for b in state]
        state=[0]*16
        for i,b in enumerate(substituted):state[(5*i+3)%16]=b
        a,b,c,d=[int.from_bytes(bytes(state[i:i+4]),'little') for i in range(0,16,4)]
        a=rot(a,(b^d)&31)
        c=rot(c,-((a^b)&31))
        a=(a+rot(b,5))&0xffffffff
        b^=rot(c,11)
        c=(c+rot(d,17))&0xffffffff
        d^=rot(a,23)
        cr=(0xA5A5A5A5+r*0x7F4A7C15)&0xffffffff
        state=list(b''.join((x^k).to_bytes(4,'little') for x,k in zip((a,b,c,d),(cr,rot(cr,7),rot(cr,13),rot(cr,21)))))
        trace.append({'round':r,'round_key_hex':keys[r-1].hex(),'state_after_round_hex':bytes(state).hex()})
    result=bytes(a^b for a,b in zip(state,keys[16]))
    return result,trace


def main():
    out=Path('data/results');out.mkdir(parents=True,exist_ok=True)
    rng=random.Random(0x4A415632)
    vectors=[]
    for index in range(35):
        if index==0:key,block=bytes(16),bytes(16)
        elif index==1:key,block=bytes(range(16)),bytes(range(16))
        elif index==2:key,block=bytes([255])*16,bytes([255])*16
        else:key,block=rng.randbytes(16),rng.randbytes(16)
        keys=expand_round_keys(key)
        expected,trace=reference_encrypt(block,keys)
        assert encrypt_block(block,keys)==expected
        assert decrypt_block(expected,keys)==block
        vectors.append({'key_hex':key.hex(),'plaintext_hex':block.hex(),'ciphertext_hex':expected.hex(),
                        'round_keys_hex':[k.hex() for k in keys], 'round_trace':trace})
    (out/'known_vectors.json').write_text(json.dumps(vectors,indent=2)+'\n')
    key=bytes(range(16));keys=expand_round_keys(key);rows=[]
    for bit in range(128):
        altered=bytearray(key);altered[bit//8]^=1<<(bit%8)
        changed=expand_round_keys(bytes(altered))
        for r,(a,b) in enumerate(zip(keys,changed),1):
            rows.append({'master_key_bit':bit,'round_key':r,'changed_bits':bit_distance(a,b)})
    with (out/'key_schedule_diffusion.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    rng = random.Random(0x4A415633)
    sensitivity = []
    relations = []
    for sample, key in enumerate([bytes(16), bytes(range(16)), bytes([255])*16] + [rng.randbytes(16) for _ in range(29)]):
        keys = expand_round_keys(key)
        p = rng.randbytes(16)
        ciphertext = encrypt_block(p, keys)
        for bit in range(128):
            mask = bytearray(16)
            mask[bit // 8] = 1 << (bit % 8)
            altered = bytes(a ^ b for a, b in zip(key, mask))
            changed = expand_round_keys(altered)
            distances = [bit_distance(a, b) for a, b in zip(keys, changed)]
            assert all(distances[1:])
            sensitivity.append({'sample': sample, 'key_hex': key.hex(), 'master_key_bit': bit,
                                'changed_generated_round_keys': sum(d > 0 for d in distances[1:]),
                                'per_round_changed_bits': json.dumps(distances)})
            if bit in (31, 63, 95):
                paired = bytes(a ^ b for a, b in zip(p, mask))
                other = encrypt_block(paired, changed)
                assert ciphertext != other
                relations.append({'sample': sample, 'master_key_bit': bit, 'key_hex': key.hex(),
                                  'related_key_hex': altered.hex(), 'plaintext_hex': p.hex(),
                                  'related_plaintext_hex': paired.hex(), 'ciphertext_hex': ciphertext.hex(),
                                  'related_ciphertext_hex': other.hex(),
                                  'K2_through_K17_identical': changed[1:] == keys[1:],
                                  'ciphertexts_equal': ciphertext == other})
    with (out/'key_schedule_regression.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(sensitivity[0]))
        writer.writeheader()
        writer.writerows(sensitivity)
    (out/'related_key_regression.json').write_text(json.dumps(relations, indent=2)+'\n')
    print('35 independent reference vectors verified; 2176 key-schedule distances; '
          '4096 key-bit comparisons changed all generated round keys; '
          '96 former paired-collision cases no longer collide.')


if __name__=='__main__':main()
