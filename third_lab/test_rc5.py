# test_rc5.py
import os
from third_lab.rc5 import RC5

def get_hamming_distance(b1: bytes, b2: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))


def test_avalanche_plaintext():
    key = os.urandom(16)
    rc5 = RC5(key, w=32, r=12)
    iv = b'\x00' * 8

    pt1 = bytearray(os.urandom(8))
    pt2 = bytearray(pt1)
    pt2[0] ^= 0x01

    ct1 = rc5.encrypt_cbc(bytes(pt1), iv)[:8]
    ct2 = rc5.encrypt_cbc(bytes(pt2), iv)[:8]

    dist = get_hamming_distance(ct1, ct2)
    assert 20 <= dist <= 44

def test_avalanche_key():
    key1 = bytearray(os.urandom(16))
    key2 = bytearray(key1)
    key2[0] ^= 0x01

    rc5_1 = RC5(bytes(key1), w=32, r=12)
    rc5_2 = RC5(bytes(key2), w=32, r=12)
    iv = b'\x00' * 8

    pt = os.urandom(8)

    ct1 = rc5_1.encrypt_cbc(pt, iv)[:8]
    ct2 = rc5_2.encrypt_cbc(pt, iv)[:8]

    dist = get_hamming_distance(ct1, ct2)
    assert 20 <= dist <= 44