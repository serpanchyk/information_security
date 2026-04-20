import pytest
from second_lab.md5 import md5_hash_string

@pytest.fixture
def rfc1321_vectors():
    return [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"),
        ("1234567890" * 8, "57edf4a22be3c955ac49da2e2107b67a")
    ]

def test_md5_hashing(rfc1321_vectors):
    for text, expected in rfc1321_vectors:
        assert md5_hash_string(text).lower() == expected.lower()


def hex_to_bin(hex_str: str) -> str:
    return bin(int(hex_str, 16))[2:].zfill(128)

def hamming_distance(bin1: str, bin2: str) -> int:
    return sum(c1 != c2 for c1, c2 in zip(bin1, bin2))

def test_avalanche_effect():
    base_text = "Anton Mykhalchuk"
    modified_text = "Antin Mykhalchuk"

    hash1 = md5_hash_string(base_text)
    hash2 = md5_hash_string(modified_text)

    bin1 = hex_to_bin(hash1)
    bin2 = hex_to_bin(hash2)

    distance = hamming_distance(bin1, bin2)
    print(distance)

    assert 45 <= distance <= 83, f"Weak avalanche effect: changed {distance} bits"