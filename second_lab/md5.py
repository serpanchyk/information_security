import math
import struct


def left_rotate(x: int, c: int) -> int:
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

def get_md5(raw_data: bytes) -> str:
    data = bytearray(raw_data)
    original_length_bits = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF

    data.append(0x80)

    while len(data) % 64 != 56:
        data.append(0x00)

    data += struct.pack('<Q', original_length_bits)

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    S = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ]
    T = [int(4294967296 * abs(math.sin(i))) & 0xFFFFFFFF for i in range(1, 65)]

    for offset in range(0, len(data), 64):
        chunk = data[offset: offset + 64]
        X = list(struct.unpack('<16I', chunk))

        a, b, c, d = A, B, C, D

        for i in range(64):
            if 0 <= i <= 15:
                F = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                F = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                F = b ^ c ^ d
                g = (3 * i + 5) % 16
            elif 48 <= i <= 63:
                F = c ^ (b | ~d)
                g = (7 * i) % 16

            F = (F + a + T[i] + X[g]) & 0xFFFFFFFF
            a = d
            d = c
            c = b
            b = (b + left_rotate(F, S[i])) & 0xFFFFFFFF

        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return struct.pack('<4I', A, B, C, D).hex()


def md5_hash_string(text: str) -> str:
    return get_md5(text.encode('utf-8'))


def md5_hash_file(filepath: str) -> str:
    with open(filepath, 'rb') as f:
        return get_md5(f.read())