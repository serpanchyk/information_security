import struct
import array
from typing import List


class RC5:
    def __init__(self, key: bytes, w: int = 32, r: int = 12):
        self.w = w
        self.R = r
        self.mod = 2 ** w
        self.mask = self.mod - 1

        if w == 16:
            self.P, self.Q, self.fmt, self.type_code = 0xB7E1, 0x9E37, 'H', 'H'
        elif w == 32:
            self.P, self.Q, self.fmt, self.type_code = 0xB7E15163, 0x9E3779B9, 'I', 'I'
        elif w == 64:
            self.P, self.Q, self.fmt, self.type_code = 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15, 'Q', 'Q'
        else:
            raise ValueError("Unsupported w. Must be 16, 32, or 64.")

        self.S = self._expand_key(key)

    def _left_rotate(self, val: int, shift: int) -> int:
        shift &= (self.w - 1)
        return ((val << shift) & self.mask) | (val >> (self.w - shift))

    def _right_rotate(self, val: int, shift: int) -> int:
        shift &= (self.w - 1)
        return (val >> shift) | ((val << (self.w - shift)) & self.mask)

    def _expand_key(self, key: bytes) -> List[int]:
        u = self.w // 8
        key_padded = bytearray(key)
        if len(key_padded) % u != 0:
            key_padded.extend(b'\x00' * (u - (len(key_padded) % u)))

        c = len(key_padded) // u
        L = list(struct.unpack('<' + self.fmt * c, key_padded))

        t = 2 * self.R + 2
        S = [0] * t
        S[0] = self.P
        for i in range(1, t):
            S[i] = (S[i - 1] + self.Q) & self.mask

        i = j = A = B = 0
        for _ in range(3 * max(c, t)):
            A = S[i] = self._left_rotate((S[i] + A + B) & self.mask, 3)
            B = L[j] = self._left_rotate((L[j] + A + B) & self.mask, (A + B))
            i = (i + 1) % t
            j = (j + 1) % c
        return S

    def encrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        u = self.w // 8
        block_size = u * 2
        pad_len = block_size - (len(data) % block_size)
        data += bytes([pad_len] * pad_len)

        words = array.array(self.type_code, data)
        iv_words = struct.unpack('<' + self.fmt * 2, iv[:block_size].ljust(block_size, b'\x00'))
        prev_a, prev_b = iv_words

        S = self.S
        mask = self.mask
        R = self.R
        left_rot = self._left_rotate

        out_words = array.array(self.type_code, [0] * len(words))

        for i in range(0, len(words), 2):
            a = words[i] ^ prev_a
            b = words[i + 1] ^ prev_b

            a = (a + S[0]) & mask
            b = (b + S[1]) & mask

            for r in range(1, R + 1):
                # Manual inlining of rotation logic for speed
                a_xor_b = a ^ b
                s_a = b & (self.w - 1)
                a = (((a_xor_b << s_a) & mask) | (a_xor_b >> (self.w - s_a)) + S[2 * r]) & mask

                b_xor_a = b ^ a
                s_b = a & (self.w - 1)
                b = (((b_xor_a << s_b) & mask) | (b_xor_a >> (self.w - s_b)) + S[2 * r + 1]) & mask

            out_words[i] = a
            out_words[i + 1] = b
            prev_a, prev_b = a, b

        return out_words.tobytes()

    def decrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        u = self.w // 8
        block_size = u * 2
        words = array.array(self.type_code, data)
        iv_words = struct.unpack('<' + self.fmt * 2, iv[:block_size].ljust(block_size, b'\x00'))
        prev_block_a, prev_block_b = iv_words

        S = self.S
        mask = self.mask
        R = self.R
        right_rot = self._right_rotate
        out_words = array.array(self.type_code, [0] * len(words))

        for i in range(0, len(words), 2):
            orig_a, orig_b = words[i], words[i + 1]
            a, b = orig_a, orig_b

            for r in range(R, 0, -1):
                # Manual inlining of rotation logic for speed
                a_xor_b = a ^ b
                s_a = b & (self.w - 1)
                a = ((((a_xor_b << s_a) & mask) | (a_xor_b >> (self.w - s_a))) + S[2 * r]) & mask

                b_xor_a = b ^ a
                s_b = a & (self.w - 1)
                b = ((((b_xor_a << s_b) & mask) | (b_xor_a >> (self.w - s_b))) + S[2 * r + 1]) & mask

            b = (b - S[1]) & mask
            a = (a - S[0]) & mask

            out_words[i] = a ^ prev_block_a
            out_words[i + 1] = b ^ prev_block_b
            prev_block_a, prev_block_b = orig_a, orig_b

        decrypted = out_words.tobytes()
        return decrypted[:-decrypted[-1]]