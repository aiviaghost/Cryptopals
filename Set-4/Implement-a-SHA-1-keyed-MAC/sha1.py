import unittest

import numpy as np


MASK_32 = 2 ** 32 - 1


def left_rotate(x, l):
    return (x << l) | (x >> (32 - l)) & MASK_32


def chunkify(chunks, width):
    return (chunks[i: i + width] for i in range(0, len(chunks), width))


class SHA1:
    __h = np.array([
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0
    ])

    __leftover_data = b""
    __num_processed_bytes = 0

    def __init__(self, msg=b""):
        self.update(msg)

    def __process_chunk(h, chunk):
        assert len(chunk) == 64, f"Chunk must be 16 bytes long! {len(chunk)=}"

        words = [int.from_bytes(word, "big") for word in chunkify(chunk, 4)]
        assert len(
            words) == 16, f"Number of 32 bit words must be 16! {len(words)=}"

        w = words + [0] * 64
        for i in range(16, 80):
            w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        a, b, c, d, e = h

        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = (
                (left_rotate(a, 5) + f + e + k + w[i]) & MASK_32,
                a,
                left_rotate(b, 30),
                c,
                d
            )

        return np.array([a, b, c, d, e])

    def update(self, msg):
        if isinstance(msg, str):
            msg = msg.encode()

        msg = self.__leftover_data + msg
        self.__leftover_data = b""

        extra_bytes = len(msg) % 64

        self.__leftover_data = msg[-extra_bytes:]
        msg = msg[:-extra_bytes]

        for chunk in chunkify(msg, 64):
            self.__num_processed_bytes += len(chunk)
            self.__h = (
                self.__h + SHA1.__process_chunk(self.__h, chunk)) & MASK_32

    def digest(self):
        msg = self.__leftover_data
        msg += b"\x80"
        print("msg:", msg)
        while len(msg) % 64 != 56:
            msg += b"\x00"

        msg += ((self.__num_processed_bytes +
                len(self.__leftover_data)) * 8).to_bytes(8, "big")

        assert len(
            msg) % 64 == 0, f"Message length must be multiple of 64 bytes! {len(msg)=}"

        h = self.__h.copy()

        for chunk in chunkify(msg, 64):
            h = (h + SHA1.__process_chunk(h, chunk)) & MASK_32

        h0, h1, h2, h3, h4 = map(int, h)
        hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
        return (hh % 2 ** 160).to_bytes(20, "big")


class Test_SHA1(unittest.TestCase):

    def test_empty(self):
        """
        Digest from https://en.wikipedia.org/wiki/SHA-1#Example_hashes
        """
        msg = ""
        digest = SHA1(msg).digest().hex()
        target_digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        self.assertEqual(digest, target_digest)

    def test_fox(self):
        """
        Digests from https://en.wikipedia.org/wiki/SHA-1#Example_hashes
        """
        msg = "The quick brown fox jumps over the lazy dog"
        digest = SHA1(msg).digest().hex()
        target_digest = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        self.assertEqual(digest, target_digest)

        msg = "The quick brown fox jumps over the lazy cog"
        digest = SHA1(msg).digest().hex()
        target_digest = "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
        self.assertEqual(digest, target_digest)
