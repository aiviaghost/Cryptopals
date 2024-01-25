import unittest


MASK_32 = 2 ** 32 - 1


def left_rotate(x, l):
    return (x << l) | (x >> (32 - l)) & MASK_32


def chunkify(chunks, width):
    return (chunks[i: i + width] for i in range(0, len(chunks), width))


class SHA1:
    __h0 = 0x67452301
    __h1 = 0xEFCDAB89
    __h2 = 0x98BADCFE
    __h3 = 0x10325476
    __h4 = 0xC3D2E1F0

    __leftover_data = b""
    __total_message_length = 0

    def __init__(self, msg=b""):
        self.update(msg)

    def __process_chunk(self, chunk):
        assert len(chunk) == 64, f"Chunk must be 16 bytes long! {len(chunk)=}"

        words = [int.from_bytes(word, "big")
                 for word in chunkify(chunk, 4)]
        assert len(
            words) == 16, f"Number of 32 bit words must be 16! {len(words)=}"

        w = words + [0] * 64
        for i in range(16, 80):
            w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        a = self.__h0
        b = self.__h1
        c = self.__h2
        d = self.__h3
        e = self.__h4

        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((MASK_32 ^ b) & d)
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

        return a, b, c, d, e

    def update(self, msg):
        if isinstance(msg, str):
            msg = msg.encode()

        msg = self.__leftover_data + msg
        self.__leftover_data = b""

        extra_bytes = len(msg) % 64

        self.__leftover_data = msg[-extra_bytes:]
        msg = msg[:-extra_bytes]

        for chunk in chunkify(msg, 64):
            self.__total_message_length += len(chunk)
            a, b, c, d, e = self.__process_chunk(chunk)
            self.__h0 = (self.__h0 + a) & MASK_32
            self.__h1 = (self.__h1 + b) & MASK_32
            self.__h2 = (self.__h2 + c) & MASK_32
            self.__h3 = (self.__h3 + d) & MASK_32
            self.__h4 = (self.__h4 + e) & MASK_32

    def digest(self):
        msg = self.__leftover_data
        msg += b"\x80"

        while len(msg) % 64 != 56:
            msg += b"\x00"

        msg += ((self.__total_message_length +
                len(self.__leftover_data)) * 8).to_bytes(8, "big")

        assert len(
            msg) % 64 == 0, f"Message length must be multiple of 64 bytes! {len(msg)=}"

        h0 = self.__h0
        h1 = self.__h1
        h2 = self.__h2
        h3 = self.__h3
        h4 = self.__h4

        for chunk in chunkify(msg, 64):
            a, b, c, d, e = self.__process_chunk(chunk)
            h0 = (self.__h0 + a) & MASK_32
            h1 = (self.__h1 + b) & MASK_32
            h2 = (self.__h2 + c) & MASK_32
            h3 = (self.__h3 + d) & MASK_32
            h4 = (self.__h4 + e) & MASK_32

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
