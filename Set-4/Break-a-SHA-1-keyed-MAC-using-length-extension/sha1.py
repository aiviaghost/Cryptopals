import numpy as np


# Ignore overflow warnings because it's actually expected behaviour here
np.seterr(over="ignore")


def left_rotate(x, l):
    return np.uint32((x << l) | (x >> (32 - l)))


def chunkify(chunks, width):
    return (chunks[i: i + width] for i in range(0, len(chunks), width))


class SHA1:

    def __init__(self, msg=b""):
        self.__h = np.array([
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ], dtype=np.uint32)
        self.__leftover_data = b""
        self.__num_processed_bytes = 0

        self.update(msg)

    def from_state(last_digest, msg_len):
        sha1 = SHA1()
        words = [int.from_bytes(word, "big")
                 for word in chunkify(last_digest, 4)]
        sha1.__h = np.array(words, dtype=np.uint32)
        sha1.__num_processed_bytes = msg_len
        return sha1

    def __process_chunk(h, chunk):
        assert len(chunk) == 64, f"Chunk must be 16 bytes long! {len(chunk)=}"

        words = [int.from_bytes(word, "big") for word in chunkify(chunk, 4)]
        assert len(
            words) == 16, f"Number of 32 bit words must be 16! {len(words)=}"

        w = np.array(words + [0] * 64, dtype=np.uint32)
        for i in range(16, 80):
            w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        a, b, c, d, e = h

        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = np.uint32(0x5A827999)
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = np.uint32(0x6ED9EBA1)
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = np.uint32(0x8F1BBCDC)
            else:
                f = b ^ c ^ d
                k = np.uint32(0xCA62C1D6)

            a, b, c, d, e = (
                left_rotate(a, 5) + f + e + k + w[i],
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
        extra_bytes = len(msg) % 64
        self.__leftover_data = msg[-extra_bytes:]
        msg = msg[:-extra_bytes]

        for chunk in chunkify(msg, 64):
            self.__num_processed_bytes += len(chunk)
            self.__h += SHA1.__process_chunk(self.__h, chunk)

    def digest(self):
        msg = self.__leftover_data
        msg += b"\x80"
        while len(msg) % 64 != 56:
            msg += b"\x00"

        msg += ((self.__num_processed_bytes +
                len(self.__leftover_data)) * 8).to_bytes(8, "big")

        assert len(
            msg) % 64 == 0, f"Message length must be multiple of 64 bytes! {len(msg)=}"

        h = self.__h.copy()

        for chunk in chunkify(msg, 64):
            h += SHA1.__process_chunk(h, chunk)

        h0, h1, h2, h3, h4 = map(int, h)
        hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
        return (hh % 2 ** 160).to_bytes(20, "big")
