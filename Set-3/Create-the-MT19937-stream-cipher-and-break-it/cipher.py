from MT19937 import MT19937


class MT_Cipher:
    def __init__(self, seed: int):
        assert(len(bin(seed)[2 : ]) <= 16)
        self.__PRNG = MT19937(seed)

    def __xor(self, xs_a: bytes, xs_b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(xs_a, xs_b))

    def __keystream_generator(self):
        while True:
            yield from self.__PRNG.extract_number().to_bytes(4, byteorder="little")
    
    def transform(self, msg: bytes) -> bytes:
        keystream = self.__keystream_generator()
        return self.__xor(msg, keystream)
