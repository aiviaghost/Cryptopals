import secrets
from Crypto.Cipher import AES


class AES_CTR:
    def __bit_length(self, x):
        return len(bin(x)[2 : ])
    
    def __init__(self, key: bytes, nonce: int = secrets.randbits(64), counter: int = 0):
        assert len(key) == 16, "key must be 16 bytes long."
        assert 0 <= self.__bit_length(nonce) <= 64, "nonce must be a valid 64 bit integer."
        assert 0 <= self.__bit_length(counter) <= 64, "counter must be a valid 64 bit integer."
        self.__KEY = key
        self.__NONCE = nonce
        self.__block_counter = counter

    def __xor(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def __keystream_generator(self):
        while True:
            curr = (self.__NONCE.to_bytes(length=8, byteorder="little") + 
                    self.__block_counter.to_bytes(length=8, byteorder="little"))
            enc = AES.new(self.__KEY, AES.MODE_ECB).encrypt(curr)
            yield from enc
            self.__block_counter += 1
    
    def ctr_transform(self, msg: bytes) -> bytes:
        return self.__xor(msg, self.__keystream_generator())

    def get_nonce(self) -> int:
        return self.__NONCE
