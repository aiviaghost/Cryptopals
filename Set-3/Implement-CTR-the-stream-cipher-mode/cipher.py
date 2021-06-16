import secrets
from Crypto.Cipher import AES


class AES_CTR:
    def __init__(self, key: bytes, nonce: int = secrets.randbits(64), counter: int = 0):
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
        keystream = self.__keystream_generator()
        return self.__xor(msg, keystream)

    def get_nonce(self) -> int:
        return self.__NONCE
