import secrets
from Crypto.Cipher import AES
from itertools import islice


class AES_CTR:
    def __bit_length(self, x):
        return len(bin(x)[2 : ])
    
    def __init__(self, key: bytes, nonce: int = secrets.randbits(64)):
        assert len(key) == 16, "key must be 16 bytes long."
        assert 0 <= self.__bit_length(nonce) <= 64, "nonce must be a valid 64 bit integer."
        self.__KEY = key
        self.__NONCE = nonce

    def __xor(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def __keystream_generator(self, counter = 0):
        while True:
            curr = (self.__NONCE.to_bytes(length=8, byteorder="little") + 
                    counter.to_bytes(length=8, byteorder="little"))
            enc = AES.new(self.__KEY, AES.MODE_ECB).encrypt(curr)
            yield from enc
            counter += 1
    
    def ctr_transform(self, msg: bytes, counter: int = 0) -> bytes:
        assert 0 <= self.__bit_length(counter) <= 64, "counter must be a valid 64 bit integer."
        return self.__xor(msg, self.__keystream_generator(counter))

    def get_nonce(self) -> int:
        return self.__NONCE

    def edit(self, ciphertext: bytes, key: bytes, offset: int, newtext: bytes) -> bytes:
        assert 0 <= offset < len(ciphertext), "Offset not in range of ciphertext!"
        new_enc = self.__xor(newtext, islice(self.__keystream_generator(), offset, offset + len(newtext)))
        return ciphertext[ : offset] + new_enc + ciphertext[offset + len(newtext) : ]
