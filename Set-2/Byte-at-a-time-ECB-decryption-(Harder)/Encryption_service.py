from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from secrets import token_bytes, randbelow


class Encryption_service:
    __BLOCKSIZE = 16
    __SECRET_KEY = token_bytes(__BLOCKSIZE)
    __RANDOM_PREFIX = token_bytes(randbelow(40))
    __SECRET_MESSAGE = b64decode("""
        Um9sbGluJyBpbiBteSA1LjAKV2l0aCBt
        eSByYWctdG9wIGRvd24gc28gbXkgaGFp
        ciBjYW4gYmxvdwpUaGUgZ2lybGllcyBv
        biBzdGFuZGJ5IHdhdmluZyBqdXN0IHRv
        IHNheSBoaQpEaWQgeW91IHN0b3A/IE5v
        LCBJIGp1c3QgZHJvdmUgYnkK
        """)

    def __pad_pkcs7(self, msg: bytes) -> bytes:
        pad = self.__BLOCKSIZE - len(msg) % self.__BLOCKSIZE
        return msg + bytes([pad] * pad)

    def encrypt(self, msg: bytes) -> bytes:
        enc = AES.new(self.__SECRET_KEY, AES.MODE_ECB).encrypt(
            self.__pad_pkcs7(self.__RANDOM_PREFIX + msg + self.__SECRET_MESSAGE)
        )
        return enc
