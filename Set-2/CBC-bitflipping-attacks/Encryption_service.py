import re
from secrets import token_bytes
from Crypto.Cipher import AES


class Encryption_service:
    __BLOCKSIZE = 16
    __SECRET_KEY = token_bytes(__BLOCKSIZE)
    __IV = b'\x00' * __BLOCKSIZE

    def __pad_pkcs7(self, msg: bytes) -> bytes:
        pad = self.__BLOCKSIZE - len(msg) % self.__BLOCKSIZE
        return msg + bytes([pad] * pad)
    
    def __unpad_pkcs7(self, msg: bytes) -> bytes:
        if len(msg) == 0 or len(msg) % self.__BLOCKSIZE != 0 or not (1 <= msg[-1] <= self.__BLOCKSIZE) or not all(i == msg[-1] for i in msg[-msg[-1] : ]):
            raise ValueError("Data is not padded with valid PKCS#7!")
        return msg[ : -msg[-1]]

    def encrypt(self, msg: bytes) -> bytes:
        msg = re.compile(b"[;=]").sub(b"", msg)
        prepend_msg = b"comment1=cooking%20MCs;userdata="
        append_msg = b";comment2=%20like%20a%20pound%20of%20bacon"
        enc = AES.new(self.__SECRET_KEY, AES.MODE_CBC, self.__IV).encrypt(
            self.__pad_pkcs7(prepend_msg + msg + append_msg)
        )
        return enc

    def decrypt(self, enc: bytes) -> dict:
        msg = self.__unpad_pkcs7(AES.new(self.__SECRET_KEY, AES.MODE_CBC, self.__IV).decrypt(enc))
        data = [(k, v) for k, v in map(lambda kv: kv.split(b"="), msg.split(b";"))]
        return data
