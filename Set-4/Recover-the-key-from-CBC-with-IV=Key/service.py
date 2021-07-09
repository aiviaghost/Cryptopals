import re
from secrets import token_bytes
from Crypto.Cipher import AES


class Encryption_service:
    __BLOCKSIZE = 16

    def __init__(self, key):
        self.__SECRET_KEY = key
        self.__IV = self.__SECRET_KEY

    def __pad_pkcs7(self, data: bytes) -> bytes:
        pad = self.__BLOCKSIZE - len(data) % self.__BLOCKSIZE
        return data + bytes([pad] * pad)
    
    def __unpad_pkcs7(self, data: bytes) -> bytes:
        if len(data) % self.__BLOCKSIZE != 0 or not (1 <= data[-1] <= self.__BLOCKSIZE) or not all(i == data[-1] for i in data[-data[-1] : ]):
            raise ValueError("Data is not padded with valid PKCS#7!")
        return data[ : -data[-1]]

    def encrypt(self, data: bytes) -> bytes:
        data = re.compile(b"[;=]").sub(b"", data)
        prepend_data = b"comment1=cooking%20MCs;userdata="
        append_data = b";comment2=%20like%20a%20pound%20of%20bacon"
        enc = AES.new(self.__SECRET_KEY, AES.MODE_CBC, self.__IV).encrypt(
            self.__pad_pkcs7(prepend_data + data + append_data)
        )
        return enc

    def decrypt(self, enc: bytes) -> tuple:
        data = self.__unpad_pkcs7(AES.new(self.__SECRET_KEY, AES.MODE_CBC, self.__IV).decrypt(enc))
        for i in data:
            if i > 127:
                return data, ValueError("Invalid byte for ASCII!")
        return data, None
