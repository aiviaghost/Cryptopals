import re
from secrets import token_bytes
from cipher import AES_CTR


class Service:
    __BLOCKSIZE = 16
    __SECRET_KEY = token_bytes(__BLOCKSIZE)

    def encrypt(self, msg: bytes) -> bytes:
        msg = re.compile(b"[;=]").sub(b"", msg)
        prepend_msg = b"comment1=cooking%20MCs;userdata="
        append_msg = b";comment2=%20like%20a%20pound%20of%20bacon"
        enc = AES_CTR(self.__SECRET_KEY).ctr_transform(prepend_msg + msg + append_msg)
        return enc

    def decrypt(self, enc: bytes) -> list:
        msg = AES_CTR(self.__SECRET_KEY).ctr_transform(enc)
        data = [(k, v) for k, v in map(lambda kv: kv.split(b"="), msg.split(b";"))]
        return data
