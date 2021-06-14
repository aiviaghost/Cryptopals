import secrets
from base64 import b64encode, b64decode
from Crypto.Cipher import AES


class Encryption_service:
    __BLOCKSIZE = 16
    __SECRET_KEY = secrets.token_bytes(__BLOCKSIZE)
    __STRINGS = list(map(b64decode, [
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", 
        b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", 
        b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", 
        b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", 
        b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", 
        b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", 
        b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", 
        b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", 
        b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", 
        b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]))

    def __pad_pkcs7(self, msg: bytes) -> bytes:
        pad = self.__BLOCKSIZE - len(msg) % self.__BLOCKSIZE
        return msg + bytes([pad] * pad)

    def __unpad_pkcs7(self, msg: bytes) -> bytes:
        if len(msg) == 0 or len(msg) % self.__BLOCKSIZE != 0 or not (1 <= msg[-1] <= self.__BLOCKSIZE) or not all(i == msg[-1] for i in msg[-msg[-1] : ]):
            raise ValueError("Data is not padded using valid PKCS#7!")
        return msg[ : -msg[-1]]

    def get_encrypted_string(self) -> bytes:
        string = secrets.choice(self.__STRINGS)
        iv = secrets.token_bytes(self.__BLOCKSIZE)
        enc = AES.new(self.__SECRET_KEY, AES.MODE_CBC, iv).encrypt(
            self.__pad_pkcs7(string)
        )
        return (enc, iv)
    
    def decryption_oracle(self, cipher) -> bool:
        enc, iv = cipher
        try:
            self.__unpad_pkcs7(AES.new(self.__SECRET_KEY, AES.MODE_CBC, iv).decrypt(enc))
            return True
        except ValueError as e:
            return False
