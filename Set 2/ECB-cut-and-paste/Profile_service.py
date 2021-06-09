import re
from base64 import b64decode, b64encode
from secrets import token_bytes
from Crypto.Cipher import AES


class Profile_service:
    secret_key = token_bytes(16)


    def __pad_pkcs7(self, msg: bytes, blocksize = 16) -> bytes:
        pad = blocksize - len(msg) % blocksize
        return msg + bytes([pad] * pad)


    def __unpad_pkcs7(self, msg: bytes, blocksize=16) -> str:
        if len(msg) == 0 or len(msg) % 16 != 0 or msg[-1] not in range(1, blocksize + 1):
            raise ValueError("Data is not padded using valid pkcs7!")
        padding = msg[-1]
        return msg[ : -padding].decode()


    def profile_for(self, email: str) -> str:
        email = re.compile("[&=]").sub("", email)
        profile = f"email={email}&uid=10&role=user"
        enc = AES.new(self.secret_key, AES.MODE_ECB).encrypt(
            self.__pad_pkcs7(bytearray(profile, "utf-8"))
        )
        return b64encode(enc)


    def parse_profile(self, encrypted_profile: str) -> dict:
        decrypted = self.__unpad_pkcs7(AES.new(self.secret_key, AES.MODE_ECB).decrypt(
            b64decode(encrypted_profile)
        ))
        return {k : v for k, v in map(lambda kv: kv.split("="), decrypted.split("&"))}


service = Profile_service()
enc = service.profile_for("jiwaaaf")
print("b64_enc:", enc)
print("enc:", b64decode(enc))
print("decrypted:", service.parse_profile(enc))
