from cipher import AES_CTR
from base64 import b64decode


cipher = AES_CTR(b"YELLOW SUBMARINE", nonce=0)
dec = cipher.ctr_transform(b64decode(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))
print(dec)


plaintext = b"super secret message"
encryptor = AES_CTR(b"sixteen byte key")
encrypted = encryptor.ctr_transform(plaintext)
decrypted = AES_CTR(b"sixteen byte key", encryptor.get_nonce()).ctr_transform(encrypted)
assert(plaintext == decrypted)
print(decrypted)
