from base64 import b64decode
from Crypto.Cipher import AES


file = b64decode(open("aesecb.txt", "r").read())
key = b'YELLOW SUBMARINE'

aes = AES.new(key, AES.MODE_ECB)
print(aes.decrypt(file))
