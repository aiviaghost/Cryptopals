from cipher import AES_CTR
from Crypto.Cipher import AES
from base64 import b64decode

"""
Solution:
C1 = P1 ^ K
C2 = P2 ^ K
C1 ^ C2 = P1 ^ K ^ P2 ^ K = P1 ^ P2
P1 = C1 ^ C2 ^ P2

We can even be a little more clever by choosing P2 to be 
all null-bytes (b"\x00"), that way P1 = C1 ^ C2 ^ P2 = C1 ^ C2 
since a ^ 0 = a. 

In the end this challenge is mostly about not getting hung up 
on the fact that we control the offset parameter of the edit-function, 
we want to start at offset 0 anyway. 
"""

def unpad_pkcs7(data: bytes, blocksize=16) -> bytes:
    if len(data) % blocksize != 0 or not (1 <= data[-1] <= blocksize) or not all(i == data[-1] for i in data[-data[-1] : ]):
        raise ValueError("Data is not padded with valid PKCS#7 padding!")
    return data[ : -data[-1]]

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

with open("encrypted.txt", "rb") as f:
    enc = b64decode(b"".join(map(bytes.strip, f.readlines())))
    plaintext = unpad_pkcs7(AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB).decrypt(enc))

key = b"sixteen byte key"
C1 = AES_CTR(key).ctr_transform(plaintext)
C2 = AES_CTR(key).edit(C1, key, 0, b"\x00" * len(C1))
recovered_plaintext = xor(C1, C2)
assert recovered_plaintext == plaintext, "Recovered plaintext does not match original plaintext!"
print(recovered_plaintext)
