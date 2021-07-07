from cipher import AES_CTR

"""
C1 = P1 ^ K
C2 = P2 ^ K
C1 ^ C2 = P1 ^ K ^ P2 ^ K = P1 ^ P2
P1 = C1 ^ C2 ^ P2
"""

key = b"sixteen byte key"
plaintext = b"a" * 4

enc = AES_CTR(key).ctr_transform(plaintext)
enc1 = [i for i in enc]
enc2 = [i for i in AES_CTR(key).edit(enc, key, 1, b"b")]

print(enc1)
print(enc2)

print(enc1[1] ^ enc2[1] ^ ord("b"))
print(ord("a"))
