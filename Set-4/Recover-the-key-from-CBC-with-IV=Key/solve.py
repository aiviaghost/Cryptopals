from service import Encryption_service


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

BLOCKSIZE = 16
key = b"sixteen byte key"
service = Encryption_service(key)

block_1_known = b"comment1=cooking"
block_2_known = b"%20MCs;userdata="
block_3_controlled = b"a" * BLOCKSIZE

assert len(block_1_known) == len(block_2_known) == len(block_3_controlled) == BLOCKSIZE, "Controlled data is not aligned with block boundary!"

C1 = service.encrypt(block_3_controlled)
valid_padding_blocks = C1[-2 * BLOCKSIZE : ] # neat trick I saw in this great writeup https://cedricvanrompay.gitlab.io/cryptopals/challenges/27.html
C2 = C1[ : BLOCKSIZE] + b"\x00" * BLOCKSIZE + C1[ : BLOCKSIZE] + valid_padding_blocks
decrypted, error = service.decrypt(C2)
recovered_key = xor(decrypted[ : BLOCKSIZE], decrypted[2 * BLOCKSIZE : 3 * BLOCKSIZE])
assert recovered_key == key, "Recovered key does not match actual key!"
print(key)
