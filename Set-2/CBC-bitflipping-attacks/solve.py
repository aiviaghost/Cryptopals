from Encryption_service import Encryption_service

"""
Solution:
If ypu look at the decryption procedure for CBC you will find that each plain-
text block is dependant on the corresponding unciphered block and the previous 
ciphertext block. More specifically it is the XOR of the two. 
Since we can control the plaintext starting at block 3 we can control anything 
after that. Our goal is then to make the 4th block contain "admin=true", 
keeping in mind that we have to respect the parsing code on the "server." That 
is we have to disperse ";" and "=" at appropriate places. 
We can't explicitly enter characters in the plaintext but we can use the fact 
that XOR is it's own inverse, like so:

    1. Plaintext_4 = Cipher_3 ^ Decrypted_4
    2. Let the controlled ciphertext be n_3 = Goal ^ Plaintext4 ^ Cipher3
    3. New_plaintext_4 = n_3 ^ Decrypted_4 = Goal ^ Plaintext4 ^ Cipher3 ^ Decrypted4
    4. It follow from (1.) that Decrypted4 = Plaintext_4 ^ Cipher_3
    5. New_plaintext_4 = Goal ^ Plaintext4 ^ Cipher3 ^ Plaintext_4 ^ Cipher_3 = Goal

So by controlling the 3rd ciphertext block we can write whatever we want (almost) 
in plaintext block 4. We mainly have to make sure to fill out the entire block 
while also putting ";" and "=" in appropriate places, see code for PoC. 
"""

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


service = Encryption_service()
BLOCKSIZE = 16

encrypted = service.encrypt(b"a" * BLOCKSIZE)
target = b";admin=true;aaa="
next_block = b";comment2=%20lik"
new_block = xor(xor(next_block, target), encrypted[2 * BLOCKSIZE : 3 * BLOCKSIZE])
new_encrypted = encrypted[ : 2 * BLOCKSIZE] + new_block + encrypted[3 * BLOCKSIZE : ]

decrypted = service.decrypt(new_encrypted)
assert((b"admin", b"true") in decrypted)
print(decrypted)
