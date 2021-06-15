from Crypto.Cipher.AES import new
from Encryption_service import Encryption_service
from pprint import pprint

"""
Solution:

If the last block of a plaintext ends with 0x1 it will always be considered 
valid PKCS#7 padding. Bitflip the last byte with all digits in the interval [0, 127], 
call the one that results in valid padding i and the actual byte P. We now have: 

    i ^ P = 0x1
    P = i ^ 0x1

We now know the last byte of the plaintext. We now repeat this process for the second 
to last character but we now look for the first i that results in i ^ P = 0x2. 

To alter bits in plaintext block k we need to flip the bits in block (k - 1). This 
works nicely for all k > 1 but to alter the first block we need to modify the IV, which 
in some sense is the zeroth block. 
"""

service = Encryption_service()
BLOCKSIZE = 16

enc, iv = service.get_encrypted_string()

decrypted = bytearray(enc)

# decrypt all but the first block
for block in range(len(enc) // BLOCKSIZE - 2, -1, -1):
    new_block = bytearray(enc[block * BLOCKSIZE : (block + 1) * BLOCKSIZE])
    for i in range(BLOCKSIZE - 1, -1, -1):
        padding = BLOCKSIZE - i
        for x in range(127, -1, -1):
            new_block[i] = x ^ enc[block * BLOCKSIZE + i]
            if service.decryption_oracle((enc[ : block * BLOCKSIZE] + bytes(new_block) + enc[(block + 1) * BLOCKSIZE : (block + 2) * BLOCKSIZE], iv)):
                decrypted[(block + 1) * BLOCKSIZE + i] = x ^ padding

                for j in range(i, BLOCKSIZE):
                    new_block[j] = enc[block * BLOCKSIZE + j] ^ decrypted[(block + 1) * BLOCKSIZE + j] ^ (padding + 1)

                break

# decrypt first block by altering iv
new_iv = bytearray(iv)
for i in range(BLOCKSIZE - 1, -1, -1):
    padding = BLOCKSIZE - i
    for x in range(127, -1, -1):
        new_iv[i] = x ^ iv[i]
        if service.decryption_oracle((enc[ : BLOCKSIZE], new_iv)):
            decrypted[i] = x ^ padding

            for j in range(i, BLOCKSIZE):
                new_iv[j] = iv[j] ^ decrypted[j] ^ (padding + 1)

            break

print(bytes(decrypted))
