from service import Service

"""
This challenge is (in my opinion) significantly easier than the CBC counterpart because we 
don't have to worry about block boundaries. We can use the null-byte trick (like we saw in
the previous challenge, "random access read/ write CTR") to extract the keystream. We want 
the plaintext to contain the string "admin=true" but we also need to add something to the 
userdata-field, so we just set it to the character "a" (In general we can set this to 
whatever we want) followed by the separating character ";". Therefore our full goal plain-
text is "a;admin=true". Now we utilize the null-byte trick by sending a number of null-
bytes equal to the length of our goal plaintext. The resulting ciphertext, C1, is now 

    C1 = goal_plaintext ^ keystream = keystream

Now we know the keystream, or more specifially we know the part of the keystream which will
decrypt our crafted ciphertext, which is our next step. 
We set our crafted ciphertext to goal_plaintext ^ keystream which, when decrypted, results 
in goal_plaintext ^ keystream ^ keystream = goal_plaintext. 
"""

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

service = Service()

known_prefix = b"comment1=cooking%20MCs;userdata="
goal_plaintext = b"a;admin=true"

C1 = service.encrypt(b"\x00" * len(goal_plaintext))
keystream_chunk = C1[len(known_prefix) : len(known_prefix) + len(goal_plaintext)]
new_cipher_chunk = xor(goal_plaintext, keystream_chunk)
C2 = C1[ : len(known_prefix)] + new_cipher_chunk + C1[len(known_prefix) + len(goal_plaintext) : ]
new_plaintext = service.decrypt(C2)
assert (b'admin', b'true') in new_plaintext, "Failed to create goal plaintext!"
print(new_plaintext)
