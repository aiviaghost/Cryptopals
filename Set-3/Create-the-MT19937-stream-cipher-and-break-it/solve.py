from cipher import MT_Cipher
from secrets import token_bytes, randbelow, randbits


known_plaintext = b"A" * 14
plaintext = token_bytes(randbelow(32)) + known_plaintext
seed = randbits(16)
encrypted = MT_Cipher(seed).transform(plaintext)

for possible_seed in range(2 ** 16):
    print(possible_seed)
    decrypted = MT_Cipher(possible_seed).transform(encrypted)
    if known_plaintext in decrypted:
        assert(possible_seed == seed)
        assert(decrypted == plaintext)
        print(f"Decrypted text: {decrypted}")
        break
else:
    print("Failed to recover seed and plaintext!")
