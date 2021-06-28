from MT19937 import MT19937
from cipher import MT_Cipher
from MT19937 import MT19937

seed = 1234

cipher = MT_Cipher(seed)

msg = b"hello there!"

enc = cipher.transform(msg)

print(msg, enc)

dec = MT_Cipher(seed).transform(enc)

assert(dec == msg)

print(dec)
