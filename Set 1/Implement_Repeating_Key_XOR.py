from base64 import b16encode


def asciiToBytes(s):
    return bytes([ord(i) for i in s])

def xor(s, key):
    a = asciiToBytes(s)
    b = asciiToBytes(key)
    return b16encode(bytes([a[i] ^ b[i % len(b)] for i in range(len(a))]))


plaintext = "picoCTF{helle there}"#"Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
key = "eeeee" #"ICE"

print(xor(plaintext, key))
