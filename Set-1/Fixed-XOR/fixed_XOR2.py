from base64 import b16encode


def hex2Bytes(b16):
    return bytes([int(b16[i : i + 2], base=16) for i in range(0, len(b16), 2)])


def xor(s1, s2):
    a = hex2Bytes(s1)
    b = hex2Bytes(s2)
    return b16encode(bytes([a[i] ^ b[i] for i in range(len(a))]))


print(xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
