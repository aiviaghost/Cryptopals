def hexToAscii(b16):
    return bytearray.fromhex(b16).decode()


def asciiToBinary(s):
    return ''.join([format(ord(i), '08b') for i in s])


def binaryToAscii(s):
    return ''.join([chr(int(s[i : i + 8], base=2)) for i in range(0, len(s), 8)])


def xor(s1, s2):
    a = asciiToBinary(hexToAscii(s1))
    b = asciiToBinary(hexToAscii(s2))
    out = ""
    for i in range(len(a)):
        out += str(int(a[i]) ^ int(b[i]))
    return binaryToAscii(out)


print(xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
