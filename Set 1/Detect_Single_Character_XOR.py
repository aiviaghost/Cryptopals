import langdetect


def hexToAscii(b16):
    return bytearray.fromhex(b16).decode()


def asciiToBinary(s):
    return ''.join([format(ord(i), '08b') for i in s])


def binaryToAscii(s):
    return ''.join([chr(int(s[i : i + 8], base=2)) for i in range(0, len(s), 8)])


def xor(s, key):
    a = asciiToBinary(hexToAscii(s))
    b = asciiToBinary(key)
    result = ""
    for i in range(len(a)):
        result += str(int(a[i]) ^ int(b[i % len(b)]))
    return binaryToAscii(result)


chars = [i for i in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]


def detect(s):
    try:
        for c in chars:
            text = xor(s, c)
            if(langdetect.detect(text) == 'en'):
                print(text)
    except:
        pass


file = open("DetectSingleCharacterXOR.txt", "r")
for line in file:
    detect(line)
