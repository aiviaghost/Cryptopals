import heapq


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
    return result


def freqScore(s):
    charFreqs = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([charFreqs.get(binaryToAscii(s[8 * i : 8 * (i + 1)]).lower(), 0) for i in range(len(s) // 8)])


#print("Enter hex cipher: ")
#cipher = input()
cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

chars = [i for i in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]
q = []
for c in chars:
    bits = xor(cipher, c)
    q.append([freqScore(bits), binaryToAscii(bits)])
    
heapq.heapify(q)
print(heapq.nlargest(1, q)[0][1])
