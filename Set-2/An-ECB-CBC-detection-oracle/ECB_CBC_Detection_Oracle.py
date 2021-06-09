from secrets import token_bytes, randbelow
from Crypto.Cipher import AES


'''
def append_controlled_bytes(b):
    bArr = bytearray(b)
    append = bytearray(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    return bytes(bArr + append)
'''


def surround_with_random_bytes(b):
    prepend = token_bytes(5 + randbelow(6))
    append = token_bytes(5 + randbelow(6))
    return prepend + b + append


def pad_pkcs7(b):
    delta = 16 - (len(b) % 16)
    if(len(b) - delta != 0):
        return b + bytes(delta * [delta])
    return b


def encrypt_AES_ECB(plaintext, key):
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def encrypt_AES_CBC(plaintext, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)


def ECB_or_CBC(cipher):
    for i in range(0, len(cipher) - 32, 16):
        if(cipher[i : i + 16] in cipher[i + 16 :]):
            return "ECB"
    return "CBC"


plaintext = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
ciphers = []
correct_answers = []

for i in range(1000):
    rand = randbelow(2)
    if(rand == 0): # if user selected input, apply append_controlled_bytes()
        ciphers.append(encrypt_AES_ECB(pad_pkcs7(surround_with_random_bytes(plaintext)), token_bytes(16)))
        correct_answers.append("ECB")
    else:
        ciphers.append(encrypt_AES_CBC(pad_pkcs7(surround_with_random_bytes(plaintext)), token_bytes(16), token_bytes(16)))
        correct_answers.append("CBC")

correct = 0
for i, cipher in enumerate(ciphers):
    # print("Mode = " + ECB_or_CBC(cipher) + ", " + "Correct answer: " + correct_answers[i])
    if(ECB_or_CBC(cipher) == correct_answers[i]):
        correct += 1

print("Correct / total : " + str(correct) + " / " + str(len(ciphers)))
