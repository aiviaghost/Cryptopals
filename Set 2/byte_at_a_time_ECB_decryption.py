from secrets import token_bytes
from base64 import b64decode
from Crypto.Cipher import AES


def encrypt_AES_ECB(plaintext, key):
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def pad_pkcs7(b):
    delta = 16 - (len(b) % 16)
    if(len(b) - delta != 0):
        return b + bytes(delta * [delta])
    return b


def is_ECB(cipher):
    for i in range(0, len(cipher) - 32, 16):
        if(cipher[i : i + 16] in cipher[i + 16 :]):
            return True
    return False


def detect_block_size(cipher):
    prepend = b'a'
    while True:
        if(is_ECB(encrypt_AES_ECB(pad_pkcs7(prepend + cipher), global_key))):
            return len(prepend) // 2
        prepend += b'a'


def create_dict(known_bytes):
    return {encrypt_AES_ECB(bytes((15 - len(known_bytes)) * [97] + [j for j in known_bytes] + [i]), global_key) : bytes([i]) for i in range(256)}


def break_cipher(cipher):
    plaintext = b''
    known_bytes = b''
    d = create_dict(known_bytes)
    for i in range(15):
        known_bytes += d[encrypt_AES_ECB(pad_pkcs7(bytes([97] * (15 - len(known_bytes))) + cipher), global_key)[0 : 16]]
        d = create_dict(known_bytes)
    
    plaintext += known_bytes
    print(plaintext[0 : 15])

    d = create_dict(known_bytes)
    for i in range(len(cipher) - 16):
        #print(plaintext)
        temp_byte = d[encrypt_AES_ECB(pad_pkcs7(plaintext[i : i + 15] + cipher), global_key)[i : i + 16]]
        plaintext += temp_byte
        d = create_dict(plaintext[i + 1: i + 16])

    return plaintext
    # first known bytes will be starting string for next block


global_key = token_bytes(16)
b64_cipher = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
unknown_bytes = b64decode(b64_cipher)

cipher = print(break_cipher(unknown_bytes))
