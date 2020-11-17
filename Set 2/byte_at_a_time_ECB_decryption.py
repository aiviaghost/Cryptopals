from secrets import token_bytes
from base64 import b64decode
from Crypto.Cipher import AES


# super secure secret key
global_key = token_bytes(16)


def pad_pkcs7(plaintext, blocksize = 16):
    delta = blocksize - (len(plaintext) % blocksize)
    return plaintext + bytes([delta] * delta)


# misunderstood the challenge the first time I did this :brain:
# but it doesn't matter that much in the end, the important parts are still there
def fake_oracle(plaintext):
    return AES.new(global_key, AES.MODE_ECB).encrypt(pad_pkcs7(plaintext))


def get_blocksize_of_oracle():
    plaintext = b'a'
    block_size = 1
    prev_len = len(fake_oracle(plaintext))
    while len(fake_oracle(plaintext)) == prev_len :
        plaintext += b'a'
        block_size += 1
    return block_size


def create_dict(known_bytes, blocksize):
    return {fake_oracle(bytes((blocksize - 1 - len(known_bytes)) * [97] + [j for j in known_bytes] + [i]))[0 : blocksize] : bytes([i]) for i in range(256)}


def break_cipher(cipher, blocksize):
    plaintext = b''
    for i in range(0, len(cipher), blocksize):
        for j in range(blocksize):
            if len(plaintext) == len(cipher):
                return plaintext
            
            d = create_dict(plaintext[-(blocksize - 1) : ], blocksize)
            plaintext += d[fake_oracle(bytes([97] * (blocksize - 1 - j)) + cipher)[i : i + blocksize]]
            # print(plaintext)


b64_cipher = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
unknown_bytes = b64decode(b64_cipher)

blocksize = get_blocksize_of_oracle()

print("Blocksize: " + str(blocksize))
print("Decrypted message: \n" + break_cipher(unknown_bytes, blocksize).decode('utf-8'))
