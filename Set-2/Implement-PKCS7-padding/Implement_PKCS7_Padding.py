def pad_pkcs7(plaintext: bytes, blocksize = 16) -> bytes:
    delta = blocksize - len(plaintext) % blocksize
    return plaintext + bytes(delta * [delta])


def unpad_pkcs7(msg: bytes, blocksize = 16) -> bytes:
    if len(msg) == 0 or len(msg) % blocksize != 0 or not (1 <= msg[-1] <= blocksize) or not all(i == msg[-1] for i in msg[-msg[-1] : ]):
        raise ValueError("Data is not padded using valid pkcs7!")
    return msg[ : -msg[-1]]


plaintext = b'YELLOW SUBMARINE'

print(f"Plaintext: {plaintext}")
print(f"Padded: {pad_pkcs7(plaintext, 20)}")
print(f"Unpadded: {unpad_pkcs7(pad_pkcs7(plaintext, 20), 20)}")
