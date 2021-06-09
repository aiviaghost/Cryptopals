def pad_pkcs7(plaintext, blocksize = 16):
    delta = blocksize - (len(plaintext) % blocksize)
    return plaintext + bytes(delta * [delta])


def unpad_pkcs7(b):
    bArr = bytearray(b)
    padding = bArr[-1]
    for i in range(-1, len(b) - padding - 1, -1):
        if(bArr[i] != padding):
            return b
    del bArr[len(bArr) - padding:]
    return bytes(bArr)


plaintext = b'YELLOW SUBMARINE'

print("Plaintext: " + str(plaintext))
print("Padded: " + str(pad_pkcs7(plaintext, 20)))
print("Unpadded: " + str(unpad_pkcs7(pad_pkcs7(plaintext, 20))))
