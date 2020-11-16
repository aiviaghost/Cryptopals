def pad_pkcs7(b, target_length):
    delta = target_length - (len(b) % target_length)
    if(len(b) - delta != 0):
        return b + bytes(delta * [delta])
    return b

'''
def unpad_pkcs7(b):
    bArr = bytearray(b)
    padding = bArr[-1]
    for i in range(-1, len(b) - padding - 1, -1):
        if(bArr[i] != padding):
            return b
    del bArr[len(bArr) - padding:]
    return bytes(bArr)
'''

plaintext = b'YELLOW SUBMARINE'

print(pad_pkcs7(plaintext, 20))
