class Invalid_Padding(Exception):
    pass


def unpad_pkcs7(b):
    bArr = bytearray(b)
    padding = bArr[-1]
    for i in range(len(b) - 1, len(b) - padding - 1, -1):
        if(bArr[i] != padding):
            # return b
            raise Invalid_Padding("The plaintext message is not padded with valid PKCS#7 padding.")
    del bArr[len(b) - padding:]
    return bytes(bArr)


s1 = b'ICE ICE BABY\x04\x04\x04\x04'
s2 = b'ICE ICE BABY\x05\x05\x05\x05'

print(unpad_pkcs7(s1))
print(unpad_pkcs7(s2))
