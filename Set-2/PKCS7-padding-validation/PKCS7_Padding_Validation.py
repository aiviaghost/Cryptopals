# Not sure if the empty string is considered valid or not
def unpad_pkcs7(msg: bytes, blocksize = 16) -> bytes:
    if len(msg) % blocksize != 0 or not (1 <= msg[-1] <= blocksize) or not all(i == msg[-1] for i in msg[-msg[-1] : ]):
        raise ValueError(f"Data is not padded using valid pkcs7! Data={msg}")
    return msg[ : -msg[-1]]


print(unpad_pkcs7(b'ICE ICE BABY\x04\x04\x04\x04'))

try:
    print(unpad_pkcs7(b'ICE ICE BABY\x05\x05\x05\x05'))
except ValueError as e:
    print(e)

try:
    print(unpad_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04"))
except ValueError as e:
    print(e)
