from base64 import b64encode

print("Enter hexadecimal string: ")
b16 = input()

b64 = b64encode(bytes([int(b16[i : i + 2], base=16) for i in range(0, len(b16), 2)]))

print(b64)
