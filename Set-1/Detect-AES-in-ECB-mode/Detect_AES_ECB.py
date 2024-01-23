def b16ToBytes(s):
    return bytes([int(s[i : i + 2], base=16) for i in range(0, len(s), 2)])


ciphers = []
file = open("Detect_AES_ECB.txt", "r")
for line in file:
    ciphers.append(b16ToBytes(line.strip()))
file.close()

for line, cipher in enumerate(ciphers):
    for i in range(0, len(cipher) - 32, 16):
        if(cipher[i : i + 16] in cipher[i + 16 :]):
            print("Line: " + str(line + 1))
            print(cipher)
            break
