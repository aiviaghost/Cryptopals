from Encryption_service import Encryption_service

"""
Solution:
This problem is easy if we can reduce it to standard byte-at-a-time ECB decryption. 
The encryption will in general have this format:
    
    AES(prefix || controlled_data || FLAG)

More specifically it might look like:

    <---BLOCKSIZE--> <---BLOCKSIZE--> <---BLOCKSIZE-->
    prefixprefixpref ix{controlled_da ta}FLAGFLAGFLAGF

If we can figure out how long the prefix is we could make sure that the flag starts 
at the start of a block, like so:

    <---BLOCKSIZE--> <---BLOCKSIZE--> <---BLOCKSIZE-->
    prefixprefixpref ixaaaaaaaaaaaaaa FLAGFLAGFLAGFLAG

Now we can view the third block and beyond as a standard byte-at-a-time problem which is easy. 
The only tricky part now is to actually figure out the length of the prefix. 
We do this by sending messages of varying length and looking at the encrypted result. 
Suppose we send two plaintexts p1 and p2, both shorter than or equal to the length of one block, 
and recieve back ciphertexts e1 and e2. Let ei[j] be block j in ciphertext i then the largest j for which 
e1[j] == e2[j] is the block containg the end of the padding plus the start of our message (p1 or p2). 
This is because we send messages of varying length, so the message that starts at the following block 
will be different. 
So to figure out how much we need to append to make the flag start at a block we send:
    ""
    "a"
    "aa"
    ...
    "a" * BLOCKSIZE
By applying the above mentioned rule we can figure out which of these to append to make sure the flag 
starts at the start of a block. (Note that if the prefix-length is a multiple of the BLOCKSIZE then the two
"matching strings" will be "" and "" * BLOCKSIZE)
"""

service = Encryption_service()
BLOCKSIZE = 16

seen = []
for offset in range(BLOCKSIZE + 1):
    res = service.encrypt(b"a" * offset)
    seen.append(res)

block_offset = -1
padding_offset = -1
for offset in range(BLOCKSIZE + 1):
    i = 0
    while seen[offset][i : i + BLOCKSIZE] == seen[(offset + 1) % len(seen)][i : i + BLOCKSIZE]:
        i += BLOCKSIZE

    if i > block_offset:
        block_offset = i
        padding_offset = offset


def create_lookup(known_bytes):
    lookup = {}
    for i in range(128):
        enc = service.encrypt(b"a" * padding_offset + b"a" * (BLOCKSIZE - 1 - len(known_bytes)) + known_bytes + bytes([i]))[block_offset : block_offset + BLOCKSIZE]
        lookup[enc] = bytes([i])
    return lookup


# You can figure out the FLAG length once you know the length of the prefix (+ some padding at the end)
FLAG_SIZE_UPPER_BOUND = 1000 # I'm a little lazy
FLAG = b""
for i in range(0, FLAG_SIZE_UPPER_BOUND, BLOCKSIZE):
    for j in range(BLOCKSIZE):
        target = service.encrypt(b"a" * padding_offset + b"a" * (BLOCKSIZE - 1 - j))[block_offset + i : block_offset + i + BLOCKSIZE]
        lookup = create_lookup(FLAG[-(BLOCKSIZE - 1) : ])
        try:
            FLAG += lookup[target]
        except:
            exit()
        print(FLAG)
