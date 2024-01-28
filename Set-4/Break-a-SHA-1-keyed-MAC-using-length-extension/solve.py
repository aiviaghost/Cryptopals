from secrets import token_bytes, randbelow

from sha1 import SHA1


class MAC_Service:
    public_info = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

    def __init__(self):
        self.__key = token_bytes(20 + randbelow(20))

    def __sha1_mac(self, msg):
        """
        Computes SHA1(key || msg)
        """
        sha1 = SHA1()
        sha1.update(self.__key)
        sha1.update(msg)
        return sha1.digest()

    def get_public_information(self):
        return self.public_info, self.__sha1_mac(self.public_info)

    def verify(self, msg, tag):
        return self.__sha1_mac(msg) == tag


sha1_mac = MAC_Service()

known_msg, known_mac = sha1_mac.get_public_information()

target_to_append = b";admin=true"

# We assume we only know a range of valid key lengths
for secret_len in range(20, 40):
    # ================ Compute glue padding ================
    glue_padding = b"\x80"
    extra_bytes = (secret_len + len(known_msg)) % 64
    while (extra_bytes + len(glue_padding)) % 64 != 56:
        glue_padding += b"\x00"
    glue_padding += ((secret_len + len(known_msg)) * 8).to_bytes(8, "big")

    assert (secret_len + len(known_msg) + len(glue_padding)) % 64 == 0

    # ================ Forge message ================
    msg = known_msg + glue_padding + target_to_append

    # ================ Forge MAC ================
    sha1 = SHA1.from_state(known_mac, secret_len +
                           len(known_msg) + len(glue_padding))
    sha1.update(target_to_append)
    forged_tag = sha1.digest()

    # ================ Test forged MAC ================
    if sha1_mac.verify(msg, forged_tag):
        print("Successfully performed length extension attack!")
        print(f"Correct key length = {secret_len}")
        print(f"Final message = {msg}")
        break
