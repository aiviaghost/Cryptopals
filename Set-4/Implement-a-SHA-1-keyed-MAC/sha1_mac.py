from sha1 import SHA1


def sha1_mac(key, msg):
    """
    Computes SHA1(key || msg)
    """
    sha1 = SHA1()
    sha1.update(key)
    sha1.update(msg)
    return sha1.digest()
