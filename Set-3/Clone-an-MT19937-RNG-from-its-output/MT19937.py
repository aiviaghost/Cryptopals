class MT19937:
    __w, __n, __m, __r = 32, 624, 397, 31
    __a = 0x9908B0DF
    __u, __d = 11, 0xFFFFFFFF
    __s, __b = 7, 0x9D2C5680
    __t, __c = 15, 0xEFC60000
    __l = 18
    __f = 1812433253
    
    __lower_bit_mask = 2 ** __r - 1 # all bits except the (2**r)-bit, i.e 01111111111111111111111111111111
    __upper_bit_mask = 2 ** __r # only the (2**r)-bit, i.e 10000000000000000000000000000000
    __w_bit_mask = 2 ** __w - 1 # all w bits set, i.e 11111111111111111111111111111111

    def __init__(self, seed: int = 5489):
        self.__mt = [0] * self.__n
        self.__mt[0] = seed
        for i in range(1, self.__n):
            self.__mt[i] = self.__f * (self.__mt[i - 1] ^ (self.__mt[i - 1] >> (self.__w - 2))) + i
            self.__mt[i] &= self.__w_bit_mask
        self.__index = self.__n + 1
    
    def __twist(self) -> None:
        for i in range(self.__n):
            x = (self.__mt[i] & self.__upper_bit_mask) + (self.__mt[(i + 1) % self.__n] & self.__lower_bit_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.__a
            self.__mt[i] = self.__mt[(i + self.__m) % self.__n] ^ xA
        self.__index = 0
    
    def extract_number(self) -> int:
        if self.__index >= self.__n:
            self.__twist()
        
        y = self.__mt[self.__index]
        y ^= (y >> self.__u) & self.__d
        y ^= (y << self.__s) & self.__b
        y ^= (y << self.__t) & self.__c
        y ^= y >> self.__l

        self.__index += 1
        return y & self.__w_bit_mask

    def get_state(self) -> list:
        return self.__mt
