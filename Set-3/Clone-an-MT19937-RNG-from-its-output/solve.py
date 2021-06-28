from MT19937 import MT19937

"""
(Note the explanation below might contain some indexing errors, see the code below it for working indexing)
Solution:

The part of the PRNG we need to reverse to clone its state is the following: 

    y ^= (y >> self.__u) & self.__d
    y ^= (y << self.__s) & self.__b
    y ^= (y << self.__t) & self.__c
    y ^= y >> self.__l

The two operations to reverse then are: 

    1. y = (x ^ (x >> S)) & M
    2. y = (x ^ (x << S)) & M

For some number S and some bitmask M. The same concept is used to reverse 
both, just some implementation details distinguishing them. Note that the last 
step in the PRNG implementation (y ^= y >> self.__l) can be seen as having an 
implicit bitmask because we are always dealing with 32 bit numbers. So the bit-
mask for the last step is the 32-bit number with all ones, 0xFFFFFFFF. 

Let's see what one of these operations look like on a bit-level:
Let var[i] denote the ith bit of the variable var and w be the bit-size of the numbers (w = 32 for MT19937). 
We then get the following for a right-shift: 
    
        <--S-->
        0 ... 0 x[w] x[w - 1] ... x[S]
    &   M[w]....M[w-S] M[w-S-1]...M[0]
    ^   x[w]....x[w-S] x[w-S-1]...x[0]
    ----------------------------------
        y[w]....y[w-S] y[w-S-1]...y[0]

We can write this more formally as:

    y[i] = {
        x[i] ^ (x[i + S] & M[i]) if 0 <= i + S <= w
        x[i]                     otherwise
    }

Which we can reverse (by xoring both sides by x[i] and y[i]) to get:

    x[i] = {
        y[i] ^ (x[i + S] & M[i]) if 0 <= i + S <= w
        y[i]                     otherwise
    }

Note that the case "otherwise" functions as our base case. 
A similar construction can be found for left-shifts (The zeros will start from the right and we get i - S instead of i + S). 
We also have to loop over the bits in the correct direction since for left shifts the zeros will be to the right and for right 
shifts the will be to the left. See the implementation below for an example of how this can be achieved. 

It should also be noted the reason this operation is reversible is, in addition to xor itself being reversible, the fact that we 
get these zeros after the bit shifting. Given any number N the result of N & 0 is always N so this allows us to recover parts of x. 
These parts of x then form the base case for the recursion step to work (y[i] = ...x[i + S]...). 

Using this formula we can recover the entire state of the PRNG given 624 of its outputs, because the state vector's length is 624. 
"""

def recover_state(known_output: list) -> list:
    w = 32
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l, w_bit_mask = 18, 0xFFFFFFFF

    def int_to_bin(x: int) -> list:
        return list(map(int, bin(x)[2 : ].rjust(w, "0")))
    
    def bin_to_int(xs: list) -> int:
        return int("".join(map(str, xs)), base=2)

    def unshift(Y, S, M, D):
        M = int_to_bin(M)
        recovered_x = [None] * w
        if D == 1:
            start, end = 0, w
        else:
            start, end = w - 1, -1
        for i in range(start, end, D):
            if 0 <= i - D * S < w:
                recovered_x[i] = Y[i] ^ (recovered_x[i - D * S] & M[i])
            else:
                recovered_x[i] = Y[i]
        return recovered_x

    def recover(output):
        x = int_to_bin(output)
        x = unshift(x, l, w_bit_mask, 1)
        x = unshift(x, t, c, -1)
        x = unshift(x, s, b, -1)
        x = unshift(x, u, d, 1)
        return bin_to_int(x)

    recovered = [None] * 624
    for i, output in enumerate(known_output):
        recovered[i] = recover(output)

    return recovered

RNG = MT19937()
seen = [RNG.extract_number() for _ in range(624)]
recovered = recover_state(seen)
assert(recovered == RNG.get_state())
print(f"Recovered[ : 10] = {recovered[ : 10]}")
print(f"Original[ : 10] = {RNG.get_state()[ : 10]}")
