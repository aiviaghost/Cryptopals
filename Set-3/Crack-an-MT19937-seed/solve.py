from MT19937 import MT19937
from time import time, sleep
from random import randint


seed = int(time())
print(f"Actual seed was {seed}")
rand_num = MT19937(seed).extract_number()

sleep(randint(10, 20)) # PoC

start_of_crack = int(time())
for i in range(0, 1000):
	guess = start_of_crack - i
	if MT19937(guess).extract_number() == rand_num:
		print(f"The recovered seed is {guess}")
		break
else:
	print("Did not recover the seed")
