from MT19937 import MT19937

rng = MT19937(0)

for _ in range(10):
    print(rng.extract_number())
