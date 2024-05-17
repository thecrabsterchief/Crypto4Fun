from Crack import *
from Utils import XorShift128
import random

if __name__ == "__main__":
    # setup context
    s1, s2  = [random.getrandbits(64) for _ in range(2)]
    mult    = random.randint(20, 40)
    pre_run = random.randint(1337, 7331)
    r1      = XorShift128(s1, s2)
    
    # generate output
    for _ in range(pre_run):
        next(r1.NextRandom())
    output  = [floor(next(r1.NextRandom()) * mult) for _ in range(random.randint(80, 100))]

    print("========== Setup Context ==========")
    print(f"Internal states: ({s1},{s2})")
    print(f"Multiplier: {mult}")
    print(f"Pre-run: {pre_run}")
    print(f"No. of outputs: {len(output)}. Actually we can crack with less than 128 outputs!")
    
    print("========== Cracking ==========")
    state0, state1 = Crack(output, mult, pre_run)
    print(f"Recovered states: ({state0},{state1})")
    assert s1 == state0 and s2 == state1, "Oh nooo :<"