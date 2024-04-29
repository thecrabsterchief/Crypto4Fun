from Utils import reverse_rounds_key, Inv_Sbox
from functools import reduce
import os

def attack(encrypt_oracle):
    """Recover the key from the encryption oracle."""
    rkey  = []
    guess = lambda ct, cand, pos: Inv_Sbox[ct[pos] ^ cand]
    for pos in range(16):
        possible = set([i for i in range(256)])

        while len(possible) > 1:
            pt = list(os.urandom(16))
            cts = []
            for i in range(256):
                pt[0] = i
                cts.append(encrypt_oracle(bytes(pt))) 

            maybe = set()
            for cand in range(256):
                ok = reduce(lambda x,y: x^y, [guess(ct, cand, pos) for ct in cts])
                if ok == 0:
                    maybe.add(cand)

            possible = possible.intersection(maybe)
            print(pos, maybe)

        rkey.append(possible.pop())

    key = reverse_rounds_key(round_key=bytes(rkey), n_rounds=4) # square attack when AES's n_rounds=4
    return key