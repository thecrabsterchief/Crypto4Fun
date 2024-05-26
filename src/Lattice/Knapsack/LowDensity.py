from sage.all import *
from math import log2, ceil

def low_density_attack(pk, s):
    # Ref: https://eprint.iacr.org/2009/537.pdf

    # step 0: sanity check
    n = len(pk)
    d = n / log2(max(pk))
    assert d < 0.9408, "Density condition not satisfied {d} not < 0.9408"

    # step 1: construct the basis
    N = ceil(1/2 * sqrt(n))
    L = identity_matrix(QQ, n).stack(vector(QQ, [1/2]*n))
    R = vector(QQ, [N*p for p in pk] + [N*s])
    B = L.augment(R)

    # step 2: latice reduction
    for row in B.LLL():
        if not all([r in [-1/2,1/2] for r in row[:-1]]): 
            continue

        res1 = [int(r < 0) for r in row[:-1]]
        res2 = [r^1 for r in res1]

        if sum([r*p for r,p in zip(res1,pk)]) == s:
            return res1
        if sum([r*p for r,p in zip(res2,pk)]) == s:
            return res2