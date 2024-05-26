from sage.all import *
from Lattice.Utils import hnp_recentering

"""
    Attacking (EC)DSA Signature Scheme with Nonce Leakage
        s = k^-1 * (h + x*r) mod q
    -> Recover secret key `x` when given (`r`, `s`, `h`, `q`) and partial knowledge of `k`.

    Partial knowledge of `k`:
    - MSB l-bits of `k` are known (e.g. Nonce biased).
    - LSB l-bits of `k` are known.
"""


def attack_known_lsb(Hs, Rs, Ss, Ks_lsb, q, l):
    # Ref: https://eprint.iacr.org/2021/455.pdf
    # We have:           s = k^-1 * (h + x*r)
    # ->               s*k = h + x*r
    # ->    s(k1 + k2*2^l) = h + xr                   (we knwon l-bits lsb of k)
    # ->       k1 + k2*2^l = h*s^(-1) + x*r*s^(-1)
    # ->                k2 = (h*s^(-1) - k1)*2^(-l) + x*r*s^(-1)*2^(-l)
    # Let:
    #                    t = r*s^(-1)*2^(-l)        [mod q]
    #                    u = (k1 - h*s^(-1))*2^(-l) [mod q]
    # ->     |x*t - u|_{q} = k2 < 2^(-l)    (HNP!!!)


    ts = [r*pow(s,-1,q)*pow(2,-l,q)%q for r, s in zip(Rs, Ss)]
    us = [pow(2,-l,q)*(k_lsb - h*pow(s,-1,q))%q for h, s, k_lsb in zip(Hs, Ss, Ks_lsb)]

    for x in hnp_recentering(ts, us, q, l, debug=True): # maybe we need to use other HNP method
        Ks = [(x*r + h)*pow(s, -1, q)%q for r, s, h in zip(Rs, Ss, Hs)]
        if all(k_lsb == k%2**l for k, k_lsb in zip(Ks, Ks_lsb)):
            return x