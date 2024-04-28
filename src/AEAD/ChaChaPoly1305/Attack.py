from sage.all import GF, PolynomialRing
from typing import List, Tuple
from Utils import *

def nonce_reuse(ct1: bytes, ad1: bytes, tag1: bytes,
                ct2: bytes, ad2: bytes, tag2: bytes) -> List[Tuple[int,int]]:
    """ Recover the ChaCha_Poly1305's keys when `nonce` is reused
    :param ct: Ciphertext
    :param ad: Associated Data
    :param tag: Tag
    :return: The list contains all possible values of (r,s)
    """

    # Step 1: Define PolynomialRing
    Fp = GF(2**130 - 5)
    PR = PolynomialRing(Fp, names="x"); x = PR.gen()

    # Step 2: Construct the polynomial
    f1 = x * PR(construct_chacha_poly1305_coeffs(ciphertext=ct1, associated_data=ad1)[::-1])
    t1 = int.from_bytes(tag1, byteorder='little')
    f2 = x * PR(construct_chacha_poly1305_coeffs(ciphertext=ct2, associated_data=ad2)[::-1])
    t2 = int.from_bytes(tag2, byteorder='little')

    # Step 3: Same nonce -> Same root `r`
    roots = []
    isvalid_r = lambda r: int(r) == int(r) & 0x0ffffffc0ffffffc0ffffffc0fffffff
    isvalid_s = lambda s: int(s) == int(s) & 0xffffffffffffffffffffffffffffffff
    in_mod, ou_mod = 2**130-5, 2**128

    # since t = (f%in_mod + s)%ou_mod
    for di in range(0, in_mod + ou_mod, ou_mod):
        for dj in range(0, in_mod + ou_mod, ou_mod):
            fr = (t1 + di - f1) - (t2 + dj - f2)
            for r, _ in fr.roots():
                if isvalid_r(r):
                    s1 = t1 + di - int(f1(x=r))
                    s2 = t2 + dj - int(f2(x=r))
                    if s1 == s2 and isvalid_s(s1):
                        roots.append((int(r),int(s1)))
    return roots

DATA_FORMAT = Tuple[bytes,bytes,bytes,bytes]
def forgery_attack(known_data: List[DATA_FORMAT], target_plaintext: bytes, 
                   target_associated_data: bytes=b"") -> Tuple[bytes, bytes]:
    """ Recover the Chacha-Poly1305 key when nonce is reused
        then forgery arbitrary message with Associated Data

    :param known_data: List of tuple (plaintext (if known else None), ciphertext, associated data, tag).
    :param target_plaintext: Target plaintext that we want to forgery.
    :param target_associated_data: Associated Data corressponding to target plaintext.
    :return: Tuple contain ciphertext and tag that can be decrypted with ChaCha_Poly1305(same nonce) 
            and resultedexpected target_plaintext
    """

    # We need at least two!!
    assert len(known_data) > 1, "We need at least two!!"

    xor = lambda msg1, msg2: bytes([m1^m2 for m1,m2 in zip(msg1, msg2)])

    # Step 1: Recover keystream and chose the longest
    keystream = b""
    for pt, ct, ad, tag in known_data:
        if pt is not None:
            key = xor(pt, ct)
            if len(key) > len(keystream):
                keystream = key
    assert len(keystream) > 0, "Can't forgery if don't have keystream"

    # Step 2: Recover poly1305's key
    data1 = known_data[0]
    data2 = known_data[1]
    # anyway just use the first key :<
    r,s = nonce_reuse(ct1=data1[1], ad1=data1[2], tag1=data1[3],
                        ct2=data2[1], ad2=data2[2], tag2=data2[3])[0]
    rs  = int(r).to_bytes(length=16, byteorder='little') +\
          int(s).to_bytes(length=16, byteorder='little')

    # Step 3: Forgery Attack!
    assert len(keystream) >= len(target_plaintext), "Target plaintext too long"
    
    target_ciphertext = xor(target_plaintext, keystream)
    target_tag = poly1305(
        msg=construct_chacha_poly1305_auth_msg(target_ciphertext, target_associated_data),
        key=rs
    )
    
    return target_ciphertext, target_tag