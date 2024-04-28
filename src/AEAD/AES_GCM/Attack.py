from typing import List, Tuple
from sage.all import GF
from Utils import *

# modified from https://github.com/jvdsn/crypto-attacks/blob/master/attacks/gcm/forbidden_attack.py

def nonce_reuse(ct1: bytes, ad1: bytes, tag1: bytes,
                ct2: bytes, ad2: bytes, tag2: bytes):
    """
    Recovers all possible authentication keys from two messages encrypted with the same authentication key.
    More information: Joux A., "Authentication Failures in NIST version of GCM"
    :param ct1: the ciphertext of the first message (bytes)
    :param ad1: the associated data of the first message (bytes)
    :param tag1: the authentication tag of the first message (bytes)
    :param ct2: the ciphertext of the second message (bytes)
    :param ad2: the associated data of the second message (bytes)
    :param tag2: the authentication tag of the second message (bytes)
    :return: All possible authentication keys (Field element)
    """

    h  = F['h'].gen()
    p1 = ghash(h, ad1, ct1) + int2field(int.from_bytes(tag1, byteorder="big"))
    p2 = ghash(h, ad2, ct2) + int2field(int.from_bytes(tag2, byteorder="big"))

    roots = []
    for _h, r in (p1 + p2).roots():
        roots.append(_h)    
    return roots

DATA_FORMAT = Tuple[bytes,bytes,bytes,bytes]
def forgery_tag(known_data: List[DATA_FORMAT], target_ciphertext: bytes, 
                   target_associated_data: bytes=b"") -> List[bytes]:
    """ Recover the GHASH key when nonce is reused
        then forgery a tag corressponding target_ciphertext with Associated Data

    :param known_data: List of tuple (plaintext (if known else None), ciphertext, associated data, tag).
    :param target_ciphertext: Target ciphertext that we want to forgery tag.
    :param target_associated_data: Associated Data corressponding to target ciphertext.
    :return: All possible forged authentication tag
    """

    # We need at least two!!
    assert len(known_data) > 1, "We need at least two!!"
    
    # Step 1: Recover GHASH key
    data1 = known_data[0]
    data2 = known_data[1]
    roots = nonce_reuse(ct1=data1[1], ad1=data1[2], tag1=data1[3],
                        ct2=data2[1], ad2=data2[2], tag2=data2[3])
    
    # Step 2: Forgery Attack!
    tags = []
    for h in roots:
        E0 = field2int(ghash(h, data1[2], data1[1])) ^ int.from_bytes(data1[3], byteorder="big")
        target_ghash = ghash(h, target_associated_data, target_ciphertext)
        tag = (E0 ^ field2int(target_ghash)).to_bytes(16, byteorder="big")
        tags.append(tag)
    
    return tags

def forgery_message(known_data: List[DATA_FORMAT], target_plaintext: bytes, 
                   target_associated_data: bytes=b"") -> Tuple[bytes, List[bytes]]:
    """ Recover the GHASH key when nonce is reused
        then forgery a tag corressponding target_plaintext with Associated Data

    :param known_data: List of tuple (plaintext (if known else None), ciphertext, associated data, tag).
    :param target_plaintext: Target plaintext that we want to forgery tag.
    :param target_associated_data: Associated Data corressponding to target plaintext.
    :return: Ciphertext and possible forged authentication tag
    """

    # We need at least two!!
    assert len(known_data) > 1, "We need at least two!!"
    
    xor = lambda msg1, msg2: bytes([m1^m2 for m1,m2 in zip(msg1, msg2)])
    
    # Step 1: Recover keystream
    keystream = b""
    for pt, ct, ad, tag in known_data:
        if pt is not None:
            key = xor(pt, ct)
            if len(key) > len(keystream):
                keystream = key
    assert len(keystream) > 0, "Can't forgery if don't have keystream"


    # Step 2: Recover GHASH key
    data1 = known_data[0]
    data2 = known_data[1]
    # anyway just use the first key :<
    roots = nonce_reuse(ct1=data1[1], ad1=data1[2], tag1=data1[3],
                    ct2=data2[1], ad2=data2[2], tag2=data2[3])
    
    # Step 3: Forgery Attack!
    assert len(keystream) >= len(target_plaintext), "Target plaintext too long"
    target_ciphertext = xor(target_plaintext, keystream)

    tags = []
    for h in roots:
        E0 = field2int(ghash(h, data1[2], data1[1])) ^ int.from_bytes(data1[3], byteorder="big")
        target_ghash = ghash(h, target_associated_data, target_ciphertext)
        tag = (E0 ^ field2int(target_ghash)).to_bytes(16, byteorder="big")
        tags.append(tag)
    
    return target_ciphertext, tags