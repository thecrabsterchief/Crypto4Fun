from typing import List
import struct

def poly1305(msg: bytes, key: bytes) -> bytes:
    """ A pure python implementation of the Poly1305 MAC function
        Reference: https://datatracker.ietf.org/doc/html/rfc7539#section-2.5.1
    :param msg: The message to authenticate
    :param key: The 32 byte key to use
    :return:    The 16 byte MAC value
    """

    assert len(key) == 32
    p = 2**130 - 5
    r = int.from_bytes(key[:16], 'little')
    s = int.from_bytes(key[16:], 'little')
    r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff

    res = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i+16] + b'\x01'
        block = int.from_bytes(block, 'little')
        res = (res + block) * r % p
    res = (res + s)
    res = int(res % 2**128)
    return res.to_bytes(16, 'little')

def construct_chacha_poly1305_auth_msg(ciphertext: bytes, associated_data: bytes=b"") -> bytes:
    """ Merge the associated data and the ciphertext
    :param ciphertext: The ciphertext of chacha encryption step
    :param data: Associated Data (ChaCha20-Poly1305 is an AEAD algorithm)
    :return: The actually message that will be passed to `poly1305` function  
    """
    def padding(data: bytes, block_sz: int):
        """Return padding for the Associated Authenticated Data"""
        if len(data)%block_sz == 0:
            return data + bytes(0)
        else:
            return data + bytes(16 - len(data)%16)

    auth_data  = padding(associated_data, block_sz=16)
    auth_data += padding(ciphertext, block_sz=16)
    auth_data += struct.pack('<Q', len(associated_data))
    auth_data += struct.pack('<Q', len(ciphertext))

    return auth_data

def construct_chacha_poly1305_coeffs(ciphertext: bytes, associated_data: bytes=b"") -> List[int]:
    """ Create poly1305's coefficients from ciphertext:
        Poly1305(r,s,c) = ((c1*r^n + c2*r^(n-1) + ... + c^n*r    mod{2^130 - 5}) + s)     mod{2^128}
                            ---------------------------------
                                            |
                                            v
                                    Return this coeffs!
    :param ciphertext: The ciphertext of chacha encryption step
    :param data: Associated Data (ChaCha20-Poly1305 is an AEAD algorithm)
    :return: Poly1305's coeffs
    """
    
    # Step 1: Create the actually message that will be passed to `poly1305` function
    auth_data = construct_chacha_poly1305_auth_msg(ciphertext, associated_data)

    # Step 2: Create Poly1305's coeffs
    coeffs = []
    for i in range(0, len(auth_data), 16):
        block = auth_data[i:i+16] + b'\x01'
        block = int.from_bytes(block, 'little')
        coeffs.append(block)
    return coeffs