from sage.all import GF

# modified from https://github.com/jvdsn/crypto-attacks/blob/master/attacks/gcm/forbidden_attack.py
x = GF(2)["x"].gen()
F = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)


# Converts an integer to a field element, little endian.
def int2field(n: int):
    return F([(n >> i) & 1 for i in range(127, -1, -1)])

# Converts a field element to an integer, little endian.
def field2int(f):
    # DeprecationWarning: `integer_representation` is deprecated. Please use `to_integer` instead.
    # See https://github.com/sagemath/sage/issues/33941 for details.
    # n = f.integer_representation()
    n = f.to_integer()  # big endian

    # convert to little endian
    res = 0
    for i in range(128):
        res <<= 1
        res  |= ((n >> i) & 1)
    return res

# Calculates the AES-GCM GHASH polynomial.
def ghash(h, a: bytes, c: bytes):
    la  = len(a) # Associated Data length
    lc  = len(c) # Ciphertext length

    # Compute the GHASH polynomial
    res = int2field(0)

    # Process the associated data
    for i in range(la // 16):
        res += int2field(int.from_bytes(a[16 * i:16 * (i + 1)], byteorder="big"))
        res *= h
    
    # Process the last block of associated data
    if la % 16 != 0:
        res += int2field(int.from_bytes(a[-(la % 16):] + bytes(16 - la % 16), byteorder="big"))
        res *= h
    
    # Process the ciphertext
    for i in range(lc // 16):
        res += int2field(int.from_bytes(c[16 * i:16 * (i + 1)], byteorder="big"))
        res *= h
    
    # Process the last block of ciphertext
    if lc % 16 != 0:
        res += int2field(int.from_bytes(c[-(lc % 16):] + bytes(16 - lc % 16), byteorder="big"))
        res *= h
    
    # Process the length of the associated data and ciphertext
    res += int2field(((8 * la) << 64) | (8 * lc))
    res *= h

    return res