from ctypes import c_int64

def PyTupleHashPreimageAttack(expected):
	""" Returns a tuple (a, b) such that hash((a, b)) == expected
	"""
	def forward(state):
        # returns the internal state after having hashed 1 tuple element
		acc = (2870177450012600261 + state * 14029467366897019727) % 2**64
		acc = ((acc << 31) | (acc >> 33)) * 11400714785074694791 % (2 ** 64)
		return acc
	def backward(expected, state):
		acc = (expected - (2 ^ 2870177450012600261 ^ 3527539)) % 2**64
		acc = acc * pow(11400714785074694791, -1, 2**64) % (2 ** 64)
		acc = (acc & 0x7fffffff) << 33 | (acc >> 31)
		acc = (acc- state) * pow(14029467366897019727, -1, 2**64) % (2 ** 64)
		return acc
	P   = 2305843009213693951 # Hashing of numeric types, Ex: hash(x) = x % P
	a,b = 0, P + 1
	while b >= P:
		a += 1
		b  = backward(expected, forward(a))
	return (a, b)

def PyTupleHash(_tuple):
    # Ref: 
	# - https://github.com/python/cpython/blob/3.9/Objects/tupleobject.c#L360-L383
	# - https://docs.python.org/3/library/stdtypes.html#hashing-of-numeric-types
    acc = 2870177450012600261
    for i in _tuple:
        acc += hash(i) * 14029467366897019727
        acc %= 2**64
        acc = ((acc << 31) | (acc >> 33))
        acc %= (2 ** 64)
        acc *= 11400714785074694791
        acc %= (2 ** 64)
    acc += len(_tuple) ^ 2870177450012600261 ^ 3527539
    acc %= (2 ** 64)
    return c_int64(acc).value