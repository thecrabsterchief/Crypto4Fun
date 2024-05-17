import struct

class XorShift128:
    def __init__(self, s0: int, s1: int) -> None:
        self.MASK   = 0xffffffffffffffff # 64-bit mask
        self.state0 = s0 & self.MASK
        self.state1 = s1 & self.MASK
    
    def __Twist(self) -> None:
        # Ref: https://github.com/v8/v8/blob/master/src/base/utils/random-number-generator.h#L119

        s1, s0 = self.state0, self.state1
        s1    ^= (s1 << 23) & self.MASK
        s1    ^= (s1 >> 17) & self.MASK
        s1    ^= s0
        s1    ^= (s0 >> 26) & self.MASK
        self.state0, self.state1 = self.state1, s1

    def NextRandom(self):
        # Caching 64 values for faster performence 
        # Ref: https://github.com/v8/v8/blob/7f55dc42841c93dbf095995ffd2f6a7ca41bf51e/src/numbers/math-random.cc#L60

        while True:
            cache = []
            for _ in range(64):
                self.__Twist()
                cache.append(Helper.ToDouble(self.state0))
            for out in reversed(cache):
                yield out

class SymbolicXorShift128:
    def __init__(self) -> None:
        self.state0 = BitVector(data=[1 << i for i in range(64)],
            nbits=64)
        self.state1 = BitVector(data=[1 << i for i in range(64, 128)],
            nbits=64)

    def __Twist(self) -> None:
        # Ref: https://github.com/v8/v8/blob/master/src/base/utils/random-number-generator.h#L119

        s1, s0 = self.state0, self.state1
        s1     = s1 ^ (s1 << 23)
        s1     = s1 ^ (s1 >> 17)
        s1     = s1 ^ s0
        s1     = s1 ^ (s0 >> 26)
        self.state0, self.state1 = self.state1, s1

    def NextRandom(self):
        # Caching 64 values for faster performence 
        # Ref: https://github.com/v8/v8/blob/7f55dc42841c93dbf095995ffd2f6a7ca41bf51e/src/numbers/math-random.cc#L60

        while True:
            cache = []
            for _ in range(64):
                self.__Twist()
                cache.append(self.state0) # Just Symbolic state0, no need to convert to double
            for out in reversed(cache):
                yield out

class BitVector:
    def __init__(self, data: list, nbits: int) -> None:
        assert len(data) == nbits
        self.data = data
    
    def __xor__(self, other):
        assert len(self.data) == len(other.data)
        return BitVector([i ^ j for i, j in zip(self.data, other.data)], len(self.data))
    
    def __rshift__(self, n):
        return BitVector(self.data[n:] + [0]*n, len(self.data))
    
    def __lshift__(self, n):
        return BitVector([0]*n + self.data[:-n], len(self.data))
    
    def extract_contraints_at_pos(self, pos):
        return list(map(int, f"{self.data[pos]:0128b}"[::-1]))

class Helper:
    @classmethod
    def FromDouble(cls, f64):
        # f64 in [0, 1) to u64 XorShift128 state (52 MSB of u64 = 52 MSB of state)
        # Ref: https://github.com/v8/v8/blob/master/src/base/utils/random-number-generator.h#L111

        if f64 == 1.0:
            return 0xffffffffffffffff
        u52 = struct.unpack("<Q", struct.pack("d", f64 + 1))[0] & 0x000fffffffffffff
        u64 = u52 << 12
        return u64

    @classmethod
    def ToDouble(cls, u64):
        # u64 XorShift128 state to f64 in [0, 1)
        # Ref: https://github.com/v8/v8/blob/master/src/base/utils/random-number-generator.h#L111

        return struct.unpack("d", struct.pack("<Q", (u64 >> 12) | 0x3FF0000000000000))[0] - 1