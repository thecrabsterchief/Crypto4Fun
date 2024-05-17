from sage.all import *
from Utils import SymbolicXorShift128, Helper

def CreateLeakTable(N, high_bits_precision=12):
    """ Ex: floor(Math.random() * N) = idx \in [0, N)
            ->  idx/N <= Math.random() < (idx + 1)/N
            ->  Leak high bits of Math.random()
        Increase high_bits_precision maybe give you more leaks
    """
    def diff(a, b):
        return "".join([i if i == j else "?" for i, j in zip(a, b)])
    def bits(n):
        return bin(n)[2:].zfill(high_bits_precision)

    intervals   = [Helper.FromDouble(i / N) >> (64 - high_bits_precision) for i in range(0, N + 1)]
    leaks_table = {}
    for idx, (left, right) in enumerate(zip(intervals[:-1], intervals[1:])):
        fixed_msb = bits(left)
        for i in range(left + 1, right + 1):
            fixed_msb = diff(fixed_msb, bits(i))
        
        fixed_msb  = fixed_msb[:fixed_msb.index("?")]
        leak_pos   = [(63 - i, int(val)) for i, val in enumerate(fixed_msb)]
        leaks_table[idx] = leak_pos
    
    return leaks_table

def Crack(output, N, skip=0) -> list:
    """ Recover the internal state of XorShift128 from the output:
        Ex: 
            for _ in range(pre_run): floor(Math.random() * N)
            hints = [floor(Math.random() * mult) for _ in range(128)]
            ->  Crack(ouput=hints, N=mult, skip=pre_run) = [state0, state1]
    """

    leaks_table = CreateLeakTable(N)
    sym_prng      = SymbolicXorShift128()

    for _ in range(skip):
        next(sym_prng.NextRandom())

    system_equations = []    
    for o in output:
        sym_o = next(sym_prng.NextRandom())
        for pos, val in leaks_table[o]:
            system_equations.append(sym_o.extract_contraints_at_pos(pos) + [val])
    
    A = matrix(GF(2), system_equations)
    if A.rank() < 128:
        raise Exception("Cannot recover the internal state")

    solution = A.rref().column(-1)[:128]
    state0   = sum([1 << i for i, bit in enumerate(solution[:64]) if bit])
    state1   = sum([1 << i for i, bit in enumerate(solution[64:]) if bit])
    return [state0, state1]