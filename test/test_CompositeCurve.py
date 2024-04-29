from sage.all import *

from CompositeCurve import inverse_point, dlog_point

def gen_composite_curve():
    # generate a composite curve
    p = random_prime(2**32)
    q = random_prime(2**32)
    a = getrandbits(64)
    b = getrandbits(64)
    E = EllipticCurve(Zmod(p*q), [a, b])

    # generate a point on the composite curve
    x = getrandbits(64)
    while True:
        try:
            G = E.lift_x(x)
            break
        except:
            x += 1
    
    return G, E, p, q

def test_inverse_point():
    G, E, p, q = gen_composite_curve()
    multiplier = random_prime(2**64)
    Q = G * multiplier
    Q_inv = inverse_point(multiplier, Q, E, p, q)
    
    assert Q_inv == G, "Inverse point calculation failed"
    print("Inverse point calculation passed")

def test_dlog_point():
    G, E, p, q = gen_composite_curve()

    x = getrandbits(64)
    P = G * x
    e, mod = dlog_point(P, G, E, p, q)
    
    assert e == x%mod, "Discrete logarithm calculation failed"
    print("Discrete logarithm calculation passed")

if __name__ == "__main__":
    test_inverse_point()
    test_dlog_point()