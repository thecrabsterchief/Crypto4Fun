from sage.all import ZZ, Zmod, GF, crt, is_prime, discrete_log, lcm

def inverse_point(multiplier, Q, Curve, p, q):
    """ Calculate the inverse point of Q on the composite curve
        Find P such that: multiplier * P = Q
    Args:
        multiplier (int): the multiplier of the inverse point
        Q (Point): the point on the composite curve
        Curve (EllipticCurve): the composite curve
        p (int): the prime number p
        q (int): the prime number q
    Returns:
        Point: the inverse point of Q on the composite curve
    """

    assert is_prime(p) and is_prime(q)
    assert Curve.base_ring() == Zmod(p*q)

    # decomposite the Curve
    Ep = Curve.change_ring(GF(p))
    Eq = Curve.change_ring(GF(q))

    # calculate the inverse point
    Qp_inv = Ep(Q) * pow(multiplier, -1, Ep.order())
    Qq_inv = Eq(Q) * pow(multiplier, -1, Eq.order())

    # combine the inverse point by using Chinese Remainder Theorem
    Qx_inv = crt([ZZ(Qp_inv[0]), ZZ(Qq_inv[0])], [p, q])
    Qy_inv = crt([ZZ(Qp_inv[1]), ZZ(Qq_inv[1])], [p, q])
    
    return Curve(Qx_inv, Qy_inv)

def dlog_point(P, Q, Curve, p, q):
    """ Calculate the discrete logarithm of P to the base Q on the composite curve
        Find e such that: x * Q = P and x = e mod lcm(ordP, ordQ)
    Args:
        P (Point): the point on the composite curve
        Q (Point): the base point on the composite curve
        Curve (EllipticCurve): the composite curve
        p (int): the prime number p
        q (int): the prime number q
    Returns:
        int, int: e, lcm(ordP, ordQ)
    """
    assert is_prime(p) and is_prime(q)
    assert Curve.base_ring() == Zmod(p*q)

    # decomposite the Curve
    Ep = Curve.change_ring(GF(p))
    Eq = Curve.change_ring(GF(q))

    # calculate the discrete logarithm
    eP = discrete_log(Ep(P), Ep(Q), operation='+')
    eQ = discrete_log(Eq(P), Eq(Q), operation='+')

    # combine the discrete logarithm by using Chinese Remainder Theorem
    ordP = Ep(Q).order()
    ordQ = Eq(Q).order()
    e  = crt([ZZ(eP), ZZ(eQ)], [ordP, ordQ])

    return int(e), lcm(ordP, ordQ)