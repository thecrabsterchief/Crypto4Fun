from sage.all import *

def hnp_recentering(Ts, Us, q, l, lattice_reduction=None, debug=False):
    """ Ref: "Phong Q. Nguyen and Mehdi Tibouchi. Lattice-based fault attacks on signatures. In Marc Joye and 
        Michael Tunstall, editors, Fault Analysis in Cryptography, pages 201-220. Springer, 2012."
        Improve lattice attack on (EC)DSA using "Recentering Technique".
        
        HNP problem:    |alpha*Ts_{i} - Us_{i}|_{q} < q/2^{l}
        -> Exists c_{i} such that:
                    0      <= alpha*Ts_{i} - Us_{i} + q*c_{i}             < q/2^{l}
                -q/2^{l+1} <= alpha*Ts_{i} - Us_{i} + q*c_{i} - q/2^{l+1} < q/2^{l+1}
                            | alpha*Ts_{i} - Us_{i} - q/2^{l+1} |_{q}     < q/2^{l+1}
    """

    # step 0: setup
    assert len(Ts) == len(Us)
    if lattice_reduction is None:
        lattice_reduction = lambda M: M.LLL()
    debug = (lambda *args: print(*args)) if debug else (lambda *args: None)
    KEF   = q # Kannan Embedding Factor <- maybe need to adjust this value
    d     = len(Ts)

    # step 1: contruct basis
    B1 = identity_matrix(QQ, d)*q*2**(l+1)
    B2 = matrix(QQ, d, 1, [0]*d)
    B3 = matrix(QQ, 1, d, [t*2**(l+1) for t in Ts])
    B4 = matrix(QQ, 1, 1, [1])
    B  = block_matrix([[B1, B2], [B3, B4]])
    debug("[hnp_recentering] Basis's dimensions:", B.dimensions())

    # step 2: contruct Kannan's embedding matrix
    t  = vector(QQ, [u*2**(l+1) + q for u in Us] + [0]) # target cvp vector
    K  = block_matrix([
        [B                     , matrix(QQ, d+1, 1, [0]*(d+1))],
        [matrix(QQ, 1, d+1, t) , matrix(QQ, 1, 1, [KEF])      ]
    ])

    # step 3: lattice reduction
    st = cputime()
    L  = lattice_reduction(K)
    debug(f"[hnp_recentering] Lattice reduction took: {cputime(st):.3f}s")
    
    # step 4: yield solutions
    for row in L:
        if abs(row[-1]) == KEF:
            yield row[-2]%q

def hnp_svp_approach(Ts, As, q, BOUND, lattice_reduction=None, debug=False):
    """ Ref: Surin, J., & Cohney, S. (2023). A Gentle Tutorial for Lattice-Based Cryptanalysis.
        Cryptology ePrint Archive.

        HNP problem:    B_{i} - Ts_{i}*alpha + As_{i} = 0  [mod q]
        where B_{i} are unknowns but satisfy that: |B_{i}| < BOUND for some BOUND < q.
    """

    # step 0: setup
    assert len(Ts) == len(As)
    if lattice_reduction is None:
        lattice_reduction = lambda M: M.LLL()
    debug = (lambda *args: print(*args)) if debug else (lambda *args: None)
    m = len(Ts)

    # step 1: construct basis
    B1 = identity_matrix(QQ, m)*q
    B2 = matrix(QQ, m, 2, [0]*(2*m))
    B3 = matrix(QQ, 2, m, Ts + As)
    B4 = matrix(QQ, 2, 2, [BOUND/q, 0, 0, BOUND])
    B  = block_matrix([[B1, B2], [B3, B4]])
    debug(f"[hnp_svp_approach] Basis's dimensions: {B.dimensions()}")

    # step 2: lattice reduction
    st = cputime()
    L  = lattice_reduction(B)
    debug(f"[hnp_svp_approach] Lattice reduction took: {cputime(st):.3f}s")

    # step 3: yield solutions
    for row in L:
        if row[-1] == -BOUND:
            alpha = (row[-2] * q / BOUND) % q
            yield row[:-2], alpha
        if row[-1] == BOUND:
            alpha = (-row[-2] * q / BOUND) % q
            yield -row[:-2], alpha