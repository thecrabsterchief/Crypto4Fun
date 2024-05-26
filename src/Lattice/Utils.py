from sage.all import *

def hnp_recentering(ts, us, q, l, lattice_reduction=None, debug=False):
    """ Ref: "Phong Q. Nguyen and Mehdi Tibouchi. Lattice-based fault attacks on signatures. In Marc Joye and 
        Michael Tunstall, editors, Fault Analysis in Cryptography, pages 201-220. Springer, 2012."
        Improve lattice attack on (EC)DSA using "Recentering Technique".
        
        HNP problem:    |alpha*t_{i} - u_{i}|_{q} < q/2^{l}
        -> Exists c_{i} such that:
                    0      <= alpha*t_{i} - u_{i} + q*c_{i}             < q/2^{l}
                -q/2^{l+1} <= alpha*t_{i} - u_{i} + q*c_{i} - q/2^{l+1} < q/2^{l+1}
                            | alpha*t_{i} - u_{i} - q/2^{l+1} |_{q}     < q/2^{l+1}
    """

    # step 0: setup
    assert len(ts) == len(us)
    if lattice_reduction is None:
        lattice_reduction = lambda M: M.LLL()
    debug = (lambda *args: print(*args)) if debug else (lambda *args: None)
    KEF   = q # Kannan Embedding Factor <- maybe need to adjust this value
    d     = len(ts)

    # step 1: contruct basis
    B1 = identity_matrix(QQ, d)*q*2**(l+1)
    B2 = matrix(QQ, d, 1, [0]*d)
    B3 = matrix(QQ, 1, d, [t*2**(l+1) for t in ts])
    B4 = matrix(QQ, 1, 1, [1])
    B  = block_matrix([[B1, B2], [B3, B4]])
    debug("[hnp_recentering] Basis's dimensions:", B.dimensions())

    # step 2: contruct Kannan's embedding matrix
    t  = vector(QQ, [u*2**(l+1) + q for u in us] + [0]) # target cvp vector
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