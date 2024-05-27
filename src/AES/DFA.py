from Utils import Inv_Sbox, Div1, Div2, Div3, reverse_rounds_key

def bruteforce_rk10_when_fault_at(c, f, dfa_indexs, round_key10):
    """ Example that flawed byte at column 0 and row 0:
        - True state:                            - Faulty state:
            A E I M           This byte is flawed! ->X E I M 
            B F J N                                  B F J N
            C G K O                                  C G K O
            D H L P                                  D H L P
        => We don't know the actual position of the fault, but we know which column is flawed!

        => DFA equations when fault at column 0, row 0:
            - DIFF = A ^ X = Div2[Inv_Sbox[c[ 0] ^ rk(10, 0]) ^ Inv_Sbox[f[ 0] ^ rk(10, 0])]    
            - DIFF = A ^ X = Div3[Inv_Sbox[c[ 7] ^ rk(10, 7]) ^ Inv_Sbox[f[ 7] ^ rk(10, 7])]    
            - DIFF = A ^ X = Div1[Inv_Sbox[c[10] ^ rk(10,10]) ^ Inv_Sbox[f[10] ^ rk(10,10])]    
            - DIFF = A ^ X = Div1[Inv_Sbox[c[13] ^ rk(10,13]) ^ Inv_Sbox[f[13] ^ rk(10,13])]
        => Bruteforce rk(10, 0) to find all possible DIFF values corresponding to the fault at row 0
        Similar to other rows 1,2,3. Then we can find all candidates of rk(10, 0), rk(10, 1), rk(10, 2), rk(10, 3)
    """
    
    ii, jj, kk, ll = dfa_indexs
    # =================================== Find all DIFF candidates ===================================
    # Assuming that byte 0 is flawed
    diff_cand0 = set(Div2[Inv_Sbox[c[ii] ^ rk10_ii] ^ Inv_Sbox[f[ii] ^ rk10_ii]] for rk10_ii in range(256)) & \
                 set(Div1[Inv_Sbox[c[jj] ^ rk10_jj] ^ Inv_Sbox[f[jj] ^ rk10_jj]] for rk10_jj in range(256)) & \
                 set(Div1[Inv_Sbox[c[kk] ^ rk10_kk] ^ Inv_Sbox[f[kk] ^ rk10_kk]] for rk10_kk in range(256)) & \
                 set(Div3[Inv_Sbox[c[ll] ^ rk10_ll] ^ Inv_Sbox[f[ll] ^ rk10_ll]] for rk10_ll in range(256))

    # Assuming that byte 1 is flawed
    diff_cand1 = set(Div3[Inv_Sbox[c[ii] ^ rk10_ii] ^ Inv_Sbox[f[ii] ^ rk10_ii]] for rk10_ii in range(256)) & \
                 set(Div2[Inv_Sbox[c[jj] ^ rk10_jj] ^ Inv_Sbox[f[jj] ^ rk10_jj]] for rk10_jj in range(256)) & \
                 set(Div1[Inv_Sbox[c[kk] ^ rk10_kk] ^ Inv_Sbox[f[kk] ^ rk10_kk]] for rk10_kk in range(256)) & \
                 set(Div1[Inv_Sbox[c[ll] ^ rk10_ll] ^ Inv_Sbox[f[ll] ^ rk10_ll]] for rk10_ll in range(256))

    # Assuming that byte 2 is flawed
    diff_cand2 = set(Div1[Inv_Sbox[c[ii] ^ rk10_ii] ^ Inv_Sbox[f[ii] ^ rk10_ii]] for rk10_ii in range(256)) & \
                 set(Div3[Inv_Sbox[c[jj] ^ rk10_jj] ^ Inv_Sbox[f[jj] ^ rk10_jj]] for rk10_jj in range(256)) & \
                 set(Div2[Inv_Sbox[c[kk] ^ rk10_kk] ^ Inv_Sbox[f[kk] ^ rk10_kk]] for rk10_kk in range(256)) & \
                 set(Div1[Inv_Sbox[c[ll] ^ rk10_ll] ^ Inv_Sbox[f[ll] ^ rk10_ll]] for rk10_ll in range(256))

    # Assuming that byte 3 is flawed
    diff_cand3 = set(Div1[Inv_Sbox[c[ii] ^ rk10_ii] ^ Inv_Sbox[f[ii] ^ rk10_ii]] for rk10_ii in range(256)) & \
                 set(Div1[Inv_Sbox[c[jj] ^ rk10_jj] ^ Inv_Sbox[f[jj] ^ rk10_jj]] for rk10_jj in range(256)) & \
                 set(Div3[Inv_Sbox[c[kk] ^ rk10_kk] ^ Inv_Sbox[f[kk] ^ rk10_kk]] for rk10_kk in range(256)) & \
                 set(Div2[Inv_Sbox[c[ll] ^ rk10_ll] ^ Inv_Sbox[f[ll] ^ rk10_ll]] for rk10_ll in range(256))

    # =================================== Find all rk10 candidates ===================================
    round_key10[ii] &= (
        set([rk10_ii for rk10_ii in range(256) if Div2[Inv_Sbox[c[ii] ^ rk10_ii] ^ Inv_Sbox[f[ii] ^ rk10_ii]] in diff_cand0]) | \
        set([rk10_ii for rk10_ii in range(256) if Div3[Inv_Sbox[c[ii] ^ rk10_ii] ^ Inv_Sbox[f[ii] ^ rk10_ii]] in diff_cand1]) | \
        set([rk10_ii for rk10_ii in range(256) if Div1[Inv_Sbox[c[ii] ^ rk10_ii] ^ Inv_Sbox[f[ii] ^ rk10_ii]] in diff_cand2]) | \
        set([rk10_ii for rk10_ii in range(256) if Div1[Inv_Sbox[c[ii] ^ rk10_ii] ^ Inv_Sbox[f[ii] ^ rk10_ii]] in diff_cand3])
    )

    round_key10[jj] &= (
        set([rk10_jj for rk10_jj in range(256) if Div1[Inv_Sbox[c[jj] ^ rk10_jj] ^ Inv_Sbox[f[jj] ^ rk10_jj]] in diff_cand0]) | \
        set([rk10_jj for rk10_jj in range(256) if Div2[Inv_Sbox[c[jj] ^ rk10_jj] ^ Inv_Sbox[f[jj] ^ rk10_jj]] in diff_cand1]) | \
        set([rk10_jj for rk10_jj in range(256) if Div3[Inv_Sbox[c[jj] ^ rk10_jj] ^ Inv_Sbox[f[jj] ^ rk10_jj]] in diff_cand2]) | \
        set([rk10_jj for rk10_jj in range(256) if Div1[Inv_Sbox[c[jj] ^ rk10_jj] ^ Inv_Sbox[f[jj] ^ rk10_jj]] in diff_cand3])
    )

    round_key10[kk] &= (
        set([rk10_kk for rk10_kk in range(256) if Div1[Inv_Sbox[c[kk] ^ rk10_kk] ^ Inv_Sbox[f[kk] ^ rk10_kk]] in diff_cand0]) | \
        set([rk10_kk for rk10_kk in range(256) if Div1[Inv_Sbox[c[kk] ^ rk10_kk] ^ Inv_Sbox[f[kk] ^ rk10_kk]] in diff_cand1]) | \
        set([rk10_kk for rk10_kk in range(256) if Div2[Inv_Sbox[c[kk] ^ rk10_kk] ^ Inv_Sbox[f[kk] ^ rk10_kk]] in diff_cand2]) | \
        set([rk10_kk for rk10_kk in range(256) if Div3[Inv_Sbox[c[kk] ^ rk10_kk] ^ Inv_Sbox[f[kk] ^ rk10_kk]] in diff_cand3])
    )

    round_key10[ll] &= (
        set([rk10_ll for rk10_ll in range(256) if Div3[Inv_Sbox[c[ll] ^ rk10_ll] ^ Inv_Sbox[f[ll] ^ rk10_ll]] in diff_cand0]) | \
        set([rk10_ll for rk10_ll in range(256) if Div1[Inv_Sbox[c[ll] ^ rk10_ll] ^ Inv_Sbox[f[ll] ^ rk10_ll]] in diff_cand1]) | \
        set([rk10_ll for rk10_ll in range(256) if Div1[Inv_Sbox[c[ll] ^ rk10_ll] ^ Inv_Sbox[f[ll] ^ rk10_ll]] in diff_cand2]) | \
        set([rk10_ll for rk10_ll in range(256) if Div2[Inv_Sbox[c[ll] ^ rk10_ll] ^ Inv_Sbox[f[ll] ^ rk10_ll]] in diff_cand3])
    )


def attack_dfa_round9(dfa_oracle):
    """ Differential Fault Analysis on AES (Round 9)
        References:
        - https://blog.quarkslab.com/differential-fault-analysis-on-white-box-aes-implementations.html
        - https://eprint.iacr.org/2003/010.pdf

        Args:
            dfa_oracle (function): Oracle function that returns [c, f, indexs], where:
            - c (bytes): the true ciphertext
            - f (bytes): the faulty ciphertext
            - indexs (list): list of indexes where the fault occurs
            [!] Important: indexs must be one of the following:
                    [0,13,10,7], 
                    [4,1,14,11], 
                    [8,5,2,15 ], 
                    [12,9,6,3 ]
            Ex: after comparing the real and faulty ciphertexts: indexs = [i for i in range(16) if c[i] != f[i]]
                You MUST rearrange the indexes to match the above format!

        Returns:
            master_key (bytes): The master key of the AES cipher
    """

    rk10 = [set(range(256)) for _ in range(16)]
    while any(len(rk10_i) > 1 for rk10_i in rk10):
        c, f, dfa_indexs = dfa_oracle()
        bruteforce_rk10_when_fault_at(c, f, dfa_indexs, rk10)
        # print(f"rk10 cands: {[len(rk10_i) for rk10_i in rk10]}")
    
    # recover the master key from expanded round key (rk10)
    return reverse_rounds_key(round_key=bytes([list(rk10_i)[0] for rk10_i in rk10]), n_rounds=10)