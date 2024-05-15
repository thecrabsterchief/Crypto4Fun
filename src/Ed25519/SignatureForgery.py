from Utils import Ed25519, EdDSA, Helper
import os

def attack(signature1: bytes, vk1: bytes, signature2: bytes, vk2: bytes, original_message: bytes, target_message: bytes, target_vk: bytes) -> bytes:
    """ Recover the private key from two signatures (of the same message) if they use the same
        secret key but different public keys.

        Args:
            signature1: The first signature corresponding to the original message
            vk1: The public key corresponding to the first signature
            signature2: The second signature corresponding to the original message
            vk2: The public key corresponding to the second signature
            original_message: The message that was signed
            target_message: The message that the attacker wants to forge a signature for
            target_vk: The public key that used to verify the forged signature
        Returns:
            The forged signature
    """
    
    assert len(vk1) == len(vk2) == 32
    assert len(signature1) == len(signature2) == 64
    assert signature1[:32] == signature2[:32]

    R  = Helper.DecodePoint(signature1[:32])
    e1 = int.from_bytes(
        Helper.HASH(signature1[:32] + vk1 + original_message), 'little' 
    )
    e2 = int.from_bytes(
        Helper.HASH(signature2[:32] + vk2 + original_message), 'little' 
    )
    s1 = int.from_bytes(signature1[32:], 'little')
    s2 = int.from_bytes(signature2[32:], 'little')

    sk_clamped_scalar = (s1 - s2) * pow(e1 - e2, -1, Ed25519.q) % Ed25519.q
    r = int.from_bytes(os.urandom(32), 'little') # don't care
    R = Ed25519.mult(Ed25519.BASE, r)
    R_bytes = Helper.EncodePoint(*R)
    S = r + int.from_bytes(
        Helper.HASH(R_bytes + target_vk + target_message), 'little'
    ) * sk_clamped_scalar
    
    return R_bytes + (S % Ed25519.q).to_bytes(32, 'little')