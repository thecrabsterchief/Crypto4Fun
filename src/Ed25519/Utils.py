from sage.all import EllipticCurve, GF
import hashlib
import os

class Ed25519:
    p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    q = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    a = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec
    d = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
    F = GF(p)
    I = pow(2,(p - 1)//4, p)
    BASE = (
        0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A,
        0x6666666666666666666666666666666666666666666666666666666666666658
    )

    # from Twisted Edwards to Weierstrass
    E = EllipticCurve(F, [
        -(a**2 + 14*a*d + d**2) * pow(48, -1, p) % p,
        (a + d) * (-a**2 + 34*a*d - d**2) * pow(864, -1, p) % p
    ])
    E.set_order(0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed * 0x08)

    @classmethod
    def __to_Weierstrass(cls, x, y):
        return (
            int((5*cls.a + cls.a*y - 5*cls.d*y - cls.d) * pow(12 - 12*y, -1, cls.p) % cls.p), 
            int((cls.a + cls.a*y - cls.d*y -cls.d) * pow(4*x - 4*x*y, -1, cls.p) % cls.p)
        )
    
    @classmethod
    def __to_TwistedEdwards(cls, u, v):
        y = (5*cls.a - 12*u - cls.d) * pow(-12*u - cls.a + 5*cls.d, -1, cls.p) % cls.p
        x = (cls.a + cls.a*y - cls.d*y -cls.d) * pow(4*v - 4*v*y, -1, cls.p) % cls.p
        return (int(x), int(y))
    
    @classmethod
    def add(cls, P: tuple, Q: tuple):
        P = cls.E(*cls.__to_Weierstrass(*P))
        Q = cls.E(*cls.__to_Weierstrass(*Q))
        R = P + Q
        return cls.__to_TwistedEdwards(*R.xy())

    @classmethod
    def mult(cls, P: tuple, n: int):
        P = cls.E(*cls.__to_Weierstrass(*P))
        R = n * P
        return cls.__to_TwistedEdwards(*R.xy())

    @classmethod
    def xRecover(cls, y: int) -> int:
        # (-x*x + y*y - 1 - d*x*x*y*y) % p == 0
        xx = (y*y - 1) * pow(cls.d*y*y + 1, -1, cls.p) % cls.p
        x  = pow(xx, (cls.p+3)//8, cls.p)      
        if (x*x - xx) % cls.p != 0: x = (x * cls.I) % cls.p
        if x % 2 != 0: x = cls.p - x
        return x
    
    @classmethod
    def isOnCurve(cls, x: int, y: int) -> bool:
        return (y*y - x*x - 1 - cls.d*x*x*y*y) % cls.p == 0
    
class EdDSA:
    @classmethod
    def bytes_to_clamped_scalar(cls, s: bytes) -> int:
        # Ed25519 private keys clamp the scalar to ensure two things:
        #   1: integer value is in L/2 .. L, to avoid small-logarithm
        #      non-wraparaound
        #   2: low-order 3 bits are zero, so a small-subgroup attack won't learn
        #      any information
        # set the top two bits to 01, and the bottom three to 000

        assert len(s) == 32
        a_unclamped = int.from_bytes(s, 'little')
        AND_CLAMP   = (1 << 254) - 1 - 7
        OR_CLAMP    = (1 << 254)
        a_clamped   = (a_unclamped & AND_CLAMP) | OR_CLAMP
        return a_clamped

    @classmethod
    def create_keypair(cls) -> bytes:
        sk = os.urandom(32)

        # from private key to public key
        a  = cls.bytes_to_clamped_scalar(Helper.HASH(sk)[:32])
        A  = Ed25519.mult(Ed25519.BASE, a)
        vk = Helper.EncodePoint(*A)
        return sk + vk

    @classmethod
    def sign_message(cls, message: bytes, sk: bytes, vk: bytes) -> bytes:
        assert len(sk) == 32 and len(vk) == 32
        h = Helper.HASH(sk)
        a_bytes, inter = h[:32], h[32:]
        a = cls.bytes_to_clamped_scalar(a_bytes)
        r = int.from_bytes(
            Helper.HASH(inter + message), 'little'
        )
        R = Ed25519.mult(Ed25519.BASE, r)
        R_bytes = Helper.EncodePoint(*R)
        S = r + int.from_bytes(
            Helper.HASH(R_bytes + vk + message), 'little'
        )*a
        return R_bytes + (S % Ed25519.q).to_bytes(32, 'little')
    
    @classmethod
    def verify_signature(cls, signature: bytes, message: bytes, vk: bytes):
        assert len(signature) == 64 and len(vk) == 32

        R = Helper.DecodePoint(signature[:32])
        A = Helper.DecodePoint(vk)
        S = int.from_bytes(signature[32:], 'little')
        h = int.from_bytes(
            Helper.HASH(signature[:32] + vk + message), 'little' 
        )

        v1 = Ed25519.mult(Ed25519.BASE, S)
        v2 = Ed25519.add(R, Ed25519.mult(A, h))
        return v1 == v2

class Helper:
    @classmethod
    def HASH(cls, m: bytes) -> bytes:
        return hashlib.sha512(m).digest()
    
    @classmethod
    def EncodeInt(cls, y: int) -> bytes:
        return y.to_bytes(32, 'little')
    
    @classmethod
    def DecodeInt(cls, y: bytes) -> int:
        return int.from_bytes(y, 'little')

    @classmethod
    def EncodePoint(cls, x: int, y: int) -> bytes:
        assert 0 <= y < (1 << 255) # always < 0x7fff..ff
        if x & 1:
            y += (1<<255)
        return y.to_bytes(32, 'little')

    @classmethod
    def DecodePoint(cls, s: bytes) -> tuple:
        t = int.from_bytes(s, 'little')
        y = t & ((1 << 255) - 1)
        x = Ed25519.xRecover(y)

        if (x&1) != (t >> 255): x = Ed25519.p - x
        assert Ed25519.isOnCurve(x, y), "Decoding point that is not on curve"
        return (x, y)