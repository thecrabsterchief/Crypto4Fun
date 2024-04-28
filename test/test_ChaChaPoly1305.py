from Crypto.Cipher import ChaCha20_Poly1305
from random import randint
from os import urandom

from Attack import forgery_attack

nonce = urandom(12)
key   = urandom(32)
    
def encrypt(msg, ad):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(data=ad)
    return cipher.encrypt_and_digest(msg)
    
def decrypt(ct, ad, tag):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(data=ad)
    return cipher.decrypt_and_verify(ct, tag)

if __name__ == "__main__":
    known_data = []
    for _ in range(3):
        m  = urandom(randint(30, 100))
        ad = urandom(16)
        c, t = encrypt(m, ad)
        if _:
            known_data.append((None, c, ad, t))
        else:
            known_data.append((m, c, ad, t))
    
    target_pt = urandom(30)
    target_ad = urandom(16)
    c, t = forgery_attack(known_data, target_pt, target_ad)

    assert decrypt(c, target_ad, t) == target_pt