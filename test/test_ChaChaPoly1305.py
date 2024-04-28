from Crypto.Cipher import ChaCha20_Poly1305
from random import randint
from os import urandom

from Attack import forgery_tag, forgery_message

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

def test_forgery_message():
    m1 = urandom(randint(30, 100))
    m2 = urandom(randint(30, 100))
    
    a1 = urandom(randint(16, 32))
    a2 = urandom(randint(16, 32))

    c1, t1 = encrypt(m1, a1)
    c2, t2 = encrypt(m2, a2)

    a3 = urandom(randint(16, 32))
    m3 = urandom(randint(16, 30))

    c3, t3 = forgery_message(
        known_data=[(m1, c1, a1, t1), (None, c2, a2, t2)], 
        target_plaintext=m3,
        target_associated_data=a3
    )

    assert decrypt(c3, a3, t3) == m3, "Failed to forgery msg"
    print("Forgery msg successfully")

def test_forgery_tag():
    m1 = urandom(randint(30, 100))
    m2 = urandom(randint(30, 100))
    m3 = urandom(randint(30, 100))
    
    a1 = urandom(randint(16, 32))
    a2 = urandom(randint(16, 32))
    a3 = urandom(randint(16, 32))

    c1, t1 = encrypt(m1, a1)
    c2, t2 = encrypt(m2, a2)
    c3, _  = encrypt(m3, a3)

    t3 = forgery_tag(
        known_data=[(None, c1, a1, t1), (None, c2, a2, t2)], 
        target_ciphertext=c3,
        target_associated_data=a3
    )

    assert decrypt(c3, a3, t3) == m3, "Failed to forgery tag"
    print("Forgery tag successfully")

if __name__ == "__main__":
    test_forgery_tag()
    test_forgery_message()