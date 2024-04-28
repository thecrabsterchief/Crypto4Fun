from os import urandom
from Crypto.Cipher import AES
from random import randint

from Attack import forgery_message, forgery_tag

nonce = urandom(12)
key   = urandom(16)

def encrypt(msg, ad=b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)
    return cipher.encrypt_and_digest(msg)
    
def decrypt(ct, tag, ad=b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)
    return cipher.decrypt_and_verify(ct, tag)

def test_forgery_message():
    m1 = urandom(randint(30, 100))
    m2 = urandom(randint(30, 100))
    m3 = urandom(randint(16, 30))
    
    a1 = urandom(randint(16, 32))
    a2 = urandom(randint(16, 32))
    a3 = urandom(randint(16, 32))

    c1, t1 = encrypt(m1, a1)
    c2, t2 = encrypt(m2, a2)

    c3, roots = forgery_message(
        known_data=[(m1, c1, a1, t1), (None, c2, a2, t2)], 
        target_plaintext=m3, target_associated_data=a3
    )
    success = 0
    for t3 in roots:
        try:
            success += (decrypt(c3, t3, a3) == m3)
        except ValueError:
            pass
    
    assert success == 1, "Failed to forge message"
    print("Forged msg successfully")

def test_forgery_tag():
    m1 = urandom(randint(30, 100))
    m2 = urandom(randint(30, 100))
    m3 = urandom(randint(30, 100))
    
    a1 = urandom(randint(16, 32))
    a2 = urandom(randint(16, 32))
    a3 = urandom(randint(16, 32))

    c1, t1 = encrypt(m1, a1)
    c2, t2 = encrypt(m2, a2)
    c3, t3 = encrypt(m3, a3)

    tags = forgery_tag(
        known_data=[(None, c1, a1, t1), (None, c2, a2, t2)], 
        target_ciphertext=c3, target_associated_data=a3
    )

    success = 0
    for t3 in tags:
        try:
            success += (decrypt(c3, t3, a3) == m3)
        except ValueError:
            pass
    
    assert success == 1, "Failed to forge tag"
    print("Forged tag successfully")

if __name__ == "__main__":

    test_forgery_tag()
    test_forgery_message()