from SignatureForgery import attack
import ed25519 # pip install ed25519
import os

if __name__ == "__main__":
    # setup context
    key, _ = ed25519.create_keypair()
    key    = key.sk_s
    sk, vk = key[:32], key[32:]
    message        = b"admin=False" + os.urandom(32)
    target_message = b"admin=True" + os.urandom(32)
    fake_vk        = os.urandom(32)

    sig1 = ed25519.SigningKey(sk + vk).sign(message)
    sig2 = ed25519.SigningKey(sk + fake_vk).sign(message)

    # attack!!!
    forged_sig = attack(sig1, vk, sig2, fake_vk, message, target_message, vk)
    try:
        ed25519.VerifyingKey(vk).verify(forged_sig, target_message)
        print("The signature is valid")
    except ed25519.BadSignatureError:
        print("The signature is invalid")