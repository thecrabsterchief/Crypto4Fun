# ChaCha20 Poly1305

ChaCha20-Poly1305 is an authenticated encryption with additional data (AEAD) algorithm, that combines the ChaCha20 stream cipher with the Poly1305 message authentication code. Its usage in IETF protocols is standardized in RFC 8439. It has fast software performance, and without hardware acceleration, is usually faster than AES-GCM

## Poly1305

$$
\textsf{Poly1305}(m, r, s) = \left( \sum_{i=0}^{} \left(m_i || 0x01\right) \cdot r^i \pmod{2^{130} - 5} \right) + s \pmod{2^{128}}
$$

## Attacks when nonce is reused

- [Forgery Tag from Ciphertext](/src/AEAD/ChaChaPoly1305/Attack.py)
- [Forgery Tag from Plaintext](/src/AEAD/ChaChaPoly1305/Attack.py)

## CTF Challenges

| Name                                                                                    | Tags                                        | Difficulty |
| --------------------------------------------------------------------------------------- | ------------------------------------------- | ---------- |
| [Forbiddden Fruit](https://aes.cryptohack.org/forbidden_fruit/) | AES_GCM, Nonce-Reused | ★★       |