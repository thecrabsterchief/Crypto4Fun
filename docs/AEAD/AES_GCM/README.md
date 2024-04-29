# AES-GCM

AES with Galois/Counter Mode (AES-GCM) provides both authenticated encryption (confidentiality and authentication) and the ability to check the integrity and authentication of additional authenticated data (AAD) that is sent in the clear. AES-GCM is specified in NIST Special Publication 800-38D

## GHASH

$$
\textsf{GHASH}(h, a, c) = \sum_{i=1}^{\lceil \tfrac{l_{a}}{16} \rceil}a_{i}h^{i+1+\lceil \tfrac{l_{c}}{16} \rceil} + \sum_{i=1}^{\lceil \tfrac{l_{c}}{16} \rceil}c_{i}h^{i+1} + Lh + E_{o} \qquad h, a, c \in \mathbb{F}_{2^{128}}
$$

- $h$ is derived `nonce`
- $a_{i},c_{i}$ is 16-bytes blocks of Associated Data and Ciphertext (after being padded)
- $l_{a}, l_{c}$ is the truth length of Associated Data and Ciphertext
- $L = ((8 \times l_{a}) << 64) | (8 \times l_{c})$

## Attacks when nonce is reused

- [Forgery Tag from Ciphertext](/src/AEAD/AES_GCM/Attack.py)
- [Forgery Tag from Plaintext](/src/AEAD/AES_GCM/Attack.py)

## CTF Challenges

| Name                                                                                    | Tags                                        | Difficulty |
| --------------------------------------------------------------------------------------- | ------------------------------------------- | ---------- |
| [DHCPPP](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/PlaidCTF/2024/DHCPPP) | ChaCha20-Poly1305, Nonce-Reused, Networking | ★★☆       |