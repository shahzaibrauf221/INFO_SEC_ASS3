#!/usr/bin/env python3
import sys
import secrets

sys.path.insert(0, 'src')
from crypto_utils import (
    generate_dh_parameters,
    dh_generate_keypair,
    dh_compute_shared_secret,
    derive_aes_key,
    aes_encrypt,
    aes_decrypt
)

print("\n" + "="*70)
print("SECTION 4: DIFFIE-HELLMAN KEY EXCHANGE DEMO")
print("="*70)

# =======================
# Test 1: DH Parameter Generation
# =======================
print("\n[TEST 1] DH Parameter Generation")
p, g = generate_dh_parameters()
print(f"Prime (p): {p}")
print(f"Generator (g): {g}")
print(f"Prime size: {len(bin(p))-2} bits")

# =======================
# Test 2: DH Key Exchange Simulation
# =======================
print("\n[TEST 2] DH Key Exchange Simulation")

# Client key pair
a, A = dh_generate_keypair(p, g)
print(f"Client Private Key: {a}")
print(f"Client Public Key (A): {A}")

# Server key pair
b, B = dh_generate_keypair(p, g)
print(f"Server Private Key: {b}")
print(f"Server Public Key (B): {B}")

# Compute shared secrets
Ks_client = dh_compute_shared_secret(B, a, p)
Ks_server = dh_compute_shared_secret(A, b, p)
print(f"Client Shared Secret: {Ks_client}")
print(f"Server Shared Secret: {Ks_server}")
print("Shared secret match:", Ks_client == Ks_server)

# =======================
# Test 3: Session Key Derivation
# =======================
print("\n[TEST 3] Session Key Derivation")
K = derive_aes_key(Ks_client)
print("Session Key (16 bytes for AES-128):", K.hex())

# =======================
# Test 4: AES Encryption/Decryption Test
# =======================
print("\n[TEST 4] AES Encryption/Decryption with DH-Derived Key")
plaintext = b'This is a secure test message for INFO SEC Assignment!'

iv, ciphertext = aes_encrypt(plaintext, K)
decrypted = aes_decrypt(iv, ciphertext, K)

print("Plaintext:", plaintext)
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted:", decrypted)
print("Encryption/Decryption match:", plaintext == decrypted)

print("\n" + "="*70)
print("ALL DH TESTS COMPLETED SUCCESSFULLY!")
print("="*70)
