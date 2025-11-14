#!/usr/bin/env python3
"""
Test 4: AES Encryption with DH-Derived Key
Tests complete flow: DH exchange -> Key derivation -> AES encryption/decryption
"""

from crypto_utils import (
    aes_encrypt, 
    aes_decrypt, 
    generate_dh_params, 
    compute_dh_public, 
    compute_shared_secret
)
import secrets
import hashlib

def main():
    print("\n[+] AES-128 ENCRYPTION WITH DH-DERIVED SESSION KEY")
    print("=" * 70)

    # Step 1: Perform DH exchange
    print("\n[STEP 1] Performing Diffie-Hellman key exchange...")
    p, g = generate_dh_params()
    a = secrets.randbelow(p-1) + 1
    b = secrets.randbelow(p-1) + 1
    A = compute_dh_public(g, a, p)
    B = compute_dh_public(g, b, p)
    Ks = compute_shared_secret(B, a, p)
    print("[✓] DH exchange completed")

    # Step 2: Derive AES key from shared secret
    print("\n[STEP 2] Deriving AES-128 session key...")
    Ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, byteorder='big')
    K = hashlib.sha256(Ks_bytes).digest()[:16]
    print(f"[✓] Session Key (K): {K.hex()}")

    # Step 3: Encrypt test message
    print("\n[STEP 3] Encrypting test message with AES-128-CBC...")
    plaintext = b'This is a secure test message for INFO SEC Assignment!'
    print(f"[+] Plaintext:  '{plaintext.decode()}'")
    print(f"[+] Length: {len(plaintext)} bytes")

    iv, ciphertext = aes_encrypt(plaintext, K)
    print(f"\n[✓] IV:         {iv.hex()}")
    print(f"[✓] Ciphertext: {ciphertext.hex()}")
    print("[✓] Encrypted successfully with PKCS#7 padding")

    # Step 4: Decrypt message
    print("\n[STEP 4] Decrypting ciphertext...")
    decrypted = aes_decrypt(iv, ciphertext, K)
    print(f"[✓] Decrypted:  '{decrypted.decode()}'")

    # Step 5: Verify integrity
    print("\n[STEP 5] Verifying encryption/decryption integrity...")
    if plaintext == decrypted:
        print("[✓] SUCCESS: Plaintext matches decrypted text!")
        print("[✓] AES-128 encryption working correctly with DH-derived key!")
    else:
        print("[✗] FAILURE: Decryption did not match original plaintext!")
        return 1

    print("\n" + "=" * 70)
    print("Complete encryption/decryption cycle successful!")
    print("=" * 70)
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())

