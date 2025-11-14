#!/usr/bin/env python3
"""
Test 3: Session Key Derivation
Demonstrates deriving AES-128 key from DH shared secret: K = Trunc16(SHA256(Ks))
"""

from crypto_utils import generate_dh_params, compute_dh_public, compute_shared_secret
import secrets
import hashlib

def main():
    print("\n[+] SESSION KEY DERIVATION: K = Trunc16(SHA256(Ks))")
    print("=" * 70)

    # Perform DH exchange
    print("\n[1] Performing DH key exchange...")
    p, g = generate_dh_params()
    a = secrets.randbelow(p-1) + 1
    b = secrets.randbelow(p-1) + 1
    A = compute_dh_public(g, a, p)
    B = compute_dh_public(g, b, p)
    Ks = compute_shared_secret(B, a, p)

    print(f"[✓] Shared Secret (Ks): {hex(Ks)[:60]}...")

    # Convert Ks to bytes (big-endian representation)
    print("\n[2] Converting Ks to bytes (big-endian)...")
    Ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, byteorder='big')
    print(f"[✓] Ks (bytes): {Ks_bytes.hex()[:60]}...")
    print(f"[✓] Byte length: {len(Ks_bytes)} bytes")

    # Compute SHA-256 hash
    print("\n[3] Computing SHA-256 hash of Ks...")
    hash_digest = hashlib.sha256(Ks_bytes).digest()
    print(f"[✓] SHA-256(Ks): {hash_digest.hex()}")
    print(f"[✓] Hash length: {len(hash_digest)} bytes (256 bits)")

    # Truncate to 16 bytes for AES-128
    print("\n[4] Truncating to 16 bytes for AES-128...")
    K = hash_digest[:16]
    print(f"[✓] Session Key (K): {K.hex()}")
    print(f"[✓] Key length: {len(K)} bytes (128 bits)")

    print("\n" + "=" * 70)
    print("✓ Session key derived successfully for AES-128 encryption!")
    print("=" * 70)
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())

