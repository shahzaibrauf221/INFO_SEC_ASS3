#!/usr/bin/env python3
"""
Security Test: Message Tampering Detection
Demonstrates that any modification to ciphertext is detected via signature verification
"""

from crypto_utils import aes_encrypt, compute_message_digest, rsa_sign, rsa_verify
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
import os

def main():
    print("\n[+] MESSAGE TAMPERING DETECTION TEST")
    print("=" * 70)

    # Setup
    key = os.urandom(16)
    plaintext = b"Original message"
    seqno = 1
    timestamp = 1234567890

    print(f"\n[STEP 1] Original Message")
    print(f"  Plaintext: {plaintext.decode()}")
    print(f"  Sequence: {seqno}")

    # Encrypt
    iv, ciphertext = aes_encrypt(plaintext, key)
    print(f"\n[STEP 2] Encrypted")
    print(f"  Ciphertext: {ciphertext.hex()[:60]}...")

    # Compute digest and sign
    digest = compute_message_digest(seqno, timestamp, ciphertext)
    print(f"\n[STEP 3] Computed Digest")
    print(f"  SHA-256: {digest.hex()[:60]}...")

    # Load private key for signing
    try:
        with open('certs/client_key.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print("[!] Error: certs/client_key.pem not found")
        return 1

    signature = rsa_sign(digest, private_key)
    print(f"\n[STEP 4] Signed Digest")
    print(f"  Signature: {signature.hex()[:60]}...")

    # Load public key for verification
    try:
        with open('certs/client_cert.pem', 'rb') as f:
            cert = load_pem_x509_certificate(f.read())
            public_key = cert.public_key()
    except FileNotFoundError:
        print("[!] Error: certs/client_cert.pem not found")
        return 1

    # Verify original (should succeed)
    print(f"\n[STEP 5] Verifying Original Message")
    is_valid = rsa_verify(digest, signature, public_key)
    if is_valid:
        print("[✓] Signature valid - message integrity confirmed")
    else:
        print("[✗] Signature invalid - unexpected!")
        return 1

    # Tamper with ciphertext (flip one bit)
    print(f"\n[STEP 6] Tampering with Ciphertext")
    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0x01  # Flip one bit
    tampered_ct = bytes(tampered_ct)
    print(f"  Original CT: {ciphertext.hex()[:40]}...")
    print(f"  Tampered CT: {tampered_ct.hex()[:40]}...")

    # Recompute digest with tampered ciphertext
    tampered_digest = compute_message_digest(seqno, timestamp, tampered_ct)
    print(f"  Tampered digest: {tampered_digest.hex()[:60]}...")

    # Verify tampered (should fail)
    print(f"\n[STEP 7] Verifying Tampered Message")
    is_valid_tampered = rsa_verify(tampered_digest, signature, public_key)
    if not is_valid_tampered:
        print("[✓] Signature invalid - tampering detected!")
        print("[✓] Message integrity protection is working!")
    else:
        print("[✗] Signature still valid - tampering NOT detected (this is bad!)")
        return 1

    print("\n" + "=" * 70)
    print("Tampering detection test completed successfully!")
    print("=" * 70)
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())

