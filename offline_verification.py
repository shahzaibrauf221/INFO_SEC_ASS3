#!/usr/bin/env python3
"""
Offline Verification Script for Session Receipts
Verifies transcript integrity and RSA signatures (hash-based signatures)
"""

import sys
import json
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509 import load_pem_x509_certificate
import base64

def main():
    print("\n[+] OFFLINE VERIFICATION OF SESSION RECEIPTS")
    print("=" * 70)

    # Find all receipt files
    receipt_files = list(Path('.').glob('*_receipt_*.json'))
    if not receipt_files:
        print("[!] No receipt files found in current directory")
        print("[!] Make sure you're in the directory with receipt files")
        sys.exit(1)

    verification_results = []

    for receipt_file in receipt_files:
        print(f"\n[VERIFYING] {receipt_file.name}")
        print("-" * 70)

        try:
            # Load receipt
            with open(receipt_file, 'r') as f:
                receipt = json.load(f)

            peer = receipt.get('peer', 'unknown')
            transcript_hash_hex = receipt.get('transcript_sha256', '')
            signature_b64 = receipt.get('sig', '')

            print(f"[+] Peer: {peer}")
            print(f"[+] Transcript Hash: {transcript_hash_hex[:60]}...")
            print(f"[+] Signature: {signature_b64[:60]}...")

            # Find corresponding transcript
            transcript_pattern = f'{peer}_transcript_*.txt'
            transcript_files = list(Path('.').glob(transcript_pattern))

            if not transcript_files:
                print(f"[!] No transcript file found for {peer}")
                verification_results.append((receipt_file.name, False, "Transcript not found"))
                continue

            transcript_file = transcript_files[0]
            print(f"[+] Transcript File: {transcript_file.name}")

            # Recompute transcript hash
            with open(transcript_file, 'rb') as f:
                transcript_data = f.read()

            computed_hash = hashlib.sha256(transcript_data).hexdigest()
            print(f"[+] Recomputed Hash: {computed_hash[:60]}...")

            # Verify hash matches
            if computed_hash != transcript_hash_hex:
                print("[✗] Transcript hash MISMATCH!")
                print(f"    Expected: {transcript_hash_hex}")
                print(f"    Got:      {computed_hash}")
                verification_results.append((receipt_file.name, False, "Hash mismatch"))
                continue

            print("[✓] Transcript hash matches receipt!")

            # Determine signer and certificate
            filename = receipt_file.name
            if filename.startswith('client_receipt'):
                signer = 'client'
                cert_file = 'certs/client_cert.pem'
            elif filename.startswith('server_receipt'):
                signer = 'server'
                cert_file = 'certs/server_cert.pem'
            else:
                signer = filename.split('_')[0]
                cert_file = f'certs/{signer}_cert.pem'

            print(f"[+] Receipt signed by: {signer}")
            print(f"[+] Using certificate: {cert_file}")

            if not Path(cert_file).exists():
                print(f"[!] Certificate not found: {cert_file}")
                verification_results.append((receipt_file.name, False, "Certificate not found"))
                continue

            # Load certificate and public key
            try:
                with open(cert_file, 'rb') as f:
                    cert = load_pem_x509_certificate(f.read())
                public_key = cert.public_key()
                print(f"[+] Loaded certificate: {cert_file}")

                # Decode signature
                try:
                    signature_bytes = base64.b64decode(signature_b64)
                except Exception as e:
                    print(f"[✗] Failed to decode signature: {e}")
                    verification_results.append((receipt_file.name, False, "Invalid signature encoding"))
                    continue

                # --- CORRECTED SIGNATURE VERIFICATION (hash-based) ---
                try:
                    hash_bytes = bytes.fromhex(transcript_hash_hex)
                    public_key.verify(
                        signature_bytes,
                        hash_bytes,
                        padding.PKCS1v15(),
                        Prehashed(hashes.SHA256())
                    )
                    print(f"[✓] RSA signature verified successfully!")
                    print(f"[✓] Receipt is authentic and transcript is unmodified")
                    verification_results.append((receipt_file.name, True, "Verified"))
                except Exception as e:
                    print(f"[✗] Signature verification failed!")
                    print(f"    Error: {str(e)}")
                    print(f"    This could mean:")
                    print(f"      - Transcript was modified after signing")
                    print(f"      - Wrong certificate used for verification")
                    print(f"      - Receipt was tampered with")
                    verification_results.append((receipt_file.name, False, f"Signature invalid: {e}"))

            except FileNotFoundError:
                print(f"[!] Certificate file not found: {cert_file}")
                verification_results.append((receipt_file.name, False, "Certificate not found"))
            except Exception as e:
                print(f"[!] Error loading certificate: {e}")
                verification_results.append((receipt_file.name, False, f"Certificate error: {e}"))

        except Exception as e:
            print(f"[✗] Error processing receipt: {e}")
            verification_results.append((receipt_file.name, False, f"Processing error: {e}"))

    # Summary
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)

    total = len(verification_results)
    passed = sum(1 for _, success, _ in verification_results if success)
    failed = total - passed

    print(f"\nTotal receipts: {total}")
    print(f"Verified:       {passed} ✓")
    print(f"Failed:         {failed} ✗")

    print("\nDetailed Results:")
    print("-" * 70)
    for filename, success, message in verification_results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status:8} {filename:40} {message}")

    print("=" * 70)

    if passed == total:
        print("✓ All receipts verified successfully!")
        print("✓ Non-repudiation achieved!")
        return 0
    else:
        print("⚠ Some receipts failed verification!")
        return 1

if __name__ == "__main__":
    sys.exit(main())

