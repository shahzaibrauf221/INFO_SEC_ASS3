#!/usr/bin/env python3
"""
Test 2: Complete DH Key Exchange Simulation
Demonstrates full Diffie-Hellman key exchange between client and server
"""

from crypto_utils import generate_dh_params, compute_dh_public, compute_shared_secret
import secrets

def main():
    print("\n[+] DIFFIE-HELLMAN KEY EXCHANGE SIMULATION")
    print("=" * 70)

    # Step 1: Generate shared DH parameters
    print("\n[STEP 1] Generating shared parameters (p, g)")
    p, g = generate_dh_params()
    print(f"[✓] Prime (p):     {hex(p)[:60]}...")
    print(f"[✓] Generator (g): {g}")

    # Step 2: Client generates private/public key pair
    print("\n[STEP 2] Client generates key pair")
    print("-" * 70)
    a = secrets.randbelow(p - 2) + 1
    A = compute_dh_public(g, a, p)  # Client's public key
    print(f"[CLIENT]")
    print(f"  Private key (a): {hex(a)[:60]}...")
    print(f"  Public key (A):  {hex(A)[:60]}...")
    print(f"  Computation: A = g^a mod p")

    # Step 3: Server generates private/public key pair
    print("\n[STEP 3] Server generates key pair")
    print("-" * 70)
    b = secrets.randbelow(p - 2) + 1
    B = compute_dh_public(g, b, p)  # Server's public key
    print(f"[SERVER]")
    print(f"  Private key (b): {hex(b)[:60]}...")
    print(f"  Public key (B):  {hex(B)[:60]}...")
    print(f"  Computation: B = g^b mod p")

    # Step 4: Exchange public keys and compute shared secret
    print("\n[STEP 4] Computing shared secret")
    print("-" * 70)
    print("[CLIENT] Receives B from server, computes: Ks = B^a mod p")
    Ks_client = compute_shared_secret(B, a, p)
    print(f"  Ks (client): {hex(Ks_client)[:60]}...")

    print("\n[SERVER] Receives A from client, computes: Ks = A^b mod p")
    Ks_server = compute_shared_secret(A, b, p)
    print(f"  Ks (server): {hex(Ks_server)[:60]}...")

    # Step 5: Verify both computed the same shared secret
    print("\n[STEP 5] Verifying shared secret")
    print("-" * 70)
    if Ks_client == Ks_server:
        print("[✓] SUCCESS: Both sides computed the same shared secret!")
        print(f"[✓] Shared Secret (Ks) matches: {Ks_client == Ks_server}")
    else:
        print("[✗] FAILURE: Shared secrets do not match!")
        return 1

    print("\n" + "=" * 70)
    print("DH Key Exchange completed successfully!")
    print("=" * 70)
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())

