#!/usr/bin/env python3
"""
Test 1: DH Parameter Generation
Demonstrates generation of Diffie-Hellman parameters (p, g)
"""

from crypto_utils import generate_dh_params  # no sys.path needed

def main():
    print("\n[+] Generating DH Parameters (p, g)")
    print("=" * 70)

    p, g = generate_dh_params()

    print(f"\n[✓] Prime (p):")
    print(f"    {p}")
    print(f"\n[✓] Generator (g):")
    print(f"    {g}")
    print(f"\n[✓] Prime size: {len(bin(p)) - 2} bits")
    print(f"[✓] DH parameters generated successfully!")
    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()

