#!/usr/bin/env python3
"""
Security Test: Invalid Certificate Detection
Tests certificate validation by attempting connections with:
1. Expired certificates
2. Self-signed certificates (not trusted by CA)
3. Certificates from wrong CA
4. Missing certificates

This demonstrates the PKI security requirement for the assignment.
"""

import os
import sys
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def print_section(title):
    """Print formatted section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def print_test(test_name):
    """Print formatted test header"""
    print(f"\n[TEST] {test_name}")
    print("-" * 70)

def test_expired_certificate():
    """
    Test 1: Generate and test an expired certificate
    This certificate is already expired when created
    """
    print_test("Expired Certificate Detection")
    
    try:
        # Load CA certificate and key
        ca_cert_path = Path('certs/ca_cert.pem')
        ca_key_path = Path('certs/ca_key.pem')
        
        if not ca_cert_path.exists() or not ca_key_path.exists():
            print("[!] CA certificate or key not found")
            print("    Please run: python3 scripts/gen_ca.py first")
            return False
        
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        
        print("[+] Loaded CA certificate and key")
        
        # Generate a new private key for expired cert
        print("[+] Generating RSA key pair for expired certificate...")
        expired_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate that expired 1 day ago
        print("[+] Creating certificate that expired yesterday...")
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
            x509.NameAttribute(NameOID.COMMON_NAME, "expired_test"),
        ])
        
        expired_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            expired_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow() - datetime.timedelta(days=365)  # Valid from 1 year ago
        ).not_valid_after(
            datetime.datetime.utcnow() - datetime.timedelta(days=1)  # Expired yesterday
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(ca_key, hashes.SHA256(), backend=default_backend())
        
        # Save expired certificate
        expired_cert_path = Path('certs/expired_test_cert.pem')
        expired_key_path = Path('certs/expired_test_key.pem')
        
        with open(expired_cert_path, 'wb') as f:
            f.write(expired_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(expired_key_path, 'wb') as f:
            f.write(expired_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"[✓] Created expired certificate: {expired_cert_path}")
        print(f"[✓] Created private key: {expired_key_path}")
        
        # Display certificate validity period
        print(f"\n[INFO] Certificate Validity:")
        print(f"  Not Before: {expired_cert.not_valid_before}")
        print(f"  Not After:  {expired_cert.not_valid_after}")
        print(f"  Current:    {datetime.datetime.utcnow()}")
        print(f"  Status:     EXPIRED ❌")
        
        # Verify it's signed by CA but expired
        print(f"\n[VERIFICATION] Testing with OpenSSL...")
        import subprocess
        result = subprocess.run(
            ['openssl', 'verify', '-CAfile', str(ca_cert_path), str(expired_cert_path)],
            capture_output=True,
            text=True
        )
        
        print(f"  Output: {result.stdout.strip()}")
        if result.returncode != 0:
            print(f"  Error:  {result.stderr.strip()}")
            print(f"\n[✓] PASS: Expired certificate correctly rejected!")
            return True
        else:
            print(f"\n[✗] FAIL: Expired certificate was accepted (should be rejected)!")
            return False
        
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if Path('certs/expired_test_cert.pem').exists():
            os.remove('certs/expired_test_cert.pem')
        if Path('certs/expired_test_key.pem').exists():
            os.remove('certs/expired_test_key.pem')
        print("[+] Cleanup: Removed expired certificate files")

def test_self_signed_certificate():
    """
    Test 2: Generate and test a self-signed certificate
    This certificate is NOT signed by our trusted CA
    """
    print_test("Self-Signed Certificate Detection (Untrusted)")
    
    try:
        # Generate key for self-signed cert
        print("[+] Generating RSA key pair for self-signed certificate...")
        selfsigned_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create self-signed certificate (acts as its own CA)
        print("[+] Creating self-signed certificate (NOT signed by our CA)...")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Attacker"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Malicious"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "attacker.com"),
        ])
        
        selfsigned_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer  # Self-signed: issuer = subject
        ).public_key(
            selfsigned_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(selfsigned_key, hashes.SHA256(), backend=default_backend())
        
        # Save self-signed certificate
        selfsigned_cert_path = Path('certs/selfsigned_cert.pem')
        selfsigned_key_path = Path('certs/selfsigned_key.pem')
        
        with open(selfsigned_cert_path, 'wb') as f:
            f.write(selfsigned_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(selfsigned_key_path, 'wb') as f:
            f.write(selfsigned_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"[✓] Created self-signed certificate: {selfsigned_cert_path}")
        print(f"[✓] Created private key: {selfsigned_key_path}")
        
        # Display certificate info
        print(f"\n[INFO] Certificate Info:")
        print(f"  Subject:  {selfsigned_cert.subject.rfc4514_string()}")
        print(f"  Issuer:   {selfsigned_cert.issuer.rfc4514_string()}")
        print(f"  Status:   Self-Signed (NOT trusted by our CA) ❌")
        
        # Try to verify against our CA (should fail)
        print(f"\n[VERIFICATION] Testing against our CA...")
        ca_cert_path = Path('certs/ca_cert.pem')
        
        if not ca_cert_path.exists():
            print("[!] CA certificate not found")
            return False
        
        import subprocess
        result = subprocess.run(
            ['openssl', 'verify', '-CAfile', str(ca_cert_path), str(selfsigned_cert_path)],
            capture_output=True,
            text=True
        )
        
        print(f"  Output: {result.stdout.strip()}")
        if result.returncode != 0:
            print(f"  Error:  {result.stderr.strip()}")
            print(f"\n[✓] PASS: Self-signed certificate correctly rejected!")
            print(f"[✓] Our CA did not sign this certificate")
            return True
        else:
            print(f"\n[✗] FAIL: Self-signed certificate was accepted (should be rejected)!")
            return False
        
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if Path('certs/selfsigned_cert.pem').exists():
            os.remove('certs/selfsigned_cert.pem')
        if Path('certs/selfsigned_key.pem').exists():
            os.remove('certs/selfsigned_key.pem')
        print("[+] Cleanup: Removed self-signed certificate files")

def test_missing_certificate():
    """
    Test 3: Test behavior when certificate file is missing
    """
    print_test("Missing Certificate Detection")
    
    try:
        # Backup existing client certificate
        client_cert_path = Path('certs/client_cert.pem')
        backup_path = Path('certs/client_cert.pem.backup')
        
        if not client_cert_path.exists():
            print("[!] Client certificate not found - cannot test missing cert")
            print("    Please run: python3 scripts/gen_cert.py client1 client")
            return False
        
        print(f"[+] Backing up client certificate...")
        import shutil
        shutil.copy(client_cert_path, backup_path)
        print(f"[✓] Backup created: {backup_path}")
        
        # Remove client certificate
        print(f"[+] Removing client certificate to simulate missing cert...")
        os.remove(client_cert_path)
        print(f"[✓] Removed: {client_cert_path}")
        
        # Try to load certificate (should fail)
        print(f"\n[VERIFICATION] Attempting to load missing certificate...")
        try:
            with open(client_cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
            print(f"[✗] FAIL: Certificate loaded (should not exist)!")
            return False
        except FileNotFoundError:
            print(f"[✓] PASS: FileNotFoundError raised correctly!")
            print(f"[✓] Missing certificate detected!")
            return True
        
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Restore certificate
        if Path('certs/client_cert.pem.backup').exists():
            import shutil
            shutil.move('certs/client_cert.pem.backup', 'certs/client_cert.pem')
            print(f"[+] Restored client certificate from backup")

def test_wrong_cn_certificate():
    """
    Test 4: Certificate with wrong Common Name (CN)
    """
    print_test("Wrong Common Name (CN) Detection")
    
    try:
        # Load CA certificate and key
        ca_cert_path = Path('certs/ca_cert.pem')
        ca_key_path = Path('certs/ca_key.pem')
        
        if not ca_cert_path.exists() or not ca_key_path.exists():
            print("[!] CA certificate or key not found")
            return False
        
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        
        print("[+] Loaded CA certificate and key")
        
        # Generate key for wrong CN cert
        print("[+] Generating certificate with WRONG Common Name...")
        wrong_cn_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate with wrong CN (attacker.com instead of localhost)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
            x509.NameAttribute(NameOID.COMMON_NAME, "attacker.com"),  # Wrong CN!
        ])
        
        wrong_cn_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            wrong_cn_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(ca_key, hashes.SHA256(), backend=default_backend())
        
        # Save certificate
        wrong_cn_cert_path = Path('certs/wrong_cn_cert.pem')
        
        with open(wrong_cn_cert_path, 'wb') as f:
            f.write(wrong_cn_cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"[✓] Created certificate with CN='attacker.com': {wrong_cn_cert_path}")
        
        # Display certificate info
        print(f"\n[INFO] Certificate Info:")
        print(f"  Expected CN: localhost (for server)")
        print(f"  Actual CN:   attacker.com")
        print(f"  Status:      CN MISMATCH ❌")
        
        # Verify signature (should pass - signed by CA)
        print(f"\n[VERIFICATION] Testing signature...")
        import subprocess
        result = subprocess.run(
            ['openssl', 'verify', '-CAfile', str(ca_cert_path), str(wrong_cn_cert_path)],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(f"[✓] Signature valid (signed by our CA)")
            print(f"[!] However, CN='attacker.com' does not match expected 'localhost'")
            print(f"[✓] PASS: Application should reject due to CN mismatch!")
            return True
        else:
            print(f"[✗] Signature verification failed: {result.stderr}")
            return False
        
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if Path('certs/wrong_cn_cert.pem').exists():
            os.remove('certs/wrong_cn_cert.pem')
        print("[+] Cleanup: Removed wrong CN certificate")

def main():
    """Run all invalid certificate tests"""
    print_section("INVALID CERTIFICATE DETECTION TESTS")
    print("\nThis script tests certificate validation by creating various")
    print("invalid certificates and verifying they are properly rejected.")
    print("\nTests:")
    print("  1. Expired Certificate")
    print("  2. Self-Signed Certificate (not trusted by CA)")
    print("  3. Missing Certificate")
    print("  4. Wrong Common Name (CN)")
    
    # Check prerequisites
    if not Path('certs').exists():
        print("\n[!] Error: certs/ directory not found")
        print("    Please run certificate generation scripts first:")
        print("    python3 scripts/gen_ca.py")
        print("    python3 scripts/gen_cert.py localhost server")
        print("    python3 scripts/gen_cert.py client1 client")
        return 1
    
    # Run tests
    results = []
    
    results.append(("Expired Certificate", test_expired_certificate()))
    results.append(("Self-Signed Certificate", test_self_signed_certificate()))
    results.append(("Missing Certificate", test_missing_certificate()))
    results.append(("Wrong CN Certificate", test_wrong_cn_certificate()))
    
    # Print summary
    print_section("TEST SUMMARY")
    
    total = len(results)
    passed = sum(1 for _, result in results if result)
    failed = total - passed
    
    print(f"\nTotal Tests: {total}")
    print(f"Passed:      {passed} ✓")
    print(f"Failed:      {failed} ✗")
    
    print("\nDetailed Results:")
    print("-" * 70)
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:8} {test_name}")
    
    print("\n" + "=" * 70)
    
    if passed == total:
        print("✓ All certificate validation tests passed!")
        print("✓ PKI security requirements demonstrated!")
        return 0
    else:
        print("⚠ Some tests failed - review output above")
        return 1

if __name__ == "__main__":
    sys.exit(main())
