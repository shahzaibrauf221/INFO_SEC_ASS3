#!/usr/bin/env python3
"""
Generate client/server certificates signed by CA
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import sys

def load_ca():
    """Load CA certificate and private key"""
    with open("certs/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open("certs/ca_key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    return ca_cert, ca_key

def generate_certificate(common_name, cert_type="server"):
    """Generate a certificate signed by CA"""
    ca_cert, ca_key = load_ca()
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
            x509.DNSName("localhost"),
        ]),
        critical=False,
    )
    
    # Sign certificate with CA
    cert = cert_builder.sign(ca_key, hashes.SHA256())
    
    # Write private key
    key_filename = f"certs/{cert_type}_key.pem"
    with open(key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate
    cert_filename = f"certs/{cert_type}_cert.pem"
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"✓ {cert_type.capitalize()} certificate generated successfully!")
    print(f"  - Private Key: {key_filename}")
    print(f"  - Certificate: {cert_filename}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python gen_cert.py <common_name> <server|client>")
        sys.exit(1)
    
    common_name = sys.argv[1]
    cert_type = sys.argv[2].lower()
    
    if cert_type not in ["server", "client"]:
        print("Error: cert_type must be 'server' or 'client'")
        sys.exit(1)
    
    generate_certificate(common_name, cert_type)
