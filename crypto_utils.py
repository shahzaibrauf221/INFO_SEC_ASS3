"""
Cryptographic utility functions for secure chat
"""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import hashlib
import secrets

def load_certificate(cert_path):
    """Load X.509 certificate from PEM file"""
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return cert

def load_private_key(key_path):
    """Load RSA private key from PEM file"""
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def verify_certificate(cert, ca_cert):
    """
    Verify certificate signature, validity period, and issuer
    Returns: (valid, error_message)
    """
    try:
        # Check if certificate is expired
        from datetime import datetime
        now = datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            return False, "Certificate expired or not yet valid"
        
        # Verify signature
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        
        # Verify issuer
        if cert.issuer != ca_cert.subject:
            return False, "Certificate not issued by trusted CA"
        
        return True, None
        
    except InvalidSignature:
        return False, "Invalid certificate signature"
    except Exception as e:
        return False, f"Certificate verification error: {str(e)}"

def generate_dh_parameters():
    """Generate Diffie-Hellman parameters (p, g)"""
    # Using a 2048-bit safe prime
    p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
    g = 2
    return p, g

def dh_generate_keypair(p, g):
    """Generate DH private and public keys"""
    private_key = secrets.randbelow(p - 2) + 1
    public_key = pow(g, private_key, p)
    return private_key, public_key

def dh_compute_shared_secret(other_public, my_private, p):
    """Compute DH shared secret"""
    shared_secret = pow(other_public, my_private, p)
    return shared_secret

def derive_aes_key(shared_secret):
    """Derive AES-128 key from shared secret using SHA-256"""
    # Convert shared secret to big-endian bytes
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    
    # Hash with SHA-256 and truncate to 16 bytes
    hash_obj = hashlib.sha256(secret_bytes)
    key = hash_obj.digest()[:16]
    return key

def aes_encrypt(plaintext, key):
    """
    Encrypt plaintext using AES-128 in CBC mode with PKCS#7 padding
    Returns: (iv, ciphertext)
    """
    # Generate random IV
    iv = os.urandom(16)
    
    # Apply PKCS#7 padding
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return iv, ciphertext

def aes_decrypt(iv, ciphertext, key):
    """
    Decrypt ciphertext using AES-128 in CBC mode and remove PKCS#7 padding
    Returns: plaintext
    """
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]
    
    return plaintext

def sha256_hash(*args):
    """Compute SHA-256 hash of concatenated arguments"""
    hash_obj = hashlib.sha256()
    for arg in args:
        if isinstance(arg, str):
            hash_obj.update(arg.encode())
        elif isinstance(arg, int):
            hash_obj.update(str(arg).encode())
        else:
            hash_obj.update(arg)
    return hash_obj.digest()

def rsa_sign(data, private_key):
    """Sign data using RSA private key"""
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def rsa_verify(data, signature, public_key):
    """
    Verify RSA signature
    Returns: True if valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

def generate_salt():
    """Generate 16-byte random salt"""
    return os.urandom(16)

def hash_password(password, salt):
    """Hash password with salt using SHA-256"""
    combined = salt + password.encode()
    return hashlib.sha256(combined).hexdigest()

def get_cert_fingerprint(cert):
    """Get SHA-256 fingerprint of certificate"""
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(cert_der).hexdigest()
