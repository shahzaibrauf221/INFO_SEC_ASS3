# Secure Chat System

A console-based secure chat system implementing CIANR (Confidentiality, Integrity, Authenticity, Non-Repudiation) using cryptographic primitives.

## Features

- X.509 certificate-based authentication
- Diffie-Hellman key exchange
- AES-128 encryption (CBC mode with PKCS#7 padding)
- RSA digital signatures
- SHA-256 hashing
- Replay protection
- Session transcripts and receipts for non-repudiation

## Prerequisites

- Python 3.8+
- MySQL 5.7+
- Ubuntu/Linux environment

## Project Structure

```
securechat/
├── scripts/
│   ├── gen_ca.py          # Generate root CA
│   ├── gen_cert.py        # Generate certificates
│   └── setup_db.py        # Setup MySQL database
├── src/
│   ├── crypto_utils.py    # Cryptographic utilities
│   ├── server.py          # Chat server
│   └── client.py          # Chat client
├── certs/                 # Certificates (generated, not committed)
├── requirements.txt
├── .env.example
└── README.md
```

## Installation Steps

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Setup Environment Variables

```bash
cp .env.example .env
nano .env  # Edit with your MySQL credentials
```

Example .env file:
```
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=securechat
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
```

### 3. Generate Certificates

```bash
# Generate Root CA
python3 gen_ca.py

# Generate Server Certificate
python3 gen_cert.py localhost server

# Generate Client Certificate
python3 gen_cert.py client1 client
```

### 4. Setup Database

```bash
python3 setup_db.py
```

## Usage

### Start Server (Terminal 1)

```bash
python3 server.py
```

Expected output:
```
[*] Server listening on 127.0.0.1:5000
```

### Start Client (Terminal 2)

```bash
python3 client.py
```

The client will prompt you to:
1. Register (r) or Login (l)
2. Provide credentials
3. Start chatting

### Example Session

**Client Terminal:**
```
[*] Connecting to 127.0.0.1:5000...
[+] Server certificate verified
Register (r) or Login (l)? r
Email: user@example.com
Username: testuser
Password: ********
[+] Authentication successful
[+] Secure chat session established

[+] Chat session started. Type 'exit' to quit.

You > Hello Server!
Server: Hi Client!
You > exit

[+] Session transcript saved: client_transcript_20250110_123456.txt
[+] Session receipt saved: client_receipt_20250110_123456.json
```

**Server Terminal:**
```
[+] Connection from ('127.0.0.1', 54321)
[+] Client certificate verified
[+] User registered: testuser
[+] Chat session established for user: testuser
[+] Entering chat mode. Type 'exit' to quit.
Client: Hello Server!
testuser > Hi Client!
testuser > exit
[+] Session receipt generated: server_receipt_20250110_123456.json
```

## Testing

### 1. Wireshark Traffic Capture

```bash
# Start Wireshark
sudo wireshark

# Filter: tcp.port == 5000
# Verify that all payloads are encrypted (no plaintext visible)
```

### 2. Certificate Validation Tests

**Test expired certificate:**
```bash
# Modify gen_cert.py to create expired cert
# Expected: BAD_CERT error
```

**Test invalid CA:**
```bash
# Use certificate from different CA
# Expected: Certificate not issued by trusted CA
```

### 3. Tampering Test

Modify a message's ciphertext before sending:
```python
# In client.py or server.py, modify ct before sending
# Expected: SIG_FAIL: Invalid signature
```

### 4. Replay Attack Test

Resend an old message with same sequence number:
```python
# Resend a previous message
# Expected: REPLAY: seqno X <= Y
```

### 5. Certificate Inspection

```bash
# View CA certificate
openssl x509 -in certs/ca_cert.pem -text -noout

# View server certificate
openssl x509 -in certs/server_cert.pem -text -noout

# View client certificate
openssl x509 -in certs/client_cert.pem -text -noout

# Verify certificate chain
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem
```

## Security Features

### Confidentiality
- All messages encrypted with AES-128
- Session keys derived from Diffie-Hellman exchange
- No plaintext credentials transmitted

### Integrity
- SHA-256 hash of message metadata and ciphertext
- Any tampering invalidates the hash

### Authenticity
- RSA signatures on all messages
- X.509 certificate-based authentication
- Mutual certificate verification

### Non-Repudiation
- Append-only transcript of all messages
- Signed session receipts
- Offline verification possible

### Additional Protections
- Sequence numbers prevent replay attacks
- Timestamps for freshness
- PKCS#7 padding for block cipher
- Salted password hashing (SHA-256)

## File Outputs

After a chat session, the following files are generated:

### Transcript Files
- `client_transcript_YYYYMMDD_HHMMSS.txt`
- `server_transcript_YYYYMMDD_HHMMSS.txt`

Format: `seqno|timestamp|ciphertext(base64)|signature(base64)|cert_fingerprint`

### Receipt Files
- `client_receipt_YYYYMMDD_HHMMSS.json`
- `server_receipt_YYYYMMDD_HHMMSS.json`

Contains:
- Session metadata (first/last sequence numbers)
- SHA-256 hash of entire transcript
- RSA signature of transcript hash

## Offline Verification

To verify a session receipt:

```python
import json
import hashlib
import base64
from crypto_utils import *

# Load receipt
with open('client_receipt_YYYYMMDD_HHMMSS.json', 'r') as f:
    receipt = json.load(f)

# Load transcript
with open('client_transcript_YYYYMMDD_HHMMSS.txt', 'r') as f:
    transcript = f.read()

# Verify transcript hash
computed_hash = hashlib.sha256(transcript.encode()).hexdigest()
assert computed_hash == receipt['transcript_sha256']

# Verify signature
cert = load_certificate('certs/client_cert.pem')
sig = base64.b64decode(receipt['sig'])
assert rsa_verify(receipt['transcript_sha256'].encode(), sig, cert.public_key())

print("✓ Receipt verified successfully!")
```

## Troubleshooting

### Connection Refused
- Ensure server is running
- Check SERVER_HOST and SERVER_PORT in .env

### Database Connection Error
- Verify MySQL is running: `sudo systemctl status mysql`
- Check database credentials in .env
- Ensure database user has proper permissions

### Certificate Errors
- Regenerate certificates if expired
- Ensure certs/ directory contains all required files:
  - ca_cert.pem, ca_key.pem
  - server_cert.pem, server_key.pem
  - client_cert.pem, client_key.pem

### Import Errors
- Ensure crypto_utils.py is in the correct location
- Install all requirements: `pip install -r requirements.txt`

## Protocol Flow

1. **Certificate Exchange**: Client and server exchange X.509 certificates
2. **Mutual Verification**: Both parties verify certificates against CA
3. **Initial DH**: Temporary key for encrypting login/registration
4. **Authentication**: Register new user or login existing user
5. **Session DH**: New key exchange for chat session
6. **Encrypted Chat**: All messages encrypted and signed
7. **Session Receipt**: Generate cryptographic proof of conversation

## Academic Notes

This implementation demonstrates:
- Public Key Infrastructure (PKI) setup
- Hybrid encryption (asymmetric + symmetric)
- Digital signatures for authentication
- Key agreement protocols (Diffie-Hellman)
- Secure credential storage (salted hashing)
- Non-repudiation mechanisms

**Important**: This is an educational implementation. For production use, consider:
- TLS/SSL for transport security
- Proper key management and rotation
- Rate limiting and DoS protection
- Input validation and sanitization
- Secure random number generation
- Certificate revocation mechanisms

## License

Educational use only - FAST-NUCES Information Security Assignment

## References

- SEED Security Labs - Public Key Infrastructure
- RFC 5246 - TLS Protocol
- NIST Guidelines on Cryptographic Standards
- Python Cryptography Library Documentation
