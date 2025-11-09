# SECURE CHAT SYSTEM - QUICK REFERENCE GUIDE

## File Structure
```
securechat/
├── scripts/
│   ├── gen_ca.py          # Generate CA
│   ├── gen_cert.py        # Generate certificates
│   └── setup_db.py        # Setup database
├── src/
│   ├── crypto_utils.py    # Crypto functions
│   ├── server.py          # Server
│   └── client.py          # Client
├── certs/                 # Certificates (generated)
├── requirements.txt
├── .env.example
├── .env                   # Your config (create from .env.example)
├── .gitignore
├── setup.sh              # Automated setup
└── README.md
```

## Quick Setup (3 Minutes)

```bash
# 1. Install dependencies
pip install cryptography PyMySQL python-dotenv

# 2. Setup config
cp .env.example .env
nano .env  # Edit MySQL password

# 3. Generate certificates
python3 gen_ca.py
python3 gen_cert.py localhost server
python3 gen_cert.py client1 client

# 4. Setup database
python3 setup_db.py

# 5. Run server
python3 server.py

# 6. Run client (new terminal)
python3 client.py
```

## Common Commands

### Certificate Operations
```bash
# Generate CA
python3 gen_ca.py

# Generate server cert
python3 gen_cert.py localhost server

# Generate client cert
python3 gen_cert.py client1 client

# View certificate
openssl x509 -in certs/server_cert.pem -text -noout

# Verify certificate chain
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
```

### Database Operations
```bash
# Setup database
python3 setup_db.py

# Connect to MySQL
mysql -u root -p

# View users
mysql -u root -p -e "USE securechat; SELECT * FROM users;"

# Reset database
mysql -u root -p -e "DROP DATABASE securechat;"
python3 setup_db.py
```

### Running the Application
```bash
# Start server
python3 server.py

# Start client
python3 client.py

# Kill server (if stuck)
sudo kill -9 $(sudo lsof -t -i:5000)
```

## Protocol Flow Summary

1. **Hello Exchange** → Certificates exchanged
2. **Certificate Verification** → Both parties verify certs
3. **DH Key Exchange #1** → For login/register encryption
4. **Authentication** → Register or login (encrypted)
5. **DH Key Exchange #2** → For chat session
6. **Encrypted Chat** → Messages encrypted + signed
7. **Session Receipt** → Non-repudiation proof

## Message Format

### Chat Message
```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1704892800000,
  "ct": "base64_encrypted_data",
  "sig": "base64_signature"
}
```

### Session Receipt
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "hash",
  "sig": "signature"
}
```

## Security Features

| Feature | Implementation |
|---------|---------------|
| **Confidentiality** | AES-128 CBC |
| **Integrity** | SHA-256 hash |
| **Authenticity** | RSA signatures + X.509 |
| **Non-Repudiation** | Signed transcripts |
| **Replay Protection** | Sequence numbers |
| **Key Exchange** | Diffie-Hellman |
| **Password Storage** | Salted SHA-256 |

## Testing Checklist

- [ ] Normal registration and login
- [ ] Encrypted chat messages
- [ ] Wireshark shows no plaintext
- [ ] Invalid certificate rejected
- [ ] Expired certificate rejected
- [ ] Tampering detected (SIG_FAIL)
- [ ] Replay attack detected
- [ ] Session receipt generated
- [ ] Transcript saved
- [ ] Offline verification works

## Wireshark Filters

```
# All traffic on port 5000
tcp.port == 5000

# Only chat messages
tcp.port == 5000 && tcp.len > 0

# Filter by IP
ip.addr == 127.0.0.1 && tcp.port == 5000
```

## Troubleshooting

### "Connection refused"
- Server not running → Start server first
- Wrong port → Check .env file

### "Certificate verification failed"
- Expired cert → Regenerate certificates
- Wrong CA → Use correct CA certificate

### "Authentication failed"
- Wrong password → Check credentials
- Database issue → Verify MySQL running

### "Module not found"
- Missing deps → `pip install -r requirements.txt`
- Wrong directory → Ensure crypto_utils.py in same dir

### "Database connection error"
- MySQL not running → `sudo systemctl start mysql`
- Wrong password → Check .env file
- No permissions → Grant MySQL user permissions

## Important Files

### Never Commit (in .gitignore)
- `.env` (contains passwords)
- `certs/*.pem` (private keys)
- `*transcript*.txt` (session data)
- `*receipt*.json` (session data)

### Always Commit
- Source code (`.py` files)
- `.env.example` (template)
- `requirements.txt`
- `README.md`
- `.gitignore`

## Performance Notes

- Certificate generation: ~1-2 seconds
- DH key exchange: ~0.5 seconds
- AES encryption: <1ms per message
- RSA signature: ~2-5ms per message
- Database query: ~10-50ms

## Security Warnings

⚠️ **This is an educational implementation**

For production:
- Use TLS/SSL
- Implement certificate revocation
- Add rate limiting
- Use hardware security modules
- Implement proper key rotation
- Add input validation
- Use prepared SQL statements
- Implement secure random number generation
- Add logging and monitoring

## Assignment Requirements Checklist

- [x] PKI setup (CA + certificates)
- [x] Certificate validation
- [x] Registration & Login
- [x] Salted password hashing
- [x] Diffie-Hellman key exchange
- [x] AES-128 encryption (CBC + PKCS#7)
- [x] RSA signatures
- [x] SHA-256 hashing
- [x] Replay protection
- [x] Session transcripts
- [x] Session receipts
- [x] Non-repudiation
- [x] MySQL database
- [x] GitHub repository
- [x] README documentation
- [x] Testing evidence

## Grading Criteria (100 points + 5 bonus)

- GitHub Workflow (20%)
- PKI Setup (20%)
- Registration/Login (20%)
- Encrypted Chat (20%)
- Integrity/Auth/Non-repudiation (10%)
- Testing (10%)

## Useful Resources

- Python Cryptography: https://cryptography.io/
- SEED PKI Lab: https://seedsecuritylabs.org/
- OpenSSL Commands: https://www.openssl.org/docs/
- MySQL Python: https://pymysql.readthedocs.io/

## Contact & Support

For issues:
1. Check README.md
2. Check this quick reference
3. Review assignment PDF
4. Check GitHub issues
5. Contact instructor

---
Last Updated: 2025-01-10
Version: 1.0
