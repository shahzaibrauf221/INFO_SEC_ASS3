# INSTALLATION GUIDE - Secure Chat System

## 📦 Downloaded Files

You should have these files:

```
✓ requirements.txt          - Python dependencies
✓ .env.example             - Environment template
✓ .gitignore               - Git ignore rules
✓ gen_ca.py                - Generate CA script
✓ gen_cert.py              - Generate certificates script
✓ setup_db.py              - Database setup script
✓ crypto_utils.py          - Cryptographic utilities
✓ server.py                - Chat server
✓ client.py                - Chat client
✓ setup.sh                 - Automated setup script
✓ README.md                - Main documentation
✓ COMMANDS.txt             - All terminal commands
✓ QUICK_REFERENCE.md       - Quick reference guide
```

## 🚀 Quick Installation (5 Minutes)

### Step 1: Create Project Structure

```bash
# Create main directory
mkdir securechat
cd securechat

# Create subdirectories
mkdir scripts src certs

# Move files to correct locations
mv gen_ca.py gen_cert.py setup_db.py scripts/
mv crypto_utils.py server.py client.py src/
```

### Step 2: Install Python Dependencies

```bash
pip3 install cryptography>=41.0.0
pip3 install PyMySQL>=1.1.0
pip3 install python-dotenv>=1.0.0

# Or using requirements.txt
pip3 install -r requirements.txt
```

### Step 3: Configure Environment

```bash
# Create .env from template
cp .env.example .env

# Edit with your MySQL password
nano .env
```

Your .env should look like:
```
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_actual_password
DB_NAME=securechat
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
```

### Step 4: Generate Certificates

```bash
# Generate Root CA
python3 scripts/gen_ca.py

# Generate Server Certificate
python3 scripts/gen_cert.py localhost server

# Generate Client Certificate
python3 scripts/gen_cert.py client1 client
```

Expected output:
```
✓ Root CA generated successfully!
  - Private Key: certs/ca_key.pem
  - Certificate: certs/ca_cert.pem
  
✓ Server certificate generated successfully!
  - Private Key: certs/server_key.pem
  - Certificate: certs/server_cert.pem
  
✓ Client certificate generated successfully!
  - Private Key: certs/client_key.pem
  - Certificate: certs/client_cert.pem
```

### Step 5: Setup MySQL Database

```bash
# Make sure MySQL is running
sudo systemctl start mysql
sudo systemctl status mysql

# Run setup script
python3 scripts/setup_db.py
```

Expected output:
```
✓ Database setup completed successfully!
  - Database: securechat
  - Table: users
```

### Step 6: Run the Application

**Terminal 1 (Server):**
```bash
cd securechat
python3 src/server.py
```

**Terminal 2 (Client):**
```bash
cd securechat
python3 src/client.py
```

## 📁 Final Directory Structure

After installation, your directory should look like:

```
securechat/
├── scripts/
│   ├── gen_ca.py
│   ├── gen_cert.py
│   └── setup_db.py
├── src/
│   ├── crypto_utils.py
│   ├── server.py
│   └── client.py
├── certs/                      # Generated during setup
│   ├── ca_cert.pem
│   ├── ca_key.pem
│   ├── server_cert.pem
│   ├── server_key.pem
│   ├── client_cert.pem
│   └── client_key.pem
├── requirements.txt
├── .env.example
├── .env                        # You create this
├── .gitignore
├── setup.sh
├── README.md
├── COMMANDS.txt
└── QUICK_REFERENCE.md
```

## 🔧 Alternative: Automated Setup

Instead of manual steps, use the setup script:

```bash
chmod +x setup.sh
./setup.sh
```

This will automatically:
1. Check Python & MySQL installation
2. Install dependencies
3. Create .env file
4. Generate certificates
5. Setup database
6. Verify installation

## ✅ Verify Installation

```bash
# Check certificates exist
ls -la certs/

# Verify certificate chain
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem

# Check database
mysql -u root -p -e "USE securechat; SHOW TABLES;"

# Test Python imports
python3 -c "from src.crypto_utils import *; print('OK')"
```

All checks should pass with no errors.

## 🎯 First Run

1. **Start Server** (Terminal 1):
   ```bash
   python3 src/server.py
   ```
   You should see:
   ```
   [*] Server listening on 127.0.0.1:5000
   ```

2. **Start Client** (Terminal 2):
   ```bash
   python3 src/client.py
   ```
   You should see:
   ```
   [*] Connecting to 127.0.0.1:5000...
   [+] Server certificate verified
   Register (r) or Login (l)?
   ```

3. **Register a new user**:
   - Enter 'r'
   - Provide email, username, password
   - Start chatting!

## 🐛 Common Installation Issues

### Issue: "mysql: command not found"
**Solution:**
```bash
sudo apt-get update
sudo apt-get install mysql-server
```

### Issue: "No module named 'cryptography'"
**Solution:**
```bash
pip3 install cryptography
# or
pip3 install -r requirements.txt
```

### Issue: "Can't connect to MySQL server"
**Solution:**
```bash
sudo systemctl start mysql
sudo systemctl enable mysql
```

### Issue: "Access denied for user 'root'"
**Solution:**
Check your .env file has correct password:
```bash
nano .env
# Update DB_PASSWORD with your MySQL root password
```

### Issue: "ImportError: cannot import name 'load_certificate'"
**Solution:**
Make sure you're in the correct directory:
```bash
cd securechat
python3 src/server.py  # Not just server.py
```

### Issue: "Address already in use"
**Solution:**
Kill existing process on port 5000:
```bash
sudo kill -9 $(sudo lsof -t -i:5000)
```

## 📝 Post-Installation Steps

1. **Test the system:**
   - Register a user
   - Send messages
   - Verify encryption with Wireshark
   - Check transcript files are created

2. **Setup Git repository:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Secure Chat System"
   ```

3. **Read documentation:**
   - README.md - Complete documentation
   - QUICK_REFERENCE.md - Quick commands
   - COMMANDS.txt - All terminal commands

4. **Run tests:**
   - Certificate validation
   - Message encryption
   - Replay protection
   - Tampering detection

## 🎓 For Assignment Submission

1. **Fork the skeleton repository**
2. **Copy your files to the forked repo**
3. **Make at least 10 meaningful commits**
4. **Include these files:**
   - All source code
   - README.md with setup instructions
   - .env.example (NOT .env)
   - .gitignore
   - MySQL schema export

5. **Do NOT commit:**
   - .env (contains passwords)
   - certs/ (contains private keys)
   - transcript/receipt files

6. **Submit on GCR:**
   - GitHub repository ZIP
   - MySQL schema dump
   - README with GitHub link
   - Report document
   - Test report document

## 📞 Need Help?

1. Check README.md
2. Check QUICK_REFERENCE.md
3. Check COMMANDS.txt
4. Review assignment PDF
5. Check error messages carefully
6. Verify file locations and permissions

## 🎉 Success Indicators

You'll know installation is successful when:

✅ All certificates generated without errors
✅ Database created and users table exists
✅ Server starts and listens on port 5000
✅ Client connects and certificate verified
✅ Can register and login users
✅ Can send and receive encrypted messages
✅ Transcript and receipt files are created
✅ No plaintext visible in Wireshark

---

**Good luck with your assignment! 🚀**

For detailed usage, see README.md
For quick commands, see QUICK_REFERENCE.md
For all commands, see COMMANDS.txt
