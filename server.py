#!/usr/bin/env python3
"""
Secure Chat Server
"""
import socket
import json
import base64
import pymysql
from dotenv import load_dotenv
import os
import sys
from datetime import datetime
import time
import hashlib  # FIX: needed for sha256 in generate_session_receipt

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from crypto_utils import *

load_dotenv()

class SecureChatServer:
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5000))
        
        # Load server certificate and private key
        self.cert = load_certificate('certs/server_cert.pem')
        self.private_key = load_private_key('certs/server_key.pem')
        self.ca_cert = load_certificate('certs/ca_cert.pem')
        
        # Session state
        self.client_cert = None
        self.session_key = None
        self.username = None
        self.seqno = 0
        self.client_seqno = 0
        self.transcript = []
        
        # Database connection
        self.db = None
        
    def connect_db(self):
        """Connect to MySQL database"""
        self.db = pymysql.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'securechat'),
            cursorclass=pymysql.cursors.DictCursor
        )
        
    def send_msg(self, conn, msg_dict):
        """Send JSON message"""
        msg_json = json.dumps(msg_dict)
        conn.sendall(msg_json.encode() + b'\n')
        
    def recv_msg(self, conn):
        """Receive JSON message"""
        data = b''
        while b'\n' not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode().strip())
        
    def handle_client(self, conn, addr):
        """Handle client connection"""
        print(f"[+] Connection from {addr}")
        
        try:
            # 1. Certificate exchange and verification
            client_hello = self.recv_msg(conn)
            if not client_hello:
                print("[-] No hello message received")
                return

            if client_hello.get('type') != 'hello':
                print("[-] Invalid hello message")
                return
                
            # Load client certificate
            client_cert_pem = client_hello['client_cert']
            self.client_cert = x509.load_pem_x509_certificate(
                client_cert_pem.encode(),
                default_backend()
            )
            
            # Verify client certificate
            valid, error = verify_certificate(self.client_cert, self.ca_cert)
            if not valid:
                print(f"[-] BAD_CERT: {error}")
                self.send_msg(conn, {"type": "error", "message": "BAD_CERT"})
                return
                
            print("[+] Client certificate verified")
            
            # Send server hello with certificate
            server_cert_pem = self.cert.public_bytes(
                serialization.Encoding.PEM
            ).decode()
            
            self.send_msg(conn, {
                "type": "server_hello",
                "server_cert": server_cert_pem,
                "nonce": base64.b64encode(os.urandom(16)).decode()
            })
            
            # 2. Initial DH exchange for registration/login encryption
            dh_client = self.recv_msg(conn)
            if not dh_client:
                print("[-] No DH client message")
                return

            p = dh_client['p']
            g = dh_client['g']
            A = dh_client['A']
            
            # Generate server DH keypair
            b, B = dh_generate_keypair(p, g)
            self.send_msg(conn, {"type": "dh_server", "B": B})
            
            # Compute shared secret and derive initial key
            Ks = dh_compute_shared_secret(A, b, p)
            initial_key = derive_aes_key(Ks)
            
            # 3. Handle registration or login
            auth_msg = self.recv_msg(conn)
            if not auth_msg:
                print("[-] No auth message received")
                return
            
            # Decrypt auth message
            iv = base64.b64decode(auth_msg['iv'])
            ct = base64.b64decode(auth_msg['ct'])
            plaintext = aes_decrypt(iv, ct, initial_key)
            auth_data = json.loads(plaintext.decode())
            
            if auth_data['type'] == 'register':
                success = self.handle_registration(auth_data)
            elif auth_data['type'] == 'login':
                success = self.handle_login(auth_data)
            else:
                success = False
                
            if not success:
                self.send_msg(conn, {"type": "auth_response", "success": False})
                return
                
            self.send_msg(conn, {"type": "auth_response", "success": True})
            
            # 4. New DH exchange for chat session key
            dh_client2 = self.recv_msg(conn)
            if not dh_client2:
                print("[-] No second DH client message")
                return

            p2 = dh_client2['p']
            g2 = dh_client2['g']
            A2 = dh_client2['A']
            
            b2, B2 = dh_generate_keypair(p2, g2)
            self.send_msg(conn, {"type": "dh_server", "B": B2})
            
            Ks2 = dh_compute_shared_secret(A2, b2, p2)
            self.session_key = derive_aes_key(Ks2)
            
            print(f"[+] Chat session established for user: {self.username}")
            
            # 5. Chat loop
            self.chat_loop(conn)
            
            # 6. Generate and send session receipt
            self.generate_session_receipt(conn)
            
        except Exception as e:
            print(f"[-] Error handling client: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            
    def handle_registration(self, auth_data):
        """Handle user registration"""
        email = auth_data['email']
        username = auth_data['username']
        password = auth_data['pwd']
        
        try:
            with self.db.cursor() as cursor:
                # Check if user exists
                cursor.execute(
                    "SELECT * FROM users WHERE email = %s OR username = %s",
                    (email, username)
                )
                if cursor.fetchone():
                    print("[-] Registration failed: user already exists")
                    return False
                
                # Generate salt and hash password
                salt = generate_salt()
                pwd_hash = hash_password(password, salt)
                
                # Insert user
                cursor.execute(
                    "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                    (email, username, salt, pwd_hash)
                )
                self.db.commit()
                
                self.username = username
                print(f"[+] User registered: {username}")
                return True
                
        except Exception as e:
            print(f"[-] Registration error: {e}")
            return False
            
    def handle_login(self, auth_data):
        """Handle user login"""
        email = auth_data['email']
        password = auth_data['pwd']
        
        try:
            with self.db.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()
                
                if not user:
                    print("[-] Login failed: user not found")
                    return False
                
                # Verify password
                pwd_hash = hash_password(password, user['salt'])
                if pwd_hash != user['pwd_hash']:
                    print("[-] Login failed: incorrect password")
                    return False
                
                self.username = user['username']
                print(f"[+] User logged in: {self.username}")
                return True
                
        except Exception as e:
            print(f"[-] Login error: {e}")
            return False
            
    def chat_loop(self, conn):
        """Main chat message loop"""
        print("[+] Entering chat mode. Type 'exit' to quit.")
        
        while True:
            # Receive message from client
            try:
                msg = self.recv_msg(conn)
                if not msg:
                    print("[-] Client disconnected")
                    break
                    
                if msg['type'] == 'exit':
                    print("[+] Client requested exit")
                    break
                    
                if msg['type'] == 'msg':
                    # Verify and decrypt message
                    if not self.verify_and_decrypt_message(msg, 'client'):
                        self.send_msg(conn, {
                            "type": "error",
                            "message": "SIG_FAIL or REPLAY"
                        })
                        continue
                    
                    # Get server response
                    response = input(f"{self.username} > ")
                    if response.lower() == 'exit':
                        self.send_msg(conn, {"type": "exit"})
                        break
                    
                    # Encrypt and sign response
                    encrypted_msg = self.encrypt_and_sign_message(response)
                    self.send_msg(conn, encrypted_msg)
                    
            except Exception as e:
                print(f"[-] Chat error: {e}")
                break
                
    def verify_and_decrypt_message(self, msg, sender):
        """Verify signature and decrypt message"""
        seqno = msg['seqno']
        ts = msg['ts']
        ct = base64.b64decode(msg['ct'])
        sig = base64.b64decode(msg['sig'])
        
        # Check sequence number (replay protection)
        if seqno <= self.client_seqno:
            print(f"[-] REPLAY: seqno {seqno} <= {self.client_seqno}")
            return False
        
        # Verify signature
        h = sha256_hash(str(seqno).encode(), str(ts).encode(), ct)
        if not rsa_verify(h, sig, self.client_cert.public_key()):
            print("[-] SIG_FAIL: Invalid signature")
            return False
        
        # Decrypt
        iv = ct[:16]
        ciphertext = ct[16:]
        plaintext = aes_decrypt(iv, ciphertext, self.session_key)
        
        # Update sequence number
        self.client_seqno = seqno
        
        # Add to transcript
        cert_fp = get_cert_fingerprint(self.client_cert)
        self.transcript.append(
            f"{seqno}|{ts}|{base64.b64encode(ct).decode()}|"
            f"{base64.b64encode(sig).decode()}|{cert_fp}"
        )
        
        print(f"Client: {plaintext.decode()}")
        return True
        
    def encrypt_and_sign_message(self, message):
        """Encrypt and sign outgoing message"""
        self.seqno += 1
        ts = int(time.time() * 1000)
        
        # Encrypt
        iv, ct = aes_encrypt(message.encode(), self.session_key)
        full_ct = iv + ct
        
        # Sign
        h = sha256_hash(str(self.seqno).encode(), str(ts).encode(), full_ct)
        sig = rsa_sign(h, self.private_key)
        
        # Add to transcript
        cert_fp = get_cert_fingerprint(self.cert)
        self.transcript.append(
            f"{self.seqno}|{ts}|{base64.b64encode(full_ct).decode()}|"
            f"{base64.b64encode(sig).decode()}|{cert_fp}"
        )
        
        return {
            "type": "msg",
            "seqno": self.seqno,
            "ts": ts,
            "ct": base64.b64encode(full_ct).decode(),
            "sig": base64.b64encode(sig).decode()
        }
        
    def generate_session_receipt(self, conn):
        """Generate and send session receipt for non-repudiation"""
        if not self.transcript:
            print("[-] No transcript to save")
            return
            
        try:
            # Compute transcript hash
            transcript_data = "\n".join(self.transcript)
            transcript_hash = hashlib.sha256(transcript_data.encode()).hexdigest()
            
            # Sign transcript hash
            sig = rsa_sign(transcript_hash.encode(), self.private_key)
            
            receipt = {
                "type": "receipt",
                "peer": "server",
                "first_seq": 1,
                "last_seq": self.seqno,
                "transcript_sha256": transcript_hash,
                "sig": base64.b64encode(sig).decode()
            }
            
            # Save transcript and receipt
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            transcript_file = f"server_transcript_{timestamp}.txt"
            receipt_file = f"server_receipt_{timestamp}.json"
            
            transcript_path = os.path.abspath(transcript_file)
            receipt_path = os.path.abspath(receipt_file)
            
            # Write transcript file
            with open(transcript_path, 'w') as f:
                f.write(transcript_data)
            print(f"[+] Transcript saved: {transcript_path}")
            
            # Write receipt file
            with open(receipt_path, 'w') as f:
                json.dump(receipt, f, indent=2)
            print(f"[+] Receipt saved: {receipt_path}")
            
            # Send receipt to client
            self.send_msg(conn, receipt)
            
        except Exception as e:
            print(f"[-] Error saving transcript/receipt: {e}")
            import traceback
            traceback.print_exc()
        
    def start(self):
        """Start the server"""
        self.connect_db()
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        
        try:
            while True:
                conn, addr = server_socket.accept()
                self.handle_client(conn, addr)
                # Reset state for next client
                self.__init__()
                self.connect_db()
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            server_socket.close()
            if self.db:
                self.db.close()

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()

