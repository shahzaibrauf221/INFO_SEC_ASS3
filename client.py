#!/usr/bin/env python3
"""
Secure Chat Client
"""
import socket
import json
import base64
from dotenv import load_dotenv
import os
import sys
from datetime import datetime
import time

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from crypto_utils import *

load_dotenv()

class SecureChatClient:
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5000))
        
        # Load client certificate and private key
        self.cert = load_certificate('certs/client_cert.pem')
        self.private_key = load_private_key('certs/client_key.pem')
        self.ca_cert = load_certificate('certs/ca_cert.pem')
        
        # Session state
        self.server_cert = None
        self.session_key = None
        self.seqno = 0
        self.server_seqno = 0
        self.transcript = []
        self.sock = None
        
    def send_msg(self, msg_dict):
        """Send JSON message"""
        msg_json = json.dumps(msg_dict)
        self.sock.sendall(msg_json.encode() + b'\n')
        
    def recv_msg(self):
        """Receive JSON message"""
        data = b''
        while b'\n' not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode().strip())
        
    def connect(self):
        """Connect to server and establish secure session"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            print(f"[*] Connecting to {self.host}:{self.port}...")
            self.sock.connect((self.host, self.port))
            
            # 1. Send client hello with certificate
            client_cert_pem = self.cert.public_bytes(
                serialization.Encoding.PEM
            ).decode()
            
            self.send_msg({
                "type": "hello",
                "client_cert": client_cert_pem,
                "nonce": base64.b64encode(os.urandom(16)).decode()
            })
            
            # 2. Receive server hello and verify certificate
            server_hello = self.recv_msg()
            if not server_hello:
                print("[-] No response from server")
                return False

            if server_hello.get('type') == 'error':
                print(f"[-] Connection failed: {server_hello.get('message')}")
                return False
                
            server_cert_pem = server_hello['server_cert']
            self.server_cert = x509.load_pem_x509_certificate(
                server_cert_pem.encode(),
                default_backend()
            )
            
            valid, error = verify_certificate(self.server_cert, self.ca_cert)
            if not valid:
                print(f"[-] BAD_CERT: {error}")
                return False
                
            print("[+] Server certificate verified")
            
            # 3. Initial DH exchange for registration/login
            # FIX: use generate_dh_params()
            p, g = generate_dh_params()
            a, A = dh_generate_keypair(p, g)
            
            self.send_msg({
                "type": "dh_client",
                "p": p,
                "g": g,
                "A": A
            })
            
            dh_server = self.recv_msg()
            if not dh_server:
                print("[-] No DH response from server")
                return False

            B = dh_server['B']
            
            Ks = dh_compute_shared_secret(B, a, p)
            initial_key = derive_aes_key(Ks)
            
            # 4. Registration or Login
            choice = input("Register (r) or Login (l)? ").lower().strip()
            if choice == 'r':
                auth_data = self.get_registration_data()
            else:
                auth_data = self.get_login_data()
                
            # Encrypt auth data
            auth_json = json.dumps(auth_data)
            iv, ct = aes_encrypt(auth_json.encode(), initial_key)
            
            self.send_msg({
                "type": "auth",
                "iv": base64.b64encode(iv).decode(),
                "ct": base64.b64encode(ct).decode()
            })
            
            # Wait for auth response
            auth_response = self.recv_msg()
            if not auth_response:
                print("[-] No auth response from server")
                return False

            if not auth_response.get('success'):
                print("[-] Authentication failed")
                return False
                
            print("[+] Authentication successful")
            
            # 5. New DH exchange for chat session
            # FIX: use generate_dh_params()
            p2, g2 = generate_dh_params()
            a2, A2 = dh_generate_keypair(p2, g2)
            
            self.send_msg({
                "type": "dh_client",
                "p": p2,
                "g": g2,
                "A": A2
            })
            
            dh_server2 = self.recv_msg()
            if not dh_server2:
                print("[-] No second DH response from server")
                return False

            B2 = dh_server2['B']
            
            Ks2 = dh_compute_shared_secret(B2, a2, p2)
            self.session_key = derive_aes_key(Ks2)
            
            print("[+] Secure chat session established")
            return True
            
        except Exception as e:
            print(f"[-] Connection error: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    def get_registration_data(self):
        """Get registration information from user"""
        email = input("Email: ")
        username = input("Username: ")
        password = input("Password: ")
        
        return {
            "type": "register",
            "email": email,
            "username": username,
            "pwd": password
        }
        
    def get_login_data(self):
        """Get login information from user"""
        email = input("Email: ")
        password = input("Password: ")
        
        return {
            "type": "login",
            "email": email,
            "pwd": password,
            "nonce": base64.b64encode(os.urandom(16)).decode()
        }
        
    def chat(self):
        """Main chat loop"""
        print("\n[+] Chat session started. Type 'exit' to quit.\n")
        
        while True:
            # Get user input
            message = input("You > ")
            
            if message.lower() == 'exit':
                self.send_msg({"type": "exit"})
                break
                
            # Encrypt and sign message
            encrypted_msg = self.encrypt_and_sign_message(message)
            self.send_msg(encrypted_msg)
            
            # Receive response
            response = self.recv_msg()
            if not response:
                print("[-] Server disconnected")
                break
            
            if response['type'] == 'exit':
                print("[+] Server closed connection")
                break
                
            if response['type'] == 'error':
                print(f"[-] Error: {response['message']}")
                continue
                
            if response['type'] == 'msg':
                self.verify_and_decrypt_message(response)
                
        # Receive session receipt
        receipt = self.recv_msg()
        if receipt and receipt.get('type') == 'receipt':
            self.save_session_receipt(receipt)
            
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
        
    def verify_and_decrypt_message(self, msg):
        """Verify signature and decrypt message"""
        seqno = msg['seqno']
        ts = msg['ts']
        ct = base64.b64decode(msg['ct'])
        sig = base64.b64decode(msg['sig'])
        
        # Check sequence number (replay protection)
        if seqno <= self.server_seqno:
            print(f"[-] REPLAY: seqno {seqno} <= {self.server_seqno}")
            return False
        
        # Verify signature
        h = sha256_hash(str(seqno).encode(), str(ts).encode(), ct)
        if not rsa_verify(h, sig, self.server_cert.public_key()):
            print("[-] SIG_FAIL: Invalid signature")
            return False
        
        # Decrypt
        iv = ct[:16]
        ciphertext = ct[16:]
        plaintext = aes_decrypt(iv, ciphertext, self.session_key)
        
        # Update sequence number
        self.server_seqno = seqno
        
        # Add to transcript
        cert_fp = get_cert_fingerprint(self.server_cert)
        self.transcript.append(
            f"{seqno}|{ts}|{base64.b64encode(ct).decode()}|"
            f"{base64.b64encode(sig).decode()}|{cert_fp}"
        )
        
        print(f"Server: {plaintext.decode()}")
        return True
        
    def save_session_receipt(self, receipt):
        """Save session receipt and transcript"""
        if not self.transcript:
            print("[-] No transcript to save")
            return
            
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save transcript
            transcript_data = "\n".join(self.transcript)
            transcript_file = f"client_transcript_{timestamp}.txt"
            transcript_path = os.path.abspath(transcript_file)
            
            with open(transcript_path, 'w') as f:
                f.write(transcript_data)
            print(f"\n[+] Transcript saved: {transcript_path}")
            
            # Save receipt
            receipt_file = f"client_receipt_{timestamp}.json"
            receipt_path = os.path.abspath(receipt_file)
            
            with open(receipt_path, 'w') as f:
                json.dump(receipt, f, indent=2)
            print(f"[+] Receipt saved: {receipt_path}")
            
        except Exception as e:
            print(f"[-] Error saving transcript/receipt: {e}")
            import traceback
            traceback.print_exc()
        
    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()

if __name__ == "__main__":
    client = SecureChatClient()
    
    if client.connect():
        client.chat()
        
    client.close()

