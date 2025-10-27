import socket
import threading
from des_core import DES, pad_text, unpad_text

class DESDevice:
    def __init__(self, server_host='127.0.0.1', server_port=5555, device_name=None):
        self.server_host = server_host
        self.server_port = server_port
        self.device_name = device_name
        self.device_number = None
        self.des = DES()
        self.shared_key = None
        self.socket = None
        self.running = False
        
    def start(self):
        """Start the DES device"""
        print("="*70)
        print("              DES ENCRYPTED CHAT - DEVICE CLIENT")
        print("="*70)
        
        # Get device name
        if not self.device_name:
            self.device_name = input("\nEnter your name : ").strip() or "Anonymous"
        
        # Note: Key will be received from server after connection
        
        # Create socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            print(f"\n[{self.device_name}] Connecting to server {self.server_host}:{self.server_port}...")
            self.socket.connect((self.server_host, self.server_port))
            
            # Send device name to server IMMEDIATELY
            self.socket.send(self.device_name.encode('utf-8'))
            
            # Small delay to ensure server receives name
            import time
            time.sleep(0.1)
            
            print(f"[CONNECTED] Successfully connected to server")
            print("="*70)
            print("[INFO] Waiting for encryption key from server...")
            print("[INFO] Waiting for other device to connect...")
            print("="*70)
            
            self.running = True
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Handle sending in main thread
            self.send_messages()
            
        except ConnectionRefusedError:
            print("[ERROR] Connection refused. Make sure the server is running.")
        except Exception as e:
            print(f"[ERROR] Device error: {e}")
        finally:
            self.cleanup()


    def encrypt_message(self, message):
        """Encrypt message using DES"""
        padded = pad_text(message)
        ciphertext_blocks = []
        
        for i in range(0, len(padded), 8):
            block = padded[i:i+8]
            block_hex = self.des.text_to_hex(block)
            cipher_block = self.des.encrypt(block_hex, self.shared_key, verbose=False)
            ciphertext_blocks.append(cipher_block)
        
        return ''.join(ciphertext_blocks)
    
    def decrypt_message(self, ciphertext_hex):
        """Decrypt message using DES"""
        plaintext_blocks = []
        
        for i in range(0, len(ciphertext_hex), 16):
            cipher_block = ciphertext_hex[i:i+16]
            plain_block_hex = self.des.decrypt(cipher_block, self.shared_key, verbose=False)
            plaintext_blocks.append(plain_block_hex)
        
        plaintext_full_hex = ''.join(plaintext_blocks)
        plaintext_text = self.des.hex_to_text(plaintext_full_hex)
        return unpad_text(plaintext_text)
    
    def receive_messages(self):
        """Receive and decrypt messages from server"""
        while self.running:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                
                if not data:
                    print("\n[DISCONNECTED] Server disconnected")
                    self.running = False
                    break
                
                # Check if receiving encryption key from server
                if data.startswith("KEY:"):
                    self.shared_key = data.split(":", 1)[1]
                    print(f"\n[KEY RECEIVED] Encryption key: {self.shared_key}")
                    print(f"[INFO] Both devices connected! You can now chat.")
                    print(f"[INFO] Type your message and press Enter to send")
                    print(f"[INFO] Type 'quit' to disconnect")
                    continue
                
                # Check if other device left
                if data.startswith("DEVICE_LEFT:"):
                    device_name = data.split(":", 1)[1]
                    print(f"\n[INFO] {device_name} has left the chat")
                    print(f"\n[{self.device_name}] ", end='', flush=True)
                    continue
                
                # Parse message: device_name|encrypted_message
                if "|" in data:
                    parts = data.split("|", 1)
                    sender_name = parts[0]
                    encrypted_msg = parts[1]
                    
                    # Decrypt message
                    decrypted_msg = self.decrypt_message(encrypted_msg)
                    
                    # Display in the format: 
                    # Encrypted Message from [Name]: HEX
                    # [Name]: message
                    print(f"\nEncrypted Message from {sender_name}: {encrypted_msg}")
                    print(f"[{sender_name}]: {decrypted_msg}")
                    print(f"\n[{self.device_name}] ", end='', flush=True)
                
            except Exception as e:
                if self.running:
                    print(f"\n[ERROR] Receive error: {e}")
                break
    
    def send_messages(self):
        """Send encrypted messages to server"""
        # Wait until we have the key from server
        while self.running and not self.shared_key:
            import time
            time.sleep(0.1)
        
        if not self.running:
            return
        
        print(f"\n[{self.device_name}] ", end='', flush=True)
        
        while self.running:
            try:
                message = input()
                
                if message.lower() == 'quit':
                    self.socket.send("QUIT".encode('utf-8'))
                    print("[INFO] Disconnecting...")
                    self.running = False
                    break
                
                if message.strip():
                    # Encrypt and send
                    encrypted_msg = self.encrypt_message(message)
                    self.socket.send(encrypted_msg.encode('utf-8'))
                    
                    # Show what we sent
                    print(f"Encrypted Message from {self.device_name}: {encrypted_msg}")
                    print(f"[{self.device_name}]: {message}")
                    print(f"\n[{self.device_name}] ", end='', flush=True)
                
            except Exception as e:
                if self.running:
                    print(f"\n[ERROR] Send error: {e}")
                break
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        if self.socket:
            self.socket.close()
        print(f"\n[{self.device_name}] Disconnected")
        print("="*70)


if __name__ == "__main__":
    import sys
    
    # Allow custom server address from command line
    if len(sys.argv) >= 2:
        server_host = sys.argv[1]
    else:
        server_host = input("Enter server IP (press Enter for localhost): ").strip() or '127.0.0.1'
    
    if len(sys.argv) >= 3:
        server_port = int(sys.argv[2])
    else:
        server_port = 5555
    
    device = DESDevice(server_host=server_host, server_port=server_port)

    device.start()
