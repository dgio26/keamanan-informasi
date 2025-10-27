import socket
import threading
from des_core import DES, pad_text, unpad_text, string_to_hex_key, generate_random_key

class DESCentralServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.des = DES()
        self.shared_key = None
        self.server_socket = None
        self.devices = []  # List to store connected devices
        self.device_lock = threading.Lock()
        self.running = False
        
    def start(self):
        """Start the DES central server"""
        print("="*70)
        print("              DES ENCRYPTED CHAT - CENTRAL SERVER")
        print("="*70)
        
        # Get or generate shared key
        self.shared_key = self.setup_key()
        
        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(2)  # Allow 2 connections
            print(f"\n[SERVER] Listening on {self.host}:{self.port}")
            print("[SERVER] Waiting for 2 devices to connect...")
            print("="*70)
            
            self.running = True
            
            # Accept connections in a loop
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Keep server running
            while self.running:
                pass
            
        except Exception as e:
            print(f"[ERROR] Server error: {e}")
        finally:
            self.cleanup()
    
    def setup_key(self):
        """Setup shared encryption key"""
        print("\n[KEY SETUP]")
        print("-"*70)
        print("Enter shared key (all devices must use this key)")
        print("Press Enter to auto-generate key")
        print("Examples: mykey123, password, 133457799BBCDFF1")
        print("-"*70)
        
        key_input = input("Shared Key: ").strip()
        
        if not key_input:
            key = generate_random_key()
            print(f"\n[KEY] Auto-generated: {key}")
            print("[IMPORTANT] Share this key with both devices!")
        elif len(key_input) == 16 and all(c in '0123456789ABCDEFabcdef' for c in key_input):
            key = key_input.upper()
            print(f"[KEY] Using hex key: {key}")
        else:
            key = string_to_hex_key(key_input)
            print(f"[KEY] Converted '{key_input}' → {key}")
        
        return key
    
    def accept_connections(self):
        """Accept device connections"""
        device_number = 1
        while self.running and device_number <= 2:
            try:
                client_socket, addr = self.server_socket.accept()
                
                # Receive device name from client FIRST
                try:
                    device_name = client_socket.recv(1024).decode('utf-8').strip()
                    if not device_name:
                        device_name = f"Device {device_number}"
                except:
                    device_name = f"Device {device_number}"
                
                device_info = {
                    'socket': client_socket,
                    'address': addr,
                    'number': device_number,
                    'name': device_name
                }
                
                with self.device_lock:
                    self.devices.append(device_info)
                
                print(f"\n[CONNECTED] {device_info['name']} connected from {addr[0]}:{addr[1]}")
                
                # Start handling this device
                device_thread = threading.Thread(target=self.handle_device, args=(device_info,))
                device_thread.daemon = True
                device_thread.start()
                
                device_number += 1
                
                if device_number > 2:
                    print("\n[INFO] Both devices connected! Chat is now active.")
                    print("="*70)
                    
                    # Send the shared key to both devices
                    with self.device_lock:
                        for device in self.devices:
                            try:
                                device['socket'].send(f"KEY:{self.shared_key}".encode('utf-8'))
                            except:
                                pass
                
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Accept error: {e}")
                break
    
    def handle_device(self, device_info):
        """Handle messages from a device"""
        while self.running:
            try:
                encrypted_msg = device_info['socket'].recv(4096).decode('utf-8')
                
                if not encrypted_msg:
                    print(f"\n[DISCONNECTED] {device_info['name']} disconnected")
                    self.remove_device(device_info)
                    break
                
                if encrypted_msg == "QUIT":
                    print(f"\n[DISCONNECTED] {device_info['name']} has left the chat")
                    self.remove_device(device_info)
                    # Notify other device
                    self.broadcast(f"DEVICE_LEFT:{device_info['name']}", device_info)
                    break
                
                # Decrypt the message
                decrypted_msg = self.decrypt_message(encrypted_msg)
                
                # Show on server console
                print(f"Encrypted Message from {device_info['name']}: {encrypted_msg}")
                print(f"[{device_info['name']}]: {decrypted_msg}\n")
                
                # Forward to other device with device name
                message_data = f"{device_info['name']}|{encrypted_msg}"
                self.broadcast(message_data, device_info)
                
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Error handling {device_info['name']}: {e}")
                self.remove_device(device_info)
                break
    
    def broadcast(self, message, sender_device):
        """Send message to all devices except sender"""
        with self.device_lock:
            for device in self.devices:
                if device['name'] != sender_device['name']:
                    try:
                        device['socket'].send(message.encode('utf-8'))
                    except:
                        pass
    
    def remove_device(self, device_info):
        """Remove device from list"""
        with self.device_lock:
            if device_info in self.devices:
                self.devices.remove(device_info)
                try:
                    device_info['socket'].close()
                except:
                    pass
    
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
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        
        with self.device_lock:
            for device in self.devices:
                try:
                    device['socket'].close()
                except:
                    pass
            self.devices.clear()
        
        if self.server_socket:
            self.server_socket.close()
        
        print("\n[SERVER] Closed")
        print("="*70)


if __name__ == "__main__":
    server = DESCentralServer(host='0.0.0.0', port=5555)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        server.cleanup()