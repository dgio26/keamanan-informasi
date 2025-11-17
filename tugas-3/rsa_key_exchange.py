import random
import math

class RSA:
    """Implementasi RSA untuk enkripsi/dekripsi DES key"""
    
    def __init__(self, key_size=512):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    
    @staticmethod
    def is_prime(n, k=5):
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    @staticmethod
    def generate_prime(bits):
        """Generate a random prime number with specified bit length"""
        while True:
            # Generate random odd number
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
            
            if RSA.is_prime(num):
                return num
    
    @staticmethod
    def gcd(a, b):
        """Greatest Common Divisor using Euclidean algorithm"""
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def extended_gcd(a, b):
        """Extended Euclidean Algorithm"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = RSA.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    @staticmethod
    def mod_inverse(e, phi):
        """Calculate modular multiplicative inverse"""
        gcd, x, _ = RSA.extended_gcd(e, phi)
        if gcd != 1:
            raise Exception('Modular inverse does not exist')
        return x % phi
    
    def generate_keypair(self):
        """Generate RSA public and private key pair"""
        print(f"[RSA] Generating {self.key_size}-bit RSA keys...")
        
        # Generate two distinct prime numbers
        p = self.generate_prime(self.key_size // 2)
        q = self.generate_prime(self.key_size // 2)
        
        while p == q:
            q = self.generate_prime(self.key_size // 2)
        
        # Calculate n and phi(n)
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Choose e (public exponent)
        e = 65537  # Common choice for e
        while self.gcd(e, phi) != 1:
            e = random.randrange(2, phi)
        
        # Calculate d (private exponent)
        d = self.mod_inverse(e, phi)
        
        # Public key: (e, n), Private key: (d, n)
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        print(f"[RSA] Key generation complete!")
        print(f"[RSA] Public Key (e, n): ({e}, {n})")
        print(f"[RSA] Key size: {n.bit_length()} bits")
        
        return self.public_key, self.private_key
    
    @staticmethod
    def encrypt(message, public_key):
        """Encrypt message using RSA public key"""
        e, n = public_key
        
        # Convert hex string to integer
        message_int = int(message, 16)
        
        # Check if message is smaller than n
        if message_int >= n:
            raise ValueError("Message too large for key size")
        
        # Encrypt: c = m^e mod n
        ciphertext = pow(message_int, e, n)
        
        return ciphertext
    
    @staticmethod
    def decrypt(ciphertext, private_key):
        """Decrypt ciphertext using RSA private key"""
        d, n = private_key
        
        # Decrypt: m = c^d mod n
        message_int = pow(ciphertext, d, n)
        
        # Convert back to hex string (16 characters for DES key)
        message_hex = format(message_int, '016X')
        
        return message_hex
    
    def encrypt_des_key(self, des_key_hex, public_key):
        """Encrypt DES key using RSA"""
        return self.encrypt(des_key_hex, public_key)
    
    def decrypt_des_key(self, encrypted_key, private_key):
        """Decrypt DES key using RSA"""
        return self.decrypt(encrypted_key, private_key)


def serialize_public_key(public_key):
    """Convert public key tuple to string for transmission"""
    e, n = public_key
    return f"{e}:{n}"


def deserialize_public_key(key_string):
    """Convert string back to public key tuple"""
    e, n = key_string.split(':')
    return (int(e), int(n))


if __name__ == "__main__":
    # Test RSA implementation
    print("="*70)
    print("Testing RSA Key Exchange Implementation")
    print("="*70)
    
    # Generate RSA keys
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keypair()
    
    # Test with a sample DES key
    des_key = "133457799BBCDFF1"
    print(f"\n[TEST] Original DES Key: {des_key}")
    
    # Encrypt DES key
    encrypted = rsa.encrypt_des_key(des_key, public_key)
    print(f"[TEST] Encrypted DES Key: {encrypted}")
    
    # Decrypt DES key
    decrypted = rsa.decrypt_des_key(encrypted, private_key)
    print(f"[TEST] Decrypted DES Key: {decrypted}")
    
    # Verify
    if des_key == decrypted:
        print("\n[SUCCESS] RSA encryption/decryption working correctly!")
    else:
        print("\n[ERROR] Decryption failed!")
    
    print("="*70)