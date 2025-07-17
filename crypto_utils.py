from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256, SHA512, SHA3_512
from Crypto.Signature import pkcs1_15, DSS
import os
import base64
import secrets
import hmac

class SymmetricCrypto:
    """Handles symmetric encryption operations"""
    
    @staticmethod
    def encrypt_aes_cbc(data: bytes, password: str) -> bytes:
        """AES-CBC with HMAC authentication"""
        salt = get_random_bytes(16)
        iv = get_random_bytes(16)
        
        # Derive keys (64 bytes: 32 for encryption, 32 for HMAC)
        key_material = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=64,
            count=100000,
            hmac_hash_module=SHA512
        )
        enc_key, auth_key = key_material[:32], key_material[32:]
        
        # Pad data
        pad_len = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_len] * pad_len)
        
        # Encrypt
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_data)
        
        # Generate authentication tag
        hmac_obj = HMAC.new(auth_key, digestmod=SHA256)
        hmac_obj.update(salt + iv + ciphertext)
        tag = hmac_obj.digest()
        
        return salt + iv + tag + ciphertext

    @staticmethod
    def decrypt_aes_cbc(encrypted_data: bytes, password: str) -> bytes:
        """Decrypt AES-CBC with HMAC"""
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        tag = encrypted_data[32:64]
        ciphertext = encrypted_data[64:]
        
        # Derive keys
        key_material = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=64,
            count=100000,
            hmac_hash_module=SHA512
        )
        enc_key, auth_key = key_material[:32], key_material[32:]
        
        # Verify authentication
        hmac_obj = HMAC.new(auth_key, digestmod=SHA256)
        hmac_obj.update(salt + iv + ciphertext)
        try:
            hmac_obj.verify(tag)
        except ValueError:
            raise ValueError("Authentication failed - wrong password or corrupted data")
        
        # Decrypt
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        
        # Validate and remove padding
        pad_len = padded_data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding length")
            
        if padded_data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Padding mismatch")
            
        return padded_data[:-pad_len]

    @staticmethod
    def encrypt_aes_gcm(data: bytes, password: str) -> bytes:
        """More efficient authenticated encryption (GCM mode)"""
        salt = get_random_bytes(16)
        nonce = get_random_bytes(12)  # 96-bit nonce for GCM
        
        # Key derivation
        key = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=32,
            count=100000,
            hmac_hash_module=SHA512
        )
        
        # Encrypt and authenticate
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        return salt + nonce + tag + ciphertext

    @staticmethod
    def decrypt_aes_gcm(encrypted_data: bytes, password: str) -> bytes:
        """Decrypt AES-GCM encrypted data"""
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        tag = encrypted_data[28:44]  # 16-byte tag
        ciphertext = encrypted_data[44:]
        
        # Key derivation
        key = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=32,
            count=100000,
            hmac_hash_module=SHA512
        )
        
        # Decrypt and verify
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            raise ValueError("Authentication failed - invalid data or password") from e

class AsymmetricCrypto:
    """Handles public-key cryptography operations"""
    
    @staticmethod
    def generate_rsa_keypair(bits=2048):
        """Generate RSA key pair"""
        key = RSA.generate(bits)
        return {
            'private': key.export_key(),
            'public': key.publickey().export_key()
        }
    
    @staticmethod
    def generate_ecc_keypair(curve='P-256'):
        """Generate ECC key pair"""
        key = ECC.generate(curve=curve)
        return {
            'private': key.export_key(format='PEM'),
            'public': key.public_key().export_key(format='PEM')
        }
    
    @staticmethod
    def rsa_encrypt(message: bytes, public_key: bytes) -> bytes:
        """RSA encryption with OAEP padding"""
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        return cipher.encrypt(message)
    
    @staticmethod
    def rsa_decrypt(ciphertext: bytes, private_key: bytes) -> bytes:
        """RSA decryption with OAEP padding"""
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        return cipher.decrypt(ciphertext)
    
    @staticmethod
    def ecdsa_sign(data: bytes, private_key: bytes) -> bytes:
        """Create ECDSA signature"""
        key = ECC.import_key(private_key)
        h = SHA256.new(data)
        signer = DSS.new(key, 'fips-186-3')
        return signer.sign(h)
    
    @staticmethod
    def ecdsa_verify(data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify ECDSA signature"""
        key = ECC.import_key(public_key)
        h = SHA256.new(data)
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False

class KeyDerivation:
    """Key derivation functions"""
    
    @staticmethod
    def pbkdf2_derive(password: str, salt: bytes, dkLen=32, count=100000, hmac_hash_module=SHA512) -> bytes:
        return PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=dkLen,
            count=count,
            hmac_hash_module=hmac_hash_module
        )
    
    @staticmethod
    def scrypt_derive(password: str, salt: bytes, dkLen=32, N=2**14, r=8, p=1) -> bytes:
        return scrypt(
            password.encode('utf-8'),
            salt,
            key_len=dkLen,
            N=N,
            r=r,
            p=p
        )

class HashingUtils:
    """Cryptographic hashing functions"""
    
    @staticmethod
    def sha256_hash(data: bytes) -> str:
        return SHA256.new(data).hexdigest()
    
    @staticmethod
    def sha512_hash(data: bytes) -> str:
        return SHA512.new(data).hexdigest()
    
    @staticmethod
    def sha3_512_hash(data: bytes) -> str:
        return SHA3_512.new(data).hexdigest()
    
    @staticmethod
    def file_checksum(file_path: str, algorithm='sha256') -> str:
        """Generate file checksum with progress support"""
        if algorithm == 'sha256':
            h = SHA256.new()
        elif algorithm == 'sha512':
            h = SHA512.new()
        elif algorithm == 'sha3_512':
            h = SHA3_512.new()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                h.update(chunk)
        return h.hexdigest()
    
    @staticmethod
    def hmac_digest(data: bytes, key: bytes, algorithm='sha256') -> bytes:
        """Generate HMAC digest"""
        if algorithm == 'sha256':
            h = HMAC.new(key, digestmod=SHA256)
        elif algorithm == 'sha512':
            h = HMAC.new(key, digestmod=SHA512)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        h.update(data)
        return h.digest()

class PasswordSecurity:
    """Password handling utilities without bcrypt"""
    
    @staticmethod
    def hash_password(password: str) -> bytes:
        """Secure password hashing using PBKDF2-HMAC-SHA512"""
        salt = get_random_bytes(32)
        iterations = 300_000  # High iteration count for security
        derived = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=64,
            count=iterations,
            hmac_hash_module=SHA512
        )
        # Store salt + derived key
        return salt + derived
    
    @staticmethod
    def verify_password(password: str, hashed: bytes) -> bool:
        """Verify password against stored hash"""
        if len(hashed) != 96:  # 32-byte salt + 64-byte key
            return False
            
        salt = hashed[:32]
        stored_key = hashed[32:]
        iterations = 300_000
        derived = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=64,
            count=iterations,
            hmac_hash_module=SHA512
        )
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_key, derived)
    
    @staticmethod
    def generate_secure_token(length=32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_otp(length=6) -> str:
        """Generate secure numeric OTP"""
        return ''.join(secrets.choice('0123456789') for _ in range(length))

class DigitalSignatures:
    """Digital signature operations"""
    
    @staticmethod
    def create_signature(data: bytes, private_key: bytes) -> bytes:
        """Create digital signature (auto-detects key type)"""
        if b'RSA' in private_key:
            key = RSA.import_key(private_key)
            h = SHA256.new(data)
            return pkcs1_15.new(key).sign(h)
        else:  # Assume ECC
            key = ECC.import_key(private_key)
            h = SHA256.new(data)
            return DSS.new(key, 'fips-186-3').sign(h)
    
    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify digital signature (auto-detects key type)"""
        if b'RSA' in public_key:
            key = RSA.import_key(public_key)
            h = SHA256.new(data)
            try:
                pkcs1_15.new(key).verify(h, signature)
                return True
            except (ValueError, TypeError):
                return False
        else:  # Assume ECC
            key = ECC.import_key(public_key)
            h = SHA256.new(data)
            verifier = DSS.new(key, 'fips-186-3')
            try:
                verifier.verify(h, signature)
                return True
            except ValueError:
                return False

class SecureDataUtils:
    """Utilities for secure data handling"""
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks"""
        return hmac.compare_digest(a, b)
    
    @staticmethod
    def secure_erase(data: bytes) -> None:
        """Overwrite bytes with random data before deletion"""
        if data:
            with memoryview(bytearray(data)) as m:
                m[:] = os.urandom(len(data))
    
    @staticmethod
    def zeroize_buffer(buffer: bytearray) -> None:
        """Securely zeroize a buffer"""
        for i in range(len(buffer)):
            buffer[i] = 0

# ==================== File Operations ====================
# ==================== File Operations ====================
def encrypt_file(input_path: str, output_path: str, password: str, mode='CBC'):
    """Encrypt a file with algorithm choice (CBC or GCM)"""
    try:
     
        with open(input_path, 'rb') as f:
            data = f.read()
        
        if mode == 'CBC':
            encrypted = SymmetricCrypto.encrypt_aes_cbc(data, password)
        elif mode == 'GCM':
            encrypted = SymmetricCrypto.encrypt_aes_gcm(data, password)
        else:
            raise ValueError(f"Unsupported encryption mode: {mode}")
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
        return True, "Encryption successful"
    
    except Exception as e:
        return False, f"Encryption failed: {str(e)}"

def decrypt_file(input_path: str, output_path: str, password: str, mode='CBC'):
    """Decrypt a file with algorithm choice (CBC or GCM)"""
    try:
     
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()
        
        if mode == 'CBC':
            decrypted = SymmetricCrypto.decrypt_aes_cbc(encrypted_data, password)
        elif mode == 'GCM':
            decrypted = SymmetricCrypto.decrypt_aes_gcm(encrypted_data, password)
        else:
            raise ValueError(f"Unsupported decryption mode: {mode}")
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        return True, "Decryption successful"
    
    except Exception as e:
        return False, f"Decryption failed: {str(e)}"

# ==================== Message Encryption/Decryption ====================
def encrypt_message(message: str, password: str, mode='CBC') -> str:
    """Encrypt a text message into a URL-safe base64 string"""
    data = message.encode('utf-8')
    if mode == 'CBC':
        encrypted_bytes = SymmetricCrypto.encrypt_aes_cbc(data, password)
    elif mode == 'GCM':
        encrypted_bytes = SymmetricCrypto.encrypt_aes_gcm(data, password)
    else:
        raise ValueError(f"Unsupported encryption mode: {mode}")
    return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

def decrypt_message(encrypted_b64: str, password: str, mode='CBC') -> str:
    """Decrypt a base64-encoded message back to original text"""
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_b64)
    if mode == 'CBC':
        decrypted_bytes = SymmetricCrypto.decrypt_aes_cbc(encrypted_bytes, password)
    elif mode == 'GCM':
        decrypted_bytes = SymmetricCrypto.decrypt_aes_gcm(encrypted_bytes, password)
    else:
        raise ValueError(f"Unsupported decryption mode: {mode}")
    return decrypted_bytes.decode('utf-8')

# ==================== Streaming Encryption ====================
class StreamingCrypto:
    """Streaming encryption for large files"""
    
    @staticmethod
    def encrypt_large_file(input_path: str, output_path: str, password: str, mode='CBC', chunk_size=64*1024):
        """Encrypt large files in chunks to conserve memory"""
        salt = get_random_bytes(16)
        
        # Derive key based on mode
        if mode == 'CBC':
            key_material = PBKDF2(
                password.encode('utf-8'),
                salt,
                dkLen=64,
                count=100000,
                hmac_hash_module=SHA512
            )
            enc_key, auth_key = key_material[:32], key_material[32:]
            iv = get_random_bytes(16)
            cipher = AES.new(enc_key, AES.MODE_CBC, iv)
            hmac_obj = HMAC.new(auth_key, digestmod=SHA256)
            hmac_obj.update(salt + iv)
            
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                fout.write(salt + iv)
                
                while chunk := fin.read(chunk_size):
                    if len(chunk) % 16 != 0:
                        pad_len = 16 - (len(chunk) % 16)
                        chunk += bytes([pad_len] * pad_len)
                    
                    encrypted_chunk = cipher.encrypt(chunk)
                    hmac_obj.update(encrypted_chunk)
                    fout.write(encrypted_chunk)
                
                fout.write(hmac_obj.digest())
                
        elif mode == 'GCM':
            key = PBKDF2(
                password.encode('utf-8'),
                salt,
                dkLen=32,
                count=100000,
                hmac_hash_module=SHA512
            )
            nonce = get_random_bytes(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
            
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                fout.write(salt + nonce)
                
                while chunk := fin.read(chunk_size):
                    encrypted_chunk = cipher.encrypt(chunk)
                    fout.write(encrypted_chunk)
                
                fout.write(cipher.digest())
                
        else:
            raise ValueError(f"Unsupported encryption mode: {mode}")

    @staticmethod
    def decrypt_large_file(input_path: str, output_path: str, password: str, mode='CBC', chunk_size=64*1024):
        """Decrypt large files in chunks"""
        with open(input_path, 'rb') as fin:
            salt = fin.read(16)
            
            if mode == 'CBC':
                iv = fin.read(16)
                # Derive keys
                key_material = PBKDF2(
                    password.encode('utf-8'),
                    salt,
                    dkLen=64,
                    count=100000,
                    hmac_hash_module=SHA512
                )
                enc_key, auth_key = key_material[:32], key_material[32:]
                cipher = AES.new(enc_key, AES.MODE_CBC, iv)
                hmac_obj = HMAC.new(auth_key, digestmod=SHA256)
                hmac_obj.update(salt + iv)
                
                # Read file in chunks except last 32 bytes (HMAC)
                file_size = os.path.getsize(input_path)
                total_chunks = (file_size - 32 - 32) // chunk_size
                remaining = (file_size - 32 - 32) % chunk_size
                
                with open(output_path, 'wb') as fout:
                    for i in range(total_chunks):
                        chunk = fin.read(chunk_size)
                        hmac_obj.update(chunk)
                        decrypted = cipher.decrypt(chunk)
                        fout.write(decrypted)
                    
                    if remaining:
                        chunk = fin.read(remaining)
                        hmac_obj.update(chunk)
                        decrypted = cipher.decrypt(chunk)
                        fout.write(decrypted)
                    
                    # Verify HMAC
                    stored_tag = fin.read(32)
                    try:
                        hmac_obj.verify(stored_tag)
                    except ValueError:
                        os.remove(output_path)
                        raise ValueError("Authentication failed - file corrupted")
                    
            elif mode == 'GCM':
                nonce = fin.read(12)
                key = PBKDF2(
                    password.encode('utf-8'),
                    salt,
                    dkLen=32,
                    count=100000,
                    hmac_hash_module=SHA512
                )
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
                
                # Read file except last 16 bytes (tag)
                file_size = os.path.getsize(input_path)
                total_chunks = (file_size - 16 - 28) // chunk_size
                remaining = (file_size - 16 - 28) % chunk_size
                
                with open(output_path, 'wb') as fout:
                    for i in range(total_chunks):
                        chunk = fin.read(chunk_size)
                        decrypted = cipher.decrypt(chunk)
                        fout.write(decrypted)
                    
                    if remaining:
                        chunk = fin.read(remaining)
                        decrypted = cipher.decrypt(chunk)
                        fout.write(decrypted)
                    
                    # Verify tag
                    stored_tag = fin.read(16)
                    try:
                        cipher.verify(stored_tag)
                    except ValueError:
                        os.remove(output_path)
                        raise ValueError("Authentication failed - file corrupted")
                        
            else:
                raise ValueError(f"Unsupported decryption mode: {mode}")