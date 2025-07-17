from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256, SHA512
import os
import io

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 4033241824  # 4GB max file size
app.secret_key = os.urandom(24)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Please select a file', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('Please select a file', 'error')
            return redirect(request.url)
        
        password = request.form.get('password')
        if not password:
            flash('Please enter an encryption password', 'error')
            return redirect(request.url)
        
        try:
            original_data = file.read()
            filename = file.filename
        except Exception as e:
            flash(f'Error reading file: {str(e)}', 'error')
            return redirect(request.url)
        
        try:
            # Generate salt
            salt = get_random_bytes(16)
            
            # Derive TWO keys (encryption + authentication)
            key_material = PBKDF2(password, salt, dkLen=64, count=100000, hmac_hash_module=SHA512)
            enc_key = key_material[:32]   # First 32 bytes for AES
            auth_key = key_material[32:]   # Next 32 bytes for HMAC
            
            # Generate IV
            iv = get_random_bytes(16)
            cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
            
            # Pad data
            pad_len = 16 - (len(original_data) % 16)
            padded_data = original_data + bytes([pad_len]) * pad_len
            
            # Encrypt
            ciphertext = cipher.encrypt(padded_data)
            
            # Generate authentication tag
            hmac = HMAC.new(auth_key, digestmod=SHA256)
            hmac.update(salt + iv + ciphertext)
            tag = hmac.digest()
            
            # Create encrypted file
            encrypted_file = io.BytesIO()
            encrypted_file.write(salt)
            encrypted_file.write(iv)
            encrypted_file.write(tag)  # Include authentication tag
            encrypted_file.write(ciphertext)
            encrypted_file.seek(0)
            
            download_filename = f"encrypted_{filename}.safe"
            
            return send_file(
                encrypted_file,
                as_attachment=True,
                download_name=download_filename,
                mimetype='application/octet-stream'
            )
        except Exception as e:
            flash(f'Encryption failed: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Please select an encrypted file', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('Please select an encrypted file', 'error')
            return redirect(request.url)
        
        password = request.form.get('password')
        if not password:
            flash('Please enter the decryption password', 'error')
            return redirect(request.url)
        
        try:
            encrypted_data = file.read()
        except Exception as e:
            flash(f'Error reading file: {str(e)}', 'error')
            return redirect(request.url)
        
        try:
            # Extract components (new format)
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            tag = encrypted_data[32:64]  # 32-byte HMAC-SHA256 tag
            ciphertext = encrypted_data[64:]
            
            # Derive TWO keys
            key_material = PBKDF2(password, salt, dkLen=64, count=100000, hmac_hash_module=SHA512)
            enc_key = key_material[:32]
            auth_key = key_material[32:]
            
            # Verify authentication tag FIRST
            hmac = HMAC.new(auth_key, digestmod=SHA256)
            hmac.update(salt + iv + ciphertext)
            try:
                hmac.verify(tag)
            except ValueError:
                flash('Incorrect password or corrupted file', 'error')
                return redirect(request.url)
            
            # Decrypt only after authentication passes
            cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
            padded_data = cipher.decrypt(ciphertext)
            
            # Validate padding
            pad_len = padded_data[-1]
            if pad_len < 1 or pad_len > 16:
                flash('File corrupted', 'error')
                return redirect(request.url)
                
            decrypted_data = padded_data[:-pad_len]
            
            # Create decrypted file
            decrypted_file = io.BytesIO(decrypted_data)
            decrypted_file.seek(0)
            
            original_filename = file.filename
            if original_filename.startswith("encrypted_") and original_filename.endswith(".safe"):
                download_filename = original_filename[10:-5]
            else:
                download_filename = f"decrypted_{original_filename}"
            
            return send_file(
                decrypted_file,
                as_attachment=True,
                download_name=download_filename,
                mimetype='application/octet-stream'
            )
        except Exception as e:
            flash(f'Decryption failed: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('decrypt.html')

if __name__ == '__main__':
    app.run(debug=True)