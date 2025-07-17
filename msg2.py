# messenger_app.py
from crypto_utils import encrypt_message, decrypt_message, encrypt_file, decrypt_file
import os

def main():
    print("🔐 Secure File Messenger 🔓")
    print("--------------------------")
    
    while True:
        print("\nMain Menu:")
        print("1. Encrypt a message to file")
        print("2. Decrypt a message from file")
        print("3. Exit")

        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == "1":
            # Encrypt message to file
            message = input("\nMessage to encrypt: ").strip()
            if not message:
                print("Error: Message cannot be empty")
                continue
                
            password = input("Encryption password: ").strip()
            if not password:
                print("Error: Password cannot be empty")
                continue
                
            output_file = "crypt\encrypt\ txtmsg.enc"
            encrypted = encrypt_message(message, password)
            
            try:
                with open(output_file, 'w') as f:
                    f.write(encrypted)
                print(f"\n✅ Message encrypted and saved to: {output_file}")
                print(f"Encrypted content: {encrypted[:30]}... (truncated)")
            except Exception as e:
                print(f"\n❌ Failed to save encrypted message: {str(e)}")
                
        elif choice == "2":
            # Decrypt message from file
            input_file = input("\nEncrypted message file:  ").strip()
            if not os.path.exists(input_file):
                print(f"Error: File '{input_file}' not found")
                continue
                
            password = input("Decryption password: ").strip()
            if not password:
                print("Error: Password cannot be empty")
                continue
                
            try:
                with open(input_file, 'r') as f:
                    encrypted_b64 = f.read().strip()
                    
                decrypted = decrypt_message(encrypted_b64, password)
                print("\n✅ Decryption successful!")
                print(f"Original message:\n{decrypted}")
            except Exception as e:
                print(f"\n❌ Decryption failed: {str(e)}")
                print("Possible reasons: Incorrect password or corrupted file")
                
        elif choice == "3":
            print("\n👋 Exiting... Goodbye!")
            break
            
        else:
            print("⚠️  Invalid choice. Please enter 1-3")

if __name__ == "__main__":
    main()