from crypto_utils import StreamingCrypto
import argparse


StreamingCrypto.encrypt_large_file(
    input_path="crypt\siles\example.html",
    output_path="crypt\encrypt\example.enc",
    password="password",
    mode='CBC',
    chunk_size=128*1024
    )

print("Your file has been encrypted!")

StreamingCrypto.decrypt_large_file(
    input_path="crypt\encrypt\example.enc",
    output_path="crypt\decrypt\done.html",
    password="password",
    mode='CBC',
    chunk_size=128*1024
)

print("Your file has been decrypted!")