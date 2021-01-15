from Crypto.Cipher import AES
from Crypto.Random import new as Random
from hashlib import sha256
from base64 import b64encode, b64decode
import scrypt
import csv
import itertools


class AESCipher:
    """
    credit to https://stackoverflow.com/a/54024595
    """
    def __init__(self, data, key):
        self.data   = data
        self.key    = sha256(key).digest()[:32]
        self.pad    = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
        self.unpad  = lambda s: s[:-ord(s[len(s) - 1:])]

    def encrypt(self):
        plain_text  = self.pad(self.data)
        iv          = Random().read(AES.block_size)
        cipher      = AES.new(self.key, AES.MODE_GCM, iv)
        return b64encode(iv + cipher.encrypt(plain_text.encode())).decode()

    def decrypt(self):
        cipher_text = b64decode(self.data.encode())
        iv          = cipher_text[:16]
        cipher      = AES.new(self.key,AES.MODE_GCM,iv)
        return self.unpad(cipher.decrypt(cipher_text[16:])).decode()


def encrypt_CSV(file_name, column_keys):
    """
    encrypts specified columns of CSV file with corresponding keys using AES-256 in GCM mode
    parameters:
        file_name:   name of CSV file to encrypt
        column_keys: dict with entries {column index : 16-byte secret key}
    """
    file = open(file_name, 'r')
    reader = csv.reader(file, delimiter=',')
    
    header = next(reader) 
    encrypted_data = []
    for line in reader:
        if line:
            encrypted_row = {}
            for i in range(len(line)):
                if i in column_keys:
                    encrypted_row[header[i]] = AESCipher(line[i], column_keys[i]).encrypt()
                else:
                    encrypted_row[header[i]] = line[i]
            encrypted_data.append(encrypted_row)
    file.close()
    with open(file_name, 'w') as enc_file:
        writer = csv.DictWriter(enc_file, fieldnames = header)
        writer.writeheader()
        for row in encrypted_data:
            writer.writerow(row)  


def decrypt_CSV(file_name, column_keys):
    """
    decrypts CSV file encrypted with encrypt_CSV
    parameters:
        file_name:   name of CSV file to decrypt
        column_keys: dict with entries {column index : 16-byte secret key}
    """
    file = open(file_name, 'r')
    reader = csv.reader(file, delimiter=',')
        
    header = next(reader) 
    decrypted_data = []
    for line in reader:
        if line:
            decrypted_row = {}
            for i in range(len(line)):
                if i in column_keys:
                    decrypted_row[header[i]] = AESCipher(line[i], column_keys[i]).decrypt()
                else:
                    decrypted_row[header[i]] = line[i]
            decrypted_data.append(decrypted_row)
    file.close()
    with open(file_name, 'w') as enc_file:
        writer = csv.DictWriter(enc_file, fieldnames = header)
        writer.writeheader()
        for row in decrypted_data:
            writer.writerow(row)
