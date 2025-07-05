import base64
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Helper: Padding and Unpadding
def pad(text, size):
    pad_len = size - len(text) % size
    return text + chr(pad_len) * pad_len

def unpad(text):
    return text[:-ord(text[-1])]

# AES
def aes_encrypt(text, key):
    key = key.ljust(16, '0')[:16].encode()
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(text, 16).encode())).decode()

def aes_decrypt(cipher_text, key):
    key = key.ljust(16, '0')[:16].encode()
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(cipher_text)).decode())

# DES
def des_encrypt(text, key):
    key = key.ljust(8, '0')[:8].encode()
    cipher = DES.new(key, DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(text, 8).encode())).decode()

def des_decrypt(cipher_text, key):
    key = key.ljust(8, '0')[:8].encode()
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(cipher_text)).decode())

# RSA
def generate_rsa_keys():
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    print("Keys saved as private.pem & public.pem")

def rsa_encrypt(text, pub_path):
    with open(pub_path, 'rb') as f:
        key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(text.encode())).decode()

def rsa_decrypt(cipher_text, priv_path):
    with open(priv_path, 'rb') as f:
        key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(cipher_text)).decode()

# Menu Interface
def menu():
    while True:
        print("\n🔐 TEXT ENCRYPTER MENU")
        print("1. AES Encrypt")
        print("2. AES Decrypt")
        print("3. DES Encrypt")
        print("4. DES Decrypt")
        print("5. RSA Encrypt")
        print("6. RSA Decrypt")
        print("7. Generate RSA Key Pair")
        print("0. Exit")

        choice = input("👉 Your Choice: ")

        try:
            if choice == '1':
                txt = input("Enter text: ")
                key = input("16-char key: ")
                print("Encrypted (AES):", aes_encrypt(txt, key))

            elif choice == '2':
                ct = input("Encrypted AES text: ")
                key = input("16-char key: ")
                print("Decrypted (AES):", aes_decrypt(ct, key))

            elif choice == '3':
                txt = input("Enter text: ")
                key = input("8-char key: ")
                print("Encrypted (DES):", des_encrypt(txt, key))

            elif choice == '4':
                ct = input("Encrypted DES text: ")
                key = input("8-char key: ")
                print("Decrypted (DES):", des_decrypt(ct, key))

            elif choice == '5':
                txt = input("Enter text: ")
                pub = input("Path to public.pem: ")
                print("Encrypted (RSA):", rsa_encrypt(txt, pub))

            elif choice == '6':
                ct = input("Encrypted RSA text: ")
                priv = input("Path to private.pem: ")
                print("Decrypted (RSA):", rsa_decrypt(ct, priv))

            elif choice == '7':
                generate_rsa_keys()

            elif choice == '0':
                print("Goodbye 👋")
                break

            else:
                print("Invalid choice, try again!")

        except Exception as e:
            print("⚠️ Error:", str(e))

if __name__ == "__main__":
    menu()
