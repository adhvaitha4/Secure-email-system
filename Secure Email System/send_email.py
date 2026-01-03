import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64  # Import base64 for encoding and decoding
from cryptography.hazmat.primitives import serialization

# Hybrid hashing function (SHA-256 and MD5 combined)
def hybrid_hash(data):
    sha256_hash = hashlib.sha256(data).digest()
    blake2b_hash = hashlib.blake2b(data).digest()
    combined_hash = bytearray(a ^ b for a, b in zip(sha256_hash, blake2b_hash[:len(sha256_hash)]))
    return combined_hash
    

# Function to generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# AES-RSA Hybrid Encryption Function
def hybrid_encrypt(data, aes_key, rsa_public_key):
    hash_value = hybrid_hash(data)
    cipher = AES.new(aes_key, AES.MODE_CBC)
    aes_encrypted = cipher.encrypt(pad(data, AES.block_size))
    rsa_encrypted = rsa_public_key.encrypt(
        aes_encrypted,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return rsa_encrypted, cipher.iv, hash_value

# Send email function with encryption
def send_encrypted_email(sender_email, recipient_email, subject, body, password):
    # Generate AES and RSA keys for encryption
    aes_key = get_random_bytes(16)  # AES key (128 bits)
    private_key, public_key = generate_rsa_keys()

    # Encrypt the email body using hybrid encryption (AES + RSA)
    encrypted_body, iv, body_hash = hybrid_encrypt(body.encode('utf-8'), aes_key, public_key)

    # Ensure IV is 16 bytes long
    if len(iv) != 16:
        print(f"Error: IV length is {len(iv)} bytes, it should be 16 bytes.")
        return

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    # Attach the encrypted body as base64 encoded string
    encrypted_body_base64 = base64.b64encode(encrypted_body).decode('utf-8')
    msg.attach(MIMEText(encrypted_body_base64, 'plain'))

    # Send the email
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)  # Connect to Gmail’s SMTP server
        server.login(sender_email, password)  # Log in to your Gmail account
        server.sendmail(sender_email, recipient_email, msg.as_string())  # Send the email
        print("Encrypted email sent successfully!")

        # Print private key, encrypted body, IV, and hash (to be shared with recipient)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        print(f"Private Key (PEM format):\n{private_key_pem.decode()}")
        print(f"Encrypted Email Body (Base64): {encrypted_body_base64}")
        print(f"Hybrid Hash of Email Body: {body_hash.hex()}")
        print(f"Initialization Vector (IV): {base64.b64encode(iv).decode()}")

    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        server.quit()

# Example usage:
sender_email = "sender@gmail.com"
recipient_email = "receiver@gmail.com"
subject = "Encrypted Message"
body = "hello this is test message"
password = "quds pqrs lmno wxyz"  # Sender's email password

# Send an encrypted email
send_encrypted_email(sender_email, recipient_email, subject, body, password)
