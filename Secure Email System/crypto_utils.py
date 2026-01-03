!pip install pycryptodome cryptography
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
def hybrid_hash(data):
    # Apply SHA-256 to the data
    sha256_hash = hashlib.sha256(data).digest()
    # Apply BLAKE2b to the data
    blake2b_hash = hashlib.blake2b(data).digest()
    # Combine the two hashes in a non-trivial way (XOR byte-by-byte)
    combined_hash = bytearray(a ^ b for a, b in zip(sha256_hash, blake2b_hash  [:len(sha256_hash)]))
    # Step 4: Return the final hybrid hash
    return combined_hash
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key
# AES-RSA Hybrid Encryption Function
def hybrid_encrypt(data, aes_key, rsa_public_key):
    print("Encrypting data using AES...")
    # Apply hybrid hashing before encryption
    hash_value = hybrid_hash(data)
    print(f"Hybrid Hash: {hash_value.hex()}")  # Display hybrid hash
    # Initialize AES cipher in CBC mode
    cipher = AES.new(aes_key, AES.MODE_CBC)
    print(f"AES Initialization Vector (IV): {cipher.iv.hex()}")  # Display IV
    # Pad data to match AES block size and encrypt using AES
    aes_encrypted = cipher.encrypt(pad(data, AES.block_size))
    print(f"AES Encrypted Data (Ciphertext): {aes_encrypted.hex()}")  # Display AES encrypted data
    print("\nEncrypting AES-encrypted data using RSA...")
    # Encrypt the AES-encrypted data with RSA public key
    rsa_encrypted = rsa_public_key.encrypt(
        aes_encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"RSA Encrypted Data: {rsa_encrypted.hex()}")  # Display RSA encrypted data
    return rsa_encrypted, cipher.iv, hash_value
# AES-RSA Hybrid Decryption Function
def hybrid_decrypt(encrypted_data, aes_key, rsa_private_key, iv, original_hash):
    print("\nDecrypting AES-encrypted data using RSA...")
    # Decrypt the RSA-encrypted data to retrieve AES-encrypted data
    rsa_decrypted = rsa_private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"RSA Decrypted Data (AES Ciphertext): {rsa_decrypted.hex()}")  # Display RSA decrypted data
    print("\nDecrypting AES-encrypted data...")
    # Decrypt the AES-encrypted data using the AES key and IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(rsa_decrypted), AES.block_size)
    # Decode byte data to string to remove the 'b' prefix
    decrypted_data = plaintext.decode('utf-8')
    print(f"Decrypted Plaintext: {decrypted_data}")  # Display the final plaintext
    # Apply hybrid hashing to the decrypted plaintext
    decrypted_hash = hybrid_hash(plaintext)
    print(f"Hybrid Hash of Decrypted Data: {decrypted_hash.hex()}")  # Display hash of decrypted data
    # Check if the decrypted hash matches the original hash
    if decrypted_hash == original_hash:
        print("\nDecryption successful! The data matches.")
    else:
        print("\nDecryption failed! The data integrity has been compromised.")

    return decrypted_data
# Main block for testing
if __name__ == "__main__":
    # Sample data to encrypt
    data = b"Hello, this is a hybrid encryption example!"
    print(f"Original Data: {data.decode('utf-8')}\n")  # Display original data as string

    aes_key = get_random_bytes(16)  # Generate a random AES key (16 bytes for AES-128)

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Encrypt data with hybrid hashing applied
    encrypted_data, iv, data_hash = hybrid_encrypt(data, aes_key, public_key)
    # Output encrypted data and hash
    print(f"\nEncrypted Data: {encrypted_data.hex()}")  # Display the encrypted data
    print(f"Data Hash: {data_hash.hex()}")  # Display the hybrid hash
    # Decrypt the data and verify the integrity using hybrid hashing
    decrypted_data = hybrid_decrypt(encrypted_data, aes_key, private_key, iv, data_hash)
    # Output results
    print(f"\nOriginal Data: {data.decode('utf-8')}")
    print(f"Decrypted Data: {decrypted_data}")
    # Check if decryption is successful
    assert data.decode('utf-8') == decrypted_data, "Decryption failed!"
    print("\nDecryption successful! The data matches.")
