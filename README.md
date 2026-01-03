Secure Email System using Hybrid AES–RSA Encryption
Project Overview:
This project implements a secure email communication system that ensures confidentiality, integrity, and authenticity of email content. The system combines symmetric and asymmetric cryptography with hybrid hashing and integrates the solution with a real-world SMTP email workflow. 
The core idea is to encrypt email content before transmission, rather than relying solely on transport-layer security (TLS), thereby protecting sensitive data even if email servers are compromised.

Security Techniques Used
1. Hybrid AES–RSA Encryption
AES (Advanced Encryption Standard) is used to encrypt the email content due to its speed and efficiency.
RSA (2048-bit) is used to securely encrypt the AES key, ensuring safe key exchange.
This hybrid approach balances performance and strong security.

2. Hybrid SHA-256 + BLAKE2b Hashing
Email content is hashed using SHA-256 and BLAKE2b.
The hashes are combined to generate a tamper-resistant hybrid hash.
This allows the receiver to verify data integrity and detect any modification.
