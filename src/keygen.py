import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys(username):
    os.makedirs("keys", exist_ok=True)

    print(f"[*] Generating RSA-2048 key pair for {username}...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save private key
    private_path = f"keys/{username}_private.pem"
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[+] Private key saved to: {private_path}")

    # Save public key
    public_path = f"keys/{username}_public.pem"
    with open(public_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"[+] Public key saved to:  {public_path}")
    print(f"[✓] Done.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate RSA key pair for a user")
    parser.add_argument("--user", required=True, help="Username to generate keys for")
    args = parser.parse_args()
    generate_keys(args.user)
