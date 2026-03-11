import argparse
import os
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_message(sender, recipient, message):
    os.makedirs("messages", exist_ok=True)

    # Load recipient's public key
    print(f"[*] Loading {recipient}'s public key...")
    with open(f"keys/{recipient}_public.pem", "rb") as f:
        recipient_public_key = serialization.load_pem_public_key(f.read())

    # Load sender's private key (for signing)
    print(f"[*] Loading {sender}'s private key for signing...")
    with open(f"keys/{sender}_private.pem", "rb") as f:
        sender_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Generate AES-256-GCM session key and nonce
    print(f"[*] Generating AES-256-GCM session key...")
    session_key = os.urandom(32)  # 256 bits
    nonce = os.urandom(12)        # 96 bits recommended for GCM

    # Encrypt message with AES-256-GCM (provides confidentiality + integrity)
    print(f"[*] Encrypting message with AES-256-GCM...")
    aesgcm = AESGCM(session_key)
    encrypted_message = aesgcm.encrypt(nonce, message.encode(), None)

    # Encrypt session key with recipient's RSA public key
    print(f"[*] Encrypting session key with {recipient}'s RSA public key...")
    encrypted_session_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Hash the original message for integrity verification
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    message_hash = digest.finalize()
    print(f"[+] Message hash (SHA-256): {message_hash.hex()[:16]}...{message_hash.hex()[-16:]}")

    # Sign the message hash with sender's private key
    print(f"[*] Signing message hash with {sender}'s private key...")
    signature = sender_private_key.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Bundle everything into a file
    bundle = {
        "sender": sender,
        "recipient": recipient,
        "timestamp": timestamp,
        "nonce": base64.b64encode(nonce).decode(),
        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
        "encrypted_message": base64.b64encode(encrypted_message).decode(),
        "message_hash": message_hash.hex(),
        "signature": base64.b64encode(signature).decode()
    }

    # Use timestamp in filename to support multiple messages between same users
    ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"messages/msg_{sender}_to_{recipient}_{ts_tag}.enc"
    with open(output_path, "w") as f:
        json.dump(bundle, f, indent=2)

    print(f"[+] Encrypted message saved to: {output_path}")
    print(f"[✓] Message encrypted and signed.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt and sign a message")
    parser.add_argument("--from", dest="sender", required=True, help="Sender username")
    parser.add_argument("--to", dest="recipient", required=True, help="Recipient username")
    parser.add_argument("--message", required=True, help="Plaintext message to send")
    args = parser.parse_args()
    encrypt_message(args.sender, args.recipient, args.message)
