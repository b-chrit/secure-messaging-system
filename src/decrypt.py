import argparse
import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_message(username, filepath):

    with open(filepath, "r") as f:
        bundle = json.load(f)

    sender = bundle["sender"]
    recipient = bundle["recipient"]
    timestamp = bundle.get("timestamp", "unknown")

    if recipient != username:
        print(f"[!] This message is addressed to {recipient}, not {username}.")
        return

    print(f"[*] Loading {username}'s private key...")
    with open(f"keys/{username}_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    print(f"[*] Loading {sender}'s public key for signature verification...")
    with open(f"keys/{sender}_public.pem", "rb") as f:
        sender_public_key = serialization.load_pem_public_key(f.read())

    print(f"[*] Decrypting session key with RSA private key...")
    encrypted_session_key = base64.b64decode(bundle["encrypted_session_key"])
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"[*] Decrypting message with AES-256-GCM...")
    nonce = base64.b64decode(bundle["nonce"])
    encrypted_message = base64.b64decode(bundle["encrypted_message"])
    aesgcm = AESGCM(session_key)

    try:
        decrypted_message = aesgcm.decrypt(nonce, encrypted_message, None)
    except Exception:
        print(f"[!] AES-GCM authentication failed — message has been tampered with.")
        return

    print(f"[*] Verifying message integrity (SHA-256)...")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(decrypted_message)
    computed_hash = digest.finalize().hex()
    stored_hash = bundle["message_hash"]

    if computed_hash == stored_hash:
        print(f"[+] Message integrity (SHA-256): VERIFIED")
    else:
        print(f"[!] Message integrity: FAILED — message may have been tampered with.")
        return

    print(f"[*] Verifying {sender}'s digital signature...")
    signature = base64.b64decode(bundle["signature"])
    try:
        sender_public_key.verify(
            signature,
            bytes.fromhex(stored_hash),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"[+] Signature: VALID")
    except Exception:
        print(f"[!] Signature: INVALID — message authenticity cannot be confirmed.")
        return

    print(f"[+] Sent by: {sender} at {timestamp}")
    print(f"[✓] Decrypted message: \"{decrypted_message.decode()}\"\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt and verify a message")
    parser.add_argument("--user", required=True, help="Recipient username")
    parser.add_argument("--file", required=True, help="Path to the encrypted message file")
    args = parser.parse_args()
    decrypt_message(args.user, args.file)
