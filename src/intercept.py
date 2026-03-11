import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def intercept_message(attacker, filepath):

    print(f"[*] Attacker '{attacker}' is attempting to intercept the message...")
    print(f"[*] Loading encrypted bundle from {filepath}...")

    with open(filepath, "r") as f:
        bundle = json.load(f)

    sender = bundle["sender"]
    recipient = bundle["recipient"]

    print(f"[*] Message is from '{sender}' to '{recipient}'")
    print(f"[*] Loading {attacker}'s private key...")

    try:
        with open(f"keys/{attacker}_private.pem", "rb") as f:
            attacker_private_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print(f"[!] No keys found for '{attacker}'. Run keygen.py --user {attacker} first.")
        return

    print(f"[*] Attempting to decrypt session key with {attacker}'s private key...")

    encrypted_session_key = base64.b64decode(bundle["encrypted_session_key"])

    try:
        session_key = attacker_private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"[+] Session key decrypted (this shouldn't happen!)")

    except Exception as e:
        print(f"\n[✗] DECRYPTION FAILED — session key was encrypted with {recipient}'s public key,")
        print(f"    not {attacker}'s. Without the session key, the message cannot be decrypted.")
        print(f"\n[✗] Intercepted ciphertext (unreadable):")
        print(f"    {bundle['encrypted_message'][:80]}...")
        print(f"\n[✓] System held secure. Attacker '{attacker}' could not read the message.\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Simulate an interception attack")
    parser.add_argument("--attacker", required=True, help="Attacker username")
    parser.add_argument("--file", required=True, help="Path to the encrypted message file")
    args = parser.parse_args()
    intercept_message(args.attacker, args.file)