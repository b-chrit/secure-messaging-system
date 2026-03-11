import argparse
import json
import base64
import os

def tamper_message(filepath):
    print(f"[*] Loading encrypted bundle from {filepath}...")

    with open(filepath, "r") as f:
        bundle = json.load(f)

    print(f"[*] Original encrypted message (first 60 chars):")
    print(f"    {bundle['encrypted_message'][:60]}...")

    # Decode, flip some bytes, re-encode to simulate tampering
    raw = base64.b64decode(bundle["encrypted_message"])
    tampered = bytearray(raw)
    tampered[0] ^= 0xFF
    tampered[1] ^= 0xFF
    tampered[2] ^= 0xFF
    bundle["encrypted_message"] = base64.b64encode(bytes(tampered)).decode()

    # Save tampered file
    tampered_path = filepath.replace(".enc", "_tampered.enc")
    with open(tampered_path, "w") as f:
        json.dump(bundle, f, indent=2)

    print(f"[!] Message bytes have been altered by attacker.")
    print(f"[*] Tampered message (first 60 chars):")
    print(f"    {bundle['encrypted_message'][:60]}...")
    print(f"[+] Tampered file saved to: {tampered_path}")
    print(f"\n[*] Now try decrypting the tampered file — the system should catch it.")
    print(f"    python3 decrypt.py --user {bundle['recipient']} --file {tampered_path}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate message tampering")
    parser.add_argument("--file", required=True, help="Path to the encrypted message file")
    args = parser.parse_args()
    tamper_message(args.file)