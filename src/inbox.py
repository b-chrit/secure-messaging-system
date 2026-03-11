import argparse
import json
import os

def show_inbox(username):
    messages_dir = "messages"

    if not os.path.exists(messages_dir):
        print(f"[!] No messages directory found.")
        return

    files = [
        f for f in os.listdir(messages_dir)
        if f.endswith(".enc") and f"to_{username}" in f
    ]

    if not files:
        print(f"[!] No messages found for '{username}'.")
        return

    # Load and sort by timestamp
    inbox = []
    for fname in files:
        fpath = os.path.join(messages_dir, fname)
        with open(fpath, "r") as f:
            bundle = json.load(f)
        inbox.append({
            "file": fname,
            "path": fpath,
            "sender": bundle.get("sender", "unknown"),
            "timestamp": bundle.get("timestamp", "unknown"),
        })

    inbox.sort(key=lambda x: x["timestamp"])

    print(f"\n{'='*50}")
    print(f"  Inbox for: {username}  ({len(inbox)} message(s))")
    print(f"{'='*50}")
    print(f"  {'#':<4} {'From':<15} {'Timestamp':<22} {'File'}")
    print(f"  {'-'*4} {'-'*15} {'-'*22} {'-'*30}")

    for i, msg in enumerate(inbox, 1):
        print(f"  {i:<4} {msg['sender']:<15} {msg['timestamp']:<22} {msg['file']}")

    print(f"{'='*50}\n")
    print(f"[*] To read a message, go back and choose option 4.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View inbox for a user")
    parser.add_argument("--user", required=True, help="Username to view inbox for")
    args = parser.parse_args()
    show_inbox(args.user)