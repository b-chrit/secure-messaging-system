import os
import sys
from keygen import generate_keys
from encrypt import encrypt_message
from decrypt import decrypt_message
from intercept import intercept_message
from tamper import tamper_message
from inbox import show_inbox

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def header():
    print("=" * 40)
    print("      Secure Messaging System")
    print("=" * 40)
    print()

def menu():
    print("1. Generate keys for a user")
    print("2. Send encrypted message")
    print("3. View inbox")
    print("4. Decrypt a message")
    print("5. Simulate interception attack")
    print("6. Simulate message tampering")
    print("7. Reset (delete all keys and messages)")
    print("8. Exit")
    print()

def user_has_keys(username):
    return (
        os.path.exists(f"keys/{username}_private.pem") and
        os.path.exists(f"keys/{username}_public.pem")
    )

def ensure_keys(username):
    if not user_has_keys(username):
        print(f"[!] No keys found for '{username}'.")
        confirm = input(f"    Generate keys for '{username}' now? (y/n): ").strip().lower()
        if confirm == "y":
            print()
            generate_keys(username)
            return True
        else:
            print(f"[!] Cannot proceed without keys for '{username}'.")
            return False
    return True

def pick_message_file(for_user=None):
    messages_dir = "messages"
    if not os.path.exists(messages_dir):
        print("[!] No messages directory found.")
        return None

    files = [f for f in os.listdir(messages_dir) if f.endswith(".enc")]
    if for_user:
        files = [f for f in files if f"to_{for_user}" in f]

    if not files:
        print(f"[!] No messages found.")
        return None

    print("[*] Available messages:")
    for i, f in enumerate(files, 1):
        print(f"    {i}. {f}")
    print()

    choice = input("Enter file number: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        return os.path.join(messages_dir, files[int(choice) - 1])
    else:
        print("[!] Invalid choice.")
        return None

def option_keygen():
    username = input("Enter username: ").strip()
    if not username:
        print("[!] Username cannot be empty.")
        return
    if user_has_keys(username):
        confirm = input(f"[!] Keys already exist for '{username}'. Overwrite? (y/n): ").strip().lower()
        if confirm != "y":
            print("[*] Skipped.")
            return
    print()
    generate_keys(username)

def option_encrypt():
    sender = input("Sender username: ").strip()
    if not sender or not ensure_keys(sender):
        return
    recipient = input("Recipient username: ").strip()
    if not recipient or not ensure_keys(recipient):
        return
    message = input("Message: ").strip()
    if not message:
        print("[!] Message cannot be empty.")
        return
    print()
    encrypt_message(sender, recipient, message)

def option_inbox():
    username = input("Your username: ").strip()
    if not username:
        print("[!] Username cannot be empty.")
        return
    print()
    show_inbox(username)

def option_decrypt():
    username = input("Your username: ").strip()
    if not username:
        print("[!] Username cannot be empty.")
        return
    if not user_has_keys(username):
        print(f"[!] No keys found for '{username}'. Generate keys first (option 1).")
        return
    print()
    filepath = pick_message_file(for_user=username)
    if filepath:
        print()
        decrypt_message(username, filepath)

def option_intercept():
    attacker = input("Attacker username: ").strip()
    if not attacker or not ensure_keys(attacker):
        return
    print()
    filepath = pick_message_file()
    if filepath:
        print()
        intercept_message(attacker, filepath)

def option_tamper():
    print("[*] This will create a tampered copy of a message to demonstrate detection.")
    print()
    filepath = pick_message_file()
    if filepath:
        print()
        tamper_message(filepath)

def option_reset():
    print("[!] This will permanently delete all keys and messages.")
    confirm = input("    Are you sure? (yes/n): ").strip().lower()
    if confirm != "yes":
        print("[*] Reset cancelled.")
        return

    import shutil
    deleted = []
    for folder in ["keys", "messages"]:
        if os.path.exists(folder):
            shutil.rmtree(folder)
            deleted.append(folder)

    if deleted:
        print(f"[✓] Deleted: {', '.join(deleted)}")
    else:
        print("[*] Nothing to delete.")

def main():
    while True:
        clear()
        header()
        menu()

        choice = input("Choose an option: ").strip()
        print()

        if choice == "1":
            option_keygen()
        elif choice == "2":
            option_encrypt()
        elif choice == "3":
            option_inbox()
        elif choice == "4":
            option_decrypt()
        elif choice == "5":
            option_intercept()
        elif choice == "6":
            option_tamper()
        elif choice == "7":
            option_reset()
        elif choice == "8":
            print("Goodbye.")
            sys.exit(0)
        else:
            print("[!] Invalid option. Please choose 1-8.")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()