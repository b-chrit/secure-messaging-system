import streamlit as st
import os
import json
import sys
import shutil
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from keygen import generate_keys
from encrypt import encrypt_message
from decrypt import decrypt_message
from intercept import intercept_message
from tamper import tamper_message
from inbox import show_inbox

st.set_page_config(
    page_title="SecureMsg",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Sans:wght@300;400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
    background-color: #F5F0E8;
    color: #2C2C2C;
}
.stApp { background-color: #F5F0E8; }
.block-container {
    padding-top: 2rem !important;
    padding-bottom: 0.5rem !important;
}
.page-course {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: #AAA;
    margin-bottom: 4px;
}
.page-title {
    font-family: 'DM Serif Display', serif;
    font-size: 2rem;
    color: #1A1A1A;
    font-weight: 400;
    line-height: 1.1;
    margin-bottom: 4px;
}
.page-sub {
    font-style: italic;
    font-size: 0.875rem;
    color: #888;
}
[data-testid="stSidebar"] {
    background-color: #EDE8DC;
    border-right: 1px solid #D8D0C0;
}
[data-testid="stSidebar"] .stRadio label {
    font-size: 0.9rem;
    color: #4A4A4A;
    font-weight: 400;
}
h1 {
    font-family: 'DM Serif Display', serif;
    color: #1A1A1A;
    font-size: 2rem !important;
    font-weight: 400 !important;
    letter-spacing: -0.5px;
    margin-bottom: 0 !important;
}
h2, h3 { font-family: 'DM Serif Display', serif; color: #2C2C2C; font-weight: 400 !important; }
.card {
    background: #FDFAF4;
    border: 1px solid #D8D0C0;
    border-radius: 12px;
    padding: 28px 32px;
    margin-bottom: 20px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.05);
}
.card-title {
    font-family: 'DM Serif Display', serif;
    font-size: 1.2rem;
    color: #1A1A1A;
    margin-bottom: 18px;
    padding-bottom: 12px;
    border-bottom: 1px solid #E8E0D0;
}
.stTextInput input, .stTextArea textarea {
    background-color: #FAF7F0 !important;
    border: 1px solid #C8C0B0 !important;
    border-radius: 8px !important;
    color: #2C2C2C !important;
    font-family: 'DM Sans', sans-serif !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
    border-color: #A09070 !important;
    box-shadow: 0 0 0 2px rgba(160,144,112,0.15) !important;
}
.stButton button {
    background-color: #2C2C2C !important;
    color: #F5F0E8 !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: 'DM Sans', sans-serif !important;
    font-weight: 500 !important;
    font-size: 0.875rem !important;
    padding: 0.5rem 1.5rem !important;
    letter-spacing: 0.3px;
}
.stButton button:hover { background-color: #1A1A1A !important; }
.stSuccess { background-color: #EDF5EC !important; border-left: 3px solid #5A8A5A !important; border-radius: 8px !important; color: #2A4A2A !important; }
.stError { background-color: #F5ECEC !important; border-left: 3px solid #8A5A5A !important; border-radius: 8px !important; color: #4A2A2A !important; }
.stInfo { background-color: #EEF2F5 !important; border-left: 3px solid #7A9AB0 !important; border-radius: 8px !important; }
.stWarning { background-color: #F5F0E0 !important; border-left: 3px solid #B0953A !important; border-radius: 8px !important; }
.stCode, code { background-color: #EDE8DC !important; border-radius: 6px !important; font-size: 0.8rem !important; color: #3A3A3A !important; }
.stSelectbox select { background-color: #FAF7F0 !important; border: 1px solid #C8C0B0 !important; border-radius: 8px !important; }
hr { border-color: #D8D0C0; margin: 24px 0; }
.sidebar-brand { font-family: 'DM Serif Display', serif; font-size: 1.4rem; color: #1A1A1A; margin-bottom: 4px; }
.sidebar-sub { font-size: 0.75rem; color: #888; margin-bottom: 24px; letter-spacing: 0.5px; text-transform: uppercase; }
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
th { background: #EDE8DC; padding: 10px 14px; text-align: left; font-weight: 500; color: #555; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 10px 14px; border-bottom: 1px solid #E8E0D0; color: #2C2C2C; }
tr:last-child td { border-bottom: none; }
[data-testid="metric-container"] { background: #FDFAF4; border: 1px solid #D8D0C0; border-radius: 10px; padding: 16px !important; }
</style>
""", unsafe_allow_html=True)

def user_has_keys(username):
    return (
        os.path.exists(f"keys/{username}_private.pem") and
        os.path.exists(f"keys/{username}_public.pem")
    )

def get_all_messages():
    if not os.path.exists("messages"):
        return []
    files = [f for f in os.listdir("messages") if f.endswith(".enc")]
    msgs = []
    for fname in sorted(files):
        fpath = os.path.join("messages", fname)
        with open(fpath) as f:
            b = json.load(f)
        msgs.append({
            "file": fname,
            "path": fpath,
            "sender": b.get("sender", "?"),
            "recipient": b.get("recipient", "?"),
            "timestamp": b.get("timestamp", "?"),
            "tampered": "_tampered" in fname
        })
    return sorted(msgs, key=lambda x: x["timestamp"], reverse=True)

def get_users():
    if not os.path.exists("keys"):
        return []
    files = os.listdir("keys")
    return sorted(set(f.replace("_private.pem", "").replace("_public.pem", "") for f in files if f.endswith(".pem")))

def capture_output(fn, *args):
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*args)
    return buf.getvalue()

with st.sidebar:
    st.markdown('<div class="sidebar-brand">SecureMsg</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-sub">Cryptographic Messaging</div>', unsafe_allow_html=True)
    page = st.radio(
        "Navigate",
        ["Overview", "Generate Keys", "Send Message", "Inbox", "Decrypt", "Intercept Attack", "Tamper Demo", "Reset"],
        label_visibility="collapsed"
    )
    st.markdown("---")
    users = get_users()
    msgs = get_all_messages()
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Users", len(users))
    with col2:
        st.metric("Messages", len(msgs))

# ── Overview ───────────────────────────────────────────────────────────────────

if page == "Overview":
    st.markdown("""
<style>
.hero {
    padding: 16px 0 14px 0;
    border-bottom: 1px solid #D8D0C0;
    margin-bottom: 20px;
}
.hero-course {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: #999;
    margin-bottom: 8px;
}
.hero-title {
    font-family: 'DM Serif Display', serif;
    font-size: 2.4rem;
    line-height: 1.1;
    color: #1A1A1A;
    font-weight: 400;
    margin-bottom: 8px;
}
.hero-subtitle {
    font-size: 0.9rem;
    color: #777;
    font-weight: 300;
    max-width: 500px;
    line-height: 1.5;
}
.hero-meta {
    margin-top: 10px;
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
}
.hero-meta-item { font-size: 0.78rem; color: #888; }
.hero-meta-item span { color: #2C2C2C; font-weight: 500; }
.step-row { display: flex; gap: 14px; margin-bottom: 10px; align-items: flex-start; }
.step-row:last-child { margin-bottom: 0; }
.step-num {
    font-family: 'DM Serif Display', serif;
    font-size: 1.2rem;
    color: #C8C0B0;
    line-height: 1.3;
    min-width: 20px;
}
.step-body strong { display: block; font-size: 0.84rem; font-weight: 500; color: #1A1A1A; margin-bottom: 1px; }
.step-body span { font-size: 0.78rem; color: #777; line-height: 1.45; }
.crypto-row { display: flex; align-items: center; padding: 9px 0; border-bottom: 1px solid #EDE8DC; gap: 14px; }
.crypto-row:last-child { border-bottom: none; }
.crypto-tag {
    background: #2C2C2C;
    color: #F5F0E8;
    border-radius: 6px;
    padding: 3px 10px;
    font-size: 0.7rem;
    font-weight: 500;
    letter-spacing: 0.5px;
    min-width: 110px;
    text-align: center;
}
.crypto-desc { font-size: 0.78rem; color: #666; }
.team-grid { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 6px; }
.team-card {
    background: #FDFAF4;
    border: 1px solid #D8D0C0;
    border-radius: 10px;
    padding: 12px 18px;
    flex: 1;
    min-width: 150px;
}
.team-name { font-size: 0.84rem; font-weight: 500; color: #1A1A1A; margin-bottom: 2px; }
.team-id { font-size: 0.72rem; color: #AAA; font-family: monospace; }
</style>

<div class="hero">
    <div class="hero-course">SOEN 321 — Information Systems Security &nbsp;·&nbsp; Winter 2026 &nbsp;·&nbsp; Concordia University</div>
    <div class="hero-title">Secure Messaging System</div>
    <div class="hero-subtitle">A cryptographic prototype implementing hybrid encryption, digital signatures, and integrity verification.</div>
    <div class="hero-meta">
        <div class="hero-meta-item">Instructor <span>Dr. Ayda Basyouni</span></div>
        <div class="hero-meta-item">Option <span>2 — Secure Communication System</span></div>
    </div>
</div>
""", unsafe_allow_html=True)

    col1, col2 = st.columns([3, 2])

    with col1:
        st.markdown('<div class="card"><div class="card-title">How It Works</div>', unsafe_allow_html=True)
        st.markdown("""
<div class="step-row"><div class="step-num">1</div><div class="step-body"><strong>Key Generation</strong><span>Each user generates an RSA-2048 key pair. Public keys are shared freely; private keys never leave the user.</span></div></div>
<div class="step-row"><div class="step-num">2</div><div class="step-body"><strong>Hybrid Encryption</strong><span>Messages are encrypted with AES-256-GCM. The session key is wrapped with the recipient's RSA public key.</span></div></div>
<div class="step-row"><div class="step-num">3</div><div class="step-body"><strong>Digital Signature</strong><span>The sender signs the SHA-256 hash with their RSA private key, proving authorship and non-repudiation.</span></div></div>
<div class="step-row"><div class="step-num">4</div><div class="step-body"><strong>Integrity Verification</strong><span>On decryption, the hash is recomputed. AES-GCM's authentication tag also detects any tampering.</span></div></div>
""", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="card"><div class="card-title">Cryptographic Stack</div>', unsafe_allow_html=True)
        st.markdown("""
<div class="crypto-row"><div class="crypto-tag">RSA-2048</div><div class="crypto-desc">Asymmetric key exchange & digital signatures</div></div>
<div class="crypto-row"><div class="crypto-tag">AES-256-GCM</div><div class="crypto-desc">Authenticated symmetric message encryption</div></div>
<div class="crypto-row"><div class="crypto-tag">SHA-256</div><div class="crypto-desc">Message hashing & integrity verification</div></div>
<div class="crypto-row"><div class="crypto-tag">RSA-PSS</div><div class="crypto-desc">Probabilistic signature scheme</div></div>
<div class="crypto-row"><div class="crypto-tag">OAEP</div><div class="crypto-desc">Optimal asymmetric encryption padding</div></div>
""", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("---")

    col_team, col_users = st.columns([3, 2])

    with col_team:
        st.markdown('<div style="font-family:\'DM Serif Display\',serif;font-size:1.1rem;margin-bottom:12px;color:#1A1A1A">Team</div>', unsafe_allow_html=True)
        st.markdown("""
<div class="team-grid">
    <div class="team-card"><div class="team-name">Baraa Chrit</div><div class="team-id">40225403</div></div>
    <div class="team-card"><div class="team-name">Rym Bensalem</div><div class="team-id">40237684</div></div>
    <div class="team-card"><div class="team-name">Mehdi Kahouache</div><div class="team-id">40250581</div></div>
</div>
""", unsafe_allow_html=True)

    with col_users:
        users = get_users()
        if users:
            st.markdown('<div style="font-family:\'DM Serif Display\',serif;font-size:1.1rem;margin-bottom:12px;color:#1A1A1A">Active Users</div>', unsafe_allow_html=True)
            for u in users:
                st.markdown(f'<div style="padding:8px 14px;background:#FDFAF4;border:1px solid #D8D0C0;border-radius:8px;margin-bottom:6px;font-size:0.84rem;color:#2C2C2C">{u}</div>', unsafe_allow_html=True)

# ── Generate Keys ──────────────────────────────────────────────────────────────

elif page == "Generate Keys":
    st.markdown("""
<div class="page-course">SOEN 321 — Information Systems Security &nbsp;·&nbsp; Winter 2026 &nbsp;·&nbsp; Concordia University</div>
<div class="page-title">Generate Keys</div>
<div class="page-sub">Create an RSA-2048 key pair for a user</div>
<hr style="border-color:#D8D0C0;margin:16px 0 20px 0">
""", unsafe_allow_html=True)

    st.markdown('<div class="card"><div class="card-title">New Key Pair</div>', unsafe_allow_html=True)
    col_input, col_btn = st.columns([3, 1])
    with col_input:
        username = st.text_input("Username", placeholder="e.g. alice", label_visibility="collapsed")
    with col_btn:
        generate_clicked = st.button("Generate Keys", use_container_width=True)

    if user_has_keys(username) and username:
        st.warning(f"Keys already exist for **{username}**. Generating new keys will overwrite them.")

    if generate_clicked and username:
        with st.spinner("Generating RSA-2048 key pair..."):
            output = capture_output(generate_keys, username)
        st.success(f"Key pair generated for **{username}**")
        st.code(output)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### Registered Users")
    users = get_users()
    if users:
        cols = st.columns(min(len(users), 4))
        for i, u in enumerate(users):
            with cols[i % 4]:
                st.markdown(f"""
                <div class="card" style="text-align:center;padding:20px 16px">
                    <div style="font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;color:#999;margin-bottom:8px">User</div>
                    <div style="font-family:'DM Serif Display',serif;font-size:1.1rem;color:#1A1A1A">{u}</div>
                    <div style="font-size:0.75rem;color:#AAA;margin-top:8px">RSA-2048</div>
                </div>""", unsafe_allow_html=True)
    else:
        st.markdown('<p style="color:#999;font-size:0.9rem">No users yet. Generate your first key pair above.</p>', unsafe_allow_html=True)

# ── Send Message ───────────────────────────────────────────────────────────────

elif page == "Send Message":
    st.markdown("""
<div class="page-course">SOEN 321 — Information Systems Security &nbsp;·&nbsp; Winter 2026 &nbsp;·&nbsp; Concordia University</div>
<div class="page-title">Send Message</div>
<div class="page-sub">Encrypt and sign a message</div>
<hr style="border-color:#D8D0C0;margin:16px 0 20px 0">
""", unsafe_allow_html=True)

    users = get_users()
    st.markdown('<div class="card"><div class="card-title">Compose</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        if users:
            sender = st.selectbox("From", users)
        else:
            sender = st.text_input("From", placeholder="Sender username")
    with col2:
        if users:
            recipient = st.selectbox("To", users)
        else:
            recipient = st.text_input("To", placeholder="Recipient username")

    message = st.text_area("Message", placeholder="Write your message here...", height=120)

    if st.button("Encrypt & Send"):
        if not sender or not recipient or not message:
            st.error("All fields are required.")
        elif not user_has_keys(sender):
            st.error(f"No keys found for **{sender}**. Generate keys first.")
        elif not user_has_keys(recipient):
            st.error(f"No keys found for **{recipient}**. Generate keys first.")
        else:
            with st.spinner("Encrypting..."):
                output = capture_output(encrypt_message, sender, recipient, message)
            st.success("Message encrypted and sent.")
            st.code(output)

    st.markdown('</div>', unsafe_allow_html=True)

# ── Inbox ──────────────────────────────────────────────────────────────────────

elif page == "Inbox":
    st.markdown("""
<div class="page-course">SOEN 321 — Information Systems Security &nbsp;·&nbsp; Winter 2026 &nbsp;·&nbsp; Concordia University</div>
<div class="page-title">Inbox</div>
<div class="page-sub">Encrypted messages — select a user to view their messages</div>
<hr style="border-color:#D8D0C0;margin:16px 0 20px 0">
""", unsafe_allow_html=True)

    users = get_users()
    if not users:
        st.info("No users found. Generate keys first.")
    else:
        selected_user = st.selectbox("View inbox for", users)
        msgs = [m for m in get_all_messages() if m["recipient"] == selected_user]

        if not msgs:
            st.info(f"No messages for **{selected_user}**.")
        else:
            st.markdown(f'<div class="card"><div class="card-title">Messages for {selected_user} ({len(msgs)})</div>', unsafe_allow_html=True)
            st.markdown("""
<table>
  <tr><th>#</th><th>From</th><th>Timestamp</th><th>Status</th><th>File</th></tr>
""" + "".join([
    f"<tr><td>{i+1}</td><td>{m['sender']}</td><td>{m['timestamp']}</td>"
    f"<td>{'⚠️ Tampered' if m['tampered'] else '🔒 Encrypted'}</td>"
    f"<td><code>{m['file']}</code></td></tr>"
    for i, m in enumerate(msgs)
]) + "</table>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

# ── Decrypt ────────────────────────────────────────────────────────────────────

elif page == "Decrypt":
    st.markdown("""
<div class="page-course">SOEN 321 — Information Systems Security &nbsp;·&nbsp; Winter 2026 &nbsp;·&nbsp; Concordia University</div>
<div class="page-title">Decrypt Message</div>
<div class="page-sub">Decrypt, verify integrity and signature</div>
<hr style="border-color:#D8D0C0;margin:16px 0 20px 0">
""", unsafe_allow_html=True)

    users = get_users()
    all_msgs = get_all_messages()

    if not users:
        st.info("No users found. Generate keys first.")
    elif not all_msgs:
        st.info("No messages found. Send a message first.")
    else:
        st.markdown('<div class="card"><div class="card-title">Select Message</div>', unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            selected_user = st.selectbox("Your username", users)
        with col2:
            user_msgs = [m for m in all_msgs if m["recipient"] == selected_user]
            if user_msgs:
                msg_labels = [f"{m['sender']} → {m['timestamp']}" for m in user_msgs]
                selected_idx = st.selectbox("Select message", range(len(msg_labels)), format_func=lambda i: msg_labels[i])
                selected_msg = user_msgs[selected_idx]
            else:
                st.warning(f"No messages for {selected_user}.")
                selected_msg = None

        if selected_msg and st.button("Decrypt & Verify"):
            with st.spinner("Decrypting..."):
                output = capture_output(decrypt_message, selected_user, selected_msg["path"])
            if "FAILED" in output or "INVALID" in output or "failed" in output:
                st.error("Decryption or verification failed.")
            else:
                st.success("Message decrypted and verified.")
            st.code(output)

        st.markdown('</div>', unsafe_allow_html=True)

# ── Intercept ──────────────────────────────────────────────────────────────────

elif page == "Intercept Attack":
    st.markdown("""
<div class="page-course">SOEN 321 — Information Systems Security &nbsp;·&nbsp; Winter 2026 &nbsp;·&nbsp; Concordia University</div>
<div class="page-title">Intercept Attack</div>
<div class="page-sub">Simulate a third party attempting to read an encrypted message</div>
<hr style="border-color:#D8D0C0;margin:16px 0 20px 0">
""", unsafe_allow_html=True)

    users = get_users()
    all_msgs = get_all_messages()

    if not users or not all_msgs:
        st.info("Generate keys and send a message first.")
    else:
        st.markdown('<div class="card"><div class="card-title">Attack Simulation</div>', unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            attacker = st.selectbox("Attacker", users)
        with col2:
            msg_labels = [f"{m['sender']} → {m['recipient']} ({m['timestamp']})" for m in all_msgs]
            selected_idx = st.selectbox("Target message", range(len(msg_labels)), format_func=lambda i: msg_labels[i])
            selected_msg = all_msgs[selected_idx]

        if st.button("Launch Intercept Attack"):
            with st.spinner("Attempting interception..."):
                output = capture_output(intercept_message, attacker, selected_msg["path"])
            if "DECRYPTION FAILED" in output or "held secure" in output:
                st.error("Attack failed — system held secure.")
            else:
                st.warning("Unexpected result.")
            st.code(output)

        st.markdown('</div>', unsafe_allow_html=True)

# ── Tamper Demo ────────────────────────────────────────────────────────────────

elif page == "Tamper Demo":
    st.markdown("""
<div class="page-course">SOEN 321 — Information Systems Security &nbsp;·&nbsp; Winter 2026 &nbsp;·&nbsp; Concordia University</div>
<div class="page-title">Tamper Demo</div>
<div class="page-sub">Alter a message in transit and watch the system detect it</div>
<hr style="border-color:#D8D0C0;margin:16px 0 20px 0">
""", unsafe_allow_html=True)

    all_msgs = [m for m in get_all_messages() if not m["tampered"]]
    users = get_users()

    if not all_msgs:
        st.info("No messages found. Send a message first.")
    else:
        st.markdown('<div class="card"><div class="card-title">Step 1 — Tamper with a message</div>', unsafe_allow_html=True)
        msg_labels = [f"{m['sender']} → {m['recipient']} ({m['timestamp']})" for m in all_msgs]
        selected_idx = st.selectbox("Select message to tamper", range(len(msg_labels)), format_func=lambda i: msg_labels[i])
        selected_msg = all_msgs[selected_idx]

        if st.button("Tamper Message"):
            with st.spinner("Altering message bytes..."):
                output = capture_output(tamper_message, selected_msg["path"])
            st.warning("Message has been tampered with.")
            st.code(output)
            st.session_state["tampered_path"] = selected_msg["path"].replace(".enc", "_tampered.enc")
            st.session_state["tampered_recipient"] = selected_msg["recipient"]

        st.markdown('</div>', unsafe_allow_html=True)

        if "tampered_path" in st.session_state and os.path.exists(st.session_state["tampered_path"]):
            st.markdown('<div class="card"><div class="card-title">Step 2 — Try to decrypt the tampered message</div>', unsafe_allow_html=True)
            recipient = st.session_state["tampered_recipient"]
            st.markdown(f"Recipient: **{recipient}**")

            if st.button("Attempt Decryption"):
                with st.spinner("Decrypting..."):
                    output = capture_output(decrypt_message, recipient, st.session_state["tampered_path"])
                st.error("Tamper detected — decryption rejected by AES-GCM authentication.")
                st.code(output)

            st.markdown('</div>', unsafe_allow_html=True)

# ── Reset ──────────────────────────────────────────────────────────────────────

elif page == "Reset":
    st.markdown("""
<div class="page-course">SOEN 321 — Information Systems Security &nbsp;·&nbsp; Winter 2026 &nbsp;·&nbsp; Concordia University</div>
<div class="page-title">Reset</div>
<div class="page-sub">Delete all keys and messages</div>
<hr style="border-color:#D8D0C0;margin:16px 0 20px 0">
""", unsafe_allow_html=True)

    st.markdown('<div class="card"><div class="card-title">⚠️ Danger Zone</div>', unsafe_allow_html=True)
    st.warning("This will permanently delete all keys and messages. This cannot be undone.")

    confirm = st.text_input("Type **RESET** to confirm", placeholder="RESET")

    if st.button("Delete Everything"):
        if confirm == "RESET":
            deleted = []
            for folder in ["keys", "messages"]:
                if os.path.exists(folder):
                    shutil.rmtree(folder)
                    deleted.append(folder)
            if deleted:
                st.success(f"Deleted: {', '.join(deleted)}")
                st.session_state.clear()
            else:
                st.info("Nothing to delete.")
        else:
            st.error("Type RESET exactly to confirm.")

    st.markdown('</div>', unsafe_allow_html=True)