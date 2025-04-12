# 📦 ALL IMPORTS AT THE TOP
import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import os
import pickle
from pathlib import Path
import secrets

# ⚙️ Streamlit Setup
st.set_page_config(page_title="Secure Data Encryption", layout="wide")

# 📁 Constants
MAX_ATTEMPTS = 3
DATA_FILE = "secure_data.pkl"
KEY_FILE = "secret.key"

# 🧠 Load or generate encryption key
def load_or_generate_key():
    if Path(KEY_FILE).exists():
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

# 💾 Load stored encrypted data
def load_data():
    if Path(DATA_FILE).exists():
        with open(DATA_FILE, "rb") as f:
            return pickle.load(f)
    return {"stored_data": {}, "failed_attempts": 0}

# 💾 Save encrypted data
def save_data(data):
    with open(DATA_FILE, "wb") as f:
        pickle.dump(data, f)

# 🔐 Hash passkey securely
def hash_passkey(passkey, salt=None):
    if not passkey:
        raise ValueError("Passkey cannot be empty")
    if salt is None:
        salt = secrets.token_bytes(16)
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000), salt

# 🔏 Encrypt text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# 🔓 Decrypt with validation
def decrypt_data(encrypted_text, passkey):
    for entry in st.session_state.stored_data.values():
        if entry["encrypted_text"] == encrypted_text:
            hashed, _ = hash_passkey(passkey, entry["salt"])
            if hashed == entry["hashed_passkey"]:
                st.session_state.failed_attempts = 0
                save_data({
                    "stored_data": st.session_state.stored_data,
                    "failed_attempts": st.session_state.failed_attempts
                })
                return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    save_data({
        "stored_data": st.session_state.stored_data,
        "failed_attempts": st.session_state.failed_attempts
    })
    return None

# 🔑 Initialize
KEY = load_or_generate_key()
cipher = Fernet(KEY)
app_data = load_data()

# 🧠 Session state
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = app_data["stored_data"]
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = app_data["failed_attempts"]

# 🧭 App Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("🔍 Menu", menu)

# 🏠 Home
if choice == "Home":
    st.markdown("## 🔐 Secure Data Encryption")
    st.markdown("Encrypt and safely store sensitive text using a secret passkey.")
    st.warning("⚠️ Don't forget your passkey! It's required for decryption.")

# 💾 Store Data
elif choice == "Store Data":
    st.subheader("📥 Store New Encrypted Data")
    with st.form("store_form"):
        user_data = st.text_area("Enter data to encrypt:")
        passkey = st.text_input("Enter a passkey:", type="password")
        confirm_passkey = st.text_input("Confirm passkey:", type="password")
        submitted = st.form_submit_button("Encrypt & Store")

        if submitted:
            if not user_data or not passkey:
                st.error("Please enter data and a passkey.")
            elif passkey != confirm_passkey:
                st.error("Passkeys do not match.")
            elif len(passkey) < 8:
                st.error("Passkey must be at least 8 characters.")
            else:
                try:
                    hashed_pass, salt = hash_passkey(passkey)
                    encrypted = encrypt_data(user_data)
                    entry_id = secrets.token_hex(16)

                    st.session_state.stored_data[entry_id] = {
                        "encrypted_text": encrypted,
                        "hashed_passkey": hashed_pass,
                        "salt": salt
                    }
                    save_data({
                        "stored_data": st.session_state.stored_data,
                        "failed_attempts": st.session_state.failed_attempts
                    })
                    st.success("✅ Data encrypted and stored.")
                    st.code(encrypted, language="text")
                except Exception as e:
                    st.error(f"Encryption failed: {e}")

# 🔍 Retrieve Data
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Encrypted Data")
    with st.form("retrieve_form"):
        encrypted_text = st.text_area("Paste encrypted data:")
        passkey = st.text_input("Enter your passkey:", type="password")
        submitted = st.form_submit_button("Decrypt")

        if submitted:
            if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.warning("🔒 Too many failed attempts. Login required.")
                st.rerun()
            elif not encrypted_text or not passkey:
                st.error("Both fields are required.")
            else:
                decrypted = decrypt_data(encrypted_text, passkey)
                if decrypted:
                    st.success("✅ Successfully decrypted!")
                    st.text_area("Decrypted Data", decrypted, height=150)
                else:
                    attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. {attempts_left} attempts remaining.")

# 🔑 Login (Reauthorization)
elif choice == "Login":
    st.subheader("🔐 Reauthorize")
    with st.form("login_form"):
        master_pass = st.text_input("Enter master password:", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            # You can improve this with a hashed master password check
            if master_pass == "admin123":
                st.session_state.failed_attempts = 0
                save_data({
                    "stored_data": st.session_state.stored_data,
                    "failed_attempts": 0
                })
                st.success("✅ Login successful.")
                st.rerun()
            else:
                st.error("❌ Incorrect master password.")
