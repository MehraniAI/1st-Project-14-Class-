# =============================
# 📦 ALL IMPORTS AT THE TOP
# =============================
import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import os
import pickle
from pathlib import Path
import secrets

# =============================
# ⚙️ CONFIGURATION
# =============================
st.set_page_config(page_title="Secure Data Encryption", layout="wide")

MAX_ATTEMPTS = 3
DATA_FILE = "secure_data.pkl"
KEY_FILE = "secret.key"

st.markdown('<h1 style="color:blue">Prepared by Devan Das Mehrani AI Student</h1>', unsafe_allow_html=True)
st.title("🔐 Secure Data Encryption")

# =============================
# 🔑 KEY MANAGEMENT
# =============================
def load_or_generate_key():
    try:
        if Path(KEY_FILE).exists():
            with open(KEY_FILE, "rb") as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as key_file:
                key_file.write(key)
            return key
    except Exception as e:
        st.error(f"Key error: {e}")
        return None

# =============================
# 🧠 ENCRYPTION & HASHING
# =============================
def hash_passkey(passkey, salt=None):
    if not passkey:
        raise ValueError("Passkey cannot be empty")
    if salt is None:
        salt = secrets.token_bytes(16)
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000), salt

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    if not encrypted_text or not passkey:
        return None
    try:
        for entry in st.session_state.stored_data.values():
            if entry["encrypted_text"] == encrypted_text:
                derived_key, _ = hash_passkey(passkey, entry["salt"])
                if derived_key == entry["hashed_passkey"]:
                    st.session_state.failed_attempts = 0
                    save_data()
                    return cipher.decrypt(encrypted_text.encode()).decode()
        st.session_state.failed_attempts += 1
        save_data()
        return None
    except Exception:
        st.session_state.failed_attempts += 1
        save_data()
        return None

# =============================
# 📁 DATA STORAGE
# =============================
def load_data():
    if Path(DATA_FILE).exists():
        try:
            with open(DATA_FILE, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            st.error(f"Failed to load data: {e}")
    return {"stored_data": {}, "failed_attempts": 0}

def save_data():
    try:
        with open(DATA_FILE, "wb") as f:
            pickle.dump({
                "stored_data": st.session_state.stored_data,
                "failed_attempts": st.session_state.failed_attempts
            }, f)
    except Exception as e:
        st.error(f"Failed to save data: {e}")

# =============================
# 🚀 INITIALIZATION
# =============================
KEY = load_or_generate_key()
if not KEY:
    st.stop()
cipher = Fernet(KEY)

data = load_data()
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = data["stored_data"]
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = data["failed_attempts"]

# =============================
# 🧭 MAIN APP NAVIGATION
# =============================
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Store and retrieve encrypted data using a secure passkey.")
    st.warning("Never share your passkey.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    with st.form("store_form"):
        data_input = st.text_area("Enter data to encrypt", height=150)
        passkey = st.text_input("Passkey", type="password")
        confirm = st.text_input("Confirm Passkey", type="password")
        submitted = st.form_submit_button("Encrypt & Save")

        if submitted:
            if not data_input or not passkey:
                st.error("All fields are required.")
            elif passkey != confirm:
                st.error("Passkeys do not match.")
            elif len(passkey) < 8:
                st.error("Passkey must be at least 8 characters.")
            else:
                try:
                    hashed, salt = hash_passkey(passkey)
                    encrypted = encrypt_data(data_input)
                    entry_id = secrets.token_hex(16)
                    st.session_state.stored_data[entry_id] = {
                        "encrypted_text": encrypted,
                        "hashed_passkey": hashed,
                        "salt": salt
                    }
                    save_data()
                    st.success("✅ Data encrypted and stored.")
                    st.code(encrypted, language="text")
                except Exception as e:
                    st.error(f"Encryption failed: {e}")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    with st.form("retrieve_form"):
        encrypted_text = st.text_area("Paste your encrypted data", height=150)
        passkey = st.text_input("Enter your passkey", type="password")
        submitted = st.form_submit_button("Decrypt")

        if submitted:
            if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.warning("Too many failed attempts. Please reauthorize.")
                st.rerun()

            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decryption successful.")
                st.text_area("Decrypted Data", value=result, height=200)
            else:
                remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                st.error(f"Decryption failed. Attempts left: {remaining}")
                if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                    st.warning("🔒 Locked out. Redirecting to login.")
                    st.rerun()

elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    with st.form("login_form"):
        master_key = st.text_input("Enter master password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            if master_key:  # Replace this with real authentication logic
                st.session_state.failed_attempts = 0
                save_data()
                st.success("Access restored.")
                st.rerun()
            else:
                st.error("Invalid password.")
