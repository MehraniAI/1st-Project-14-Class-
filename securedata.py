import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import os
import pickle
from pathlib import Path
import secrets

# This must be the first Streamlit command 
st.set_page_config(page_title="Secure Data Encryption", layout="wide")

# Constants
MAX_ATTEMPTS = 3
DATA_FILE = "secure_data.pkl"
KEY_FILE = "secret.key"

# Header
st.markdown('<h1 style="color:blue">Prepared by Devan Das Mehrani AI Student</h1>', unsafe_allow_html=True)

# Title
st.title("Secure Data Encryption")

# Key generation/loading
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
        st.error(f"Failed to generate key: {e}")
        return None

# Secure data storage with error handling
def load_data():
    try:
        if Path(DATA_FILE).exists():
            with open(DATA_FILE, "rb") as data_file:
                return pickle.load(data_file)
    except Exception as e:
        st.error(f"Failed to load data: {e}")
    return {"stored_data": {}, "failed_attempts": 0}

def save_data(data):
    try:
        with open(DATA_FILE, "wb") as data_file:
            pickle.dump(data, data_file)
    except Exception as e:
        st.error(f"Failed to save data: {e}")

# Initialize with error checking
KEY = load_or_generate_key()
if not KEY:
    st.error("Critical error: Failed to initialize encryption key")
    st.stop()

try:
    cipher = Fernet(KEY)
except Exception as e:
    st.error(f"Failed to initialize cipher: {e}")
    st.stop()

app_data = load_data()

# Session state initialization
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = app_data.get("stored_data", {})
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = app_data.get("failed_attempts", 0)

# Improved security functions
def hash_passkey(passkey, salt=None):
    if not passkey:
        raise ValueError("Passkey cannot be empty")
    if salt is None:
        salt = secrets.token_bytes(16)  # More secure than os.urandom
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000), salt

def encrypt_data(text, passkey):
    if not text:
        raise ValueError("Text cannot be empty")
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    if not encrypted_text or not passkey:
        return None
        
    try:
        # First verify the passkey
        for entry in st.session_state.stored_data.values():
            if entry["encrypted_text"] == encrypted_text:
                key_derived, _ = hash_passkey(passkey, entry["salt"])
                if key_derived == entry["hashed_passkey"]:
                    # Only decrypt if passkey is correct
                    decrypted = cipher.decrypt(encrypted_text.encode()).decode()
                    st.session_state.failed_attempts = 0
                    save_data({
                        "stored_data": st.session_state.stored_data,
                        "failed_attempts": st.session_state.failed_attempts
                    })
                    return decrypted
        
        st.session_state.failed_attempts += 1
        save_data({
            "stored_data": st.session_state.stored_data,
            "failed_attempts": st.session_state.failed_attempts
        })
        return None
    except Exception as e:
        st.session_state.failed_attempts += 1
        save_data({
            "stored_data": st.session_state.stored_data,
            "failed_attempts": st.session_state.failed_attempts
        })
        return None

# Streamlit UI with improved layout
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to securely store and retrieve data using unique passkeys.")
    st.warning("Important: Never share your passkeys with anyone!")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    with st.form("store_form"):
        user_data = st.text_area("Enter Data:", height=150)
        passkey = st.text_input("Enter Passkey:", type="password")
        confirm_passkey = st.text_input("Confirm Passkey:", type="password")
        
        if st.form_submit_button("Encrypt & Save"):
            if not user_data or not passkey:
                st.error("All fields are required!")
            elif passkey != confirm_passkey:
                st.error("Passkeys don't match!")
            elif len(passkey) < 8:
                st.error("Passkey must be at least 8 characters long!")
            else:
                try:
                    hashed_passkey, salt = hash_passkey(passkey)
                    encrypted_text = encrypt_data(user_data, passkey)
                    
                    entry_id = secrets.token_hex(32)
                    st.session_state.stored_data[entry_id] = {
                        "encrypted_text": encrypted_text,
                        "hashed_passkey": hashed_passkey,
                        "salt": salt
                    }
                    
                    save_data({
                        "stored_data": st.session_state.stored_data,
                        "failed_attempts": st.session_state.failed_attempts
                    })
                    
                    st.success("✅ Data stored securely!")
                    st.code(encrypted_text, language="text")
                    st.info("Copy and save this encrypted data along with your passkey")
                except Exception as e:
                    st.error(f"Error: {str(e)}")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    with st.form("retrieve_form"):
        encrypted_text = st.text_area("Enter Encrypted Data:", height=150)
        passkey = st.text_input("Enter Passkey:", type="password")
        
        if st.form_submit_button("Decrypt"):
            if not encrypted_text or not passkey:
                st.error("Both fields are required!")
            elif st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.warning("🔒 Too many failed attempts! Please login.")
                choice = "Login"
                st.experimental_rerun()
            else:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                
                if decrypted_text:
                    st.success("✅ Decrypted successfully!")
                    st.text_area("Decrypted Data:", value=decrypted_text, height=200)
                else:
                    remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"❌ Decryption failed! Attempts remaining: {remaining}")
                    
                    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        choice = "Login"
                        st.experimental_rerun()

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    with st.form("login_form"):
        login_pass = st.text_input("Enter Master Password:", type="password")
        
        if st.form_submit_button("Login"):
            # You should replace this with a proper password verification mechanism
            # Currently it just checks if any password was entered
            if login_pass:  # This is insecure - replace with proper password check
                st.session_state.failed_attempts = 0
                save_data({
                    "stored_data": st.session_state.stored_data,
                    "failed_attempts": st.session_state.failed_attempts
                })
                st.success("✅ Reauthorized successfully!")
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect password!")