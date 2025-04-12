import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import pickle
from pathlib import Path
import secrets

# This must be the first Streamlit command 
st.set_page_config(page_title="Secure Data Encryption", layout="wide")

# Constants
MAX_ATTEMPTS = 3
DATA_FILE = "secure_data.pkl"
KEY_FILE = "secret.key"
MASTER_PASSWORD_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # hash of "password"

# Header
st.markdown('<h1 style="color:blue">Prepared by Devan Das Mehrani AI Student</h1>', unsafe_allow_html=True)

# Title
st.title("Secure Data Encryption")

# Key generation/loading with improved error handling
def load_or_generate_key():
    try:
        if Path(KEY_FILE).exists():
            try:
                with open(KEY_FILE, "rb") as key_file:
                    return key_file.read()
            except PermissionError:
                st.error("Permission denied when accessing key file")
                return None
        else:
            key = Fernet.generate_key()
            try:
                with open(KEY_FILE, "wb") as key_file:
                    key_file.write(key)
                return key
            except PermissionError:
                st.error("Permission denied when creating key file")
                return None
    except Exception as e:
        st.error(f"Failed to generate key: {e}")
        return None

# Secure data storage with enhanced error handling
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

# Password complexity checker
def is_password_complex(password):
    return (len(password) >= 8 and 
            any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password))

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
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

# Security functions
def hash_passkey(passkey, salt=None):
    if not passkey:
        raise ValueError("Passkey cannot be empty")
    if salt is None:
        salt = secrets.token_bytes(16)
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000), salt

def encrypt_data(text):
    if not text:
        raise ValueError("Text cannot be empty")
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    if not encrypted_text:
        return None
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation - only show options based on authentication
if st.session_state.authenticated:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
else:
    menu = ["Home", "Login"]

choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to securely store and retrieve data using unique passkeys.")
    st.warning("Important: Never share your passkeys with anyone!")
    
    if st.session_state.authenticated:
        st.success("You are currently logged in")
    else:
        st.warning("Please login to access all features")

elif choice == "Store Data" and st.session_state.authenticated:
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
            elif not is_password_complex(passkey):
                st.error("Password must be at least 8 characters with uppercase, lowercase, and numbers")
            else:
                try:
                    hashed_passkey, salt = hash_passkey(passkey)
                    encrypted_text = encrypt_data(user_data)
                    
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

elif choice == "Retrieve Data" and st.session_state.authenticated:
    st.subheader("🔍 Retrieve Your Data")
    with st.form("retrieve_form"):
        encrypted_text = st.text_area("Enter Encrypted Data:", height=150)
        passkey = st.text_input("Enter Passkey:", type="password")
        
        if st.form_submit_button("Decrypt"):
            if not encrypted_text or not passkey:
                st.error("Both fields are required!")
            elif st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.session_state.authenticated = False
                st.warning("🔒 Too many failed attempts! Please login again.")
                st.experimental_rerun()
            else:
                decrypted_text = None
                
                # Verify passkey and decrypt
                for entry in st.session_state.stored_data.values():
                    if entry["encrypted_text"] == encrypted_text:
                        key_derived, _ = hash_passkey(passkey, entry["salt"])
                        if key_derived == entry["hashed_passkey"]:
                            decrypted_text = decrypt_data(encrypted_text)
                            break
                
                if decrypted_text:
                    st.session_state.failed_attempts = 0
                    save_data({
                        "stored_data": st.session_state.stored_data,
                        "failed_attempts": st.session_state.failed_attempts
                    })
                    st.success("✅ Decrypted successfully!")
                    st.text_area("Decrypted Data:", value=decrypted_text, height=200)
                else:
                    st.session_state.failed_attempts += 1
                    save_data({
                        "stored_data": st.session_state.stored_data,
                        "failed_attempts": st.session_state.failed_attempts
                    })
                    remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"❌ Decryption failed! Attempts remaining: {remaining}")
                    
                    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                        st.session_state.authenticated = False
                        st.warning("🔒 Too many failed attempts! You have been logged out.")
                        st.experimental_rerun()

elif choice == "Login" and not st.session_state.authenticated:
    st.subheader("🔑 Authentication Required")
    with st.form("login_form"):
        login_pass = st.text_input("Enter Master Password:", type="password")
        
        if st.form_submit_button("Login"):
            if hashlib.sha256(login_pass.encode()).hexdigest() == MASTER_PASSWORD_HASH:
                st.session_state.failed_attempts = 0
                st.session_state.authenticated = True
                save_data({
                    "stored_data": st.session_state.stored_data,
                    "failed_attempts": st.session_state.failed_attempts
                })
                st.success("✅ Login successful!")
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect password!")

elif choice == "Logout" and st.session_state.authenticated:
    st.session_state.authenticated = False
    st.success("You have been logged out successfully")
    st.experimental_rerun()

# Requirements for deployment (this is a comment - create requirements.txt file separately)
# streamlit>=1.22.0
# cryptography>=38.0.0
