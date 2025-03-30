import streamlit as st
import json
import os
from datetime import datetime

class ATM:
    def __init__(self):
        self.accounts_file = 'accounts.json'
        self.accounts = self._load_accounts()
        self.current_account = None

    def _load_accounts(self):
        return json.load(open(self.accounts_file)) if os.path.exists(self.accounts_file) else {}

    def _save_accounts(self):
        json.dump(self.accounts, open(self.accounts_file, 'w'), indent=2)

    def create_account(self, account_num, pin, name):
        if account_num in self.accounts: return False
        self.accounts[account_num] = {'pin': pin, 'name': name, 'balance': 0, 'transactions': []}
        self._save_accounts()
        return True

    def login(self, account_num, pin):
        if account_num in self.accounts and self.accounts[account_num]['pin'] == pin:
            self.current_account = account_num
            return True
        return False

    def deposit(self, amount):
        if amount <= 0: return False
        self.accounts[self.current_account]['balance'] += amount
        self._record_transaction('deposit', amount)
        self._save_accounts()
        return True

    def withdraw(self, amount):
        if amount <= 0 or amount > self.accounts[self.current_account]['balance']: return False
        self.accounts[self.current_account]['balance'] -= amount
        self._record_transaction('withdrawal', amount)
        self._save_accounts()
        return True

    def _record_transaction(self, type, amount):
        self.accounts[self.current_account]['transactions'].append({
            'type': type, 'amount': amount, 'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'balance': self.accounts[self.current_account]['balance']
        })

    def get_balance(self): return self.accounts[self.current_account]['balance']
    def get_transactions(self): return self.accounts[self.current_account]['transactions'][-5:]
    def get_all_accounts(self): return self.accounts  # New method to get all accounts

def main():
    st.title("ATM System")
    if 'atm' not in st.session_state: st.session_state.atm = ATM()

    # Add admin password (insecure for demo - use environment variables in production)
    ADMIN_PASSWORD = "admin123"
    
    menu_options = ["Home", "Create Account", "Login", "Account"]
    
    # Add View Accounts option if admin is logged in
    if hasattr(st.session_state, 'is_admin') and st.session_state.is_admin:
        menu_options.append("View Accounts")
    
    menu = st.sidebar.radio("Menu", menu_options)

    # Add admin login in the sidebar
    if not hasattr(st.session_state, 'is_admin'):
        st.sidebar.subheader("Admin Login")
        admin_pw = st.sidebar.text_input("Admin Password", type="password")
        if st.sidebar.button("Admin Login"):
            if admin_pw == ADMIN_PASSWORD:
                st.session_state.is_admin = True
                st.sidebar.success("Admin logged in!")
                st.rerun()
            else:
                st.sidebar.error("Invalid admin password")

    if menu == "Home":
        st.write("Welcome to Simple ATM. Select an option from the sidebar.")

    elif menu == "Create Account":
        st.subheader("Create Account")
        account_num = st.text_input("Account Number")
        pin = st.text_input("PIN", type="password")
        name = st.text_input("Name")
        if st.button("Create"):
            if account_num and pin and name:
                if st.session_state.atm.create_account(account_num, pin, name):
                    st.success("Account created!")
                else: st.error("Account exists")
            else: st.warning("Fill all fields")

    elif menu == "Login":
        st.subheader("Login")
        account_num = st.text_input("Account Number")
        pin = st.text_input("PIN", type="password")
        if st.button("Login"):
            if st.session_state.atm.login(account_num, pin):
                st.session_state.logged_in = True
                st.success("Logged in!")
                st.rerun()
            else: st.error("Invalid credentials")

    elif menu == "Account" and hasattr(st.session_state, 'logged_in') and st.session_state.logged_in:
        atm = st.session_state.atm
        st.subheader(f"Welcome, {atm.accounts[atm.current_account]['name']}")
        
        col1, col2 = st.columns(2)
        col1.metric("Balance", f"${atm.get_balance():.2f}")
        if col2.button("Logout"):
            st.session_state.logged_in = False
            st.rerun()

        action = st.selectbox("Action", ["", "Deposit", "Withdraw", "Transactions"])
        if action == "Deposit":
            amount = st.number_input("Amount", min_value=0.01)
            if st.button("Deposit") and atm.deposit(amount):
                st.success(f"Deposited ${amount:.2f}")
                st.rerun()

        elif action == "Withdraw":
            amount = st.number_input("Amount", min_value=0.01, max_value=atm.get_balance())
            if st.button("Withdraw") and atm.withdraw(amount):
                st.success(f"Withdrew ${amount:.2f}")
                st.rerun()

        elif action == "Transactions":
            st.write("Last 5 transactions:")
            for t in reversed(atm.get_transactions()):
                st.write(f"{t['date']} - {t['type']}: ${t['amount']:.2f}")

    elif menu == "View Accounts" and hasattr(st.session_state, 'is_admin') and st.session_state.is_admin:
        st.subheader("All Accounts")
        accounts = st.session_state.atm.get_all_accounts()
        
        if st.button("Refresh Accounts"):
            st.rerun()
            
        if accounts:
            for account_num, details in accounts.items():
                with st.expander(f"Account: {account_num} - {details['name']}"):
                    st.write(f"Balance: ${details['balance']:.2f}")
                    st.write(f"PIN: {details['pin']}")  # Note: Showing PIN is a security risk in real apps
                    
                    st.subheader("Last 5 Transactions")
                    for t in reversed(details['transactions'][-5:]):
                        st.write(f"{t['date']} - {t['type']}: ${t['amount']:.2f} (Balance: ${t['balance']:.2f})")
        else:
            st.warning("No accounts found")
            
        if st.sidebar.button("Admin Logout"):
            st.session_state.is_admin = False
            st.rerun()

if __name__ == "__main__":
    main()