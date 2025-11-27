# run.py
import streamlit as st
import sys
import os

# Add the app directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

def main():
    # Set page configuration
    st.set_page_config(
        page_title="Privileged Rapper Inc. - Security Platform",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Import and run the main app
    from app.main import PrivilegedRapperApp
    app = PrivilegedRapperApp()
    app.run()

if __name__ == "__main__":
    main()