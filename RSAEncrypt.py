import streamlit as st
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

# Function to load private key from string
def load_private_key_from_string(private_key_str):
    if not private_key_str.startswith("-----BEGIN PRIVATE KEY-----"):
        private_key_str = f"-----BEGIN PRIVATE KEY-----\n{private_key_str}"
    if not private_key_str.endswith("-----END PRIVATE KEY-----"):
        private_key_str = f"{private_key_str}\n-----END PRIVATE KEY-----"
    private_key_bytes = private_key_str.encode()
    return serialization.load_pem_private_key(private_key_bytes, password=None)

# Function to decrypt message
def decrypt_message(encrypted_message, private_key_str):
    private_key = load_private_key_from_string(private_key_str)
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# Function to generate RSA keys
def generate_rsa_keys(key_size):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_private_key, pem_public_key

# Function to load public key from string
def load_public_key_from_string(public_key_str):
    public_key_bytes = f"-----BEGIN PUBLIC KEY-----\n{public_key_str}\n-----END PUBLIC KEY-----".encode()
    return serialization.load_pem_public_key(public_key_bytes)

# Function to encrypt message
def encrypt_message(message, public_key_str):
    public_key = load_public_key_from_string(public_key_str)
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Streamlit app layout
st.title("RSA Encryption & Decryption")

st.sidebar.header("Options")
option = st.sidebar.selectbox("Choose an option", ["Generate Keys", "Encrypt Message", "Decrypt Message"])

if option == "Generate Keys":
    st.header("Generate RSA Keys")
    key_size = st.select_slider("Select Key Size (bits)", options=[2048, 3072, 4096, 8192, 12288, 16384, 24576, 32768], value=2048)
    if st.button("Generate Keys"):
        private_key, public_key = generate_rsa_keys(key_size)
        public_key_one_line = public_key.decode().replace("\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
        private_key_one_line = private_key.decode().replace("\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")
        st.text_area("Private Key", private_key_one_line)
        st.text_area("Public Key", public_key_one_line)

elif option == "Encrypt Message":
    st.header("Encrypt Message")
    public_key = st.text_area("Public Key")
    message = st.text_area("Message to Encrypt")
    if st.button("Encrypt"):
        try:
            encrypted_message = encrypt_message(message, public_key)
            encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
            st.text_area("Encrypted Message", encrypted_message_b64)
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")

elif option == "Decrypt Message":
    st.header("Decrypt Message")
    private_key = st.text_area("Private Key")
    encrypted_message = st.text_area("Encrypted Message (Base64)")
    if st.button("Decrypt"):
        try:
            encrypted_message_bytes = base64.b64decode(encrypted_message.encode())
            decrypted_message = decrypt_message(encrypted_message_bytes, private_key)
            st.text_area("Decrypted Message", decrypted_message)
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
