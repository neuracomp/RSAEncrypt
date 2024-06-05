import streamlit as st
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
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

# Function to sign a message by hashing it and then encrypting the hash with the private key
def sign_message(message, private_key_str):
    private_key = load_private_key_from_string(private_key_str)
    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(message.encode())
    digest = message_hash.finalize()
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Function to verify a signature
def verify_signature(message, signature, public_key_str):
    public_key = load_public_key_from_string(public_key_str)
    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(message.encode())
    digest = message_hash.finalize()
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Streamlit app layout
st.title("RSA Encryption, Decryption, and Digital Signatures")

st.sidebar.header("Options")
option = st.sidebar.selectbox("Choose an option", ["Instructions", "Generate Keys", "Encrypt Message", "Decrypt Message", "Sign Message", "Verify Signature"])

if option == "Instructions":
    st.header("How to Use the RSA Encryption, Decryption, and Digital Signatures App")
    st.markdown("""
    This app allows you to generate RSA keys, encrypt messages using a public key, decrypt messages using a private key, and create and verify digital signatures.
    
    **Steps to Use the App:**
    
    1. **Generate Keys**:
        - Go to the "Generate Keys" tab.
        - Select the desired key size using the slider (2048, 3072, 4096, 8192, 12288, 16384, 24576, 32768 bits).
        - Click "Generate Keys".
        - Copy the generated keys and save them in a notepad for later use.
        
    2. **Encrypt Message**:
        - Go to the "Encrypt Message" tab.
        - Paste the public key (from the notepad) into the "Public Key" field.
        - Enter the message you want to encrypt in the "Message to Encrypt" field.
        - Click "Encrypt".
        - Copy the encrypted message from the output field and save it if needed.
        
    3. **Decrypt Message**:
        - Go to the "Decrypt Message" tab.
        - Paste the private key (from the notepad) into the "Private Key" field.
        - Paste the encrypted message (from the notepad) into the "Encrypted Message (Base64)" field.
        - Click "Decrypt".
        - The decrypted message will be displayed in the output field.
    
    4. **Sign Message**:
        - Go to the "Sign Message" tab.
        - Paste the private key (from the notepad) into the "Private Key" field.
        - Enter the message you want to sign in the "Message to Sign" field.
        - Click "Sign".
        - Copy the signature from the output field and save it if needed.
        
    5. **Verify Signature**:
        - Go to the "Verify Signature" tab.
        - Paste the public key (from the notepad) into the "Public Key" field.
        - Paste the message and the signature you want to verify into their respective fields.
        - Click "Verify".
        - The verification result will be displayed in the output field.
    
    **Note**: Ensure to keep your private key safe and do not share it with anyone. The public key can be shared freely for others to encrypt messages or verify signatures.
    """)

elif option == "Generate Keys":
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

elif option == "Sign Message":
    st.header("Sign Message")
    private_key = st.text_area("Private Key")
    message = st.text_area("Message to Sign")
    if st.button("Sign"):
        try:
            signature = sign_message(message, private_key)
            signature_b64 = base64.b64encode(signature).decode()
            st.text_area("Signature", signature_b64)
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")

elif option == "Verify Signature":
    st.header("Verify Signature")
    public_key = st.text_area("Public Key")
    message = st.text_area("Message")
    signature = st.text_area("Signature (Base64)")
    if st.button("Verify"):
        try:
            signature_bytes = base64.b64decode(signature.encode())
            is_valid = verify_signature(message, signature_bytes, public_key)
            if is_valid:
                st.success("The signature is valid.")
            else:
                st.error("The signature is invalid.")
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
