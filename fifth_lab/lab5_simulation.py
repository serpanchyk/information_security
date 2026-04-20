from .dss import DSSManager

def generate_keys_ui(key_size_str):
    key_size = int(key_size_str)
    dss = DSSManager()
    priv, pub = dss.generate_keys(key_size)

    priv_path = "dsa_private.pem"
    pub_path = "dsa_public.pem"

    with open(priv_path, "wb") as f:
        f.write(priv)
    with open(pub_path, "wb") as f:
        f.write(pub)

    return priv_path, pub_path, "Keys generated successfully."

def sign_ui(input_text, input_file, priv_key_file):
    if not priv_key_file:
        return None, "Error: Private key file is required.", None

    with open(priv_key_file, "rb") as f:
        priv_data = f.read()

    dss = DSSManager()
    try:
        dss.load_private_key(priv_data)
    except Exception as e:
        return None, f"Error loading private key: {e}", None

    if input_file:
        with open(input_file, "rb") as f:
            data = f.read()
    else:
        data = input_text.encode('utf-8') if input_text else b""

    try:
        signature_hex = dss.sign(data)
        sig_path = "signature.hex"
        with open(sig_path, "w") as f:
            f.write(signature_hex)
        return signature_hex, "Signed successfully.", sig_path
    except Exception as e:
        return None, f"Error signing: {e}", None

def verify_ui(input_text, input_file, pub_key_file, sig_hex_text, sig_file):
    if not pub_key_file:
        return "Error: Public key file is required."

    with open(pub_key_file, "rb") as f:
        pub_data = f.read()

    dss = DSSManager()
    try:
        dss.load_public_key(pub_data)
    except Exception as e:
        return f"Error loading public key: {e}"

    if input_file:
        with open(input_file, "rb") as f:
            data = f.read()
    else:
        data = input_text.encode('utf-8') if input_text else b""

    sig_hex = ""
    if sig_file:
        with open(sig_file, "r") as f:
            sig_hex = f.read().strip()
    elif sig_hex_text:
        sig_hex = sig_hex_text.strip()
    else:
        return "Error: Signature is required (either text or file)."

    try:
        is_valid = dss.verify(data, sig_hex)
        return "✅ Signature is VERIFIED (Valid)" if is_valid else "❌ Signature is NOT VERIFIED (Invalid)"
    except Exception as e:
        return f"Error during verification: {e}"