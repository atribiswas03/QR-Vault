from cryptography.fernet import Fernet
import qrcode
import io
from pyzbar.pyzbar import decode
from PIL import Image

# Encrypt string or bytes depending on content
def encrypt_data(data, key):
    f = Fernet(key)
    if isinstance(data, str):
        return f.encrypt(data.encode())
    elif isinstance(data, bytes):
        return f.encrypt(data)
    else:
        raise TypeError("Data must be str or bytes.")


# Decrypt and optionally return bytes or decoded string
def decrypt_data(token, key, as_text=True):
    f = Fernet(key)
    decrypted = f.decrypt(token)
    return decrypted.decode() if as_text else decrypted


# Generate QR from string data
def generate_qr_code(data):
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf


# Decode QR code from image to extract string
def decode_qr_code(image_file):
    try:
        img = Image.open(image_file).convert("RGB")
        decoded = decode(img)
        if decoded:
            data = decoded[0].data
            return data.decode('utf-8') if isinstance(data, bytes) else data
    except Exception as e:
        print(f"❌ QR decoding error: {e}")
    return None

