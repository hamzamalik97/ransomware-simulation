import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_FILE = "recovery_key.json"


def generate_key():
    return AESGCM.generate_key(bit_length=256)


def save_key(key):

    encoded_key = base64.b64encode(key).decode()

    with open(KEY_FILE, "w") as f:
        json.dump({"key": encoded_key}, f)


def load_key():

    if not os.path.exists(KEY_FILE):
        raise RuntimeError("Recovery key not found.")

    with open(KEY_FILE, "r") as f:
        data = json.load(f)

    return base64.b64decode(data["key"])


def encrypt_data(data, key):

    nonce = os.urandom(12)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        data,
        None
    )

    return nonce + ciphertext


def decrypt_data(data, key):

    nonce = data[:12]

    ciphertext = data[12:]

    aes = AESGCM(key)

    return aes.decrypt(
        nonce,
        ciphertext,
        None
    )
