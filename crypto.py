import base64
import pickle

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes


def passwd_to_key(passwd):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(passwd)
    return base64.urlsafe_b64encode(digest.finalize())


def encrypt(data, passwd):
    key = passwd_to_key(passwd)
    f = Fernet(key)
    serialized = pickle.dumps(data)
    return f.encrypt(serialized).decode()

def decrypt(token, passwd):
    try:
        key = passwd_to_key(passwd)
        f = Fernet(key)
        decrypted_bytes = f.decrypt(token.encode())
        return pickle.loads(decrypted_bytes)
    except InvalidToken:
        return None
