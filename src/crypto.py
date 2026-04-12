import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_key(master_password: str, salt: bytes) -> bytes:
    """Создает криптографический ключ из мастер-пароля и соли."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    # Превращаем пароль в байты и генерируем ключ
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def encrypt_data(data: str, key: bytes) -> bytes:
    """Шифрует строку."""
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Расшифровывает данные обратно в строку."""
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()