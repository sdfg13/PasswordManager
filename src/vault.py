import json
import os
from dataclasses import dataclass, asdict
from crypto import encrypt_data, decrypt_data


@dataclass
class PasswordEntry:
    """Класс для хранения одной записи (сайт, логин, пароль)."""
    service: str
    login: str
    password: str

    def to_dict(self):
        return asdict(self)


class Vault:
    """Класс для управления всеми сохраненными данными."""

    def __init__(self):
        self.entries = []

    def add_entry(self, entry: PasswordEntry):
        self.entries.append(entry)

    def get_all(self):
        return self.entries

    def save_to_file(self, filename: str, key: bytes):
        """Превращает список в JSON, шифрует и сохраняет в файл."""
        # Готовим данные
        data_to_serialize = [e.to_dict() for e in self.entries]
        json_string = json.dumps(data_to_serialize)

        # Шифруем
        encrypted_content = encrypt_data(json_string, key)

        # Записываем
        os.makedirs('data', exist_ok=True)
        with open(os.path.join('data', filename), 'wb') as f:
            f.write(encrypted_content)

    def load_from_file(self, filename: str, key: bytes):
        """Читает зашифрованный файл, дешифрует и восстанавливает объекты."""
        path = os.path.join('data', filename)
        if not os.path.exists(path):
            return

        with open(path, 'rb') as f:
            encrypted_content = f.read()

        # Дешифруем и превращаем обратно в объекты
        try:
            decrypted_json = decrypt_data(encrypted_content, key)
            data_list = json.loads(decrypted_json)
            self.entries = [PasswordEntry(**item) for item in data_list]
        except Exception:
            # Если пароль неверный, дешифровка выдаст ошибку
            raise ValueError("Неверный мастер-пароль или поврежденные данные")