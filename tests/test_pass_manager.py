import pytest
import os
import json
from cryptography.fernet import InvalidToken
from src.generator import generate_password
from src.crypto import get_key, encrypt_data, decrypt_data
from src.vault import PasswordEntry, Vault

# UNIT TESTS

def test_password_generator_length():
    """Позитивный тест генератора: проверка длины и символов"""
    # Arrange
    required_length = 16

    # Act
    password = generate_password(length=required_length)

    # Assert
    assert len(password) == required_length
    assert any(c.isdigit() for c in password)
    assert any(c.isupper() for c in password)

def test_password_entry_to_dict():
    """Тест структуры данных: корректность преобразования в словарь."""
    # Arrange
    entry = PasswordEntry(service="github.com", login="user123", password="safe_password")

    # Act
    result_dict = entry.to_dict()

    # Assert
    assert result_dict == {
        "service": "github.com",
        "login": "user123",
        "password": "safe_password"
    }


def test_get_key_generation():
    """Тест криптографии: генерация ключа детерминирована и возвращает байты."""
    # Arrange
    master_password = "MyMasterPassword"
    salt = b"constant_16_bytes"

    # Act
    key_1 = get_key(master_password, salt)
    key_2 = get_key(master_password, salt)

    # Assert
    assert isinstance(key_1, bytes)
    assert key_1 == key_2


def test_encrypt_decrypt_cycle():
    """Тест криптографии: успешный цикл шифрования и дешифрования строки."""
    # Arrange
    original_text = '{"secret": "data"}'
    key = get_key("password", b"random_salt_bytes")

    # Act
    encrypted = encrypt_data(original_text, key)
    decrypted = decrypt_data(encrypted, key)

    # Assert
    assert encrypted != original_text.encode()  # Данные действительно зашифрованы
    assert decrypted == original_text  # Данные успешно восстановлены


def test_decrypt_with_wrong_key_raises_error():
    """Негативный тест криптографии: дешифрование неверным мнемоническим ключом."""
    # Arrange
    original_text = "Secret Data"
    correct_key = get_key("correct_pass", b"salt_salt_salt_sa")
    wrong_key = get_key("wrong_pass", b"salt_salt_salt_sa")
    encrypted = encrypt_data(original_text, correct_key)

    # Act & Assert
    # Библиотека Fernet при неверном ключе должна выбросить InvalidToken
    with pytest.raises(InvalidToken):
        decrypt_data(encrypted, wrong_key)


def test_vault_add_entry_and_get_all():
    """Тест логики Vault: добавление записей в память без работы с диском."""
    # Arrange
    vault = Vault()
    entry1 = PasswordEntry("google.com", "login1", "pass1")
    entry2 = PasswordEntry("yandex.ru", "login2", "pass2")

    # Act
    vault.add_entry(entry1)
    vault.add_entry(entry2)
    all_entries = vault.get_all()

    # Assert
    assert len(all_entries) == 2
    assert all_entries[0].service == "google.com"
    assert all_entries[1].login == "login2"


# INTEGRATION TESTS

def test_vault_save_and_load_success(tmp_path, monkeypatch):
    """Позитивный интеграционный тест: полный цикл сохранения и загрузки из файла."""
    # Arrange
    # Временно переносим рабочую директорию во временную папку, чтобы не создавать 'data' в корне проекта
    monkeypatch.chdir(tmp_path)

    salt = b"test_salt_16_byte"
    key = get_key("master_pass", salt)
    filename = "passwords.bin"

    vault_to_save = Vault()
    entry = PasswordEntry("vk.com", "vk_user", "vk_pass")
    vault_to_save.add_entry(entry)

    # Act
    vault_to_save.save_to_file(filename, key)

    vault_to_load = Vault()
    vault_to_load.load_from_file(filename, key)
    loaded_entries = vault_to_load.get_all()

    # Assert
    assert len(loaded_entries) == 1
    assert loaded_entries[0].service == "vk.com"
    assert loaded_entries[0].login == "vk_user"
    assert loaded_entries[0].password == "vk_pass"
    assert os.path.exists(os.path.join("data", filename))  # Проверяем физическое создание файла


def test_vault_load_wrong_password_raises_value_error(tmp_path, monkeypatch):
    """Негативный интеграционный тест: загрузка файла с неверным ключом."""
    # Arrange
    monkeypatch.chdir(tmp_path)
    salt = b"test_salt_16_byte"
    correct_key = get_key("correct_password", salt)
    wrong_key = get_key("attacker_password", salt)
    filename = "vault.bin"

    vault = Vault()
    vault.add_entry(PasswordEntry("secure.bank", "admin", "token"))
    vault.save_to_file(filename, correct_key)

    # Act & Assert
    # Твой код в vault.py перехватывает ошибку Fernet и кидает ValueError с понятным текстом
    new_vault = Vault()
    with pytest.raises(ValueError, match="Неверный мастер-пароль или поврежденные данные"):
        new_vault.load_from_file(filename, wrong_key)


def test_vault_load_nonexistent_file(tmp_path, monkeypatch):
    """Негативный интеграционный тест: попытка загрузить файл, которого нет на диске."""
    # Arrange
    monkeypatch.chdir(tmp_path)
    key = get_key("any_password", b"some_salt_bytes_")
    vault = Vault()

    # Act
    # Метод должен просто завершить выполнение через return, не вызывая падения
    vault.load_from_file("ghost_file.bin", key)

    # Assert
    assert len(vault.get_all()) == 0