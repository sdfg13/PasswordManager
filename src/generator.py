import secrets
import string


def generate_password(length: int = 16, use_digits: bool = True, use_special: bool = True) -> str:
    """
    Генерирует надежный случайный пароль.
    :param length: Длина пароля.
    :param use_digits: Включать ли цифры (0-9).
    :param use_special: Включать ли специальные символы (!@#$%^&*).
    :return: Сгенерированная строка пароля.
    """
    # Базовый набор символов — латиница (верхний и нижний регистр)
    chars = string.ascii_letters

    if use_digits:
        chars += string.digits
    if use_special:
        chars += string.punctuation

    # Генерируем пароль, выбирая случайные символы из набора
    # Используем secrets.choice для криптографической стойкости
    password = ''.join(secrets.choice(chars) for _ in range(length))

    return password