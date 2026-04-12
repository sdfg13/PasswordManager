import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
                             QLineEdit, QLabel, QMessageBox, QInputDialog, QHeaderView)
from crypto import get_key
from vault import Vault, PasswordEntry
from generator import generate_password


class MainWindow(QMainWindow):
    def __init__(self, master_password, salt):
        super().__init__()
        self.master_password = master_password
        self.salt = salt
        self.key = get_key(master_password, salt)
        self.vault = Vault()
        self.vault_file = "vault.bin"

        # Пытаемся загрузить данные сразу при входе
        try:
            self.vault.load_from_file(self.vault_file, self.key)
        except Exception:
            pass  # Если файла нет, просто начнем с пустого списка

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Хранилище паролей")
        self.resize(700, 500)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # --- Панель инструментов (Поиск и Генератор) ---
        top_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Поиск сервиса...")
        self.search_input.textChanged.connect(self.update_table)

        gen_btn = QPushButton("Сгенерировать пароль")
        gen_btn.clicked.connect(self.show_generated_password)

        top_layout.addWidget(QLabel("🔍"))
        top_layout.addWidget(self.search_input)
        top_layout.addWidget(gen_btn)
        main_layout.addLayout(top_layout)

        # --- Таблица паролей ---
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Сервис", "Логин", "Пароль"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        main_layout.addWidget(self.table)

        # --- Кнопки управления ---
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Добавить запись")
        add_btn.clicked.connect(self.add_entry_dialog)

        save_btn = QPushButton("Сохранить изменения")
        save_btn.clicked.connect(self.save_vault)

        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(save_btn)
        main_layout.addLayout(btn_layout)

        self.update_table()

    def update_table(self):
        self.table.setRowCount(0)
        query = self.search_input.text().lower()

        for entry in self.vault.get_all():
            if query in entry.service.lower() or query in entry.login.lower():
                row = self.table.rowCount()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(entry.service))
                self.table.setItem(row, 1, QTableWidgetItem(entry.login))
                self.table.setItem(row, 2, QTableWidgetItem(entry.password))

    def add_entry_dialog(self):
        # В реальном приложении лучше сделать отдельное окно,
        # но для краткости используем простые диалоги ввода
        service, ok1 = QInputDialog.getText(self, "Новая запись", "Введите сервис (напр. GitHub):")
        login, ok2 = QInputDialog.getText(self, "Новая запись", "Введите логин:")
        password, ok3 = QInputDialog.getText(self, "Новая запись",
                                             "Введите пароль (или оставьте пустым для генерации):")

        if ok1 and ok2:
            if not password:
                password = generate_password()
            self.vault.add_entry(PasswordEntry(service, login, password))
            self.update_table()

    def show_generated_password(self):
        pw = generate_password()
        QMessageBox.information(self, "Генератор", f"Ваш надежный пароль:\n\n{pw}\n\n(Скопировано в буфер обмена)")
        clipboard = QApplication.clipboard()
        clipboard.setText(pw)

    def save_vault(self):
        self.vault.save_to_file(self.vault_file, self.key)
        QMessageBox.information(self, "Успех", "Данные зашифрованы и сохранены!")


# --- Логика запуска с проверкой Соли ---
if __name__ == "__main__":
    app = QApplication(sys.argv)

    salt_path = "data/salt.dat"
    os.makedirs('data', exist_ok=True)

    if not os.path.exists(salt_path):
        # Первый запуск — создаем соль
        salt = os.urandom(16)
        with open(salt_path, "wb") as f:
            f.write(salt)
        QMessageBox.information(None, "Первый запуск", "Создан новый файл ключа. Запомните ваш мастер-пароль!")
    else:
        with open(salt_path, "rb") as f:
            salt = f.read()

    password, ok = QInputDialog.getText(None, "Вход", "Введите мастер-пароль:", QLineEdit.Password)

    if ok and password:
        window = MainWindow(password, salt)
        window.show()
        sys.exit(app.exec_())
    else:
        sys.exit()