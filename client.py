import sys
import threading
import grpc
import os
import re
from server import chat_pb2, chat_pb2_grpc
from PyQt6.QtGui import QPixmap, QTextCursor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QTextBrowser,
    QVBoxLayout, QWidget, QComboBox, QHBoxLayout, QListWidget, QAbstractItemView, QTextEdit, QFileDialog
)
from PyQt6.QtCore import Qt, QEvent, QUrl, QUrlQuery

import deffiehellman, loki97, mars, cryptoContext as cc

algo_dict = {
    "loki97": loki97.LOKI97(key=b"1234567890abcdef"),  # 16-байтовый ключ
    "mars": mars.Mars(key=b'myqwerty12345678'),  # 16-байтовый ключ
}

padding_dict = {
    "PKCS7": cc.PaddingScheme.PKCS7,
    "ZERO": cc.PaddingScheme.ZERO,
    "ISO7816": cc.PaddingScheme.ISO7816,
}

class GRPCClient:
    def __init__(self):
        self.channel = grpc.insecure_channel("localhost:8090")
        self.auth_stub = chat_pb2_grpc.AuthServiceStub(self.channel)
        self.chat_stub = chat_pb2_grpc.ChatServiceStub(self.channel)

        self.username = None

        self.key_rooms = {}
        self.cryptoContext = {}

    def set_username(self, username):
        self.username = username

class LoginWindow(QMainWindow):
    def __init__(self, grpc_client):
        super().__init__()
        self.grpc_client = grpc_client
        self.setWindowTitle("Log/Reg")
        self.setGeometry(200, 200, 400, 300)

        # Основной контейнер
        container = QWidget()
        layout = QVBoxLayout(container)
        self.setCentralWidget(container)

        # Логотип
        logo_label = QLabel(self)
        logo_path = "..."

        if QPixmap(logo_path).isNull():
            logo_label.setText("Добро пожаловать!")
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        else:
            logo_label.setPixmap(QPixmap(logo_path))
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Поля ввода и кнопки
        self.login_label = QLabel("Логин:")
        self.login_input = QLineEdit()
        self.login_input.setPlaceholderText("Enter your username")

        self.password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_button = QPushButton("Авторизация")
        self.login_button.clicked.connect(self.handle_login)

        self.register_button = QPushButton("Регистрация")
        self.register_button.clicked.connect(self.handle_register)

        layout.addWidget(logo_label)
        layout.addWidget(self.login_label)
        layout.addWidget(self.login_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)

        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)


    def handle_login(self):
        username = self.login_input.text()
        password = self.password_input.text()
        try:
            response = self.grpc_client.auth_stub.Login(
                chat_pb2.AuthRequest(username=username, password=password)
            )
            print(f"Login successful. Token: {response.token}")

            self.grpc_client.set_username(username)

            self.chat_window = ChatWindow(self.grpc_client)
            self.chat_window.show()

            self.close()
        except grpc.RpcError as e:
            print(f"Login failed: {e.code()} - {e.details()}")
        except Exception as e:
            print(f"Unexpected error during login: {e}")

    def handle_register(self):
        username = self.login_input.text()
        password = self.password_input.text()
        try:
            response = self.grpc_client.auth_stub.Register(
                chat_pb2.AuthRequest(username=username, password=password)
            )
            print(f"Registration successful. Token: {response.token}")
        except grpc.RpcError as e:
            print(f"Registration failed: {e.code()} - {e.details()}")
        except Exception as e:
            print(f"Unexpected error during registration: {e}")

class CreateRoomWindow(QMainWindow):
    def __init__(self, grpc_client):
        super().__init__()
        self.grpc_client = grpc_client
        self.setWindowTitle("Create Room")
        self.setGeometry(300, 300, 450, 400)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        header_label = QLabel("Создание нового чата")
        layout.addWidget(header_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.algorithm_label = QLabel("Алгоритм:")
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["LOKI97", "Mars"])

        self.mode_label = QLabel("Режим шифрования:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["ECB", "CFB", "OFB", "CBC", "CTR"])

        self.padding_label = QLabel("Режим набивки:")
        self.padding_combo = QComboBox()
        self.padding_combo.addItems(["PKCS7", "ZERO", "ISO7816"])

        self.chat_name_label = QLabel("Название чата:")
        self.chat_name_input = QLineEdit()
        self.chat_name_input.setPlaceholderText("Введите имя")

        self.create_button = QPushButton("Создать")

        layout.addWidget(self.algorithm_label)
        layout.addWidget(self.algorithm_combo)
        layout.addWidget(self.mode_label)
        layout.addWidget(self.mode_combo)
        layout.addWidget(self.padding_label)
        layout.addWidget(self.padding_combo)
        layout.addWidget(self.chat_name_label)
        layout.addWidget(self.chat_name_input)
        layout.addWidget(self.create_button, alignment=Qt.AlignmentFlag.AlignCenter)

        container = QWidget()
        container.setLayout(layout)

        self.setCentralWidget(container)

        self.create_button.clicked.connect(self.handle_create)

    def handle_create(self):
        algorithm = self.algorithm_combo.currentText()
        mode = self.mode_combo.currentText()
        padding = self.padding_combo.currentText()
        chat_name = self.chat_name_input.text()
        try:
            response = self.grpc_client.chat_stub.CreateRoom(
                chat_pb2.CreateRoomRequest(room_id=chat_name, algorithm=algorithm, mode=mode, padding=padding)
            )
            print(f"Room created: {response.message}")

            self.close()
        except grpc.RpcError as e:
            print(f"Create Room failed: {e.details()}")
        except Exception as e:
            print(f"Unexpected error during create room: {e}")

class JoinRoomWindow(QMainWindow):
    def __init__(self, grpc_client, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.grpc_client = grpc_client
        self.setWindowTitle("Join Room")
        self.setGeometry(300, 300, 400, 250)

        layout = QVBoxLayout()
        layout.setSpacing(15)

        header_label = QLabel("Присоединение к чату")

        layout.addWidget(header_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.room_name_label = QLabel("Название чата:")
        self.room_name_input = QLineEdit()
        self.room_name_input.setPlaceholderText("Введите имя чата")

        self.join_button = QPushButton("Присоединиться")

        layout.addWidget(self.room_name_label)
        layout.addWidget(self.room_name_input)
        layout.addWidget(self.join_button, alignment=Qt.AlignmentFlag.AlignCenter)

        container = QWidget()
        container.setLayout(layout)

        self.setCentralWidget(container)

        self.join_button.clicked.connect(self.handle_join)

    def handle_join(self):
        room_name = self.room_name_input.text()
        if not room_name:
            print("Please enter a room name.")
            return

        try:
            # Получаем p и g от сервера
            join_response = self.grpc_client.chat_stub.JoinRoom(chat_pb2.JoinRoomRequest(room_id=room_name, username=self.grpc_client.username))
            try:
                p = int.from_bytes(join_response.p, byteorder="big")
            except OverflowError:
                print("Ошибка: число слишком большое для преобразования.")
                return
            g = join_response.g

            private_key, public_key = deffiehellman.diffie_hellman(p, g)

            self.grpc_client.key_rooms[room_name] = {
                "p": p,
                "g": g,
                "private_key": private_key,
                "public_key": public_key,
                "session_key": None
            }

            room_response = self.grpc_client.chat_stub.SendPublicKey(chat_pb2.SendPublicKeyRequest(
                room_id=room_name,
                username=self.grpc_client.username,
                public_key=public_key.to_bytes((public_key.bit_length() + 7) // 8, byteorder='big')
            ))

            self.parent.chat_list.append(f"Joined room: {room_name}")
            self.parent.active_room = room_name

            if room_name not in self.parent.connected_rooms:
                self.parent.connected_rooms.append(room_name)
                self.parent.update_room_list()

            if room_response.mode in ["CBC", "CFB", "OFB"]:
                iv = b"vbnfjtyughabcdef"  # 16 байт
                self.grpc_client.cryptoContext[room_response.room_id] = cc.CryptoContext(
                    algo_dict[room_response.algorithm.lower()],
                    room_response.mode.upper(),
                    padding_dict[room_response.padding.upper()],
                    iv,
                )
            elif room_response.mode == "CTR":
                nonce = 12345
                nonce_bytes = nonce.to_bytes(8, 'big')
                self.grpc_client.cryptoContext[room_response.room_id] = cc.CryptoContext(
                    algo_dict[room_response.algorithm.lower()],
                    room_response.mode.upper(),
                    padding_dict[room_response.padding.upper()],
                    nonce=nonce_bytes,
                )
            else:
                self.grpc_client.cryptoContext[room_response.room_id] = cc.CryptoContext(
                    algo_dict[room_response.algorithm.lower()],
                    room_response.mode.upper(),
                    padding_dict[room_response.padding.upper()],
                )

            threading.Thread(target=self.parent.receive_messages, args=(self.parent.active_room,), daemon=True).start()

            self.close()
            print(f"Публичный ключ отправлен: {room_response.message} и пользователь {self.grpc_client.username} присоединен к комнате: {room_name}")
        except grpc.RpcError as e:
            print(f"Ошибка присоединения к комнате: {e.code()} - {e.details()}")
        except Exception as e:
            print(f"Неожиданная ошибка: {e}")

class ChatWindow(QMainWindow):
    def __init__(self, grpc_client):
        super().__init__()
        self.grpc_client = grpc_client
        self.username = self.grpc_client.username
        self.setWindowTitle("ChatPage")
        self.setGeometry(200, 200, 600, 600)

        self.room_messages = {}
        self.send_button_state = {}
        self.file_messages = {}  # Словарь для хранения информации о файлах

        self.connected_rooms = []
        self.active_room = None
        self.session_key_generated = False

        # Основная горизонтальная раскладка: список комнат слева, чат справа.
        main_layout = QHBoxLayout()

        # Список комнат
        self.room_list_widget = QListWidget()
        self.room_list_widget.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.room_list_widget.clicked.connect(self.handle_room_selection)
        main_layout.addWidget(self.room_list_widget, stretch=1)

        # Вертикальная раскладка для области чата
        self.chat_layout = QVBoxLayout()

        # Верхний блок: название чата и имя пользователя
        header_layout = QHBoxLayout()
        chat_label = QLabel("Чат")
        header_layout.addWidget(chat_label)
        self.user_label = QLabel(f"Пользователь: {self.username}")
        self.user_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        header_layout.addWidget(self.user_label)
        self.chat_layout.addLayout(header_layout)

        # Область вывода сообщений
        self.chat_list = QTextBrowser()
        self.chat_list.setReadOnly(True)
        self.chat_list.setOpenExternalLinks(False)
        self.chat_list.anchorClicked.connect(self.handle_anchor_clicked)
        self.chat_layout.addWidget(self.chat_list)

        # Поле ввода сообщения
        self.chat_layout.addWidget(QLabel("Сообщение"))
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Введите сообщение...")
        self.chat_layout.addWidget(self.message_input)

        # Кнопки отправки сообщения и отправки файла
        send_button_layout = QHBoxLayout()
        self.send_button = QPushButton("Отправить")
        self.send_button.clicked.connect(self.handle_send)
        self.send_button.setEnabled(False)
        send_button_layout.addWidget(self.send_button)
        self.send_file_button = QPushButton("Отправить файл")
        self.send_file_button.clicked.connect(self.handle_send_file)
        send_button_layout.addWidget(self.send_file_button)
        self.chat_layout.addLayout(send_button_layout)

        self.generate_key_button = QPushButton("Сгенерировать сессионный ключ")
        self.generate_key_button.clicked.connect(self.handle_generate_key)
        self.chat_layout.addWidget(self.generate_key_button)

        bottom_buttons_layout = QHBoxLayout()
        self.create_chat_button = QPushButton("Создать чат")
        self.create_chat_button.clicked.connect(self.handle_create_room)
        bottom_buttons_layout.addWidget(self.create_chat_button)
        self.join_chat_button = QPushButton("Подключиться к чату")
        self.join_chat_button.clicked.connect(self.handle_join_room)
        bottom_buttons_layout.addWidget(self.join_chat_button)
        self.leave_chat_button = QPushButton("Выйти из чата")
        self.leave_chat_button.clicked.connect(self.handle_leave_room)
        bottom_buttons_layout.addWidget(self.leave_chat_button)
        self.chat_layout.addLayout(bottom_buttons_layout)

        main_layout.addLayout(self.chat_layout, stretch=3)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def handle_anchor_clicked(self, url: QUrl):
        """
        Обработчик клика по ссылке.
        Сбрасываем источник, чтобы предотвратить переход, и запускаем скачивание.
        """
        self.chat_list.setSource(QUrl())
        if url.scheme() == "download":
            query = QUrlQuery(url)
            room = query.queryItemValue("room")
            file_name = query.queryItemValue("file")
            self.download_file(room, file_name)

    def eventFilter(self, obj, event):
        """Обрабатывает двойной клик по сообщению в чате.
           Если строка соответствует формату 'файл <имя_файла> получен',
           запускается загрузка файла."""
        if obj is self.chat_list and event.type() == QEvent.Type.MouseButtonDblClick:
            cursor = self.chat_list.cursorForPosition(event.pos())
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            line_text = cursor.selectedText().strip()
            match = re.match(r"файл (.+) получен", line_text)
            if match:
                file_name = match.group(1)
                self.download_file(self.active_room, file_name)
                return True
        return super().eventFilter(obj, event)

    def update_room_list(self):
        """Обновить список комнат в выпадающем меню и список комнат на левой панели."""
        self.room_list_widget.clear()
        self.room_list_widget.addItems(self.connected_rooms)

    def handle_room_selection(self):
        """Обрабатывает выбор комнаты из списка и открывает чат."""
        selected_item = self.room_list_widget.currentItem()
        if selected_item:
            room_name = selected_item.text()
            self.active_room = room_name

            # Очищаем текущие сообщения
            self.chat_list.clear()

            # Отображаем сообщения для выбранной комнаты
            if room_name in self.room_messages:
                for message in self.room_messages[room_name]:
                    self.chat_list.append(message)

            # Активируем/деактивируем кнопку в зависимости от состояния сессионного ключа
            self.send_button.setEnabled(self.send_button_state.get(room_name, False))

    def receive_messages(self, room_id):
        """
        Принимает сообщения из комнаты.
        Системные сообщения центрируются, сообщения других пользователей выравниваются влево,
        а ваши сообщения (если их получать echo от сервера) можно игнорировать, т.к. они уже отображены локально.
        """
        try:
            for response in self.grpc_client.chat_stub.ReceiveMessages(
                    chat_pb2.RoomRequest(room_id=room_id, username=self.grpc_client.username)):

                # Системное сообщение
                if response.sender == "System":
                    try:
                        text = response.encrypted_message.decode()
                        if text.startswith("FILE:"):
                            # Формат: FILE:<имя_файла>:<отправитель>
                            parts = text.split(":", 2)
                            if len(parts) == 3:
                                file_name = parts[1]
                                sender_username = parts[2]
                                if sender_username == self.grpc_client.username:
                                    display_text = f"Файл {file_name} отправлен"
                                else:
                                    display_text = (
                                        f"Файл {file_name} получен. "
                                        f'<a href="download://?room={room_id}&file={file_name}">Сохранить</a>'
                                    )
                                # Центрируем системное сообщение
                                html = f'<p align="center" style="color: gray;">{display_text}</p>'
                                self.chat_list.append(html)
                                continue
                        else:
                            # Прочие системные сообщения
                            html = f'<p align="center" style="color: gray;">{text}</p>'
                            self.chat_list.append(html)
                            continue
                    except Exception as e:
                        print(f"Ошибка обработки системного сообщения: {e}")

                if response.sender == self.grpc_client.username:
                    continue

                try:
                    crypto_ctx = self.grpc_client.cryptoContext[room_id]
                    decrypted_message = crypto_ctx.decrypt(response.encrypted_message).decode()
                except Exception:
                    decrypted_message = response.encrypted_message.decode()
                html = f'<p align="left"><b>{response.sender}:</b> {decrypted_message}</p>'
                self.chat_list.append(html)
        except grpc.RpcError as e:
            print(f"Error receiving messages: {e.details()}")

    def handle_send(self):
        """
        Отправляет сообщение в очередь комнаты.
        Отображает сообщение локально как отправленное (выравнивание по правому краю).
        """
        message = self.message_input.text()
        if not message:
            return

        message_encode = self.grpc_client.cryptoContext[self.active_room].encrypt(message.encode())
        try:
            def message_iterator():
                yield chat_pb2.MessageRequest(
                    room_id=self.active_room,
                    sender=self.grpc_client.username,
                    encrypted_message=message_encode,
                )

            for _ in self.grpc_client.chat_stub.SendMessage(message_iterator()):
                pass

            # Отображаем сообщение локально с выравниванием по правому краю
            html = f'<p align="right"><b>Вы:</b> {message}</p>'
            if self.active_room not in self.room_messages:
                self.room_messages[self.active_room] = []
            self.room_messages[self.active_room].append(html)
            self.chat_list.append(html)
            self.message_input.clear()
        except grpc.RpcError as e:
            print(f"Failed to send message: {e.details()}")
        except Exception as e:
            print(f"Unexpected error during message sending: {e}")

    def handle_create_room(self):
        """Создает комнату через отдельный класс."""
        self.create_room_window = CreateRoomWindow(self.grpc_client)
        self.create_room_window.show()

    def handle_join_room(self):
        """Присоединение к комнате."""
        self.join_room_window = JoinRoomWindow(self.grpc_client, parent=self)
        self.join_room_window.show()

    def handle_generate_key(self):
        """Генерирует сессионный ключ для комнаты."""
        if self.active_room:
            try:
                response = self.grpc_client.chat_stub.GenerateSessionKey(
                    chat_pb2.GenerateKeyRequest(room_id=self.active_room, username=self.grpc_client.username)
                )

                other_public_key = int.from_bytes(response.other_public_key, byteorder='big')

                shared_secret = deffiehellman.compute_shared_secret(other_public_key, self.grpc_client.key_rooms[self.active_room]['private_key'], self.grpc_client.key_rooms[self.active_room]['p'])
                hash_shared_key = deffiehellman.hash_shared_key(shared_secret)

                self.grpc_client.key_rooms[self.active_room]['session_key'] = hash_shared_key
                self.grpc_client.cryptoContext[self.active_room].set_key(hash_shared_key)
                self.send_button_state[self.active_room] = True

                # Активируем кнопку, если эта комната сейчас выбрана
                if self.active_room:
                    self.send_button.setEnabled(True)
            except grpc.RpcError as e:
                print(f"Ошибка генерации ключа: {e.details()}")
            except Exception as e:
                print(f"Неожиданная ошибка: {e}")

    def handle_leave_room(self):
        """Выходит из комнаты."""
        room_name = self.active_room
        if not room_name:
            print("Please enter a room name.")
            return

        try:
            response = self.grpc_client.chat_stub.LeaveRoom(
                chat_pb2.RoomRequest(room_id=room_name, username=self.grpc_client.username)
            )
            print(f"Left room: {response.message}")

            if room_name in self.connected_rooms:
                self.connected_rooms.remove(room_name)
                self.update_room_list()

            # Удаляем сообщения для этой комнаты
            if room_name in self.room_messages:
                del self.room_messages[room_name]

            # Убираем состояние кнопки
            if room_name in self.send_button_state:
                del self.send_button_state[room_name]

            # Очищаем отображение чата
            self.chat_list.clear()

            # Переключаемся на другую комнату, если есть подключенные
            if self.connected_rooms:
                self.active_room = self.connected_rooms[0]
                self.handle_room_selection()
            else:
                self.active_room = None
                self.send_button.setEnabled(False)

        except grpc.RpcError as e:
            print(f"Leave room failed: {e.details()}")
        except Exception as e:
            print(f"Unexpected error during room leave: {e}")

    def handle_send_file(self):
        """Отправляет зашифрованный файл и после завершения передачи
           отправляет системное сообщение с информацией о файле."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл для отправки")
        if not file_path:
            return  # Пользователь отменил выбор файла

        try:
            # Создаем временный путь для зашифрованного файла
            enc_file_path = file_path + ".enc"

            # Используем функцию encrypt_file из CryptoContext для шифрования целиком
            crypto_ctx = self.grpc_client.cryptoContext[self.active_room]
            crypto_ctx.encrypt_file(file_path, enc_file_path)

            # Читаем зашифрованный файл целиком
            with open(enc_file_path, "rb") as f:
                encrypted_data = f.read()

            # Удаляем временный зашифрованный файл
            os.remove(enc_file_path)

            # Отправляем зашифрованное содержимое одним сообщением (поскольку файл небольшой)
            def file_chunk_generator():
                yield chat_pb2.FileRequest(
                    room_id=self.active_room,
                    sender=self.grpc_client.username,
                    file_name=os.path.basename(file_path),
                    file_size=len(encrypted_data),
                    chunk=encrypted_data
                )

            for response in self.grpc_client.chat_stub.SendFile(file_chunk_generator()):
                if response.complete:
                    print(f"Отправка файла '{response.file_name}' завершена.")

            # Отправляем системное сообщение о файле
            def file_message_iter():
                yield chat_pb2.MessageRequest(
                    room_id=self.active_room,
                    sender="System",
                    encrypted_message=f"FILE:{os.path.basename(file_path)}:{self.grpc_client.username}".encode()
                )

            for _ in self.grpc_client.chat_stub.SendMessage(file_message_iter()):
                pass
        except Exception as e:
            print(f"Ошибка при отправке файла: {e}")

    def download_file(self, room_id, file_name):
        save_path, _ = QFileDialog.getSaveFileName(self, "Сохранить файл", file_name)
        if not save_path:
            return

        # Если пользователь выбрал имя, содержащее расширение .enc, удаляем его
        if save_path.lower().endswith(".enc"):
            save_path = save_path[:-4]

        # Если расширение не указано, добавляем его из исходного имени файла
        if not os.path.splitext(save_path)[1]:
            _, ext = os.path.splitext(file_name)
            save_path += ext

        try:
            responses = self.grpc_client.chat_stub.DownloadFile(
                chat_pb2.DownloadFileRequest(room_id=room_id, file_name=file_name)
            )
            encrypted_data = b""
            for response in responses:
                if response.chunk:
                    encrypted_data += response.chunk
                if response.complete:
                    break

            # Записываем зашифрованные данные во временный файл с расширением .enc
            temp_enc_file = save_path + ".enc"
            with open(temp_enc_file, "wb") as f:
                f.write(encrypted_data)

            # Расшифровываем временный файл, записывая результат в save_path
            crypto_ctx = self.grpc_client.cryptoContext[room_id]
            crypto_ctx.decrypt_file(temp_enc_file, save_path)

            # Удаляем временный зашифрованный файл
            os.remove(temp_enc_file)

            self.chat_list.append(f"Файл '{file_name}' сохранён в {save_path}")
        except grpc.RpcError as e:
            print(f"Ошибка загрузки файла: {e.details()}")
        except Exception as e:
            print(f"Неожиданная ошибка при загрузке файла: {e}")

class MainApp:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.grpc_client = GRPCClient()

        self.login_window = LoginWindow(self.grpc_client)
        self.login_window.show()

    def run(self):
        sys.exit(self.app.exec())

if __name__ == "__main__":
    app = MainApp()
    app.run()
