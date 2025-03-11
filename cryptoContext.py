from enum import Enum
from concurrent.futures import ThreadPoolExecutor

class PaddingScheme(Enum):
    PKCS7 = "PKCS7"
    ZERO = "ZERO"
    ISO7816 = "ISO7816"

class CryptoContext:
    def __init__(self, cipher, mode: str, padding: PaddingScheme = PaddingScheme.PKCS7, iv: bytes = None, nonce: bytes = None):
        """
        Инициализация криптоконтекста.
        :param cipher: Шифр
        :param mode: Режим шифрования ("ECB", "CBC", "CFB", "OFB", "CTR").
        :param padding: Схема набивки (PaddingScheme.PKCS7, PaddingScheme.ZERO, PaddingScheme.ISO7816).
        :param iv: Вектор инициализации (для CBC, CFB, OFB).
        :param nonce: Уникальное значение (для CTR).
        """
        self.cipher = cipher
        self.mode = mode
        self.padding = padding
        self.iv = iv
        self.nonce = nonce

        if mode in ["CBC", "CFB", "OFB"] and iv is None:
            raise ValueError(f"IV должен быть предоставлен для режима {mode}.")
        if mode == "CTR" and nonce is None:
            raise ValueError("Nonce должен быть предоставлен для режима CTR.")

    def set_key(self, key: bytes):
        self.cipher.set_key(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        padded_data = self._apply_padding(plaintext)
        mode_to_encrypt_method = {
            "ECB": self._encrypt_ecb_parallel,
            "CBC": self._encrypt_cbc,
            "CFB": self._encrypt_cfb,
            "OFB": self._encrypt_ofb,
            "CTR": self._encrypt_ctr_parallel,
        }

        encrypt_method = mode_to_encrypt_method.get(self.mode)
        if encrypt_method is None:
            raise ValueError("Неподдерживаемый режим шифрования.")

        return encrypt_method(padded_data)

    def decrypt(self, ciphertext: bytes) -> bytes:
        mode_to_decrypt_method = {
            "ECB": self._decrypt_ecb_parallel,
            "CBC": self._decrypt_cbc,
            "CFB": self._decrypt_cfb,
            "OFB": self._decrypt_ofb,
            "CTR": self._decrypt_ctr_parallel,
        }

        decrypt_method = mode_to_decrypt_method.get(self.mode)
        if decrypt_method is None:
            raise ValueError("Неподдерживаемый режим шифрования.")

        decrypted_data = decrypt_method(ciphertext)
        return self._remove_padding(decrypted_data)

    def encrypt_file(self, input_file: str, output_file: str) -> None:
        """
        Шифрование файла.
        :param input_file: Путь к исходному файлу.
        :param output_file: Путь к зашифрованному файлу.
        """
        with open(input_file, "rb") as f_in:
            plaintext = f_in.read()

        ciphertext = self.encrypt(plaintext)

        with open(output_file, "wb") as f_out:
            f_out.write(ciphertext)

    def decrypt_file(self, input_file: str, output_file: str) -> None:
        """
        Расшифровка файла.
        :param input_file: Путь к зашифрованному файлу.
        :param output_file: Путь к расшифрованному файлу.
        """
        with open(input_file, "rb") as f_in:
            ciphertext = f_in.read()

        plaintext = self.decrypt(ciphertext)

        with open(output_file, "wb") as f_out:
            f_out.write(plaintext)

    def encrypt_stream(self, input_stream, output_stream) -> None:
        """
        Шифрование потока данных.
        :param input_stream: Входной поток (например, файловый объект).
        :param output_stream: Выходной поток (например, файловый объект).
        """
        plaintext = input_stream.read()
        ciphertext = self.encrypt(plaintext)
        output_stream.write(ciphertext)

    def decrypt_stream(self, input_stream, output_stream) -> None:
        """
        Расшифровка потока данных.
        :param input_stream: Входной поток (например, файловый объект).
        :param output_stream: Выходной поток (например, файловый объект).
        """
        ciphertext = input_stream.read()
        plaintext = self.decrypt(ciphertext)
        output_stream.write(plaintext)

    def _apply_padding(self, data: bytes) -> bytes:
        block_size = self.cipher.block_size
        padding_length = block_size - (len(data) % block_size)
        if self.padding == PaddingScheme.PKCS7:
            return data + bytes([padding_length] * padding_length)
        elif self.padding == PaddingScheme.ZERO:
            return data + bytes([0] * padding_length)
        elif self.padding == PaddingScheme.ISO7816:
            return data + b'\x80' + bytes([0] * (padding_length - 1))
        else:
            raise ValueError("Неподдерживаемая схема набивки.")

    def _remove_padding(self, data: bytes) -> bytes:
        if self.padding == PaddingScheme.PKCS7:
            padding_length = data[-1]
            return data[:-padding_length]
        elif self.padding == PaddingScheme.ZERO:
            return data.rstrip(b'\x00')
        elif self.padding == PaddingScheme.ISO7816:
            return data.rstrip(b'\x00').rstrip(b'\x80')
        else:
            raise ValueError("Неподдерживаемая схема набивки.")

    def _encrypt_ecb_parallel(self, data: bytes, chunk_size: int = 1024) -> bytes:
        ciphertext = bytearray()

        def encrypt_chunk(chunk: bytes) -> bytes:
            encrypted_chunk = bytearray()
            for i in range(0, len(chunk), self.cipher.block_size):
                block = chunk[i:i + self.cipher.block_size]
                encrypted_chunk.extend(self.cipher.encrypt(block))
            return encrypted_chunk

        with ThreadPoolExecutor() as executor:
            futures = []
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                futures.append(executor.submit(encrypt_chunk, chunk))
            for future in futures:
                ciphertext.extend(future.result())
        return bytes(ciphertext)

    def _decrypt_ecb_parallel(self, ciphertext: bytes, chunk_size: int = 1024) -> bytes:
        plaintext = bytearray()

        def decrypt_chunk(chunk: bytes) -> bytes:
            decrypted_chunk = bytearray()
            for i in range(0, len(chunk), self.cipher.block_size):
                block = chunk[i:i + self.cipher.block_size]
                decrypted_chunk.extend(self.cipher.decrypt(block))
            return decrypted_chunk

        with ThreadPoolExecutor() as executor:
            futures = []
            for i in range(0, len(ciphertext), chunk_size):
                chunk = ciphertext[i:i + chunk_size]
                futures.append(executor.submit(decrypt_chunk, chunk))
            for future in futures:
                plaintext.extend(future.result())
        return bytes(plaintext)

    def _encrypt_cbc(self, data: bytes) -> bytes:
        ciphertext = b""
        previous_block = self.iv
        for i in range(0, len(data), self.cipher.block_size):
            block = data[i:i + self.cipher.block_size]
            block = bytes(a ^ b for a, b in zip(block, previous_block))
            encrypted_block = self.cipher.encrypt(block)
            ciphertext += encrypted_block
            previous_block = encrypted_block
        return ciphertext

    def _decrypt_cbc(self, ciphertext: bytes) -> bytes:
        plaintext = b""
        previous_block = self.iv
        for i in range(0, len(ciphertext), self.cipher.block_size):
            block = ciphertext[i:i + self.cipher.block_size]
            decrypted_block = self.cipher.decrypt(block)
            plaintext_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
            plaintext += plaintext_block
            previous_block = block
        return plaintext

    def _encrypt_cfb(self, data: bytes) -> bytes:
        ciphertext = b""
        previous_block = self.iv
        for i in range(0, len(data), self.cipher.block_size):
            block = data[i:i + self.cipher.block_size]
            encrypted_block = self.cipher.encrypt(previous_block)
            ciphertext_block = bytes(a ^ b for a, b in zip(block, encrypted_block))
            ciphertext += ciphertext_block
            previous_block = ciphertext_block
        return ciphertext

    def _decrypt_cfb(self, ciphertext: bytes) -> bytes:
        plaintext = b""
        previous_block = self.iv
        for i in range(0, len(ciphertext), self.cipher.block_size):
            block = ciphertext[i:i + self.cipher.block_size]
            encrypted_block = self.cipher.encrypt(previous_block)
            plaintext_block = bytes(a ^ b for a, b in zip(block, encrypted_block))
            plaintext += plaintext_block
            previous_block = block
        return plaintext

    def _encrypt_ofb(self, data: bytes) -> bytes:
        ciphertext = b""
        previous_block = self.iv
        for i in range(0, len(data), self.cipher.block_size):
            block = data[i:i + self.cipher.block_size]
            encrypted_block = self.cipher.encrypt(previous_block)
            ciphertext_block = bytes(a ^ b for a, b in zip(block, encrypted_block))
            ciphertext += ciphertext_block
            previous_block = encrypted_block
        return ciphertext

    def _decrypt_ofb(self, ciphertext: bytes) -> bytes:
        return self._encrypt_ofb(ciphertext)

    def _encrypt_ctr_parallel(self, data: bytes, chunk_size: int = 1024) -> bytes:
        ciphertext = bytearray()
        counter = int.from_bytes(self.nonce, byteorder='big')

        def encrypt_chunk(chunk: bytes, start_counter: int) -> bytes:
            encrypted_chunk = bytearray()
            for i in range(0, len(chunk), self.cipher.block_size):
                block = chunk[i:i + self.cipher.block_size]
                counter_block = (start_counter + i // self.cipher.block_size).to_bytes(self.cipher.block_size, byteorder='big')
                encrypted_block = self.cipher.encrypt(counter_block)
                encrypted_chunk.extend(bytes(a ^ b for a, b in zip(block, encrypted_block)))
            return encrypted_chunk

        with ThreadPoolExecutor() as executor:
            futures = []
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                futures.append(executor.submit(encrypt_chunk, chunk, counter + i // self.cipher.block_size))
            for future in futures:
                ciphertext.extend(future.result())
        return bytes(ciphertext)

    def _decrypt_ctr_parallel(self, ciphertext: bytes, chunk_size: int = 1024) -> bytes:
        # В CTR режиме шифрование и расшифрование идентичны
        return self._encrypt_ctr_parallel(ciphertext, chunk_size)

    # --- Потоковое шифрование ---
    def get_encryptor(self):
        """
        Возвращает объект для потокового шифрования.
        """
        return StreamEncryptor(self)

# Класс для потокового шифрования, сохраняющий внутреннее состояние.
class StreamEncryptor:
    def __init__(self, context: CryptoContext):
        self.context = context
        self.block_size = context.cipher.block_size
        self.buffer = bytearray()
        if self.context.mode in ["CBC", "CFB", "OFB"]:
            self.previous_block = context.iv
        if self.context.mode == "CTR":
            self.counter = int.from_bytes(context.nonce, byteorder='big')

    def update(self, data: bytes) -> bytes:
        """
        Обрабатывает входные данные и возвращает зашифрованный результат для полных блоков.
        """
        self.buffer.extend(data)
        output = bytearray()
        while len(self.buffer) >= self.block_size:
            block = self.buffer[:self.block_size]
            del self.buffer[:self.block_size]
            if self.context.mode == "ECB":
                enc_block = self.context.cipher.encrypt(block)
            elif self.context.mode == "CBC":
                block_to_encrypt = bytes(a ^ b for a, b in zip(block, self.previous_block))
                enc_block = self.context.cipher.encrypt(block_to_encrypt)
                self.previous_block = enc_block
            elif self.context.mode == "CFB":
                enc_prev = self.context.cipher.encrypt(self.previous_block)
                enc_block = bytes(a ^ b for a, b in zip(block, enc_prev))
                self.previous_block = enc_block
            elif self.context.mode == "OFB":
                self.previous_block = self.context.cipher.encrypt(self.previous_block)
                enc_block = bytes(a ^ b for a, b in zip(block, self.previous_block))
            elif self.context.mode == "CTR":
                counter_block = self.counter.to_bytes(self.block_size, 'big')
                keystream = self.context.cipher.encrypt(counter_block)
                self.counter += 1
                enc_block = bytes(a ^ b for a, b in zip(block, keystream))
            else:
                raise ValueError("Unsupported mode for streaming encryption.")
            output.extend(enc_block)
        return bytes(output)

    def finalize(self) -> bytes:
        """
        Обрабатывает оставшиеся данные с добавлением набивки и возвращает финальный зашифрованный блок.
        """
        padded_data = self.context._apply_padding(bytes(self.buffer))
        output = bytearray()
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i+self.block_size]
            if self.context.mode == "ECB":
                enc_block = self.context.cipher.encrypt(block)
            elif self.context.mode == "CBC":
                block_to_encrypt = bytes(a ^ b for a, b in zip(block, self.previous_block))
                enc_block = self.context.cipher.encrypt(block_to_encrypt)
                self.previous_block = enc_block
            elif self.context.mode == "CFB":
                enc_prev = self.context.cipher.encrypt(self.previous_block)
                enc_block = bytes(a ^ b for a, b in zip(block, enc_prev))
                self.previous_block = enc_block
            elif self.context.mode == "OFB":
                self.previous_block = self.context.cipher.encrypt(self.previous_block)
                enc_block = bytes(a ^ b for a, b in zip(block, self.previous_block))
            elif self.context.mode == "CTR":
                enc_block = bytearray()
                # Если блок больше, чем размер блока шифра, обрабатываем по кускам
                for j in range(0, len(block), self.block_size):
                    sub_block = block[j:j+self.block_size]
                    counter_block = self.counter.to_bytes(self.block_size, 'big')
                    keystream = self.context.cipher.encrypt(counter_block)
                    self.counter += 1
                    enc_block.extend(bytes(a ^ b for a, b in zip(sub_block, keystream)))
                enc_block = bytes(enc_block)
            else:
                raise ValueError("Unsupported mode for streaming encryption.")
            output.extend(enc_block)
        self.buffer.clear()
        return bytes(output)
