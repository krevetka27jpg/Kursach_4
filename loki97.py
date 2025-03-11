import symmetricCipherABC
import hashlib

def _rotate_left(x: int, n: int, bits: int = 64) -> int:
    """Циклический сдвиг влево для 64-битного числа."""
    return ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)

def substitution(x: int) -> int:
    """
    Применяет простейшую побайтовую замену к 64-битному числу.
    Каждый из 8 байтов заменяется по формуле: new_byte = (byte * 7 + 3) mod 256.
    Это упрощённая S‑функция (в оригинале S‑блоки сложнее).
    """
    result = 0
    for i in range(8):
        byte = (x >> (i * 8)) & 0xFF
        new_byte = (byte * 7 + 3) & 0xFF
        result |= (new_byte << (i * 8))
    return result

class LOKI97(symmetricCipherABC.SymmetricCipher):
    def __init__(self, key: bytes):
        """
        Инициализация LOKI97.
        :param key: Исходный ключ. Если длина не 16 байт, он преобразуется с помощью MD5.
        """
        self.block_size = 16  # 128 бит
        self.rounds = 16
        self.round_keys = []
        self.set_key(key)

    def set_key(self, key: bytes) -> None:
        """
        Устанавливает ключ и генерирует 16 раундовых ключей по 64 бита.
        Если длина ключа не равна 16 байт, используется MD5 для приведения к 16 байтам.
        Каждый раундовый ключ генерируется как первые 8 байт MD5(key || round_number).
        """
        if len(key) != 16:
            key = hashlib.md5(key).digest()
        self.key = key
        self.round_keys = []
        for i in range(self.rounds):
            # Генерируем раундовый ключ как MD5(key || i)
            round_key = hashlib.md5(key + i.to_bytes(1, 'big')).digest()[:8]
            self.round_keys.append(int.from_bytes(round_key, 'big'))

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Шифрует данные блоками по 16 байт.
        Длина plaintext должна быть кратна 16 байтам (все паддинги обрабатываются на уровне CryptoContext).
        """
        if len(plaintext) % self.block_size != 0:
            raise ValueError("Plaintext length must be a multiple of block_size")
        ciphertext = bytearray()
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]
            ciphertext.extend(self._encrypt_block(block))
        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Дешифрует данные блоками по 16 байт.
        Длина ciphertext должна быть кратна 16 байтам.
        """
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be a multiple of block_size")
        plaintext = bytearray()
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            plaintext.extend(self._decrypt_block(block))
        return bytes(plaintext)

    def _F(self, half: int, round_key: int) -> int:
        """
        Раундовая функция.
        Применяет побайтовую замену к 64-битной половине, затем циклический сдвиг влево на 3 бита,
        и выполняет XOR с раундовым ключом.
        """
        sub = substitution(half)
        rot = _rotate_left(sub, 3, 64)
        return rot ^ round_key

    def _encrypt_block(self, block: bytes) -> bytes:
        """
        Шифрует один 16-байтовый блок по схеме Фейстеля.
        Блок разбивается на две 64-битные половины: L и R.
        На каждом раунде:
          L, R = R, L XOR F(R, round_key)
        """
        L = int.from_bytes(block[:8], 'big')
        R = int.from_bytes(block[8:], 'big')
        for i in range(self.rounds):
            F_val = self._F(R, self.round_keys[i])
            newL = R
            newR = L ^ F_val
            L, R = newL, newR
        # После четного количества раундов (16) конечное состояние равно (L, R)
        return L.to_bytes(8, 'big') + R.to_bytes(8, 'big')

    def _decrypt_block(self, block: bytes) -> bytes:
        """
        Дешифрует один 16-байтовый блок, инвертируя процесс Фейстеля.
        Пусть после шифрования блок равен (L, R) (каждая половина по 64 бита).
        Тогда для каждого раунда (в обратном порядке) выполняется:
          L, R = R' XOR F(L, round_key), L   (где (L, R) из дешифрования равны (L', R') из шифрования)
        Это позволяет восстановить исходный блок.
        """
        L = int.from_bytes(block[:8], 'big')
        R = int.from_bytes(block[8:], 'big')
        for i in reversed(range(self.rounds)):
            # Здесь в обратном раунде используем L (которое в шифровании соответствовало R предыдущего шага)
            F_val = self._F(L, self.round_keys[i])
            newL = R ^ F_val
            newR = L
            L, R = newL, newR
        return L.to_bytes(8, 'big') + R.to_bytes(8, 'big')
