import cryptoContext, mars, loki97

# Инициализация алгоритма
mars = mars.Mars(b"1234567890abcdef")
loki97 = loki97.LOKI97(b"1234567890abcdef")

# Выбор алгоритма между MARS и Loki97
algorithm = loki97  # mars loki97

# Создаем контекст с выбранным алгоритмом и режимом

# ECB
# CBC
# CFB
# OFB
# CTR

# PKCS7
# ZERO
# ISO7816

context = cryptoContext.CryptoContext(algorithm, "ECB", # ECB CBC CFB OFB CTR
                                      cryptoContext.PaddingScheme.PKCS7) # PKCS7 ZERO ISO7816

plaintext = b"HelloWorld!"

# Шифрование
encrypt_text = context.encrypt(plaintext)
print(f"Encrypt text: {encrypt_text}")

# Дешифрование
decrypt_text = context.decrypt(encrypt_text)
print(f"Decrypt text: {decrypt_text}")
