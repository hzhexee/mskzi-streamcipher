from cipher.rc4 import rc4
from cipher.chacha20 import chacha20
from cipher.salsa20 import salsa20
import os
import binascii
import secrets

def main():
    print("Потоковые шифры (16-bit block size для RC4)")
    print("-" * 50)
    
    while True:
        print("\nВыберите алгоритм шифрования:")
        print("1. RC4")
        print("2. ChaCha20")
        print("3. Salsa20")
        print("4. Выход")
        
        algorithm_choice = input("> ")
        
        if algorithm_choice == '4':
            break
            
        if algorithm_choice in ['1', '2', '3']:
            # Получаем параметры в зависимости от выбранного алгоритма
            if algorithm_choice == '1':  # RC4
                key_str = input("Введите ключ шифрования: ")
                key = key_str.encode('utf-8')
                cipher_name = "RC4"
                
                # Функция шифрования/дешифрования
                def encrypt_decrypt(data):
                    return rc4(key, data)
                    
            elif algorithm_choice == '2':  # ChaCha20
                key_str = input("Введите ключ шифрования (минимум 32 символа): ")
                if len(key_str) < 32:
                    key_str = key_str.ljust(32, '0')  # Дополняем ключ нулями, если он короткий
                key = key_str[:32].encode('utf-8')  # Берем только первые 32 байта
                
                # Генерация случайного nonce или ввод пользователем
                nonce_choice = input("Сгенерировать случайный nonce? (д/н): ")
                if nonce_choice.lower() in ['д', 'y', 'да', 'yes']:
                    nonce = secrets.token_bytes(12)
                    print(f"Сгенерированный nonce (hex): {nonce.hex()}")
                else:
                    nonce_str = input("Введите nonce в формате hex (24 символа): ")
                    nonce = bytes.fromhex(nonce_str) if len(nonce_str) >= 24 else secrets.token_bytes(12)
                
                counter = 0
                cipher_name = "ChaCha20"
                
                # Функция шифрования/дешифрования
                def encrypt_decrypt(data):
                    return chacha20(key, nonce, counter, data)
                
            elif algorithm_choice == '3':  # Salsa20
                key_str = input("Введите ключ шифрования (минимум 32 символа): ")
                if len(key_str) < 32:
                    key_str = key_str.ljust(32, '0')  # Дополняем ключ нулями, если он короткий
                key = key_str[:32].encode('utf-8')  # Берем только первые 32 байта
                
                # Генерация случайного nonce или ввод пользователем
                nonce_choice = input("Сгенерировать случайный nonce? (д/н): ")
                if nonce_choice.lower() in ['д', 'y', 'да', 'yes']:
                    nonce = secrets.token_bytes(8)
                    print(f"Сгенерированный nonce (hex): {nonce.hex()}")
                else:
                    nonce_str = input("Введите nonce в формате hex (16 символов): ")
                    nonce = bytes.fromhex(nonce_str) if len(nonce_str) >= 16 else secrets.token_bytes(8)
                
                counter = 0
                cipher_name = "Salsa20"
                
                # Функция шифрования/дешифрования
                def encrypt_decrypt(data):
                    return salsa20(key, nonce, counter, data)
            
            # Операции с выбранным алгоритмом
            while True:
                print(f"\nВыбран алгоритм: {cipher_name}")
                print("Выберите операцию:")
                print("1. Зашифровать текст")
                print("2. Расшифровать текст")
                print("3. Вернуться к выбору алгоритма")
                
                choice = input("> ")
                
                if choice == '3':
                    break
                
                if choice in ['1', '2']:
                    if choice == '1':
                        # Получаем входной текст
                        input_text = input("\nВведите текст: ")
                        input_bytes = input_text.encode('utf-8')
                        
                        # Шифруем текст
                        try:
                            result_bytes = encrypt_decrypt(input_bytes)
                            print(f"\nЗашифрованный текст (hex): {result_bytes.hex()}")
                            
                            # Сохраняем бинарные данные для последующей расшифровки
                            save_option = input("Сохранить зашифрованный текст в файл? (д/н): ")
                            if save_option.lower() in ['д', 'y', 'да', 'yes']:
                                filename = input("Имя файла: ")
                                with open(filename, 'wb') as f:
                                    f.write(result_bytes)
                                print(f"Зашифрованный текст сохранен в {filename}")
                        except Exception as e:
                            print(f"Ошибка при шифровании: {e}")
                    else:  # Расшифровка
                        print("\nВыберите формат ввода:")
                        print("1. Текст в формате HEX")
                        print("2. Обычный текст")
                        print("3. Загрузить из файла")
                        
                        input_format = input("> ")
                        
                        try:
                            if input_format == '1':  # HEX формат
                                hex_text = input("\nВведите зашифрованный текст в hex-формате: ")
                                try:
                                    # Преобразование hex в байты
                                    input_bytes = binascii.unhexlify(hex_text.strip())
                                    # Расшифровка
                                    result_bytes = encrypt_decrypt(input_bytes)
                                    try:
                                        result_text = result_bytes.decode('utf-8')
                                        print("\nРасшифрованный текст: ", result_text)
                                    except UnicodeDecodeError:
                                        print("\nОшибка при расшифровке. Возможно, данные повреждены или ключ неверный.")
                                        print("Байты результата (hex): ", result_bytes.hex())
                                except binascii.Error:
                                    print("\nОшибка: Введено некорректное hex-значение.")
                            
                            elif input_format == '2':  # Обычный текст
                                input_text = input("\nВведите зашифрованный текст: ")
                                input_bytes = input_text.encode('utf-8')
                                
                                # Расшифровка
                                result_bytes = encrypt_decrypt(input_bytes)
                                try:
                                    result_text = result_bytes.decode('utf-8')
                                    print("\nРасшифрованный текст: ", result_text)
                                except UnicodeDecodeError:
                                    print("\nОшибка при расшифровке. Возможно, данные повреждены или ключ неверный.")
                                    print("Байты результата (hex): ", result_bytes.hex())
                            
                            elif input_format == '3':  # Загрузка из файла
                                filename = input("\nВведите имя файла: ")
                                try:
                                    with open(filename, 'rb') as f:
                                        encrypted_data = f.read()
                                    decrypted = encrypt_decrypt(encrypted_data)
                                    try:
                                        decrypted_text = decrypted.decode('utf-8')
                                        print("\nРасшифрованный текст из файла: ", decrypted_text)
                                    except UnicodeDecodeError:
                                        print("\nОшибка при расшифровке файла. Возможно неверный ключ.")
                                        print("Байты результата (hex): ", decrypted.hex())
                                except FileNotFoundError:
                                    print(f"Файл {filename} не найден")
                            
                            else:
                                print("Неверный выбор формата ввода.")
                        except Exception as e:
                            print(f"Ошибка: {e}")
                else:
                    print("Неверный выбор. Пожалуйста, выберите 1, 2 или 3.")
        else:
            print("Неверный выбор алгоритма. Пожалуйста, выберите число от 1 до 4.")

if __name__ == "__main__":
    main()