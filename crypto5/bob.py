import socket
import rsa
import time
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread

trent_public_key = rsa.PublicKey.load_pkcs1(b"""
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAnvqFdA2G3dsbUZs9JZ84XOhzcqr11FIwCVTQil4mb3y9XafPQ2RC
zjSHerEL2jikYC+2GYKieWvaCg3fRHVhjJi1LI6sSoPU/g9mG/u6tPT8yQ2JMzrx
k1gVrvbRqZP2XY+obkvowF1Vco+aohPOLPkaoUBK1PMXZn5IrLyYUw6NpYzCQelw
Qx8NUiUsxc7FgaUrC+k0vU2zJJG7N3RVXZEN8OPp/6wHssYgQeys2bovIkcQyNw1
pL3jTvkf9HqDfARPNbKvYNIxSUGLle+Kd7ltIywqtfwUvEf82N/dsa/5U0AfGblE
iUBF9LS7w5d8vTrDAtBeOhvXg/Kpne6lfwIDAQAB
-----END RSA PUBLIC KEY-----
""")

bob_private_key = rsa.PrivateKey.load_pkcs1(open("bob_private.pem", "rb").read())


def bob_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('localhost', 2222))
        server.listen(1)
        print("Bob: Ожидаем подключение Алисы...")

        conn, addr = server.accept()
        with conn:
            print(f"Bob: Соединение с Алисой установлено {addr}")

            alice_key_message = conn.recv(2048)
            print(f"Bob: Получено сообщение от Алисы (ключ Алисы): {alice_key_message}")

            try:
                part1_alice, part2_alice = alice_key_message.split(b"::")
            except ValueError:
                print("Bob: Ошибка разделения данных (ключ Алисы).")
                return

            message_alice, signed_alice_hex = part1_alice.decode(), part2_alice.decode()
            signed_alice = bytes.fromhex(signed_alice_hex)

            try:
                rsa.verify(message_alice.encode(), signed_alice, trent_public_key)
                print("Bob: Подпись для ключа Алисы верна.")
            except rsa.VerificationError:
                print("Bob: Подпись для ключа Алисы неверна.")

            if "PublicKey" in message_alice:
                key_data = message_alice.split("PublicKey(", 1)[1].split(")")[0]
                modulus, exponent = map(int, key_data.split(", "))
                alice_public_key = rsa.PublicKey(modulus, exponent)
                print(f"Bob: Открытый ключ Алисы успешно извлечён: {alice_public_key}")
            else:
                print("Bob: Ошибка извлечения ключа Алисы.")
                return

            trent_bob_message = conn.recv(2048)
            print(f"Bob: Получено сообщение от Трента для Боба: {trent_bob_message}")

            try:
                message_bob, signed_bob_hex = trent_bob_message.split(b"::")
                signed_bob = bytes.fromhex(signed_bob_hex.decode())
                rsa.verify(message_bob, signed_bob, trent_public_key)
                print("Bob: Подпись Трента для сообщения Боба верна.")
            except (ValueError, rsa.VerificationError):
                print("Bob: Ошибка проверки подписи для сообщения Боба.")
                return

            session_data_encrypted = conn.recv(2048)
            encrypted_session_data, signature = session_data_encrypted.split(b"::")
            print(f"Bob: Получены зашифрованные сессионные данные.")

            session_data = rsa.decrypt(encrypted_session_data, bob_private_key).decode()

            try:
                rsa.verify(session_data.encode(), signature, alice_public_key)
                print("Bob: Подпись Алисы для сессионных данных верна.")
            except rsa.VerificationError:
                print("Bob: Подпись Алисы для сессионных данных неверна.")
                return

            session_key, timestamp = session_data.split(":")
            print(f"Bob: Сессионный ключ: {session_key}, метка времени: {timestamp}")

            current_time = int(time.time())
            if current_time - int(timestamp) > 60:
                print("Bob: Метка времени устарела.")
                return

            cipher_session = Fernet(session_key.encode())
            print("Bob: Сессионный ключ успешно инициализирован.")

            # После обмена ключами и подтверждения открываем чат
            print("Bob: Открываем чат...")
            start_chat(cipher_session, conn)


def start_chat(cipher_session, conn):
    def send_message():
        message = message_entry.get()
        if message:
            encrypted_message = cipher_session.encrypt(message.encode())
            chat_window.insert(tk.END, f"Bob: {message}\n")
            conn.sendall(encrypted_message)
            message_entry.delete(0, tk.END)

    def receive_messages():
        while True:
            try:
                encrypted_message = conn.recv(2048)
                if encrypted_message:
                    decrypted_message = cipher_session.decrypt(encrypted_message).decode()
                    chat_window.insert(tk.END, f"Alice: {decrypted_message}\n")
            except Exception as e:
                print(f"Ошибка при получении сообщения: {e}")
                break

    # Создание окна чата
    chat_root = tk.Tk()
    chat_root.title("Чат: Боб")
    chat_window = scrolledtext.ScrolledText(chat_root, wrap=tk.WORD, width=50, height=20)
    chat_window.pack(padx=10, pady=10)
    chat_window.insert(tk.END, "Вы подключены к чату с Алисой.\n")
    message_entry = tk.Entry(chat_root, width=40)
    message_entry.pack(side=tk.LEFT, padx=10)
    send_button = tk.Button(chat_root, text="Отправить", command=send_message)
    send_button.pack(side=tk.RIGHT, padx=10)

    Thread(target=receive_messages, daemon=True).start()

    chat_root.mainloop()

if __name__ == "__main__":
    bob_server()