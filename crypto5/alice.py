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

alice_private_key = rsa.PrivateKey.load_pkcs1(open("alice_private.pem", "rb").read())


def alice_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as trent_client:
        trent_client.connect(('localhost', 1111))
        trent_client.sendall("Alice: Bob".encode())

        data_bob = trent_client.recv(2048)
        print(f"Alice: Получено от Трента (Боб): {data_bob}")

        try:
            part1_bob, part2_bob = data_bob.split(b"::")
        except ValueError:
            print("Alice: Ошибка разделения данных (Боб).")
            return

        message_bob, signed_bob_hex = part1_bob.decode(), part2_bob.decode()
        signed_bob = bytes.fromhex(signed_bob_hex)

        try:
            rsa.verify(message_bob.encode(), signed_bob, trent_public_key)
            print("Alice: Подпись для ключа Боба верна.")
        except rsa.VerificationError:
            print("Alice: Подпись для ключа Боба неверна.")
            return

        if "PublicKey" in message_bob:
            key_data = message_bob.split("PublicKey(", 1)[1].split(")")[0]
            modulus, exponent = map(int, key_data.split(", "))
            bob_public_key = rsa.PublicKey(modulus, exponent)
            print(f"Alice: Открытый ключ Боба успешно извлечён: {bob_public_key}")
        else:
            print("Alice: Ошибка извлечения ключа Боба.")
            return

        data_alice = trent_client.recv(2048)
        print(f"Alice: Получено от Трента (Алиса): {data_alice}")

        try:
            part1_alice, part2_alice = data_alice.split(b"::")
        except ValueError:
            print("Alice: Ошибка разделения данных (Алиса).")
            return

        message_alice, signed_alice_hex = part1_alice.decode(), part2_alice.decode()
        signed_alice = bytes.fromhex(signed_alice_hex)

        try:
            rsa.verify(message_alice.encode(), signed_alice, trent_public_key)
            print("Alice: Подпись для ключа Алисы верна.")
        except rsa.VerificationError:
            print("Alice: Подпись для ключа Алисы неверна.")

        print("Alice: Закрытие соединения с Трентом.")
        trent_client.close()

        timestamp = str(int(time.time()))
        print(f"Alice: Метка времени создана: {timestamp}")

        session_key = Fernet.generate_key().decode()
        cipher_session = Fernet(session_key.encode())
        print(f"Alice: Сессионный ключ сгенерирован: {session_key}")

        session_data = f"{session_key}:{timestamp}".encode()
        session_signature = rsa.sign(session_data, alice_private_key, 'SHA-256')
        print("Alice: Сессионные данные подписаны.")

        encrypted_session_data = rsa.encrypt(session_data, bob_public_key)
        print("Alice: Сессионные данные зашифрованы.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob_client:
        bob_client.connect(('localhost', 2222))

        bob_client.sendall(data_alice)
        print("Alice: Переслано сообщение от Трента для Алисы.")
        time.sleep(0.5)

        bob_client.sendall(data_bob)
        print("Alice: Переслано сообщение от Трента для Боба.")
        time.sleep(0.5)

        bob_client.sendall(encrypted_session_data + b"::" + session_signature)
        print("Alice: Отправлены зашифрованные и подписанные сессионные данные для Боба.")
        time.sleep(0.5)

        print("Alice: Открываем чат...")
        start_chat(cipher_session, bob_client)



def start_chat(cipher_session, bob_client):
    def send_message():
        message = message_entry.get()
        if message:
            encrypted_message = cipher_session.encrypt(message.encode())
            chat_window.insert(tk.END, f"Alice: {message}\n")
            bob_client.sendall(encrypted_message)
            message_entry.delete(0, tk.END)

    def receive_messages():
        while True:
            try:
                encrypted_message = bob_client.recv(2048)
                if encrypted_message:
                    decrypted_message = cipher_session.decrypt(encrypted_message).decode()
                    chat_window.insert(tk.END, f"Bob: {decrypted_message}\n")
            except Exception as e:
                print(f"Ошибка при получении сообщения: {e}")
                break

    chat_root = tk.Tk()
    chat_root.title("Чат: Алиса")
    chat_window = scrolledtext.ScrolledText(chat_root, wrap=tk.WORD, width=50, height=20)
    chat_window.pack(padx=10, pady=10)
    chat_window.insert(tk.END, "Вы подключены к чату с Бобом.\n")
    message_entry = tk.Entry(chat_root, width=40)
    message_entry.pack(side=tk.LEFT, padx=10)
    send_button = tk.Button(chat_root, text="Отправить", command=send_message)
    send_button.pack(side=tk.RIGHT, padx=10)

    Thread(target=receive_messages, daemon=True).start()

    chat_root.mainloop()

if __name__ == "__main__":
    alice_client()
