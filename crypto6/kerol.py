import socket
import random
import time
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from cryptography.fernet import Fernet
import hashlib
import base64

p = 23
g = 5

def generate_symmetric_key(secret):
    return hashlib.sha256(str(secret).encode()).digest()

class CipherSession:
    def __init__(self, key):
        self.fernet = Fernet(base64.urlsafe_b64encode(key[:32]))

    def encrypt(self, message):
        return self.fernet.encrypt(message)

    def decrypt(self, message):
        return self.fernet.decrypt(message)

def start_chat(role, connections, cipher_session):
    def send_message():
        message = input_field.get()
        if not message.strip():
            return
        for conn in connections:
            encrypted_message = cipher_session.encrypt(f"{role}: {message}".encode())
            conn.sendall(encrypted_message)
        chat_window.insert(tk.END, f"Вы: {message}\n")
        input_field.delete(0, tk.END)

    def receive_messages():
        while True:
            for conn in connections:
                try:
                    data = conn.recv(1024)
                    if not data:
                        continue
                    decrypted_message = cipher_session.decrypt(data).decode()
                    chat_window.insert(tk.END, f"{decrypted_message}\n")
                except Exception as e:
                    print(f"Ошибка приема сообщений: {e}")
                    continue

    root = tk.Tk()
    root.title(f"Чат: {role}")
    chat_window = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=20)
    chat_window.pack(padx=10, pady=10)
    chat_window.insert(tk.END, f"Вы подключены к чату.\n")
    input_field = tk.Entry(root, width=40)
    input_field.pack(side=tk.LEFT, padx=10)
    send_button = tk.Button(root, text="Отправить", command=send_message)
    send_button.pack(side=tk.RIGHT, padx=10)

    Thread(target=receive_messages, daemon=True).start()
    root.mainloop()


k = random.randint(1, p-1)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 5001))
print(f"Кэрол подключилась к Бобу")

B = int(client_socket.recv(1024).decode())
print(f"Кэрол получила B: {B}")

K = pow(B, k, p)
print(f"Кэрол вычислила общий секретный ключ K: {K}")

client_socket.close()

client_socket_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket_bob.connect(('localhost', 5002))
print(f"Кэрол подключилась к Бобу")

BB = int(client_socket_bob.recv(1024).decode())
print(f"Кэрол получила BB: {BB}")

KK = pow(BB, k, p)
print(f"Кэрол вычислила KK: {KK}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5003))
server_socket.listen(1)
print("Кэрол ожидает подключения от Алисы...")
client_socket, address = server_socket.accept()
print(f"Подключилась Алиса: {address}")

client_socket.send(str(KK).encode())
print(f"Алисе отправлено сообщение")

client_socket.close()
server_socket.close()

KKK = pow(g, k, p)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5004))
server_socket.listen(1)
print("Кэрол ожидает подключения от Алисы")
client_socket_alice, address = server_socket.accept()
print(f"Подключилась Алиса: {address}")

client_socket_alice.send(str(KKK).encode())
print(f"Алисе отправлено сообщение KKK")

symmetric_key = generate_symmetric_key(K)
cipher_session = CipherSession(symmetric_key)

connections = [client_socket_alice, client_socket_bob]
start_chat("Кэрол", connections, cipher_session)
