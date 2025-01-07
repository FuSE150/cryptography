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


b = random.randint(1, p-1)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 5000))
print(f"Боб подключился к Алисе")

A = int(client_socket.recv(1024).decode())
print(f"Боб получил A: {A}")

B = pow(A, b, p)
print(f"Боб вычислил B: {B}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5001))
server_socket.listen(1)
print("Боб ожидает подключения от Кэрол...")
client_socket, address = server_socket.accept()
print(f"Подключилась Кэрол: {address}")

client_socket.send(str(B).encode())
print(f"Кэрол отправлено сообщение B")

client_socket.close()
server_socket.close()

BB = pow(g, b, p)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5002))
server_socket.listen(1)
print("Боб ожидает подключения от Кэрол")
client_socket_kerol, address = server_socket.accept()
print(f"Подключилась Кэрол: {address}")

client_socket_kerol.send(str(BB).encode())
print(f"Кэрол отправлено сообщение BB")

server_socket.close()

client_socket_alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        client_socket_alice.connect(('localhost', 5005))
        print("Подключение к Алисе успешно!")
        break
    except ConnectionRefusedError:
        print("Не удалось подключиться к Алисе. Повторная попытка через 5 секунд...")
        time.sleep(5)

AAA = int(client_socket_alice.recv(1024).decode())
print(f"Боб получила AAA: {AAA}")

BBB = pow(AAA, b, p)
print(f"Боб вычислила общий секретный ключ BBB: {BBB}")

symmetric_key = generate_symmetric_key(BBB)
cipher_session = CipherSession(symmetric_key)

connections = [client_socket_alice, client_socket_kerol]
start_chat("Боб", connections, cipher_session)