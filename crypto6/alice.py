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


a = random.randint(1, p-1)

A = pow(g, a, p)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5000))
server_socket.listen(1)
print("Алиса ожидает подключения...")
client_socket, address = server_socket.accept()
print(f"Подключился Боб: {address}")

client_socket.send(str(A).encode())
print(f"Бобу отправлено сообщение")

client_socket.close()
server_socket.close()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        client_socket.connect(('localhost', 5003))
        print("Подключение к Кэрол успешно!")
        break
    except ConnectionRefusedError:
        print("Не удалось подключиться к Кэрол. Повторная попытка через 5 секунд...")
        time.sleep(5)

KK = int(client_socket.recv(1024).decode())
print(f"Алиса получила KK: {KK}")

AA = pow(KK, a, p)
print(f"Алиса вычислила общий секретный ключ AA: {AA}")

client_socket.close()

client_socket_kerol = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket_kerol.connect(('localhost', 5004))

KKK = int(client_socket_kerol.recv(1024).decode())
print(f"Алиса получила KKK: {KKK}")

AAA = pow(KKK, a, p)
print(f"Алиса вычислила AAA: {AAA}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5005))
server_socket.listen(1)
print("Алиса ожидает подключения от Боба...")
client_socket_bob, address = server_socket.accept()
print(f"Подключился Боб: {address}")

client_socket_bob.send(str(AAA).encode())
print(f"Бобу отправлено сообщение AAA")

symmetric_key = generate_symmetric_key(AA)
cipher_session = CipherSession(symmetric_key)

connections = [client_socket_bob, client_socket_kerol]
start_chat("Алиса", connections, cipher_session)
