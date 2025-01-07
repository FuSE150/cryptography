import socket
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext
import time


def send_message():
    message = input_field.get()
    if not message.strip():
        return
    encrypted_message = cipher_session.encrypt(message.encode())
    conn_alice.sendall(encrypted_message)
    chat_window.insert(tk.END, f"Вы: {message}\n")
    input_field.delete(0, tk.END)


def receive_messages():
    while True:
        try:
            data = conn_alice.recv(1024)
            if not data:
                break
            decrypted_message = cipher_session.decrypt(data).decode()
            chat_window.insert(tk.END, f"Алиса: {decrypted_message}\n")
        except Exception as e:
            print(f"Ошибка приема сообщений: {e}")
            break


def validate_timestamp(received_timestamp):
    current_timestamp = int(time.time())
    difference = current_timestamp - int(received_timestamp)
    if difference > 60:
        raise ValueError(f"Метка времени недействительна! Разница {difference} секунд.")
    print("Метка времени действительна.")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect(("127.0.0.1", 1111))
    print("Боб подключился к Тренту и ожидает данных.")
    data = sock.recv(1024)
    if data:
        key_trent_bob = b'Iu0630oTOnpvcQXH_mgLSXm7aCtTErZFex1vCB6wsN8='
        cipher_trent_bob = Fernet(key_trent_bob)
        decrypted_data = cipher_trent_bob.decrypt(data).decode()
        timestamp, alice_id, session_key = decrypted_data.split(":")

        try:
            validate_timestamp(timestamp)
        except ValueError as e:
            print(e)
            exit(1)

        SESSION_KEY = session_key.encode()
        cipher_session = Fernet(SESSION_KEY)
        print(f"Боб получил: метка времени={timestamp}, ID Алисы={alice_id}, сеансовый ключ={session_key}")


server_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_bob.bind(("127.0.0.1", 1112))
server_bob.listen(1)
print("Боб ожидает подключения Алисы...")

conn_alice, addr_alice = server_bob.accept()
print(f"Алиса подключилась: {addr_alice}")

root = tk.Tk()
root.title("Чат: Боб")
chat_window = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=20)
chat_window.pack(padx=10, pady=10)
chat_window.insert(tk.END, "Вы подключены к чату с Алисой.\n")
input_field = tk.Entry(root, width=40)
input_field.pack(side=tk.LEFT, padx=10)
send_button = tk.Button(root, text="Отправить", command=send_message)
send_button.pack(side=tk.RIGHT, padx=10)
Thread(target=receive_messages, daemon=True).start()

root.mainloop()
