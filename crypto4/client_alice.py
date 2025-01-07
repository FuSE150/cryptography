import socket
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import time


def send_message():
    message = input_field.get()
    if not message.strip():
        return
    encrypted_message = cipher_session.encrypt(message.encode())
    conn_bob.sendall(encrypted_message)
    chat_window.insert(tk.END, f"Вы: {message}\n")
    input_field.delete(0, tk.END)


def receive_messages():
    while True:
        try:
            data = conn_bob.recv(1024)
            if not data:
                break
            decrypted_message = cipher_session.decrypt(data).decode()
            chat_window.insert(tk.END, f"Боб: {decrypted_message}\n")
        except Exception as e:
            print(f"Ошибка приема сообщений: {e}")
            break


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect(("127.0.0.1", 1111))
    print("Подключение к Тренту установлено.")

    timestamp = str(int(time.time()))
    bob_id = "Bob"
    session_key = Fernet.generate_key().decode()
    SESSION_KEY = session_key.encode()
    cipher_session = Fernet(SESSION_KEY)
    alice_name = "Алиса"

    data = f"{timestamp}:{bob_id}:{session_key}"
    key_alice_trent = b'3h-oi9ZzlCw4UGwA_H8mVbDFpR_QW1wkupvHtTFcsB4='
    cipher_alice_trent = Fernet(key_alice_trent)
    encrypted_data = cipher_alice_trent.encrypt(data.encode())

    message_to_send = f"{alice_name}:{encrypted_data.decode()}"

    sock.sendall(message_to_send.encode())
    print(f"Имя Алисы и зашифрованные данные отправлены Тренту.")
    print(f"Сеансовый ключ{session_key} .")

except ConnectionRefusedError:
    print("Не удалось подключиться к Тренту. Проверьте, работает ли сервер.")
    exit()


conn_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Ожидаем подключения к Бобу...")
while True:
    try:
        conn_bob.connect(("127.0.0.1", 1112))
        print("Алиса подключилась к Бобу.")
        break
    except ConnectionRefusedError:
        print("Боб ещё не готов. Повторяем попытку...")
        time.sleep(2)

root = tk.Tk()
root.title("Чат: Алиса")
chat_window = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=20)
chat_window.pack(padx=10, pady=10)
chat_window.insert(tk.END, "Вы подключены к чату с Бобом.\n")
input_field = tk.Entry(root, width=40)
input_field.pack(side=tk.LEFT, padx=10)
send_button = tk.Button(root, text="Отправить", command=send_message)
send_button.pack(side=tk.RIGHT, padx=10)

Thread(target=receive_messages, daemon=True).start()

root.mainloop()
