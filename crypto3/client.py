import tkinter as tk
import socket
import threading
import rsa
from tkinter import scrolledtext

client_public_key, client_private_key = rsa.newkeys(512)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_public_key = None


def connect_to_server():
    global client_socket, server_public_key
    client_socket.connect(('192.168.1.119', 1111))
    client_socket.send(client_public_key.save_pkcs1())
    server_key_data = client_socket.recv(1024)
    if not server_key_data:
        chat_display.insert(tk.END, "Не удалось получить публичный ключ сервера.\n", 'client')
        chat_display.see(tk.END)
        return

    server_public_key = rsa.PublicKey.load_pkcs1(server_key_data)
    chat_display.insert(tk.END, "Вы подключены к серверу, приятного общения!\n", 'client')
    chat_display.see(tk.END)



def send_message():
    global server_public_key
    message = entry_message.get().strip()
    if not message:
        return
    if server_public_key is None:
        chat_display.insert(tk.END, "Не удалось отправить сообщение, серверный ключ недоступен.\n", 'client')
        chat_display.see(tk.END)
        return
    encrypted_message = rsa.encrypt(message.encode(), server_public_key)
    chat_display.insert(tk.END, f"Зашифрованное сообщение: {encrypted_message}\n", 'encrypted')
    chat_display.insert(tk.END, f"Клиент: {message}\n", 'client')
    chat_display.see(tk.END)

    entry_message.delete(0, tk.END)
    client_socket.send(encrypted_message)



def receive_messages():
    global server_public_key
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            message = rsa.decrypt(encrypted_message, client_private_key).decode()
            chat_display.insert(tk.END, f"Зашифрованное сообщение: {encrypted_message}\n", 'encrypted')
            chat_display.insert(tk.END, f"Сервер: {message}\n", 'server')
            chat_display.see(tk.END)
        except:
            chat_display.insert(tk.END, "Соединение с сервером прервано.\n", 'client')
            chat_display.see(tk.END)
            break


root = tk.Tk()
root.title("Client Chat")

chat_display = scrolledtext.ScrolledText(root, height=20, width=50, state='normal', bg="#f0f0f0", fg="black")
chat_display.pack(pady=10, padx=10)
chat_display.tag_config('client', foreground="blue")
chat_display.tag_config('server', foreground="green")
chat_display.tag_config('encrypted', foreground="gray")

entry_message = tk.Entry(root, width=50)
entry_message.pack(pady=10, padx=10)
entry_message.bind("<Return>", lambda event: send_message())

send_button = tk.Button(root, text="Отправить", command=send_message, bg="#4CAF50", fg="white")
send_button.pack(pady=10)

connect_to_server()
threading.Thread(target=receive_messages, daemon=True).start()
root.mainloop()
