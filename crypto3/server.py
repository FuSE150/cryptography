import tkinter as tk
import socket
import threading
import rsa
from tkinter import scrolledtext

server_public_key, server_private_key = rsa.newkeys(512)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('192.168.1.119', 1111))
server_socket.listen()

clients = []
client_public_keys = {}


def send_message():
    global client_public_keys
    message = entry_message.get().strip()
    if not message:
        return
    for client_socket in clients:
        if client_socket in client_public_keys:
            encrypted_message = rsa.encrypt(message.encode(), client_public_keys[client_socket])
            chat_display.insert(tk.END, f"Зашифрованное сообщение: {encrypted_message}\n", 'encrypted')
            chat_display.insert(tk.END, f"Сервер: {message}\n", 'server')
            chat_display.see(tk.END)
            client_socket.send(encrypted_message)
    entry_message.delete(0, tk.END)


def receive_messages(client_socket):
    global client_public_keys
    try:
        client_key_data = client_socket.recv(1024)
        client_public_keys[client_socket] = rsa.PublicKey.load_pkcs1(client_key_data)
        client_socket.send(server_public_key.save_pkcs1())
        while True:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break
            message = rsa.decrypt(encrypted_message, server_private_key).decode()
            chat_display.insert(tk.END, f"Зашифрованное сообщение: {encrypted_message}\n", 'encrypted')
            chat_display.insert(tk.END, f"Клиент: {message}\n", 'client')
            chat_display.see(tk.END)
    except:
        pass
    finally:
        clients.remove(client_socket)
        del client_public_keys[client_socket]
        chat_display.insert(tk.END, "Клиент отключился.\n", 'server')
        chat_display.see(tk.END)


root = tk.Tk()
root.title("Server Chat")

chat_display = scrolledtext.ScrolledText(root, height=20, width=50, state='normal', bg="#f0f0f0", fg="black")
chat_display.pack(pady=10, padx=10)
chat_display.tag_config('client', foreground="blue")
chat_display.tag_config('server', foreground="green")
chat_display.tag_config('encrypted', foreground="gray")
chat_display.insert(tk.END, "Сервер запущен, ожидает подключения клиента...\n", 'server')

entry_message = tk.Entry(root, width=50)
entry_message.pack(pady=10, padx=10)
entry_message.bind("<Return>", lambda event: send_message())

send_button = tk.Button(root, text="Отправить", command=send_message, bg="#4CAF50", fg="white")
send_button.pack(pady=10)


def accept_clients():
    while True:
        client_socket, client_address = server_socket.accept()
        clients.append(client_socket)
        chat_display.insert(tk.END, f"Клиент подключен: {client_address}\n", 'server')
        chat_display.see(tk.END)
        threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()


threading.Thread(target=accept_clients, daemon=True).start()
root.mainloop()
