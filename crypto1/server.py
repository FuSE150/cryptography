import socket

def start_server():

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 22334))
    server_socket.listen(1)
    print("Сервер запущен. Ожидание подключения клиента...")

    conn, addr = server_socket.accept()
    print(f"Клиент подключен: {addr}")

    while True:

        data = conn.recv(1024)
        if not data:
            break
        print(f"Сообщение от клиента: {data.decode()}")

        message = input("Ответьте клиенту: ")
        conn.sendall(message.encode())

    conn.close()

if __name__ == "__main__":
    start_server()
