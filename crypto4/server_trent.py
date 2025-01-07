import socket
from cryptography.fernet import Fernet
import time


def is_timestamp_valid(received_timestamp, threshold=60):
    current_time = int(time.time())
    received_time = int(received_timestamp)
    return abs(current_time - received_time) <= threshold


key_alice_trent = Fernet.generate_key()
key_trent_bob = Fernet.generate_key()

cipher_alice_trent = Fernet(key_alice_trent)
cipher_trent_bob = Fernet(key_trent_bob)

print("Ключи сгенерированы:")
print(f"Ключ Алиса-Трент: {key_alice_trent}")
print(f"Ключ Трент-Боб: {key_trent_bob}")

HOST = "127.0.0.1"
PORT = 1111

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print("Трент ожидает подключения...")


while True:
    print("Ожидание подключения от Алисы...")
    conn_alice, addr_alice = server.accept()
    print(f"Подключение от Алисы: {addr_alice}")

    try:
        data_from_alice = conn_alice.recv(1024)
        if not data_from_alice:
            print("Данные от Алисы не получены.")
            continue

        received_message = data_from_alice.decode()
        alice_name, encrypted_data = received_message.split(":", 1)
        decrypted_data = cipher_alice_trent.decrypt(encrypted_data).decode()
        timestamp, bob_id, session_key = decrypted_data.split(":")

        if not is_timestamp_valid(timestamp):
            print("Ошибка: метка времени Ta устарела.")
            conn_alice.close()
            continue

        print(f"Трент получил: имя Алисы={alice_name}, метка времени={timestamp}, ID Боба={bob_id}, сеансовый ключ={session_key}")

        new_timestamp = str(int(time.time()))
        data_for_bob = f"{new_timestamp}:Alice:{session_key}"
        encrypted_data_for_bob = cipher_trent_bob.encrypt(data_for_bob.encode())

        print("Ожидание подключения от Боба...")
        conn_bob, addr_bob = server.accept()
        print(f"Подключение от Боба: {addr_bob}")

        conn_bob.sendall(encrypted_data_for_bob)
        print(f"Данные отправлены Бобу с новой меткой времени: {new_timestamp}")

    except Exception as e:
        print(f"Ошибка: {e}")

    finally:
        conn_alice.close()
        if 'conn_bob' in locals():
            conn_bob.close()
