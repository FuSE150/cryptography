import socket
import rsa

alice_public_key = rsa.PublicKey.load_pkcs1(b"""
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAl0YxQzjqBJDyMtO1RJbOXCpnw3S/QyECETf43/ijIbQAinQN3hgr
+gYQx18BTXJ/HHrHWz0DQgC6oJ+s8GpIU0a+OVdXeMrC5BxYRT5jajqNdKset4ld
Y8UMlf5Y8Cvy1zGUlm/YIPaKbt6ddJ989/LlP7deLgVBrGzBnVAMkYEqCWQHmb62
kMkMDgXwyLUSgyCjxuc6b0z6W5iAHlHDJbvfQmrumwLT3D+PLH3yF3K+dnNPxMIl
3XYbH21o0x/kL4viO3X1IGjKQ7iVS0bs8pgcjExJIn1a/xZMICxA7CfOJGceH8r9
K2HXO4pCO5fM+TzO4T16Y1RtuUWHlyrJCQIDAQAB
-----END RSA PUBLIC KEY-----
""")

bob_public_key = rsa.PublicKey.load_pkcs1(b"""
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAs+wrjsV44n/FQ+zmXm5pngU0R8tWxSs7igcNIlV849hGa2qIXtjZ
S1tifKHnqg5Gx2FbweNHf1souGfhktXe9jVvL9PjLRvGWTJa+Lfr/q8LBCc0RzBx
GID+ZHwaCTtJ0LsevpwhOsbEwIWLM+hchbtNZdOnlA2ZxVvgiVRBcax34c2W96Hl
0s3FQyw1VXYCbUbM88gC0e4pUptjAW7DNTE4fUX0TPQ9vad62yuJTEr3xMWjgnnW
zSAC0HCK909PBNTFRjS/0dXMBUftIMr9q+3p1sD7OTc4DN1xuBKFxGRCLrge2/Rf
jj2e02ForPaXJj4IHMvNQpVlovhxYThtlwIDAQAB
-----END RSA PUBLIC KEY-----
""")

trent_private_key = rsa.PrivateKey.load_pkcs1(open("trent_private.pem", "rb").read())

def trent_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        try:
            server.bind(('localhost', 1111))
            server.listen(1)
            print("Trent: Сервер запущен и ждет подключения...")


            conn, addr = server.accept()
            with conn:
                print(f"Trent: Получен запрос от {addr}")
                data = conn.recv(1024).decode()
                print(f"Trent: Полученные данные: {data}")

                if data == "Alice: Bob":
                    message_bob = f"Bob:{bob_public_key}"
                    message_alice = f"Alice:{alice_public_key}"

                    signed_bob = rsa.sign(message_bob.encode(), trent_private_key, 'SHA-256')
                    signed_alice = rsa.sign(message_alice.encode(), trent_private_key, 'SHA-256')

                    conn.sendall(f"{message_bob}::{signed_bob.hex()}".encode())
                    conn.sendall(f"{message_alice}::{signed_alice.hex()}".encode())

                    print("Trent: Подписанные ключи отправлены Алисе.")
                else:
                    print("Trent: Получен неожиданный запрос.")
        except Exception as e:
            print(f"Trent: Ошибка при запуске сервера: {e}")
        finally:
            print("Trent: Сервер завершает работу.")

if __name__ == "__main__":
    trent_server()
