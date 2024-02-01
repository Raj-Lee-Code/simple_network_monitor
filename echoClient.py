import socket


def echo_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = '127.0.0.1'
    server_port = 12345

    try:
        sock.connect((server_address, server_port))
        message = 'goodbye'
        print(f"Sending {message}")
        sock.sendall(message.encode())

        response = sock.recv(1024)
        print(f"Receieved: {response.decode()}")
    finally:
        sock.close()


if __name__ == "__main__":
    echo_client()