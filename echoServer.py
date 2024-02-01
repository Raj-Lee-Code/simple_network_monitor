import socket


def echo_server():
	"""start echo server"""
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = '127.0.0.1'
	server_port = 12345
	server_socket.bind((server_address, server_port))
	server_socket.listen(5)
	print("Server is listening for incoming communication")
	try:
		clientResponse = True
		while clientResponse:
			client_sock, client_address = server_socket.accept()
			print(f"connection from {client_address}")
			try:
				message = client_sock.recv(1024)
				print(f"Received Message: {message.decode()}")
				if message.decode() == "goodbye":
					print("yo")
					clientResponse = False
					client_sock.close()
					print(f"Connection with {client_address} is closed")
					break
				response = "Message received from echo client!"
				client_sock.sendall(response.encode())
			finally:
				client_sock.close()
				print(f"Connection with {client_address} is closed")

	except KeyboardInterrupt:
		print("server is shutting down")
	finally:
		server_socket.close()
		print("server socket closed")


if __name__ == "__main__":
	echo_server()
