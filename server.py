import socket
import subprocess
import os


def send_command(client_socket, command, host='192.168.124.158', port=8005):
    bytes_padded = 80 - len(command)
    command = command + '\x00' * bytes_padded
    client_socket.sendall(command.encode('utf-8'))    

def start_server(server_socket):
	conn, addr = server_socket.accept()
	print("COnnection ACCEPTED")
	count = 0
	while True:
		data = conn.recv(80).decode()
		data = data.rstrip("\x00")
		if not data:
			break
		print(f"Received command: {data}")
		if data == './flowradar enp2s0':
			print("Hello World")
			process = subprocess.Popen(data.split(" "), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE);
			send_command(conn, "ACK")
		else:
			os.system(data)
			send_command(conn, "ACK")
	conn.close()

if __name__ == '__main__':
	host = '192.168.124.158'
	port = 65432
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((host, port))
	server.listen(3)
	start_server(server)

