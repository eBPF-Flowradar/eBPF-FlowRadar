import socket
import subprocess
import os

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
		cmd1 =  subprocess.Popen(['echo', 'rajesh@2003'], stdout=subprocess.PIPE)
		process = subprocess.Popen(data.split(" "), stdin=cmd1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE);
	conn.close()

if __name__ == '__main__':
	host = '192.168.124.158'
	port = 65432
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((host, port))
	server.listen(3)
	start_server(server)

