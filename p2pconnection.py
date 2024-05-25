import socket
import threading

class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = []

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        print(f"Connection from {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received: {data}")
            # Handle received data (e.g., new blocks, transactions)
        conn.close()

    def connect_to_peer(self, host, port):
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.connect((host, port))
        self.peers.append(peer)
        print(f"Connected to peer {host}:{port}")

    def broadcast(self, message):
        for peer in self.peers:
            peer.sendall(message.encode())