import socket
import sys

def simulate_traffic(host, port, message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    client_socket.connect((host, port))
    
    client_socket.sendall(message.encode())

    client_socket.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client.py <HOST> <PORT> <MESSAGE>")
    else:
        simulate_traffic(sys.argv[1], int(sys.argv[2]), sys.argv[3])
