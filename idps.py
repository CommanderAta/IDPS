import socket
import re
from collections import defaultdict
from time import time, sleep
import threading

request_times = defaultdict(list)
blocked_ips = set()
reset_flag = threading.Event()

def is_sql_injection(data):
    patterns = [
        r"(?i)\bunion\b.*\bselect\b",
        r"(?i)\bselect\b.*\bfrom\b",
        r"(?i)\bdrop\b.*\btable\b",
        "--",
        r"(?i)or 1=1",
        r"(?i)';--",
        r"(?i)' or '1'='1",
        r"(?i)or '1'='1' --",
        r"(?i)exec(\s|\()+",
        r"(?i)xp_cmdshell"
    ]
    for pattern in patterns:
        if re.search(pattern, data):
            return True
    return False

def detect_ddos(ip):
    time_threshold = 10 
    request_limit = 20 
    current_time = time()

    # Remove old entries
    request_times[ip] = [t for t in request_times[ip] if current_time - t < time_threshold]
    request_times[ip].append(current_time)

    return len(request_times[ip]) > request_limit

def is_vulnerability_scan(data):
    scan_patterns = [
        r"\.php",
        r"\.asp",
        r"\.jsp",
        r"(?i)admin",
        r"(?i)wp-admin",
        r"(?i)login",
        r"(?i)shell",
        r"(?i)cmd",
        r"(?i)upload"
    ]
    for pattern in scan_patterns:
        if re.search(pattern, data):
            return True
    return False

def contains_suspicious_words(data):
    suspicious_words = [
        r"(?i)ISIS",
        r"(?i)Jihad"
    ]
    for word in suspicious_words:
        if re.search(word, data):
            return True
    return False

def block_ip(ip):
    blocked_ips.add(ip)
    print(f"IP {ip} has been blocked due to suspicious activity.")

def reset_blocked_ips():
    global blocked_ips
    while True:
        if reset_flag.is_set():
            blocked_ips.clear()
            print("Blocked IPs have been reset.")
            reset_flag.clear()
        sleep(1)

def monitor_input():
    while True:
        if input() == 'r':
            reset_flag.set()

def start_idps(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"IDPS is listening on {host}:{port}")

    try:
        while True:
            client_socket, (addr, _) = server_socket.accept()
            if addr in blocked_ips:
                print(f"Blocked IP {addr} tried to connect.")
                client_socket.close()
                continue

            data = client_socket.recv(1024).decode()
            print(f"Received data from {addr}: {data}")

            if detect_ddos(addr):
                print(f"Potential DDoS attack detected from {addr}!")
                block_ip(addr)
            elif is_sql_injection(data):
                print("SQL Injection detected!")
                block_ip(addr)
            elif is_vulnerability_scan(data):
                print("Vulnerability scan attempt detected!")
                block_ip(addr)
            elif contains_suspicious_words(data):
                print("Suspicious words detected!")
                block_ip(addr)
            else:
                print("Normal traffic.")

            client_socket.close()
    finally:
        server_socket.close()

if __name__ == "__main__":
    threading.Thread(target=reset_blocked_ips, daemon=True).start()
    threading.Thread(target=monitor_input, daemon=True).start()
    start_idps("localhost", 9999)
