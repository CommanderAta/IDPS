
# Intrusion Detection and Prevention System (IDPS)

This project implements a simple Intrusion Detection and Prevention System (IDPS) that listens for incoming traffic and detects various types of malicious activities including SQL injections, DDoS attacks, vulnerability scans, and suspicious words.

## Running the Server

To start the IDPS server, use the following command:

```bash
python idps.py
```

## Simulating Traffic

You can simulate different types of traffic to test the IDPS using the `client.py` script. Below are the commands to trigger each use case.

### Normal Traffic

```bash
python3 client.py localhost 9999 "Hello, this is a normal message."
```

### SQL Injection

```bash
python3 client.py localhost 9999 "SELECT * FROM users WHERE username='admin' --"
```

### DDoS Attack (Simulated by sending multiple requests in a short time)

```bash
for i in {1..21}; do python3 client.py localhost 9999 "Normal request $i"; done
```

### Vulnerability Scan

```bash
python3 client.py localhost 9999 "/admin/login.php"
```

### Suspicious Words

```bash
python3 client.py localhost 9999 "This message contains suspicious words like ISIS and Jihad."
```

### Reset Blocked IPs

To reset the blocked IPs, press the 'r' key in the terminal where the server is running.

## File Structure

- `idps.py`: The server script that implements the IDPS.
- `client.py`: A client script to simulate traffic to the server.

## Notes

- Ensure both `idps.py` and `client.py` are in the same directory.
- Modify the `<HOST>` and `<PORT>` values in the commands as per your server's configuration.