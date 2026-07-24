import socket
import threading
import time

def echo_server(port, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(5)
    print(f"[{name}] Listening on 127.0.0.1:{port}")
    while True:
        conn, addr = s.accept()
        data = conn.recv(4096)
        print(f"[{name}] Received {len(data)} bytes from {addr}: {data[:50].hex()}")
        conn.send(b"OK")
        conn.close()

for port, name in [(20880, "dubbo"), (9876, "rocketmq"), (27017, "mongo")]:
    threading.Thread(target=echo_server, args=(port, name), daemon=True).start()

print("All listeners started. Press Ctrl+C to stop.")
while True:
    time.sleep(1)
