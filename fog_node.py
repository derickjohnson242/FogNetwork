# fog_node.py
import socket
import threading
import struct
import time
from hqc_wrapper import generate_keypair, decapsulate, CT_LEN, PK_LEN

HOST = '127.0.0.1'
PORT = 5000

# --- System Config (Real) ---
SYSTEM_CONFIG = {
    "node_type": "Fog Node",
    "CPU": "4-core 2.4GHz",          # affects processing delay per message
    "RAM": "4GB",
    "OS": "Kali Linux",
    "Network": f"TCP {HOST}:{PORT}",
    "Max_Edge_Nodes": 3
}

print("[FogNode] System Config:", SYSTEM_CONFIG)

# --- CPU delay simulation ---
def cpu_delay():
    # Simulate processing based on CPU speed: slower CPU → longer delay
    delay = 0.2  # for 2.4GHz
    time.sleep(delay)

# --- Length-prefixed receive ---
def recv_msg(conn):
    raw_len = conn.recv(4)
    if not raw_len:
        return None
    length = struct.unpack(">I", raw_len)[0]
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# --- Generate HQC keypair ---
pk, sk = generate_keypair()
print("[FogNode] Public Key:", pk[:20].hex(), "...")
print("[FogNode] Secret Key:", sk[:20].hex(), "...")

# --- Handle each edge node (stable, pure HQC) ---
def handle_edge(conn, addr):
    print(f"[FogNode] Connected by EdgeNode at {addr}")
    try:
        # 1: send HQC public key to edge node
        conn.sendall(pk)

        # 2: receive 5 HQC messages
        for i in range(5):
            raw_ct = conn.recv(CT_LEN)
            if not raw_ct:
                print(f"[FogNode] Connection lost while receiving message {i+1} from {addr}")
                break

            # 3: decapsulate HQC ciphertext to get shared secret
            shared_secret = decapsulate(raw_ct, sk)

            # 4: simulate CPU processing delay based on node config
            cpu_delay()

            # 5: print shared secret as hex for research purposes
            print(f"[FogNode] Received HQC message {i+1} from {addr}: {shared_secret.hex()[:32]}...")

        print(f"[FogNode] Finished communication with {addr}")

    except Exception as e:
        print(f"[FogNode] Error with {addr}: {e}")
    finally:
        conn.close()

# --- Start TCP server ---
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(SYSTEM_CONFIG["Max_Edge_Nodes"])
print(f"[FogNode] Listening for up to {SYSTEM_CONFIG['Max_Edge_Nodes']} edge nodes...")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_edge, args=(conn, addr), daemon=True).start()
