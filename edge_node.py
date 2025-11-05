# edge_node.py
import socket
import struct
import time
from hqc_wrapper import encapsulate, PK_LEN

HOST = '127.0.0.1'
PORT = 5000

# --- System Config (Real) ---
SYSTEM_CONFIG = {
    "node_type": "Edge Node",
    "CPU": "1-core 1.6GHz",          # affects processing delay per message
    "RAM": "512MB",
    "OS": "Kali Linux",
    "Sensor_Types": ["temperature", "humidity", "AQI"]
}

print("[EdgeNode] System Config:", SYSTEM_CONFIG)

# --- CPU delay simulation ---
def cpu_delay():
    delay = 0.5  # slower CPU, more delay per message
    time.sleep(delay)

# --- Length-prefixed send ---
def send_msg(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)

# --- Run one edge node ---
def run_edge(node_id):
    print(f"[EdgeNode-{node_id}] Connecting to Fog Node...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            # 1: receive HQC public key from Fog Node
            fog_pk = s.recv(PK_LEN)
            print(f"[EdgeNode-{node_id}] Received public key from Fog Node.")

            # 2: send 5 HQC-encrypted sensor messages
            for i in range(5):
                # Generate sensor data according to Sensor_Types
                data_items = []
                if "temperature" in SYSTEM_CONFIG["Sensor_Types"]:
                    data_items.append(f"T:{22 + node_id + i}C")
                if "humidity" in SYSTEM_CONFIG["Sensor_Types"]:
                    data_items.append(f"H:{43 + i}%")
                if "AQI" in SYSTEM_CONFIG["Sensor_Types"]:
                    data_items.append(f"AQI:{50 + node_id*2}")
                data_str = f"Node{node_id}-" + ",".join(data_items)
                data_bytes = data_str.encode()

                # HQC encapsulate each message
                ct, _ = encapsulate(fog_pk)  # _ is shared secret, not used
                send_msg(s, ct)
                print(f"[EdgeNode-{node_id}] Sent HQC message {i+1}: {ct.hex()[:32]}...")
                cpu_delay()
        print(f"[EdgeNode-{node_id}] Finished sending data.")
    except Exception as e:
        print(f"[EdgeNode-{node_id}] Error: {e}")
