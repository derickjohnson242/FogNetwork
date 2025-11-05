# run_network.py
import threading
import subprocess
import time
from edge_node import run_edge

# --- Launch Fog Node ---
subprocess.Popen(["python3", "fog_node.py"])
time.sleep(2)  # wait for Fog Node to start

# --- Launch 3 Edge Nodes ---
threads = []
for node_id in range(1, 4):
    t = threading.Thread(target=run_edge, args=(node_id,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("[Main] All edge nodes finished sending HQC messages.")
