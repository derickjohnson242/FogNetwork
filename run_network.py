# run_network.py
import threading
import time
import os
import csv
import pandas as pd
import matplotlib.pyplot as plt
from Crypto.Random import get_random_bytes

# import FogServer and EdgeClient classes
from fog_server import FogServer
from edge_client import EdgeClient

# ---------------- Configuration ----------------
FOG_COUNT = 2
EDGES_PER_FOG = 5
PAYLOAD_SIZE = 100  # bytes
REKEY_INTERVAL = 60  # seconds
JITTER_MS = 1  # for reference, already baked into modules

BASE_HOST = "127.0.0.1"
BASE_PORT = 6000  # fog ports will be BASE_PORT, BASE_PORT+1
PRE_SHARED_KEY = get_random_bytes(32)  # in real-life each edge would have its own PSK; here we share one for simplicity

# metrics collector (thread-safe list)
metrics = []

# create fog servers
fogs = []
for i in range(FOG_COUNT):
    port = BASE_PORT + i
    fs = FogServer(fog_id=i+1, host=BASE_HOST, port=port, max_edges=EDGES_PER_FOG,
                   pre_shared_key=PRE_SHARED_KEY, metrics_collector=metrics,
                   rekey_interval=REKEY_INTERVAL)
    fs.start()
    fogs.append(fs)

# small startup wait
time.sleep(2.0)

# launch edge clients
threads = []
edge_id = 1
for f_index, fs in enumerate(fogs):
    for j in range(EDGES_PER_FOG):
        ec = EdgeClient(node_id=edge_id, fog_host=fs.host, fog_port=fs.port,
                        pre_shared_key=PRE_SHARED_KEY, payload_size=PAYLOAD_SIZE,
                        metrics_collector=metrics)
        t = threading.Thread(target=ec.run, daemon=True)
        t.start()
        threads.append(t)
        edge_id += 1
        time.sleep(0.05)  # slight stagger

# wait for all edges to finish
for t in threads:
    t.join()

# Give some time for fog to process any remaining
time.sleep(2.0)

# Stop fogs
for fs in fogs:
    fs.stop()

# ---------------- Persist metrics to CSV and Excel ----------------
OUT_CSV = "metrics.csv"
OUT_XLSX = "metrics.xlsx"
OUT_PNG = "enc_dec_times.png"

# normalize metrics to rows (some entries have keygen only)
rows = []
for m in metrics:
    rows.append({
        "timestamp": m.get("timestamp"),
        "fog_id": m.get("fog_id"),
        "edge_id": m.get("edge_id"),
        "rekey_round": m.get("rekey_round"),
        "keygen_time_ms": m.get("keygen_time_ms"),
        "enc_time_ms": m.get("enc_time_ms"),
        "dec_time_ms": m.get("dec_time_ms")
    })

df = pd.DataFrame(rows)
df.to_csv(OUT_CSV, index=False)
df.to_excel(OUT_XLSX, index=False)

print(f"Saved metrics to {OUT_CSV} and {OUT_XLSX}")

# ---------------- Make a simple chart ----------------
# compute average enc/dec times per fog
grouped = df.groupby("fog_id").agg({"enc_time_ms": "mean", "dec_time_ms": "mean"}).reset_index()
grouped = grouped.fillna(0)

plt.figure(figsize=(8,4))
x = grouped['fog_id'].astype(str)
enc = grouped['enc_time_ms']
dec = grouped['dec_time_ms']
width = 0.35
plt.bar([int(i)-width/2 for i in range(1, len(x)+1)], enc, width=width, label='avg enc (ms)')
plt.bar([int(i)+width/2 for i in range(1, len(x)+1)], dec, width=width, label='avg dec (ms)')
plt.xticks(range(1, len(x)+1), x)
plt.xlabel("fog_id")
plt.ylabel("time (ms)")
plt.title("Average encryption/decryption time per fog")
plt.legend()
plt.tight_layout()
plt.savefig(OUT_PNG)
print(f"Saved chart to {OUT_PNG}")
