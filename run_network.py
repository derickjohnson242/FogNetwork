# run_network.py
import threading
import time
import os
import csv
import pandas as pd
import matplotlib.pyplot as plt
from Crypto.Random import get_random_bytes

from fog_server import FogServer
from edge_client import EdgeClient

# ---------------- Configuration ----------------
FOG_COUNT = 2
EDGES_PER_FOG = 5
PAYLOAD_SIZE = 100  # bytes
REKEY_INTERVAL = 60  # seconds
JITTER_MS = 1

BASE_HOST = "127.0.0.1"
BASE_PORT = 6000

PRE_SHARED_KEY = get_random_bytes(32)

metrics = []  # global metrics list (thread-safe usage in fog + edge)

# ---------------- Start Fog Servers ----------------
fogs = []
for i in range(FOG_COUNT):
    port = BASE_PORT + i
    fs = FogServer(
        fog_id=i + 1,
        host=BASE_HOST,
        port=port,
        max_edges=EDGES_PER_FOG,
        pre_shared_key=PRE_SHARED_KEY,
        metrics_collector=metrics,
        rekey_interval=REKEY_INTERVAL
    )
    fs.start()
    fogs.append(fs)

time.sleep(2)

# ---------------- Start Edge Nodes ----------------
threads = []
edge_id = 1

for f_index, fs in enumerate(fogs):
    for j in range(EDGES_PER_FOG):
        ec = EdgeClient(
            node_id=edge_id,
            fog_host=fs.host,
            fog_port=fs.port,
            pre_shared_key=PRE_SHARED_KEY,
            payload_size=PAYLOAD_SIZE,
            metrics_collector=metrics
        )
        t = threading.Thread(target=ec.run, daemon=True)
        t.start()
        threads.append(t)
        edge_id += 1
        time.sleep(0.05)

for t in threads:
    t.join()

time.sleep(2)

for fs in fogs:
    fs.stop()

# ---------------- Save Metrics to CSV/XLSX ----------------
OUT_CSV = "output/metrics.csv"
OUT_XLSX = "output/metrics.xlsx"
OUT_PNG1 = "output/enc_dec_times.png"
OUT_PNG2 = "output/cpu_utilization.png"

rows = []
for m in metrics:
    rows.append({
        "timestamp": m.get("timestamp"),
        "fog_id": m.get("fog_id"),
        "edge_id": m.get("edge_id"),
        "rekey_round": m.get("rekey_round"),

        "keygen_time_ms": m.get("keygen_time_ms"),
        "enc_time_ms": m.get("enc_time_ms"),
        "dec_time_ms": m.get("dec_time_ms"),

        "cpu_util_keygen": m.get("cpu_util_keygen"),
        "cpu_util_enc": m.get("cpu_util_enc"),
        "cpu_util_dec": m.get("cpu_util_dec"),
    })

df = pd.DataFrame(rows)
df.to_csv(OUT_CSV, index=False)
df.to_excel(OUT_XLSX, index=False)

print(f"✅ Saved metrics to {OUT_CSV} and {OUT_XLSX}")

# ---------------- Graph 1: Encryption/Decryption Time ----------------
grouped = df.groupby("fog_id").agg({
    "enc_time_ms": "mean",
    "dec_time_ms": "mean"
}).reset_index()

grouped = grouped.fillna(0)

# ✅ treat fog_id as string label (ISSUE FIX)
grouped["fog_id"] = grouped["fog_id"].astype(str)

plt.figure(figsize=(8, 4))

x = range(len(grouped))  # numeric positions
enc = grouped["enc_time_ms"]
dec = grouped["dec_time_ms"]

width = 0.35
plt.bar([i - width/2 for i in x], enc, width=width, label="avg enc (ms)")
plt.bar([i + width/2 for i in x], dec, width=width, label="avg dec (ms)")

plt.xticks(x, grouped["fog_id"])
plt.xlabel("Fog Node")
plt.ylabel("Time (ms)")
plt.title("Average Encryption / Decryption Time per Fog Node")
plt.legend()
plt.tight_layout()
plt.savefig(OUT_PNG1)
print(f"✅ Saved chart to {OUT_PNG1}")

# ---------------- Graph 2: CPU Utilization ----------------
cpu_group = df.groupby("fog_id").agg({
    "cpu_util_keygen": "mean",
    "cpu_util_enc": "mean",
    "cpu_util_dec": "mean"
}).reset_index()

cpu_group = cpu_group.fillna(0)

# ✅ fog_id as string label
cpu_group["fog_id"] = cpu_group["fog_id"].astype(str)

plt.figure(figsize=(10, 4))
x2 = range(len(cpu_group))

plt.bar([i - 0.25 for i in x2], cpu_group["cpu_util_keygen"], width=0.25, label="Keygen CPU%")
plt.bar([i        for i in x2], cpu_group["cpu_util_enc"], width=0.25, label="Enc CPU%")
plt.bar([i + 0.25 for i in x2], cpu_group["cpu_util_dec"], width=0.25, label="Dec CPU%")

plt.xticks(x2, cpu_group["fog_id"])
plt.xlabel("Fog Node")
plt.ylabel("CPU Utilization (%)")
plt.title("Average CPU Utilization per Fog Node")
plt.legend()
plt.tight_layout()
plt.savefig(OUT_PNG2)
print(f"✅ Saved CPU utilization chart to {OUT_PNG2}")

