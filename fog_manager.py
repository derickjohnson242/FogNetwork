import threading
import time
import random
import psutil

JITTER_SEC = 0.001  # 1 ms jitter

FOG_SYSTEM_CONFIG = {
    "CPU": "4-core 2.4GHz",
    "RAM": "4GB",
    "OS": "Kali Linux",
    "Max_Edge_Nodes": 5
}

class FogManager:
    def __init__(self, fog_id, host, port, max_edges, pre_shared_key, metrics_collector):
        self.fog_id = fog_id
        self.host = host
        self.port = port
        self.max_edges = max_edges
        self.pre_shared_key = pre_shared_key
        self.metrics = metrics_collector
        self.active_edges = []
        self._stop = threading.Event()
        print(f"[FogManager-{self.fog_id}] System Config: {FOG_SYSTEM_CONFIG}")

    def register_edge(self, edge_client):
        self.active_edges.append(edge_client)

    def simulate_rekeying(self, interval_sec=60):
        while not self._stop.is_set():
            time.sleep(interval_sec)
            for edge in self.active_edges:
                # Here you would trigger fog to regenerate key and send via AES
                pass  # Placeholder for integration

    def start_simulation(self):
        # jittered message sending
        for edge in self.active_edges:
            threading.Thread(target=edge.run, daemon=True).start()
            time.sleep(random.uniform(-JITTER_SEC, JITTER_SEC))
