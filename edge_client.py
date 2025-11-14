import socket
import struct
import time
import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from hqc_wrapper import encapsulate, PK_LEN

JITTER_SEC = 0.001  # 1 ms jitter

class EdgeClient:
    def __init__(self, node_id, fog_host, fog_port, pre_shared_key, payload_size, metrics_collector):
        self.node_id = node_id
        self.fog_host = fog_host
        self.fog_port = fog_port
        self.pre_shared_key = pre_shared_key  # bytes (32)
        self.payload_size = payload_size
        self.metrics = metrics_collector

    def _recv_exact(self, s, n):
        data = b""
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _decrypt_pk_with_psk(self, blob):
        nonce = blob[:12]
        ct = blob[12:-16]
        tag = blob[-16:]
        cipher = AES.new(self.pre_shared_key, AES.MODE_GCM, nonce=nonce)
        pk = cipher.decrypt_and_verify(ct, tag)
        return pk

    def _derive_aes_from_ss(self, ss):
        h = SHA256.new(ss)
        return h.digest()  # 32 bytes

    def _make_payload(self, seq):
        prefix = f"Node{self.node_id}-seq{seq}-".encode()
        remaining = self.payload_size - len(prefix)
        if remaining < 0:
            payload = prefix[:self.payload_size]
        else:
            filler = (bytes([self.node_id % 256]) * remaining)
            payload = prefix + filler
        return payload

    def run(self):
        addr = (self.fog_host, self.fog_port)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect_delay = random.uniform(0.1, 0.5)
            time.sleep(connect_delay)
            s.connect(addr)
            print(f"[Edge-{self.node_id}] Connected to Fog at {addr}")

            raw_len = self._recv_exact(s, 4)
            if not raw_len:
                print(f"[Edge-{self.node_id}] No PK length received")
                s.close()
                return
            pk_len = struct.unpack(">I", raw_len)[0]
            blob = self._recv_exact(s, pk_len)
            if blob is None:
                print(f"[Edge-{self.node_id}] No PK blob received")
                s.close()
                return

            try:
                t0 = time.perf_counter()
                fog_pk = self._decrypt_pk_with_psk(blob)
                t1 = time.perf_counter()
                pk_decrypt_time_ms = (t1 - t0) * 1000.0
            except Exception as e:
                print(f"[Edge-{self.node_id}] PK decrypt failed: {e}")
                s.close()
                return

            print(f"[Edge-{self.node_id}] Decrypted Fog PK prefix: {fog_pk.hex()[:32]}... pk_decrypt_time_ms={pk_decrypt_time_ms:.2f}")

            for seq in range(1, 6):
                payload = self._make_payload(seq)
                ct, ss = encapsulate(fog_pk)
                aes_key = self._derive_aes_from_ss(ss)
                nonce = get_random_bytes(12)
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

                t0 = time.perf_counter()
                ct_payload, tag = cipher.encrypt_and_digest(payload)
                t1 = time.perf_counter()
                enc_time_ms = (t1 - t0) * 1000.0

                payload_blob = nonce + ct_payload + tag

                try:
                    s.sendall(struct.pack(">I", len(ct)) + ct)
                    delay = random.uniform(-JITTER_SEC, JITTER_SEC)
                    time.sleep(max(0, delay))

                    s.sendall(struct.pack(">I", len(payload_blob)) + payload_blob)
                    delay = random.uniform(-JITTER_SEC, JITTER_SEC)
                    time.sleep(max(0, delay))
                except BrokenPipeError:
                    print(f"[Edge-{self.node_id}] Connection closed early (BrokenPipe)")
                    break

                self.metrics.append({
                    "timestamp": time.time(),
                    "fog_id": f"{self.fog_host}:{self.fog_port}",
                    "edge_id": self.node_id,
                    "rekey_round": int(time.time()),
                    "keygen_time_ms": None,
                    "enc_time_ms": enc_time_ms,
                    "dec_time_ms": None
                })

                print(f"[Edge-{self.node_id}] Sent msg {seq} enc_time_ms={enc_time_ms:.2f}")
                delay = random.uniform(-JITTER_SEC, JITTER_SEC)
                time.sleep(max(0, delay))

            s.close()
            print(f"[Edge-{self.node_id}] Finished sending payloads")

        except Exception as e:
            print(f"[Edge-{self.node_id}] Error: {e}")
