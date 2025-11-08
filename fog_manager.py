# fog_manager.py
import socket
import threading
import struct
import time
import os
import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from hqc_wrapper import decapsulate, CT_LEN

JITTER_SEC = 0.001  # 1 ms jitter

class FogHandler:
    def __init__(self, fog_id, host, port, pre_shared_key, metrics_collector):
        self.fog_id = fog_id
        self.host = host
        self.port = port
        self.pre_shared_key = pre_shared_key
        self.metrics = metrics_collector
        self._stop = threading.Event()
        self.server_thread = None

    def start(self):
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

    def _recv_exact(self, conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _run_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(20)
        print(f"[FogHandler-{self.fog_id}] Listening on {self.host}:{self.port}")

        while not self._stop.is_set():
            try:
                server.settimeout(1.0)
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[FogHandler-{self.fog_id}] Server error: {e}")
                break
            threading.Thread(target=self._client_thread, args=(conn, addr), daemon=True).start()

    def _client_thread(self, conn, addr):
        print(f"[FogHandler-{self.fog_id}] Connection from {addr}")
        try:
            # Expect to receive many pairs of (ct, payload_blob) for 5 messages
            for i in range(5):
                # read ct length & ct
                raw_len = self._recv_exact(conn, 4)
                if not raw_len:
                    print(f"[FogHandler-{self.fog_id}] closed while reading ct length")
                    break
                ct_len = struct.unpack(">I", raw_len)[0]
                ct = self._recv_exact(conn, ct_len)
                if ct is None:
                    print(f"[FogHandler-{self.fog_id}] closed while reading ct")
                    break

                # decapsulate
                t0 = time.perf_counter()
                ss = decapsulate(ct, None)  # NOTE: if you use a combined design where decapsulate uses SK, adapt
                t1 = time.perf_counter()
                dec_time_ms = (t1 - t0) * 1000.0

                # read payload blob
                raw_len2 = self._recv_exact(conn, 4)
                if not raw_len2:
                    print(f"[FogHandler-{self.fog_id}] closed while reading payload length")
                    break
                payload_len = struct.unpack(">I", raw_len2)[0]
                payload_blob = self._recv_exact(conn, payload_len)
                if payload_blob is None:
                    print(f"[FogHandler-{self.fog_id}] closed while reading payload blob")
                    break

                # Now decrypt payload using key derived from ss
                # (measure decrypt time)
                aes_key = SHA256.new(ss).digest()
                nonce = payload_blob[:12]
                ciphertext = payload_blob[12:-16]
                tag = payload_blob[-16:]

                t0d = time.perf_counter()
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                except Exception as e:
                    plaintext = b"<DECRYPT_FAIL>"
                    print(f"[FogHandler-{self.fog_id}] AES GCM verify failed: {e}")
                t1d = time.perf_counter()
                payload_dec_time_ms = (t1d - t0d) * 1000.0

                # record metrics (attach dec_time)
                self.metrics.append({
                    "timestamp": time.time(),
                    "fog_id": self.fog_id,
                    "edge_id": addr[1],
                    "rekey_round": int(time.time()),
                    "keygen_time_ms": None,
                    "enc_time_ms": None,
                    "dec_time_ms": payload_dec_time_ms
                })

                print(f"[FogHandler-{self.fog_id}] Received msg {i+1} from {addr} plaintext prefix: {plaintext[:32]}... dec_time_ms={payload_dec_time_ms:.2f}")

        except Exception as e:
            print(f"[FogHandler-{self.fog_id}] Client error {e}")
        finally:
            conn.close()
            print(f"[FogHandler-{self.fog_id}] Connection with {addr} closed")
