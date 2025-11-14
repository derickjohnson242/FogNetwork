import socket
import threading
import struct
import time
import os
import random
import psutil
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from hqc_wrapper import generate_keypair, decapsulate, CT_LEN, PK_LEN

JITTER_SEC = 0.001

class FogServer:
    def __init__(self, fog_id, host, port, max_edges, pre_shared_key, metrics_collector, rekey_interval=60):
        self.fog_id = fog_id
        self.host = host
        self.port = port
        self.max_edges = max_edges
        self.pre_shared_key = pre_shared_key
        self.rekey_interval = rekey_interval
        self.metrics = metrics_collector
        self._stop = threading.Event()

        self.pk = None
        self.sk = None
        self.pk_lock = threading.Lock()

        self.active_conns = []
        self.conns_lock = threading.Lock()

        self.rekey_thread = threading.Thread(target=self._rekey_loop, daemon=True)
        self.rekey_thread.start()

    def start(self):
        t = threading.Thread(target=self._server_loop, daemon=True)
        t.start()

    def stop(self):
        self._stop.set()
        with self.conns_lock:
            for c in self.active_conns:
                try:
                    c.close()
                except:
                    pass

    def _server_loop(self):
        self._generate_keypair_and_record()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(self.max_edges * 2)
        print(f"[Fog-{self.fog_id}] Listening on {self.host}:{self.port}")

        while not self._stop.is_set():
            try:
                server.settimeout(1.0)
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Fog-{self.fog_id}] Server socket error: {e}")
                break

            with self.conns_lock:
                self.active_conns.append(conn)
            threading.Thread(target=self._handle_edge, args=(conn, addr), daemon=True).start()

    def _generate_keypair_and_record(self):
        cpu_before = psutil.cpu_percent(interval=None)
        t0 = time.perf_counter()
        pk, sk = generate_keypair()
        t1 = time.perf_counter()
        cpu_after = psutil.cpu_percent(interval=None)

        keygen_time_ms = (t1 - t0) * 1000.0
        cpu_util_keygen = max(0, cpu_after - cpu_before)

        with self.pk_lock:
            self.pk = pk
            self.sk = sk

        self.metrics.append({
            "timestamp": time.time(),
            "fog_id": self.fog_id,
            "edge_id": None,
            "rekey_round": int(time.time()),
            "keygen_time_ms": keygen_time_ms,
            "enc_time_ms": None,
            "dec_time_ms": None,
            "cpu_util_keygen": cpu_util_keygen,
            "cpu_util_enc": None,
            "cpu_util_dec": None
        })

        print(f"[Fog-{self.fog_id}] Generated HQC keypair in {keygen_time_ms:.2f} ms cpu_util_keygen={cpu_util_keygen:.2f}")

    def _rekey_loop(self):
        while not self._stop.is_set():
            time.sleep(self.rekey_interval)
            if self._stop.is_set():
                break
            self._generate_keypair_and_record()
            with self.conns_lock:
                conns = list(self.active_conns)
            for conn in conns:
                try:
                    self._send_encrypted_pk(conn)
                except Exception:
                    pass

    def _encrypt_pk_with_psk(self, pk_bytes):
        nonce = get_random_bytes(12)
        cipher = AES.new(self.pre_shared_key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(pk_bytes)
        return nonce + ct + tag

    def _send_encrypted_pk(self, conn):
        with self.pk_lock:
            pkb = self.pk
        blob = self._encrypt_pk_with_psk(pkb)
        try:
            conn.sendall(struct.pack(">I", len(blob)) + blob)
            delay = random.uniform(-JITTER_SEC, JITTER_SEC)
            time.sleep(max(0, delay))
        except Exception as e:
            print(f"[Fog-{self.fog_id}] Error sending PK: {e}")

    def _recv_exact(self, conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _handle_edge(self, conn, addr):
        print(f"[Fog-{self.fog_id}] Connected by Edge at {addr}")
        try:
            self._send_encrypted_pk(conn)

            for i in range(5):
                raw_len = self._recv_exact(conn, 4)
                if not raw_len:
                    break
                ct_len = struct.unpack(">I", raw_len)[0]
                ct = self._recv_exact(conn, ct_len)
                if ct is None:
                    break

                cpu_before_dec = psutil.cpu_percent(interval=None)
                t0 = time.perf_counter()
                shared_secret = decapsulate(ct, self.sk)
                t1 = time.perf_counter()
                cpu_after_dec = psutil.cpu_percent(interval=None)
                dec_time_ms = (t1 - t0) * 1000.0
                cpu_util_dec = max(0, cpu_after_dec - cpu_before_dec)

                raw_len2 = self._recv_exact(conn, 4)
                if not raw_len2:
                    break
                payload_len = struct.unpack(">I", raw_len2)[0]
                payload_blob = self._recv_exact(conn, payload_len)
                if payload_blob is None:
                    break

                aes_key = SHA256.new(shared_secret).digest()
                nonce = payload_blob[:12]
                ciphertext = payload_blob[12:-16]
                tag = payload_blob[-16:]

                cpu_before_enc = psutil.cpu_percent(interval=None)
                t0d = time.perf_counter()
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                except Exception:
                    plaintext = b"<DECRYPT_FAIL>"
                t1d = time.perf_counter()
                cpu_after_enc = psutil.cpu_percent(interval=None)
                payload_dec_time_ms = (t1d - t0d) * 1000.0
                cpu_util_enc = max(0, cpu_after_enc - cpu_before_enc)

                self.metrics.append({
                    "timestamp": time.time(),
                    "fog_id": self.fog_id,
                    "edge_id": addr[1],
                    "rekey_round": int(time.time()),
                    "keygen_time_ms": None,
                    "enc_time_ms": None,
                    "dec_time_ms": payload_dec_time_ms,
                    "cpu_util_keygen": None,
                    "cpu_util_enc": cpu_util_enc,
                    "cpu_util_dec": cpu_util_dec
                })

                print(f"[Fog-{self.fog_id}] Msg {i+1} from {addr} dec_time_ms={payload_dec_time_ms:.2f} cpu_enc={cpu_util_enc:.2f} cpu_dec={cpu_util_dec:.2f}")

                delay = random.uniform(-JITTER_SEC, JITTER_SEC)
                time.sleep(max(0, delay))

        except Exception as e:
            print(f"[Fog-{self.fog_id}] Error with {addr}: {e}")
        finally:
            with self.conns_lock:
                try:
                    self.active_conns.remove(conn)
                except ValueError:
                    pass
            conn.close()
