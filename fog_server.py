# fog_server.py
import socket
import threading
import struct
import time
import os
import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from hqc_wrapper import generate_keypair, decapsulate, CT_LEN, PK_LEN

JITTER_SEC = 0.001  # 1 ms jitter

class FogServer:
    def __init__(self, fog_id, host, port, max_edges, pre_shared_key, metrics_collector, rekey_interval=60):
        self.fog_id = fog_id
        self.host = host
        self.port = port
        self.max_edges = max_edges
        self.pre_shared_key = pre_shared_key  # bytes (32)
        self.rekey_interval = rekey_interval
        self.metrics = metrics_collector  # list-like to append metric dicts
        self._stop = threading.Event()

        # current HQC keypair
        self.pk = None
        self.sk = None
        self.pk_lock = threading.Lock()

        # store active connections to broadcast rekeys
        self.active_conns = []
        self.conns_lock = threading.Lock()

        # start rekey thread
        self.rekey_thread = threading.Thread(target=self._rekey_loop, daemon=True)
        self.rekey_thread.start()

    def start(self):
        t = threading.Thread(target=self._server_loop, daemon=True)
        t.start()

    def stop(self):
        self._stop.set()

    def _server_loop(self):
        # initial keypair generation before listening
        self._generate_keypair_and_record()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(self.max_edges)
        print(f"[Fog-{self.fog_id}] Listening on {self.host}:{self.port} (max {self.max_edges})")

        while not self._stop.is_set():
            try:
                server.settimeout(1.0)
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Fog-{self.fog_id}] Server socket error: {e}")
                break

            # handle connection in its own thread
            with self.conns_lock:
                self.active_conns.append(conn)
            threading.Thread(target=self._handle_edge, args=(conn, addr), daemon=True).start()

    def _generate_keypair_and_record(self):
        # generate and time it
        t0 = time.perf_counter()
        pk, sk = generate_keypair()
        t1 = time.perf_counter()
        keygen_time_ms = (t1 - t0) * 1000.0

        with self.pk_lock:
            self.pk = pk
            self.sk = sk

        # record keygen metric (fog-level)
        self.metrics.append({
            "timestamp": time.time(),
            "fog_id": self.fog_id,
            "edge_id": None,
            "rekey_round": int(time.time()),
            "keygen_time_ms": keygen_time_ms,
            "enc_time_ms": None,
            "dec_time_ms": None
        })
        print(f"[Fog-{self.fog_id}] Generated HQC keypair in {keygen_time_ms:.2f} ms")

    def _rekey_loop(self):
        # periodically regenerate keypair and broadcast encrypted pk to active edges
        while not self._stop.is_set():
            time.sleep(self.rekey_interval)
            if self._stop.is_set():
                break
            self._generate_keypair_and_record()
            # broadcast new pk encrypted with pre-shared key
            with self.conns_lock:
                conns = list(self.active_conns)
            for conn in conns:
                try:
                    self._send_encrypted_pk(conn)
                except Exception as e:
                    # ignore broken connections; handle removal elsewhere
                    pass

    def _encrypt_pk_with_psk(self, pk_bytes):
        # AES-256-GCM using pre-shared key to encrypt pk
        nonce = get_random_bytes(12)
        cipher = AES.new(self.pre_shared_key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(pk_bytes)
        return nonce + ct + tag  # send this blob

    def _send_encrypted_pk(self, conn):
        with self.pk_lock:
            pkb = self.pk
        blob = self._encrypt_pk_with_psk(pkb)
        # length-prefix then send
        conn.sendall(struct.pack(">I", len(blob)) + blob)
        # small jitter
        time.sleep(random.uniform(-JITTER_SEC, JITTER_SEC))

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
            # Step 1: send current pk encrypted with PSK
            self._send_encrypted_pk(conn)

            # Step 2: receive 5 HQC ciphertext messages (length-prefixed ct blobs)
            for i in range(5):
                # read 4-byte length
                raw_len = self._recv_exact(conn, 4)
                if not raw_len:
                    print(f"[Fog-{self.fog_id}] connection closed by edge during length read")
                    break
                length = struct.unpack(">I", raw_len)[0]
                ct = self._recv_exact(conn, length)
                if ct is None:
                    print(f"[Fog-{self.fog_id}] connection closed while receiving ct")
                    break

                # decapsulate and measure time
                t0 = time.perf_counter()
                shared_secret = decapsulate(ct, self.sk)
                t1 = time.perf_counter()
                dec_time_ms = (t1 - t0) * 1000.0

                # for research we will print hex of shared secret (preview)
                print(f"[Fog-{self.fog_id}] Message {i+1} from {addr} decapsulated ss (hex prefix): {shared_secret.hex()[:32]}...  dec_time_ms={dec_time_ms:.2f}")

                # record metric: attach to most recent metric entry with no enc/dec times set for this fog-edge
                self.metrics.append({
                    "timestamp": time.time(),
                    "fog_id": self.fog_id,
                    "edge_id": f"{addr[1]}",
                    "rekey_round": int(time.time()),
                    "keygen_time_ms": None,
                    "enc_time_ms": None,         # will be filled by the edge process before sending; we also record dec_time here
                    "dec_time_ms": dec_time_ms
                })

                # small jitter to simulate network
                time.sleep(random.uniform(-JITTER_SEC, JITTER_SEC))

        except Exception as e:
            print(f"[Fog-{self.fog_id}] Error with {addr}: {e}")
        finally:
            with self.conns_lock:
                try:
                    self.active_conns.remove(conn)
                except ValueError:
                    pass
            conn.close()
            print(f"[Fog-{self.fog_id}] Connection {addr} closed")
