# edge_client.py
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
        # create payload_size bytes of sensor-ish data (repeatable)
        # construct readable prefix, fill remainder with deterministic bytes
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
            s.connect(addr)
            print(f"[Edge-{self.node_id}] Connected to Fog at {addr}")

            # Receive encrypted PK from Fog (length-prefixed)
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

            # Decrypt PK with PSK (not timing-critical for requested metrics)
            try:
                t0 = time.perf_counter()
                fog_pk = self._decrypt_pk_with_psk(blob)
                t1 = time.perf_counter()
                pk_decrypt_time_ms = (t1 - t0) * 1000.0
            except Exception as e:
                print(f"[Edge-{self.node_id}] PK decrypt failed: {e}")
                s.close()
                return
            print(f"[Edge-{self.node_id}] Received and decrypted Fog PK (prefix hex): {fog_pk.hex()[:32]}...  pk_decrypt_time_ms={pk_decrypt_time_ms:.2f}")

            # Now for each message: encapsulate (generate ct & ss) then encrypt payload with AES-256 (derived from ss)
            for seq in range(1, 6):
                # create payload
                payload = self._make_payload(seq)

                # encapsulate with fog_pk (we do not time encapsulation here; user requested encryption/decryption times)
                ct, ss = encapsulate(fog_pk)

                # derive AES key from ss
                aes_key = self._derive_aes_from_ss(ss)
                nonce = get_random_bytes(12)
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

                # measure encryption time (payload encryption)
                t0 = time.perf_counter()
                ct_payload, tag = cipher.encrypt_and_digest(payload)
                t1 = time.perf_counter()
                enc_time_ms = (t1 - t0) * 1000.0

                # compose message to send: we will send the KEM ciphertext length-prefixed and then the AES payload length-prefixed
                # first, send payload (encrypted) as length-prefixed blob (per Fog expects ct payloads in its queue)
                payload_blob = nonce + ct_payload + tag

                # For compatibility with fog_server in this design we will send a *single* message composed of:
                # [len(ct)] [ct] [len(payload_blob)] [payload_blob]
                # So fog can read both and decapsulate then decrypt
                # But to keep earlier simpler design (fog expects single ct per message), we instead send ct alone as earlier,
                # and the fog will decapsulate and treat the shared secret as if it was the plaintext. To keep the metrics asked (enc/dec
                # of payload), we will instead send the encrypted payload only and record enc time locally, and rely on fog to decapsulate
                # this example expects the fog to already have the correct SK and will decapsulate a separate KEM message.
                # To keep minimal network, we'll *send ct first (len-prefixed) then payload_blob (len-prefixed)*.

                # send ct
                s.sendall(struct.pack(">I", len(ct)) + ct)
                time.sleep(random.uniform(-JITTER_SEC, JITTER_SEC))

                # send payload blob
                s.sendall(struct.pack(">I", len(payload_blob)) + payload_blob)
                time.sleep(random.uniform(-JITTER_SEC, JITTER_SEC))

                # record metric for this sent payload (encryption time)
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
                # jitter between messages
                time.sleep(random.uniform(-JITTER_SEC, JITTER_SEC))

            s.close()
            print(f"[Edge-{self.node_id}] Finished sending 5 payloads")
        except Exception as e:
            print(f"[Edge-{self.node_id}] Error: {e}")
