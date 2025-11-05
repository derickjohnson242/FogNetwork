# hqc_wrapper.py
import ctypes
import os

# Load the compiled shared library
lib = ctypes.CDLL(os.path.abspath("libhqc.so"))

# HQC-128 parameter sizes (from PQClean implementation)
PK_LEN = 2249
SK_LEN = 4522
CT_LEN = 4481
SS_LEN = 64

uchar_p = ctypes.POINTER(ctypes.c_ubyte)

# ----- PQClean symbol names (HQC-128, clean implementation) -----
KEYPAIR_FN = "PQCLEAN_HQC128_CLEAN_crypto_kem_keypair"
ENCAP_FN   = "PQCLEAN_HQC128_CLEAN_crypto_kem_enc"
DECAP_FN   = "PQCLEAN_HQC128_CLEAN_crypto_kem_dec"

# Set argtypes
getattr(lib, KEYPAIR_FN).argtypes = [uchar_p, uchar_p]
getattr(lib, ENCAP_FN).argtypes   = [uchar_p, uchar_p, uchar_p]
getattr(lib, DECAP_FN).argtypes   = [uchar_p, uchar_p, uchar_p]

# ----- High-level Python wrappers -----
def generate_keypair():
    """Generate (pk, sk)"""
    pk = (ctypes.c_ubyte * PK_LEN)()
    sk = (ctypes.c_ubyte * SK_LEN)()
    getattr(lib, KEYPAIR_FN)(pk, sk)
    return bytes(pk), bytes(sk)

def encapsulate(pk: bytes):
    """Encapsulate shared secret using public key -> (ct, ss)"""
    ct = (ctypes.c_ubyte * CT_LEN)()
    ss = (ctypes.c_ubyte * SS_LEN)()
    pk_buf = (ctypes.c_ubyte * len(pk)).from_buffer_copy(pk)
    getattr(lib, ENCAP_FN)(ct, ss, pk_buf)
    return bytes(ct), bytes(ss)

def decapsulate(ct: bytes, sk: bytes):
    """Decapsulate ciphertext using secret key -> ss"""
    ss = (ctypes.c_ubyte * SS_LEN)()
    ct_buf = (ctypes.c_ubyte * len(ct)).from_buffer_copy(ct)
    sk_buf = (ctypes.c_ubyte * len(sk)).from_buffer_copy(sk)
    getattr(lib, DECAP_FN)(ss, ct_buf, sk_buf)
    return bytes(ss)
