import os
import statistics
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------- Parameters ----------------
KEY_SIZE = 32          # AES-256
MSG_SIZE = 32          # 32-byte message
ITERATIONS = 10000
WARMUP = 200

# ---------------- Test Data ----------------
key = AESGCM.generate_key(bit_length=256)
aes = AESGCM(key)

nonce = os.urandom(12)
plaintext = os.urandom(MSG_SIZE)
aad = None

# ---------------- Warm-up ----------------
for _ in range(WARMUP):
    ct = aes.encrypt(nonce, plaintext, aad)
    aes.decrypt(nonce, ct, aad)

# ---------------- Encryption  ----------------
enc_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    ciphertext = aes.encrypt(nonce, plaintext, aad)

    end = time.perf_counter_ns()

    enc_times.append(end - start)

# ---------------- Prepare Ciphertext ----------------
ciphertext = aes.encrypt(nonce, plaintext, aad)

# ---------------- Decryption  ----------------
dec_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    recovered = aes.decrypt(nonce, ciphertext, aad)

    end = time.perf_counter_ns()

    dec_times.append(end - start)

assert recovered == plaintext

# ---------------- Statistics ----------------
print("=" * 60)
print("AES-256-GCM Benchmark")
print("=" * 60)

print(f"Message Size      : {MSG_SIZE} bytes")
print(f"Iterations        : {ITERATIONS}")
print()



print()

print(f"Encryption : {statistics.mean(enc_times)/1000:.3f} µs")
print(f"Decryption : {statistics.mean(dec_times)/1000:.3f} µs")
