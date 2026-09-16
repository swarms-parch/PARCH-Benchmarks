#!/usr/bin/env python3

import hashlib
import hmac
import os
import statistics
import time

import oqs


ITERATIONS = 1000
WARMUP = 200
KEM_ALGORITHM = "ML-KEM-512"


def benchmark(name, operation):
    for _ in range(WARMUP):
        operation()

    times = []

    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        operation()
        end = time.perf_counter_ns()
        times.append(end - start)

    mean_ns = statistics.mean(times)

    print(f"{name:<28}: {mean_ns / 1000:.3f} us")

    return mean_ns


print("Cryptographic Primitive Benchmark")
print("=" * 50)
print(f"Iterations : {ITERATIONS}")
print(f"Warm-up    : {WARMUP}")
print()


# SHA-256: 32-byte input
sha_data = os.urandom(32)

T_SHA256 = benchmark(
    "SHA-256 (32-byte input)",
    lambda: hashlib.sha256(sha_data).digest()
)


# HMAC-SHA256: 32-byte key, 64-byte message
hmac_key = os.urandom(32)
hmac_message = os.urandom(64)

T_HMAC = benchmark(
    "HMAC-SHA256",
    lambda: hmac.digest(
        hmac_key,
        hmac_message,
        "sha256"
    )
)


# ML-KEM-512
if KEM_ALGORITHM not in oqs.get_enabled_kem_mechanisms():
    raise RuntimeError(
        f"{KEM_ALGORITHM} is not enabled in the installed liboqs build."
    )

kem_keygen = oqs.KeyEncapsulation(KEM_ALGORITHM)
kem_encap = oqs.KeyEncapsulation(KEM_ALGORITHM)


T_KEM_KEYGEN = benchmark(
    "ML-KEM-512 KeyGen",
    lambda: kem_keygen.generate_keypair()
)


public_key = kem_keygen.generate_keypair()

T_KEM_ENCAP = benchmark(
    "ML-KEM-512 Encapsulation",
    lambda: kem_encap.encap_secret(public_key)
)


ciphertext, shared_secret_encap = kem_encap.encap_secret(
    public_key
)

T_KEM_DECAP = benchmark(
    "ML-KEM-512 Decapsulation",
    lambda: kem_keygen.decap_secret(ciphertext)
)


shared_secret_decap = kem_keygen.decap_secret(ciphertext)

if shared_secret_encap != shared_secret_decap:
    raise RuntimeError("ML-KEM correctness check failed.")


try:
    kem_keygen.free()
    kem_encap.free()
except AttributeError:
    pass