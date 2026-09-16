#!/usr/bin/env python3

import hashlib
import os
import time
import statistics
import math


# ---------------------------------------------------------
# Parameters
# ---------------------------------------------------------

MESSAGE_SIZE = 32       # Q = 256 bits
DIGEST_SIZE = 36        # PARCH output = 288 bits
ITERATIONS = 1000
WARMUP = 200


# ---------------------------------------------------------
# Utility functions
# ---------------------------------------------------------

def percentile(data, p):
    data = sorted(data)
    index = max(0, math.ceil((p / 100.0) * len(data)) - 1)
    return data[index]


def print_stats(name, samples_ns):
    samples_us = [x / 1000.0 for x in samples_ns]

    print(f"\n{name}")
    print("-" * 55)
    print(f"Iterations : {len(samples_us)}")
    print(f"Mean       : {statistics.mean(samples_us):.3f} us")
    print(f"Median     : {statistics.median(samples_us):.3f} us")
    print(f"Std. dev.  : {statistics.stdev(samples_us):.3f} us")
    print(f"Minimum    : {min(samples_us):.3f} us")
    print(f"Maximum    : {max(samples_us):.3f} us")
    print(f"95th pct.  : {percentile(samples_us, 95):.3f} us")


# ---------------------------------------------------------
# Prepare input OUTSIDE timed region
# ---------------------------------------------------------

message = os.urandom(MESSAGE_SIZE)


# ---------------------------------------------------------
# Benchmark parameters
# ---------------------------------------------------------

print("Benchmark parameters")
print("-" * 55)
print("Algorithm          : BLAKE2b")
print(f"Input size         : {MESSAGE_SIZE} bytes")
print(f"Digest size        : {DIGEST_SIZE} bytes ({DIGEST_SIZE * 8} bits)")
print(f"Warm-up iterations : {WARMUP}")
print(f"Measured iterations: {ITERATIONS}")


# ---------------------------------------------------------
# Warm-up
# ---------------------------------------------------------

for _ in range(WARMUP):
    hashlib.blake2b(
        message,
        digest_size=DIGEST_SIZE
    ).digest()


# ---------------------------------------------------------
# Benchmark
# ---------------------------------------------------------

times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    digest = hashlib.blake2b(
        message,
        digest_size=DIGEST_SIZE
    ).digest()

    end = time.perf_counter_ns()

    times.append(end - start)


# ---------------------------------------------------------
# Correctness check
# ---------------------------------------------------------

if len(digest) != DIGEST_SIZE:
    raise RuntimeError("Incorrect BLAKE2b digest size")


# ---------------------------------------------------------
# Results
# ---------------------------------------------------------

print_stats(
    "BLAKE2b-288",
    times
)

avg_us = statistics.mean(times) / 1000.0


# ---------------------------------------------------------
# Summary
# ---------------------------------------------------------

print("\n" + "=" * 55)
print("SUMMARY")
print("=" * 55)

print(f"T_BLAKE2b = {avg_us:.3f} us")

print("=" * 55)