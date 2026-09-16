import time
import statistics

from charm.toolbox.pairinggroup import (
    PairingGroup,
    ZR,
    G1,
    pair
)

# ============================================================
# Parameters
# ============================================================

CURVE = "SS512"

ITERATIONS = 1000
WARMUP = 100


POOL_SIZE = 64




def print_statistics(name, times):

    avg = statistics.mean(times)
    median = statistics.median(times)
    minimum = min(times)
    maximum = max(times)
    std = statistics.stdev(times)

    print("=" * 70)
    print(name)
    print("=" * 70)
    print(f"Curve            : {CURVE}")
    print(f"Iterations       : {ITERATIONS}")
    print()

    print(f"Average Time     : {avg:.2f} ns")
    print(f"Median Time      : {median:.2f} ns")
    print(f"Minimum Time     : {minimum} ns")
    print(f"Maximum Time     : {maximum} ns")
    print(f"Std. Deviation   : {std:.2f} ns")

    print()
    print(f"Average = {avg / 1000:.3f} µs")
    print(f"Average = {avg / 1e6:.6f} ms")
    print()




def benchmark(name, operation):

    # ---------------- Warm-up ----------------
    for i in range(WARMUP):
        operation(i)

    # ---------------- Benchmark ----------------
    times = []

    result = None

    for i in range(ITERATIONS):

        start = time.perf_counter_ns()

        result = operation(i)

        end = time.perf_counter_ns()

        times.append(end - start)


    if result is None:
        raise RuntimeError("Benchmark operation failed.")

    print_statistics(name, times)

    return statistics.mean(times)


# ============================================================
# Pairing initialization
# ============================================================

print("Initializing pairing group...")

group = PairingGroup(CURVE)

# Base group element
G = group.random(G1)



samples = []

for _ in range(POOL_SIZE):

    a = group.random(ZR)
    b = group.random(ZR)
    c = group.random(ZR)

    A = G ** a       # aG in BCUA notation
    B = G ** b       # bG
    C = G ** c       # cG

    samples.append((a, b, c, A, B, C))




a, b, c, A, B, C = samples[0]

K1 = pair(B, C) ** a
K2 = pair(A, C) ** b
K3 = pair(A, B) ** c

assert K1 == K2 == K3

print("BCUA tripartite pairing correctness check: PASSED")
print()




gt_elements = []

for _, _, _, _, B, C in samples:
    gt_elements.append(pair(B, C))


# ============================================================
# Benchmark 1:
# G1 scalar multiplication / exponentiation
#
# ============================================================

def scalar_mult_operation(i):

    a = samples[i % POOL_SIZE][0]

    return G ** a


T_G1 = benchmark(
    "G1 Scalar Multiplication / Exponentiation (aG)",
    scalar_mult_operation
)


# ============================================================
# Benchmark 2:
# Bilinear pairing
# ============================================================

def pairing_operation(i):

    sample = samples[i % POOL_SIZE]

    B = sample[4]
    C = sample[5]

    return pair(B, C)


T_PAIR = benchmark(
    "Bilinear Pairing e(bG, cG)",
    pairing_operation
)


# ============================================================
# Benchmark 3:
# GT exponentiation only
# ============================================================

def gt_exponentiation_operation(i):

    index = i % POOL_SIZE

    a = samples[index][0]
    E = gt_elements[index]

    return E ** a


T_GT = benchmark(
    "GT Exponentiation e(bG,cG)^a",
    gt_exponentiation_operation
)


# ============================================================
# Benchmark 4:
# Actual BCUA participant-side key derivation
# ============================================================

def bcua_key_derivation(i):

    sample = samples[i % POOL_SIZE]

    a = sample[0]
    B = sample[4]
    C = sample[5]

    return pair(B, C) ** a


T_KEY = benchmark(
    "BCUA One-Party Tripartite Key Derivation: e(bG,cG)^a",
    bcua_key_derivation
)


# ============================================================
# Benchmark 5:
#
# 
#     1 G1 scalar multiplication
#     1 pairing
#     1 GT exponentiation
# ============================================================

def bcua_participant_operation(i):

    sample = samples[i % POOL_SIZE]

    a = sample[0]
    B = sample[4]
    C = sample[5]

    own_contribution = G ** a
    shared_key = pair(B, C) ** a

    return own_contribution, shared_key


T_PARTICIPANT = benchmark(
    "BCUA One Participant: aG + e(bG,cG)^a",
    bcua_participant_operation
)


# ============================================================
# Summary
# ============================================================

print("=" * 70)
print("BCUA PAIRING SUMMARY")
print("=" * 70)

print(f"G1 scalar multiplication : {T_G1 / 1000:.3f} µs")
print(f"Bilinear pairing         : {T_PAIR / 1000:.3f} µs")
print(f"GT exponentiation        : {T_GT / 1000:.3f} µs")

print()
