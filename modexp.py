# Configuration:
#   p = 2048-bit finite-field modulus
#   r = 256-bit random exponent
#
# No external libraries required.

import time
import secrets
import statistics
import gc

ROUNDS = 5000
REPEATS = 5
EXP_BITS = 256

# RFC 3526 - 2048-bit MODP Group (Group 14)
P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""

p = int("".join(P_HEX.split()), 16)
g = 2


def random_exact_bits(bits):
    """Generate a positive integer with exactly 'bits' bits."""
    x = secrets.randbits(bits - 1)
    return x | (1 << (bits - 1))


print("=" * 60)
print("Modular Exponentiation Benchmark")
print("=" * 60)
print(f"Modulus size       : {p.bit_length()} bits")
print(f"Exponent size      : {EXP_BITS} bits")
print(f"Rounds per repeat  : {ROUNDS}")
print(f"Repeats            : {REPEATS}")
print()


# ---------------------------------------------------
# Warm-up
# ---------------------------------------------------
warmup_exponents = [
    random_exact_bits(EXP_BITS)
    for _ in range(500)
]

for r in warmup_exponents:
    pow(g, r, p)


# ---------------------------------------------------
# Actual benchmark
# ---------------------------------------------------
all_times_us = []
repeat_means = []

gc.disable()

try:
    for repeat in range(REPEATS):


        exponents = [
            random_exact_bits(EXP_BITS)
            for _ in range(ROUNDS)
        ]

        times_us = []

        for r in exponents:

            start = time.perf_counter_ns()

            result = pow(g, r, p)

            end = time.perf_counter_ns()

            elapsed_us = (end - start) / 1000.0
            times_us.append(elapsed_us)

        mean_us = statistics.mean(times_us)
        repeat_means.append(mean_us)
        all_times_us.extend(times_us)

        print(
            f"Repeat {repeat + 1}: "
            f"{mean_us:.3f} us/op"
        )

finally:
    gc.enable()


# ---------------------------------------------------
# Results
# ---------------------------------------------------
mean_us = statistics.mean(all_times_us)
median_us = statistics.median(all_times_us)
stdev_us = statistics.stdev(all_times_us)
minimum_us = min(all_times_us)
maximum_us = max(all_times_us)

sorted_times = sorted(all_times_us)
p95_index = int(0.95 * len(sorted_times)) - 1
p95_us = sorted_times[p95_index]

print()
print("=" * 60)
print("FINAL RESULT")
print("=" * 60)

print(f"Mean      : {mean_us:.3f} us")
print(f"Median    : {median_us:.3f} us")
print(f"Std. dev. : {stdev_us:.3f} us")
print(f"Minimum   : {minimum_us:.3f} us")
print(f"P95       : {p95_us:.3f} us")
print(f"Maximum   : {maximum_us:.3f} us")

print()
print(
    f"T_ModExp = {mean_us:.3f} us"
)
