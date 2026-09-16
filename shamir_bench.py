#!/usr/bin/env python3

import argparse
import secrets
import statistics
import time
import math

from Crypto.Util.number import getPrime


# ---------------------------------------------------------
# Utility functions
# ---------------------------------------------------------

def percentile(values, p):
    values = sorted(values)
    index = max(0, math.ceil((p / 100.0) * len(values)) - 1)
    return values[index]


def print_stats(title, samples_ns):
    samples_us = [x / 1000.0 for x in samples_ns]

    print(f"\n{title}")
    print("-" * 55)
    print(f"Iterations : {len(samples_us)}")
    print(f"Mean       : {statistics.mean(samples_us):.3f} us")
    print(f"Median     : {statistics.median(samples_us):.3f} us")

    if len(samples_us) > 1:
        print(f"Std. dev.  : {statistics.stdev(samples_us):.3f} us")

    print(f"Minimum    : {min(samples_us):.3f} us")
    print(f"Maximum    : {max(samples_us):.3f} us")


# ---------------------------------------------------------
# Polynomial evaluation
# ---------------------------------------------------------

def evaluate_polynomial(coefficients, x, prime):
    
    result = 0

    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % prime

    return result


# ---------------------------------------------------------
# Shamir share generation
# ---------------------------------------------------------

def generate_shares(secret, threshold, num_shares, prime, coefficients=None):
   

    if coefficients is None:
        coefficients = [secret]

        for _ in range(threshold - 1):
            coefficients.append(secrets.randbelow(prime))
    else:
        # First coefficient must be the secret.
        coefficients = [secret] + list(coefficients)

    shares = []

    for x in range(1, num_shares + 1):
        y = evaluate_polynomial(coefficients, x, prime)
        shares.append((x, y))

    return shares


# ---------------------------------------------------------
# Shamir reconstruction
# ---------------------------------------------------------

def reconstruct_secret(shares, prime):
    

    secret = 0

    for i, (x_i, y_i) in enumerate(shares):

        numerator = 1
        denominator = 1

        for j, (x_j, _) in enumerate(shares):

            if i == j:
                continue

            numerator = (numerator * (-x_j)) % prime
            denominator = (denominator * (x_i - x_j)) % prime

        denominator_inverse = pow(denominator, -1, prime)

        lagrange_coefficient = (
            numerator * denominator_inverse
        ) % prime

        secret = (
            secret +
            y_i * lagrange_coefficient
        ) % prime

    return secret


# ---------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="Generic Shamir Secret Sharing benchmark."
    )

    parser.add_argument(
        "--field-bits",
        type=int,
        default=256,
        help="Prime-field size in bits (default: 256)",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Minimum shares required for reconstruction",
    )

    parser.add_argument(
        "--shares",
        type=int,
        default=5,
        help="Total number of generated shares",
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Measured iterations (default: 1000)",
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=200,
        help="Warm-up iterations (default: 200)",
    )

    args = parser.parse_args()

    if args.threshold < 2:
        raise ValueError("Threshold must be at least 2.")

    if args.threshold > args.shares:
        raise ValueError(
            "Threshold cannot exceed total number of shares."
        )

    # ---------------------------------------------------------
    # Generate prime field
    #
    # NOT included in benchmark timing
    # ---------------------------------------------------------

    print("Generating prime field...", flush=True)

    prime = getPrime(args.field_bits)

    secret = secrets.randbelow(prime - 1) + 1

    print("\nBenchmark parameters")
    print("-" * 55)
    print(f"Field size         : {prime.bit_length()} bits")
    print(f"Threshold (t)      : {args.threshold}")
    print(f"Total shares (n)   : {args.shares}")
    print(f"Warm-up iterations : {args.warmup}")
    print(f"Measured iterations: {args.iterations}")

    print("\nPrime generation is NOT included in timing.")

    # ---------------------------------------------------------
    # Pre-generate coefficients
    #
    # This allows arithmetic-only share-generation timing,
    # excluding RNG.
    # ---------------------------------------------------------

    fixed_coefficients = [
        secrets.randbelow(prime)
        for _ in range(args.threshold - 1)
    ]

    # ---------------------------------------------------------
    # Generate one valid share set for reconstruction
    # ---------------------------------------------------------

    reference_shares = generate_shares(
        secret,
        args.threshold,
        args.shares,
        prime,
        fixed_coefficients
    )

    reconstruction_shares = reference_shares[
        :args.threshold
    ]

    recovered = reconstruct_secret(
        reconstruction_shares,
        prime
    )

    if recovered != secret:
        raise RuntimeError(
            "Shamir reconstruction failed."
        )

    # ---------------------------------------------------------
    # Warm-up
    # ---------------------------------------------------------

    print("\nRunning warm-up...", flush=True)

    for _ in range(args.warmup):

        generate_shares(
            secret,
            args.threshold,
            args.shares,
            prime,
            fixed_coefficients
        )

        reconstruct_secret(
            reconstruction_shares,
            prime
        )

    print("Warm-up complete.", flush=True)

    # ---------------------------------------------------------
    # 1. Share generation WITHOUT RNG
    # ---------------------------------------------------------

    gen_no_rng_samples = []

    for _ in range(args.iterations):

        start = time.perf_counter_ns()

        shares = generate_shares(
            secret,
            args.threshold,
            args.shares,
            prime,
            fixed_coefficients
        )

        end = time.perf_counter_ns()

        gen_no_rng_samples.append(
            end - start
        )

    # ---------------------------------------------------------
    # 2. Share generation INCLUDING coefficient RNG
    # ---------------------------------------------------------

    gen_rng_samples = []

    for _ in range(args.iterations):

        start = time.perf_counter_ns()

        shares = generate_shares(
            secret,
            args.threshold,
            args.shares,
            prime
        )

        end = time.perf_counter_ns()

        gen_rng_samples.append(
            end - start
        )

    # ---------------------------------------------------------
    # 3. Reconstruction from exactly t shares
    # ---------------------------------------------------------

    reconstruction_samples = []

    for _ in range(args.iterations):

        start = time.perf_counter_ns()

        recovered = reconstruct_secret(
            reconstruction_shares,
            prime
        )

        end = time.perf_counter_ns()

        reconstruction_samples.append(
            end - start
        )

    if recovered != secret:
        raise RuntimeError(
            "Incorrect reconstructed secret."
        )

    # ---------------------------------------------------------
    # Results
    # ---------------------------------------------------------

    print_stats(
        "Share Generation (RNG excluded)",
        gen_no_rng_samples
    )

    print_stats(
        "Share Generation (RNG included)",
        gen_rng_samples
    )

    print_stats(
        f"Secret Reconstruction ({args.threshold} shares)",
        reconstruction_samples
    )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    gen_no_rng_mean = (
        statistics.mean(gen_no_rng_samples)
        / 1000.0
    )

    gen_rng_mean = (
        statistics.mean(gen_rng_samples)
        / 1000.0
    )

    rec_mean = (
        statistics.mean(reconstruction_samples)
        / 1000.0
    )

    print("\n" + "=" * 55)
    print("SUMMARY")
    print("=" * 55)

    print(
        f"T_SSS_Gen_NoRNG = "
        f"{gen_no_rng_mean:.3f} us"
    )

    print(
        f"T_SSS_Gen_RNG   = "
        f"{gen_rng_mean:.3f} us"
    )

    print(
        f"T_SSS_Rec       = "
        f"{rec_mean:.3f} us"
    )

    print(
        f"T_SSS_Rec       = "
        f"{rec_mean / 1000.0:.6f} ms"
    )

    print("=" * 55)


if __name__ == "__main__":
    main()
