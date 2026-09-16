#!/usr/bin/env python3

import argparse
import math
import secrets
import statistics
import time

from cryptography.hazmat.primitives.asymmetric import rsa


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
    print(f"95th pct.  : {percentile(samples_us, 95):.3f} us")


def random_fixed_bits(bits):
    """
    Generate a positive integer having exactly the requested bit length.

    Random generation is NOT included in benchmark timing.
    """
    value = secrets.randbits(bits)
    value |= 1 << (bits - 1)
    value |= 1
    return value


def multiply_elements(elements):

    product = 1

    for x in elements:
        product *= x

    return product


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark equation-form RSA-style accumulator evaluation "
        )
    )

    parser.add_argument(
        "--modulus-bits",
        type=int,
        default=2048,
        help="RSA modulus size in bits (default: 2048)",
    )

    parser.add_argument(
        "--element-bits",
        type=int,
        default=2048,
        help="Bit length of each accumulated element (default: 2048)",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of elements accumulated (default: 10)",
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="Measured iterations (default: 100)",
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=10,
        help="Warm-up iterations (default: 10)",
    )

    args = parser.parse_args()

    if args.modulus_bits < 1024:
        raise ValueError("Use a modulus of at least 1024 bits.")

    if args.element_bits <= 0:
        raise ValueError("Element size must be positive.")

    if args.count <= 0:
        raise ValueError("Count must be positive.")
    # ---------------------------------------------------------
    print("Generating RSA modulus...", flush=True)

    rsa_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=args.modulus_bits,
    )

    public_numbers = rsa_key.public_key().public_numbers()
    modulus = public_numbers.n


    base = 2


    elements = [
        random_fixed_bits(args.element_bits)
        for _ in range(args.count)
    ]

    reference_exponent = multiply_elements(elements)

    print("\nBenchmark parameters")
    print("-" * 55)
    print(f"Modulus size       : {modulus.bit_length()} bits")
    print(f"Element size       : {args.element_bits} bits")
    print(f"Number of elements : {args.count}")
    print(f"Product exponent   : {reference_exponent.bit_length()} bits")
    print(f"Warm-up iterations : {args.warmup}")
    print(f"Measured iterations: {args.iterations}")


    # ---------------------------------------------------------
    # Warm-up
    # Complete accumulator evaluation
    # ---------------------------------------------------------
    print("\nRunning warm-up...", flush=True)

    for _ in range(args.warmup):
        exponent = multiply_elements(elements)
        result = pow(base, exponent, modulus)

    print("Warm-up complete.", flush=True)

    # ---------------------------------------------------------
    # Benchmark multiplication
    # ---------------------------------------------------------
    multiplication_samples = []

    for _ in range(args.iterations):
        start = time.perf_counter_ns()

        exponent = multiply_elements(elements)

        end = time.perf_counter_ns()

        multiplication_samples.append(end - start)

    # ---------------------------------------------------------
    # Benchmark modular exponentiation
    #
    # ---------------------------------------------------------
    exponent = reference_exponent

    modexp_samples = []

    for i in range(args.iterations):
        start = time.perf_counter_ns()

        result = pow(base, exponent, modulus)

        end = time.perf_counter_ns()

        modexp_samples.append(end - start)

        if (i + 1) % 10 == 0 or i == 0:
            print(
                f"ModExp progress: {i + 1}/{args.iterations}",
                flush=True,
            )

    # ---------------------------------------------------------
    # Benchmark complete accumulator evaluation directly
    #
    # ---------------------------------------------------------
    total_samples = []

    for i in range(args.iterations):
        start = time.perf_counter_ns()

        exponent = multiply_elements(elements)
        result = pow(base, exponent, modulus)

        end = time.perf_counter_ns()

        total_samples.append(end - start)

        if (i + 1) % 10 == 0 or i == 0:
            print(
                f"Accumulator progress: {i + 1}/{args.iterations}",
                flush=True,
            )

    if result <= 0:
        raise RuntimeError("Unexpected accumulator result.")

    # ---------------------------------------------------------
    # Results
    # ---------------------------------------------------------
    print_stats(
        "Integer Multiplication Product",
        multiplication_samples,
    )

    print_stats(
        "Single Modular Exponentiation",
        modexp_samples,
    )

    print_stats(
        "Complete Accumulator Evaluation",
        total_samples,
    )

    mul_mean = statistics.mean(multiplication_samples) / 1000.0
    modexp_mean = statistics.mean(modexp_samples) / 1000.0
    total_mean = statistics.mean(total_samples) / 1000.0

    print("\n" + "=" * 55)
    print("SUMMARY")
    print("=" * 55)
    print(f"T_Mul      = {mul_mean:.3f} us")
    print(f"T_ModExp   = {modexp_mean:.3f} us")
    print(f"T_AccEval  = {total_mean:.3f} us")
    print(f"T_AccEval  = {total_mean / 1000.0:.6f} ms")
    print("=" * 55)


if __name__ == "__main__":
    main()
