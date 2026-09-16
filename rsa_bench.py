#!/usr/bin/env python3

import argparse
import hashlib
import math
import statistics
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


def percentile(data, p):
    data = sorted(data)
    index = max(0, math.ceil((p / 100.0) * len(data)) - 1)
    return data[index]


def print_stats(name, samples_ns):
    samples_us = [x / 1000.0 for x in samples_ns]

    print(f"\n{name}")
    print("-" * 50)
    print(f"Iterations : {len(samples_us)}")
    print(f"Mean       : {statistics.mean(samples_us):.3f} us")
    print(f"Median     : {statistics.median(samples_us):.3f} us")
    print(f"Std. dev.  : {statistics.stdev(samples_us):.3f} us")
    print(f"Minimum    : {min(samples_us):.3f} us")
    print(f"Maximum    : {max(samples_us):.3f} us")
    print(f"95th pct.  : {percentile(samples_us, 95):.3f} us")


def get_padding(name):
    if name == "pkcs1v15":
        return padding.PKCS1v15()

    if name == "pss":
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        )

    raise ValueError("Unsupported padding")


def main():
    parser = argparse.ArgumentParser(
        description="Generic RSA signature generation/verification benchmark."
    )

    parser.add_argument(
        "--key-bits",
        type=int,
        required=True,
        help="RSA modulus size in bits, e.g. 2048 or 3072",
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Number of measured iterations (default: 1000)",
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=200,
        help="Number of warm-up iterations (default: 200)",
    )

    parser.add_argument(
        "--padding",
        choices=["pkcs1v15", "pss"],
        default="pkcs1v15",
        help="RSA signature padding (default: pkcs1v15)",
    )

    args = parser.parse_args()

    print("Generating RSA key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=args.key_bits,
    )

    public_key = private_key.public_key()

    # Hash is deliberately computed outside the timed region.
    message = b"Generic cryptographic benchmark message"
    digest = hashlib.sha256(message).digest()

    prehashed = utils.Prehashed(hashes.SHA256())
    rsa_padding = get_padding(args.padding)

    print(f"RSA modulus : {args.key_bits} bits")
    print(f"Padding     : {args.padding}")
    print(f"Warmups     : {args.warmup}")
    print(f"Iterations  : {args.iterations}")

    # -----------------------------
    # Warm-up: signing
    # -----------------------------
    for _ in range(args.warmup):
        private_key.sign(
            digest,
            rsa_padding,
            prehashed,
        )

    # -----------------------------
    # Measure signing
    # -----------------------------
    sign_samples = []

    signature = None

    for _ in range(args.iterations):
        start = time.perf_counter_ns()

        signature = private_key.sign(
            digest,
            rsa_padding,
            prehashed,
        )

        end = time.perf_counter_ns()
        sign_samples.append(end - start)

    # -----------------------------
    # Warm-up: verification
    # -----------------------------
    for _ in range(args.warmup):
        public_key.verify(
            signature,
            digest,
            rsa_padding,
            prehashed,
        )

    # -----------------------------
    # Measure verification
    # -----------------------------
    verify_samples = []

    for _ in range(args.iterations):
        start = time.perf_counter_ns()

        public_key.verify(
            signature,
            digest,
            rsa_padding,
            prehashed,
        )

        end = time.perf_counter_ns()
        verify_samples.append(end - start)

    print_stats("RSA Signature Generation", sign_samples)
    print_stats("RSA Signature Verification", verify_samples)

    print(f"\nSignature size: {len(signature)} bytes")
    print(f"Signature size: {len(signature) * 8} bits")


if __name__ == "__main__":
    main()
