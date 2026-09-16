# PARCH Cryptographic Benchmark Code

This repository contains the cryptographic primitive benchmarking scripts used
for the computational-cost evaluation of PARCH.

## Evaluation Platform

- Device: Raspberry Pi 5
- OS: Debian GNU/Linux
- Python: 3.13.5


The Python benchmarks were executed from the `crypto-bench` virtual
environment.

Activate it using:
source ~/crypto-bench/bin/activate


Command to run pairing_bench.py:
source ~/crypto-bench/bin/activate
python3 pairing_bench.py

Command to run shamir_bench.py
source ~/crypto-bench/bin/activate
taskset -c 2 python3 shamir_bench.py --field-bits 256 --threshold 6 --shares 10 --iterations 1000 --warmup 200

command to run rsa_bench.py
source ~/crypto-bench/bin/activate
taskset -c 2 python rsa_bench.py --key-bits 2048 --iterations 1000 --warmup 200 --padding pkcs1v15

command to run WOTS+ 
cd sphincsplus/ref
make PARAMS=sphincs-sha2-128s THASH=simple LDLIBS="-lm" test/wots_parch
taskset -c 2 ./test/wots_parch
