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