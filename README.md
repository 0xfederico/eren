# Eren

This script is a pen knife for enumerating and recognizing vulnerabilities.

<br>

## dependencies
- `pip3 install ezprogress dnslib json5 flask`
- `sudo -H pip3 install cython`

## examples dependencies
- `pip3 install flask`
- `sudo apt install socat`

## generate binary
- `bash genbin.sh`

<br>

## help
To see the manual just run the `eren.bin` file.

<br>

## examples

### subdomain fuzzing
- `./eren.bin subdomain_fuzzing gitlab.com --threads 50 --kdomains www.gitlab.com`

### injection
- shell 1: `python3 examples/injection.py`
- shell 2: `./eren.bin injection localhost:8080 POST test 'body p'`

### ports scan
- shell 1: `socat UDP-LISTEN:1250 system:'echo pong',nofork`
- shell 2: `./eren.bin ports_scan localhost --threads 50 --prange 1100-1300`
