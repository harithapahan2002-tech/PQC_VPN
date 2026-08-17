# PQ-VPN — Post-Quantum Virtual Private Network

A fully functional VPN implemented in C using two NIST post-quantum cryptography standards finalised in August 2024:

- **ML-KEM-768** (FIPS 203) — ephemeral key exchange
- **ML-DSA-65** (FIPS 204) — mutual certificate authentication
- **AES-256-GCM** — symmetric tunnel encryption
- **HKDF-SHA256** (RFC 5869) — session key derivation
- **RFC 4303** sliding-window replay protection

Built as an MSc Cyber Security dissertation project at Coventry University. The system has been deployed and verified end-to-end on a real public cloud VM: `curl ifconfig.me` returns the server's IP while connected.

---

## Table of Contents

- [Why post-quantum?](#why-post-quantum)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Building](#building)
- [Certificate setup](#certificate-setup)
- [Running the server](#running-the-server)
- [Connecting a client](#connecting-a-client)
- [Verification](#verification)
- [Running tests](#running-tests)
- [Benchmarking](#benchmarking)
- [Project structure](#project-structure)
- [Known limitations](#known-limitations)
- [Security notes](#security-notes)

---

## Why post-quantum?

Classical VPN protocols (WireGuard, IPsec, OpenVPN) use ECDH and ECDSA — both broken by Shor's algorithm on a sufficiently large quantum computer. The "harvest now, decrypt later" threat means adversaries can record today's VPN traffic and decrypt it once quantum computers mature.

NIST finalised ML-KEM and ML-DSA in August 2024. This project implements both in a working, deployed VPN — demonstrating that the engineering cost of migration is practical.

---

## Architecture

```
Client                                    Server
──────                                    ──────
Phase 1: Certificate exchange (ML-DSA-65)
  client_cert.bin  ──────────────────────►  verify against ca_cert.pub
  ca_cert.pub      ◄──────────────────────  server_cert.bin

Phase 2: Key encapsulation (ML-KEM-768)
  fresh keypair generated
  public key       ──────────────────────►  encapsulate → ciphertext
                   ◄──────────────────────  ciphertext
  decapsulate → shared_secret              shared_secret (identical)

Phase 3: Session key derivation
  HKDF-SHA256(shared_secret, "vpn-session-key") → 32-byte AES key

Tunnel: AES-256-GCM, counter-based nonces, RFC 4303 replay protection
  encrypted packets ◄────────────────────► encrypted packets
  keepalive every 10s, idle disconnect at 45s
```

Up to **8 simultaneous clients** are supported. Each client gets its own dedicated POSIX thread with fully isolated cryptographic state.

---

## Requirements

### Build dependencies

| Dependency | Purpose | Version |
|---|---|---|
| gcc | C11 compiler | ≥ 9 |
| liboqs | ML-KEM-768, ML-DSA-65 | ≥ 0.10 |
| OpenSSL | AES-256-GCM, HKDF, X25519/ECDSA (benchmarks) | ≥ 3.0 |
| cmake + ninja | Required to build liboqs from source | any |
| pthread | POSIX threads for multi-client support | system |

### Runtime requirements

- Linux (TUN/TAP kernel support required)
- Root or `CAP_NET_ADMIN` capability (TUN interface creation)
- UDP port 5555 open on the server firewall

### Installing liboqs from source

```bash
sudo apt update
sudo apt install -y git cmake ninja-build gcc libssl-dev

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
sudo ldconfig
cd ../..
```

---

## Building

```bash
git clone https://github.com/YOUR_USERNAME/pqvpn.git
cd pqvpn

# Build everything: server, client, tools, tests, benchmarks
make all

# Or build specific targets
make bin/vpn_server
make bin/vpn_client
make bin/bench_crypto
```

All binaries are placed in `bin/`.

---

## Certificate setup

The certificate system uses a two-tier hierarchy. Run these steps once before starting the server for the first time.

### Step 1 — Generate the CA keypair

```bash
sudo ./bin/gen_ca
```

Creates:
- `ca_key.priv` — CA private key. **Keep this secret. Never distribute it.**
- `ca_cert.pub` — CA public key. Copy this to all servers and all clients.

### Step 2 — Issue the server certificate

```bash
sudo ./bin/gen_cert server
```

Creates `server_cert.bin` and `server_key.priv`. Both stay on the server.

### Step 3 — Issue client certificates

```bash
sudo ./bin/gen_cert alice
sudo ./bin/gen_cert bob
```

Creates per-identity certificates. Distribute each set to the client:

```bash
# Each client needs these three files:
scp ca_cert.pub alice_cert.bin alice_key.priv alice@client-machine:~/pqvpn/
```

### Certificate file reference

| File | Who needs it | Secret? |
|---|---|---|
| `ca_key.priv` | Server only (CA operations) | ✅ Yes |
| `ca_cert.pub` | Server + every client | No |
| `server_cert.bin` | Server | No |
| `server_key.priv` | Server | ✅ Yes |
| `alice_cert.bin` | Alice's machine | No |
| `alice_key.priv` | Alice's machine | ✅ Yes |

Certificates are valid for **365 days**. Re-run `gen_cert` when they expire.

---

## Running the server

### One-time server setup

```bash
# Enables IP forwarding and configures NAT so client traffic reaches the internet
sudo ./server_setup.sh
```

### Start the server

```bash
sudo ./bin/vpn_server
```

The server binds to `0.0.0.0:5555/UDP` and accepts up to 8 simultaneous clients.

### Cloud deployment (fresh Ubuntu 22.04 VM)

```bash
# 1. Install dependencies
sudo apt update && apt install -y git cmake ninja-build gcc libssl-dev

# 2. Build liboqs (see Requirements above)

# 3. Clone and build
git clone https://github.com/YOUR_USERNAME/pqvpn.git
cd pqvpn && make all

# 4. Copy server certificates from your local machine
scp ca_cert.pub server_cert.bin root@YOUR_SERVER_IP:~/pqvpn/
sudo scp server_key.priv root@YOUR_SERVER_IP:~/pqvpn/

# 5. Open firewall
ufw allow 5555/udp && ufw enable

# 6. Run setup script and start server
sudo ./server_setup.sh
sudo ./bin/vpn_server
```

### Run as a background process

```bash
sudo ./bin/vpn_server > /tmp/vpn_server.log 2>&1 &
echo "Server PID: $!"
tail -f /tmp/vpn_server.log
```

---

## Connecting a client

### Connect to a remote server

```bash
sudo ./bin/vpn_client --server YOUR_SERVER_IP
```

### All options

```
--server IP    VPN server IP address (default: 127.0.0.1)
--tun NAME     TUN interface name (default: tun1)
--ip IP        Client tunnel IP address (default: 10.8.0.2)
--cert PATH    Client certificate file (default: client_cert.bin)
--help         Show usage
```

### Multiple clients on the same machine

Use different `--tun` and `--ip` values:

```bash
# Client 1
sudo ./bin/vpn_client --server 203.0.113.1

# Client 2
sudo ./bin/vpn_client --server 203.0.113.1 \
  --tun tun2 --ip 10.8.0.3 --cert bob_cert.bin
```

### What the client does automatically

On connect:
1. Verifies client certificate against CA public key
2. Completes ML-DSA-65 mutual certificate handshake with server
3. Generates fresh ML-KEM-768 keypair; server encapsulates shared secret
4. Derives AES-256-GCM session key via HKDF-SHA256
5. Saves current default route and gateway
6. Adds host route for VPN server IP via real gateway (prevents routing loop)
7. Sets tunnel as default route — all traffic exits via server
8. Updates DNS to 8.8.8.8

On disconnect (Ctrl+C):
- Original routing table restored
- DNS restored from backup
- Session statistics printed

---

## Verification

After connecting, confirm your traffic is exiting via the VPN:

```bash
# Should return the server's public IP, not your own
curl ifconfig.me

# Ping the server's tunnel interface
ping -c 5 10.8.0.1

# Confirm internet access through the tunnel
curl https://api.ipify.org
```

---

## Running tests

```bash
# All 56 tests across four suites
sudo make tests

# Individual suites
sudo make test_foundation   # 18 tests: HKDF, nonces, AES-GCM, I/O helpers
sudo make test_auth         # 11 tests: PSK authentication
sudo make test_replay       # 12 tests: RFC 4303 replay protection
sudo make test_cert         # 15 tests: ML-DSA-65 certificate system
```

Tests write temporary files to `/tmp/` and never touch your real certificate files.

Expected output:

```
Results: 18/18 passed
Results: 11/11 passed
Results: 12/12 passed
Results: 15/15 passed
All test suites completed
```

---

## Benchmarking

### Primitive-level benchmark

Compares ML-KEM-768 vs X25519, ML-DSA-65 vs ECDSA-P256, and AES-256-GCM throughput.

```bash
# Local machine
make bench
# or with custom tag and output:
./bin/bench_crypto --tag local --output local_results.csv

# Cloud VM (run the binary directly with the cloud tag)
./bin/bench_crypto --tag cloud --output cloud_results.csv
```

Output: CSV with min/max/mean/median/stddev for each operation across 500–2000 iterations.

### End-to-end handshake benchmark

Measures real connection timing over the public internet.

```bash
chmod +x benchmarks/bench_handshake.sh

# Run 20 connection attempts against the cloud server
./benchmarks/bench_handshake.sh YOUR_SERVER_IP 20

# Parse the results
python3 benchmarks/parse_handshake_log.py handshake_log.txt
```

> **Note:** requires a 50-second cooldown between runs. See [Known limitations](#known-limitations).

---

## Project structure

```
pqvpn/
├── src/
│   ├── common/
│   │   ├── pqc_common.h/c      HKDF-SHA256, nonce management, replay window,
│   │   │                       packet header definition, I/O helpers
│   │   ├── pqc_crypto.h/c      AES-256-GCM encrypt/decrypt
│   │   ├── pqc_auth.h/c        PSK mutual authentication (baseline)
│   │   ├── pqc_cert.h/c        ML-DSA-65 certificate authority, issuance,
│   │   │                       verification, mutual handshake
│   │   ├── gen_psk_main.c      Generates random PSK file
│   │   ├── gen_ca_main.c       Generates CA keypair
│   │   └── gen_cert_main.c     Issues a signed identity certificate
│   ├── vpn/
│   │   ├── tun.h/c             TUN interface lifecycle, MTU-enforced I/O
│   │   ├── udp_support.h/c     UDP socket, send/recv with timeout
│   │   ├── session.h/c         Multi-client session table, per-thread crypto state
│   │   ├── vpn_server.c        Server: cert auth loop, spawns worker thread per client
│   │   └── vpn_client.c        Client: cert auth, KEM, tunnel, routing, DNS
│   ├── tests/
│   │   ├── test_foundation.c   18 tests: HKDF, nonce, AES-GCM, I/O
│   │   ├── test_auth.c         11 tests: PSK authentication
│   │   ├── test_replay.c       12 tests: replay protection
│   │   └── test_cert.c         15 tests: ML-DSA-65 certificate system
│   └── bench/
│       ├── bench_common.h/c    Timing, statistics, CSV export
│       ├── bench_kem.c         ML-KEM-768 vs X25519 benchmark
│       ├── bench_sig.c         ML-DSA-65 vs ECDSA-P256 benchmark
│       ├── bench_aead.c        AES-256-GCM throughput at 64/576/1400 B
│       └── bench_main.c        Orchestrator, CLI, tagged CSV output
├── benchmarks/
│   ├── bench_handshake.sh      Real handshake timing over public internet
│   └── parse_handshake_log.py  Parses handshake log to statistics CSV
├── server_setup.sh             One-command NAT + IP forwarding on server
├── Makefile
├── .gitignore                  Excludes *.priv, cert files from version control
├── README.md
└── SECURITY.md
```

### Packet format

Every tunnel packet has a fixed 41-byte header:

```
 0       4   5       13      25      41
 ┌───────┬───┬───────┬───────┬───────┬──────────────┐
 │ magic │ T │  seq  │  IV   │  tag  │  ciphertext  │
 │ 4 B   │1 B│ 8 B   │ 12 B  │ 16 B  │  ≤ 1400 B   │
 └───────┴───┴───────┴───────┴───────┴──────────────┘
```

| Field | Size | Purpose |
|---|---|---|
| magic | 4 B | `0x50515643` ("PQVC") — discards stale/foreign packets |
| type | 1 B | `0x01` = data, `0x02` = keepalive |
| seq | 8 B | Big-endian uint64 counter for RFC 4303 replay detection |
| IV | 12 B | 32-bit session random prefix + 64-bit monotonic counter |
| tag | 16 B | AES-256-GCM authentication tag |
| ciphertext | ≤ 1400 B | Encrypted IP packet payload |

---

## Known limitations

**Manual certificate distribution.** Each new client requires you to run `gen_cert`, then copy three files out-of-band. A production system would add a web portal for automated provisioning. This is documented as future work.

**Same-machine multi-client UDP contention.** Two clients from the same machine (same source IP) share one UDP socket and can race for each other's packets. Clients from separate machines work correctly. This is an architectural constraint of the shared UDP port design.

**50-second reconnect cooldown for the benchmark script.** The server uses a 45-second idle timer to detect disconnects (UDP is connectionless — there is no disconnect signal). Rapid scripted reconnection therefore requires a 50-second gap between attempts.

**No IPv6 tunnel support.** The data plane handles IPv4 packets only.

**OpenSSL 3.0 HMAC deprecation warnings.** `pqc_common.c` and `pqc_auth.c` use the legacy `HMAC_CTX_*` API which is deprecated in OpenSSL 3.0. These are compile-time warnings only — the code is functionally correct.

---

## Security notes

See [SECURITY.md](SECURITY.md) for the full security design documentation, threat model, and known constraints.

Quick summary:

- ML-KEM-768: NIST Category 3 post-quantum security (≈ 192-bit classical equivalent)
- ML-DSA-65: NIST Category 3 post-quantum security for authentication
- AES-256-GCM: 128-bit authenticated encryption, information-theoretically secure nonces
- HKDF-SHA256: cryptographic domain separation between KEM output and session key
- RFC 4303 replay window: 64-packet bitmap, rejects duplicates and large forward jumps

---

## References

- [NIST FIPS 203 — ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [NIST FIPS 204 — ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [liboqs — Open Quantum Safe project](https://github.com/open-quantum-safe/liboqs)
- [RFC 5869 — HKDF-SHA256](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 4303 — IPsec ESP replay protection](https://datatracker.ietf.org/doc/html/rfc4303)
- [WireGuard paper — Donenfeld (2017)](https://www.wireguard.com/papers/wireguard.pdf)
- [CRYSTALS-Kyber paper — Bos et al. (2018)](https://doi.org/10.1109/EuroSP.2018.00032)

---

## Licence

MIT — see LICENSE file.