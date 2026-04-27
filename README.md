# PQ-VPN — Post-Quantum VPN

A research implementation of a post-quantum secure VPN tunnel, built from scratch in C as an MSc dissertation project.

Uses **ML-KEM-768** (NIST FIPS 203) for key exchange and **AES-256-GCM** for symmetric encryption, providing security against both classical and quantum adversaries.

---

## Why Post-Quantum?

Classical VPNs (WireGuard, OpenVPN) use elliptic-curve Diffie-Hellman for key exchange. This is broken by Shor's algorithm on a quantum computer. Nation-state adversaries are already recording encrypted traffic today to decrypt later once quantum computers mature — the **harvest now, decrypt later** attack.

This project replaces the vulnerable key exchange with ML-KEM-768, standardised by NIST in August 2024 as the first post-quantum KEM standard, while keeping AES-256-GCM for symmetric encryption (Grover's algorithm only gives a quadratic speedup against symmetric crypto, so 256-bit keys remain secure).

---

## Security Architecture

```
Client                                    Server
──────                                    ──────
1. PSK mutual authentication    ←────→    HMAC-SHA256 challenge-response
2. ML-KEM-768 key exchange      ←────→    Encapsulation / Decapsulation
3. HKDF-SHA256 key derivation   ══════    Both derive same AES-256 key
4. AES-256-GCM tunnel           ←────→    Counter nonces + replay protection
```

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Key exchange | ML-KEM-768 | NIST FIPS 203 (2024) |
| Symmetric encryption | AES-256-GCM | NIST FIPS 197 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Authentication | HMAC-SHA256 PSK | RFC 2104 |
| Replay protection | Sliding window | RFC 4303 |
| Nonce generation | Counter-based | — |

**Security properties:**
- Quantum-resistant key exchange (ML-KEM-768, NIST FIPS 203)
- Authenticated encryption (AES-256-GCM — confidentiality + integrity)
- Mutual authentication (both sides prove PSK knowledge before key exchange)
- Forward secrecy (per-session ephemeral keys)
- Replay attack prevention (64-packet RFC 4303 sliding window)
- Nonce uniqueness guaranteed (counter + random prefix, no birthday bound risk)

---

## Project Structure

```
pqvpn/
├── Makefile
├── psk.conf              ← generated locally, never committed
├── server_setup.sh       ← one-time NAT/routing setup
│
└── src/
    ├── common/
    │   ├── pqc_common.h/c      HKDF, nonce management, replay protection
    │   ├── pqc_crypto.h/c      AES-256-GCM encrypt/decrypt
    │   ├── pqc_auth.h/c        PSK mutual authentication
    │   └── gen_psk_main.c      PSK generator utility
    │
    ├── vpn/
    │   ├── tun.h/c             TUN interface (create, configure, read/write)
    │   ├── udp_support.h/c     UDP socket layer
    │   ├── vpn_server.c        VPN server (single client)
    │   └── vpn_client.c        VPN client (routing + DNS management)
    │
    └── tests/
        ├── test_foundation.c   HKDF, nonce, AES-GCM, I/O tests
        ├── test_auth.c         PSK loading, MAC, domain separation tests
        └── test_replay.c       Sliding window replay protection tests
```

---

## Dependencies

| Dependency | Purpose | Install |
|------------|---------|---------|
| liboqs | ML-KEM-768 (Open Quantum Safe) | Build from source |
| libssl / libcrypto | AES-GCM, HMAC, HKDF, RAND | `apt install libssl-dev` |
| Linux kernel | TUN/TAP driver | `modprobe tun` |

### Installing liboqs (Open Quantum Safe)

```bash
# Install build dependencies
sudo apt install cmake gcc ninja-build libssl-dev

# Clone and build liboqs
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
# Clone the repository
git clone https://github.com/YOUR_USERNAME/pqvpn.git
cd pqvpn

# Run all tests first
make tests

# Build server, client, and PSK generator
make all
```

Expected test output:
```
Results: 18/18 passed   (foundation)
Results: 11/11 passed   (auth)
Results: 12/12 passed   (replay)
```

---

## Quick Start

### Step 1 — Generate a shared PSK

Run this once. Copy `psk.conf` to both machines before starting.

```bash
sudo ./bin/gen_psk
chmod 600 psk.conf
```

`psk.conf` contains a 256-bit random key in hex. **Keep it secret — treat it like a private key. Never commit it to version control.**

### Step 2 — Server setup (run once after first boot)

```bash
# Enables IP forwarding and NAT so client traffic reaches the internet
sudo ./server_setup.sh

# To undo:
sudo ./server_setup.sh --undo
```

### Step 3 — Start the server

```bash
sudo ./bin/vpn_server
```

### Step 4 — Connect the client

Before connecting, set the server IP in `src/vpn/vpn_client.c`:

```c
#define SERVER_IP  "YOUR_SERVER_IP"
```

Then rebuild and connect:

```bash
make all
sudo ./bin/vpn_client
```

The client automatically:
- Saves your existing default route
- Routes all traffic through the VPN tunnel after a successful handshake
- Sets DNS to 8.8.8.8 through the tunnel
- Restores your original route and DNS on disconnect (Ctrl+C)

### Step 5 — Verify

```bash
# Should show the server's IP, not your own
curl ifconfig.me

# Should resolve and get replies through the tunnel
ping google.com

# Tunnel ping
ping 10.8.0.1
```

---

## Network Configuration

| Address | Purpose |
|---------|---------|
| `10.8.0.1` | Server TUN interface |
| `10.8.0.2` | Client TUN interface |
| UDP `5555` | VPN tunnel port |
| `8.8.8.8` | DNS pushed to client |

To change any of these, edit the `#define` constants at the top of `vpn_server.c` and `vpn_client.c` and rebuild.

---

## Running Tests

```bash
# All tests
make tests

# Individual suites
make test_foundation    # HKDF, nonces, AES-GCM, I/O
make test_auth          # PSK loading, key derivation, MAC
make test_replay        # Sliding window, bitmap, boundary cases
```

Tests do not require root and do not need liboqs — they cover the common cryptographic layer only.

---

## Packet Format

Every VPN data packet has a 36-byte header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────────────────────────────────────────────────────────┤
│                    Sequence Number (64-bit BE)                    │
├───────────────────────────────────────────────────────────────────┤
│                        IV / Nonce (96-bit)                        │
├───────────────────────────────────────────────────────────────────┤
│                    Authentication Tag (128-bit)                   │
├───────────────────────────────────────────────────────────────────┤
│                    Ciphertext (variable)                          │
└───────────────────────────────────────────────────────────────────┘
```

Overhead: **36 bytes per packet** (8 seq + 12 IV + 16 tag).

---

## Handshake Protocol

```
Client                                          Server
──────                                          ──────

── Phase 1: Mutual Authentication ──────────────────────────────────
  generate client_challenge (32B random)
  send client_challenge              ─────────>
                                                compute server_mac =
                                                  HMAC(auth_key,
                                                    "server"||challenge)
                                                generate server_challenge
                                     <─────────  send server_mac||server_challenge
  verify server_mac
  compute client_mac =
    HMAC(auth_key, "client"||server_challenge)
  send client_mac                    ─────────>
                                                verify client_mac
                                                ✅ client authenticated

── Phase 2: ML-KEM-768 Key Exchange ─────────────────────────────────
  generate keypair (pk, sk)
  send pk                            ─────────>
                                                encaps(pk) → (ciphertext, ss)
                                     <─────────  send ciphertext
  decaps(ciphertext, sk) → ss

── Phase 3: Session Key Derivation ──────────────────────────────────
  HKDF(ss, info="vpn-session-key")  ══════════  HKDF(ss, info="vpn-session-key")
           └─── AES-256 session key ════════════ AES-256 session key ───┘
```

---

## Limitations and Future Work

This is a research prototype. Current known limitations:

- **Single client** — server accepts one connection at a time. Multi-client session management (`session.h/session.c`) is designed but not yet implemented.
- **PSK authentication** — production deployment would replace PSK with ML-DSA-65 certificate-based authentication (NIST FIPS 204) for scalable user onboarding.
- **No key rotation** — session keys are fixed for the duration of a connection. Long sessions should re-key periodically.
- **Linux only** — uses Linux TUN/TAP and `ip`/`iptables` for routing. macOS/Windows support would require platform-specific tunnel drivers.

Planned extensions:
1. ML-DSA-65 certificate authentication (FIPS 204) replacing PSK
2. Multi-client session table
3. Session re-keying
4. Cloud VM deployment with public IP
5. Performance benchmarking vs WireGuard and OpenVPN

---

## References

- NIST FIPS 203 — ML-KEM Standard (2024): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- Bos et al. — CRYSTALS-Kyber: https://eprint.iacr.org/2017/634.pdf
- Shor (1994) — Quantum algorithm for discrete logarithms
- Mosca (2018) — Cybersecurity in an era with quantum computers
- RFC 5869 — HKDF: https://www.rfc-editor.org/rfc/rfc5869
- RFC 4303 — IPsec ESP (replay protection): https://www.rfc-editor.org/rfc/rfc4303
- Open Quantum Safe / liboqs: https://openquantumsafe.org
- Donenfeld (2017) — WireGuard: https://www.wireguard.com/papers/wireguard.pdf

---

## Academic Context

This project was developed as an MSc dissertation exploring the practical implementation of post-quantum cryptography in network applications. The primary research question is whether NIST-standardised post-quantum primitives can be integrated into a functional VPN with acceptable performance overhead — addressing the harvest-now-decrypt-later threat against classical VPN deployments.

---

## License

Research and educational use. See LICENSE for details.