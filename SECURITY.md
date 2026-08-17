# Security Design — PQ-VPN

This document describes the cryptographic design, threat model, security properties, and known constraints of the PQ-VPN implementation.

---

## Threat model

The system is designed to protect against:

**Network-level adversaries** who can observe, record, modify, inject, or replay packets on the network path between client and server.

**Harvest-now-decrypt-later (HNDL) attacks** where an adversary records encrypted traffic today and decrypts it in the future using a cryptographically relevant quantum computer (CRQC). This is the primary motivation for replacing classical ECDH/ECDSA with ML-KEM-768/ML-DSA-65.

**Active man-in-the-middle (MITM) attacks** where an adversary intercepts the key exchange and substitutes their own public key. Defeated by ML-DSA-65 mutual certificate authentication.

**Replay attacks** where a recorded packet is retransmitted to the server. Defeated by RFC 4303 sliding-window sequence checking.

**Packet injection** where a forged packet is inserted into the tunnel. Defeated by AES-256-GCM authentication tag verification.

The system does **not** protect against:

- Compromise of the server's `server_key.priv` or CA's `ca_key.priv`
- Compromise of a client's `client_key.priv`
- Traffic analysis (packet sizes and timing are not obfuscated)
- Endpoint compromise (malware on the client or server machine)

---

## Cryptographic stack

### Key exchange: ML-KEM-768 (NIST FIPS 203)

ML-KEM-768 is a lattice-based key encapsulation mechanism built on the Module Learning With Errors (Module-LWE) problem. It is one of the three algorithms standardised by NIST in August 2024 for post-quantum key establishment.

**Security level:** NIST Category 3 (approximately 192-bit classical security equivalent). No known classical or quantum algorithm can break this faster than an exhaustive search over a 192-bit key space.

**How it is used:**

1. The client generates a fresh ephemeral keypair for each connection: `(pk, sk) ← ML-KEM.KeyGen()`
2. The client sends `pk` (1,184 bytes) to the authenticated server
3. The server encapsulates: `(ct, ss) ← ML-KEM.Encaps(pk)` and sends `ct` (1,088 bytes) back
4. The client decapsulates: `ss ← ML-KEM.Decaps(sk, ct)`
5. Both parties now hold identical `ss` (32 bytes) known only to them

The ephemeral keypair is generated fresh per connection, providing **perfect forward secrecy**: compromise of long-term keys does not expose past session keys.

**Key sizes:**

| Parameter | Size |
|---|---|
| Public key | 1,184 bytes |
| Secret key | 2,400 bytes |
| Ciphertext | 1,088 bytes |
| Shared secret | 32 bytes |

### Authentication: ML-DSA-65 (NIST FIPS 204)

ML-DSA-65 is a lattice-based digital signature scheme built on Module-LWE/Module-SIS. Standardised by NIST as FIPS 204 in August 2024.

**Security level:** NIST Category 3 (approximately 192-bit classical security equivalent).

**How it is used:**

A minimal two-tier certificate hierarchy:
- A certificate authority (CA) generates a root keypair. The CA public key (`ca_cert.pub`) is distributed to all participants.
- The CA signs per-identity certificates for the server and each client.
- At handshake time, client and server exchange certificates and each verifies the other's signature against the shared CA public key.

This provides **mutual authentication**: the client proves it holds a certificate signed by the trusted CA, and the server does the same. An attacker without a CA-signed certificate cannot impersonate either party.

**Certificate format:**

```
pqc_cert_t {
    identity[64]         — identity string (e.g. "vpn-server", "alice")
    public_key[1952]     — ML-DSA-65 public key
    issued_at[8]         — big-endian Unix timestamp
    expires_at[8]        — big-endian Unix timestamp (issued_at + 365 days)
    signature[3309]      — CA's ML-DSA-65 signature over the above fields
}
Total: 5,341 bytes
```

**Verification order:** expiry is checked first (cheap), then the ML-DSA-65 signature (expensive). Expired certificates are rejected before any cryptographic work is performed.

**Signature sizes:**

| Parameter | Size |
|---|---|
| Public key | 1,952 bytes |
| Private key | 4,032 bytes (liboqs encoding, 4,000 bytes in FIPS 204 spec) |
| Signature | 3,309 bytes |

### Session key derivation: HKDF-SHA256 (RFC 5869)

The raw KEM shared secret is not used directly as the AES key. Instead, HKDF-SHA256 is applied:

```
session_key = HKDF-SHA256(
    ikm  = shared_secret,     // 32 bytes from ML-KEM-768
    salt = NULL,
    info = "vpn-session-key", // domain separation label
    len  = 32
)
```

This provides:
- **Domain separation:** the derived key is cryptographically independent of the raw KEM output
- **Key stretching:** the same KEM output could safely derive multiple independent keys by varying the `info` label
- **Compliance:** RFC 5869 is a well-analysed standard construction

### Symmetric encryption: AES-256-GCM

All tunnel traffic is encrypted with AES-256-GCM using the derived session key.

**Properties:**
- 256-bit key (128-bit security against Grover's algorithm on a quantum computer)
- 128-bit authentication tag — detects any modification of the ciphertext or header
- AEAD (Authenticated Encryption with Associated Data) — packet integrity is cryptographically guaranteed

### Nonce construction

AES-GCM security requires that the same (key, nonce) pair is **never reused**. Random nonces would have a birthday-bound collision risk after approximately 2^48 packets. This implementation uses counter-based nonces instead:

```
nonce[12] = random_prefix[4] || counter[8]
```

- `random_prefix`: 4 bytes generated by `RAND_bytes()` at session startup
- `counter`: 64-bit monotonic counter, incremented for every packet

At one million packets per second, the counter would not overflow for over 580,000 years. Nonce reuse within a session is therefore impossible.

### Replay protection: RFC 4303 sliding window

The receiver maintains:
- `rx_expected`: the highest sequence number seen so far
- `rx_bitmap`: a 64-bit bitmap recording which of the last 64 sequence numbers have been received

A packet is **accepted** only if its sequence number passes all three checks:
1. Not already received (bit not set in bitmap)
2. Not more than 63 positions behind `rx_expected` (not too old)
3. Not more than 63 positions ahead of `rx_expected` (not an anomalously large jump)

Check 3 prevents injection attacks that attempt to advance the window artificially far forward.

---

## Key management

### Private key protection

All private key files (`*.priv`) are created with `chmod 600` (owner read-only). The `.gitignore` excludes all `*.priv` and certificate files from version control.

**CA private key (`ca_key.priv`):** This is the most sensitive file in the system. Anyone with access to it can issue certificates for any identity. It should be stored on an air-gapped machine and only brought online to issue new certificates.

**Server private key (`server_key.priv`):** Needed by the running server. Keep on the server, restrict to root access.

**Client private keys (`*_key.priv`):** Each client needs only their own private key. They cannot impersonate other clients even if compromised.

### Sensitive data in memory

After use, all sensitive intermediate values are explicitly zeroed with `memset()`:
- HKDF intermediate values (PRK, T blocks)
- ML-KEM shared secret after key derivation
- PSK values after authentication key derivation
- Challenge/MAC buffers in authentication handshake

### Certificate lifetime

Certificates are valid for 365 days from issuance. The verification function checks `expires_at < time(NULL)` and rejects expired certificates without performing the signature check.

---

## Implementation security decisions

### MSG_PEEK in certificate listener

The certificate handshake listener uses `MSG_PEEK` to inspect incoming packet sizes before consuming them from the socket buffer. Only packets matching exactly `sizeof(pqc_cert_t)` (5,341 bytes) are consumed. All other packets remain in the buffer for the tunnel thread to process. This prevents the certificate listener from accidentally consuming tunnel keepalives or KEM messages intended for another code path.

### TUNNEL_READY barrier

After spawning a worker thread for a newly authenticated client, the main server thread waits until the worker thread completes ML-KEM exchange and sets `SESSION_STATE_TUNNEL_READY` before beginning to accept the next client. Without this barrier, the main thread's certificate listener could consume the KEM public key packet intended for the worker thread, causing KEM exchange failure. The barrier is polled at 5ms intervals with a 30-second timeout.

### Routing loop prevention

The client adds a specific host route for the VPN server's IP via the real gateway before changing the default route. Without this, VPN packets themselves would be routed through the tunnel, creating an infinite encrypt-and-resend loop. After adding the host route, the client verifies it using `ip route get <server_ip>` before modifying the default route. If verification fails, the routing change is aborted.

### Constant-time MAC comparison

The PSK authentication uses OpenSSL's `CRYPTO_memcmp()` for MAC comparison rather than `memcmp()`. Standard `memcmp()` short-circuits on the first mismatching byte, leaking timing information that could allow an attacker to distinguish closer-to-correct MACs from completely wrong ones.

---

## Known security constraints

**Manual certificate distribution.** The CA is minimal — there is no revocation mechanism (no CRL or OCSP). If a client certificate is compromised, the only remedy is to re-issue the CA and all certificates. For a production system, certificate revocation should be added.

**No hybrid mode.** This implementation uses post-quantum algorithms exclusively. For deployment in environments where classical interoperability is also required, a hybrid classical + post-quantum handshake (per NIST IR 8547) would be more appropriate.

**Single shared UDP socket.** The server uses one UDP socket for all clients. In a high-traffic deployment, this could become a contention point. A production architecture would allocate a per-client UDP port after the initial handshake.

**HMAC_CTX deprecation.** `pqc_common.c` and `pqc_auth.c` use the OpenSSL 3.0 deprecated `HMAC_CTX_*` API. The replacement `EVP_MAC_*` API is available and would be the correct choice in a production codebase. The deprecated API remains functionally correct and is not a security vulnerability — it is a code maintenance concern.

---

## Responsible disclosure

If you find a security vulnerability in this implementation, please open a GitHub issue marked `[SECURITY]` or contact the project maintainer directly. Do not publicly disclose vulnerabilities that could be exploited before a fix is available.

---

## References

- [NIST FIPS 203 — ML-KEM specification](https://doi.org/10.6028/NIST.FIPS.203)
- [NIST FIPS 204 — ML-DSA specification](https://doi.org/10.6028/NIST.FIPS.204)
- [RFC 5869 — HMAC-based key derivation (HKDF)](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 4303 — IP Encapsulating Security Payload (ESP)](https://datatracker.ietf.org/doc/html/rfc4303)
- [Regev (2005) — Learning With Errors](https://doi.org/10.1145/1060590.1060603)
- [Bos et al. (2018) — CRYSTALS-Kyber](https://doi.org/10.1109/EuroSP.2018.00032)
- [liboqs documentation](https://github.com/open-quantum-safe/liboqs)