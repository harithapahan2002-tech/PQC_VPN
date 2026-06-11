// pqc_common.h
// Common constants, structs, and utility declarations for PQ-VPN
//
// Dependency: none (this is the root header)
// Included by: pqc_crypto.h, pqc_auth.h, tun.h, udp_support.h,
//              vpn_server.c, vpn_client.c, all test files

#ifndef PQC_COMMON_H
#define PQC_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>

// ============================================================================
// ALGORITHM SELECTION
// ============================================================================

#define KEM_ALG "ML-KEM-768"        // NIST PQC standard KEM

// ============================================================================
// NETWORK CONFIGURATION
// ============================================================================

#define VPN_PORT         5555
#define SERVER_IP_DEFAULT "127.0.0.1"

// ============================================================================
// AES-256-GCM PARAMETERS
// ============================================================================

#define AES_KEY_LEN  32   // AES-256 key (256 bits)
#define IV_LEN       12   // GCM standard IV length (96 bits)
#define TAG_LEN      16   // GCM authentication tag (128 bits)

// ============================================================================
// BUFFER SIZES
// ============================================================================

// Maximum IP packet size we will handle through the TUN interface.
// Standard Ethernet MTU is 1500. We cap at 1400 to leave headroom for
// the VPN packet header (36 bytes) and UDP/IP overhead, keeping the
// final UDP datagram safely under the 1472-byte UDP payload limit.
#define MAX_TUN_PAYLOAD   1400

// Encrypted packet = header + ciphertext (same length as plaintext for GCM)
// Header: MAGIC(4) + TYPE(1) + SEQ(8) + IV(12) + TAG(16) = 41 bytes
#define VPN_HEADER_SIZE   (sizeof(vpn_packet_header_t))

// UDP receive buffer must hold a full encrypted packet
#define UDP_RECV_BUFSIZE  (MAX_TUN_PAYLOAD + VPN_HEADER_SIZE + 64)

// Maximum framed message size for the TCP-style send/recv helpers
// (used in the auth handshake, not the data tunnel)
#define MAX_MESSAGE_SIZE  (64 * 1024)   // 64 KB — sufficient for handshake msgs

// ============================================================================
// REPLAY PROTECTION
// ============================================================================

// Sliding window size for out-of-order packet acceptance.
// 64 means we tolerate up to 64 packets arriving out of order
// before treating a packet as a replay. Must be <= 64 (fits uint64_t bitmap).
#define SEQUENCE_WINDOW   64

// ============================================================================
// PACKET HEADER
// ============================================================================

// Magic number — first 4 bytes of every VPN data packet.
// Allows the receiver to quickly identify and silently discard stale
// packets from previous sessions, OS background traffic, or any other
// foreign UDP datagrams that arrive on port 5555.
// "PQVC" = Post-Quantum VPN Client
#define VPN_MAGIC        0x50515643U
#define VPN_MAGIC_SIZE   4

// Packet types — carried in the type field of vpn_packet_header_t.
// Allows the receiver to distinguish data packets from keepalives
// without decrypting the payload first.
#define PKT_TYPE_DATA      0x01   // Normal encrypted IP packet
#define PKT_TYPE_KEEPALIVE 0x02   // Heartbeat — payload is a single zero byte

// Keepalive interval — client sends a heartbeat if no data sent in this time.
// Server ends session if no packet (data or keepalive) received within
// KEEPALIVE_IDLE_SEC seconds.
#define KEEPALIVE_INTERVAL_SEC  10   // Client sends keepalive every 10s
#define KEEPALIVE_IDLE_SEC      45  // Server ends session after 45s silence

// Wire format for every VPN data packet:
//   [magic: 4][type: 1][sequence: 8][iv: 12][tag: 16][ciphertext]
//
// packed to ensure no compiler padding alters the wire layout.
typedef struct {
    uint32_t magic;       // VPN_MAGIC — identifies this as a valid VPN packet
    uint8_t  type;        // PKT_TYPE_DATA or PKT_TYPE_KEEPALIVE
    uint64_t sequence;    // Big-endian sequence number (replay protection)
    uint8_t  iv[IV_LEN];  // Nonce used for this packet's AES-GCM encryption
    uint8_t  tag[TAG_LEN];// AES-GCM authentication tag
    // Ciphertext follows immediately in the wire buffer (not in this struct)
} __attribute__((packed)) vpn_packet_header_t;

// Compile-time check: header must be exactly 41 bytes
_Static_assert(sizeof(vpn_packet_header_t) == 41,
               "vpn_packet_header_t size mismatch — check padding");

// ============================================================================
// COUNTER-BASED NONCE STATE
// ============================================================================

// Nonce format (12 bytes total):
//   [random_prefix: 4 bytes][counter: 8 bytes]
//
// The random prefix is generated once per session (from RAND_bytes).
// The counter increments monotonically. Together they guarantee:
//   - Uniqueness within a session (counter never repeats)
//   - Uniqueness across sessions (prefix differs each time)
//
// This replaces random-per-packet IVs, which have a birthday-bound
// collision risk after ~2^48 packets (for 96-bit IVs).
typedef struct {
    uint64_t counter;        // Monotonic counter, starts at 0
    uint32_t random_prefix;  // Session-unique random prefix
    int      initialised;    // 1 if init_nonce_state() has been called
} nonce_state_t;

// ============================================================================
// TIMING UTILITIES  (inline — no .c needed)
// ============================================================================

static inline double elapsed_us(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec  - start.tv_sec)  * 1e6 +
           (double)(end.tv_nsec - start.tv_nsec) / 1e3;
}

static inline double elapsed_ms(struct timespec start, struct timespec end) {
    return elapsed_us(start, end) / 1000.0;
}

// ============================================================================
// NETWORK I/O   (implemented in pqc_common.c)
// ============================================================================

// Read exactly n bytes from fd, retrying on EINTR.
// Returns n on success, 0 on clean EOF, -1 on error or partial EOF.
// Distinguishes partial EOF from success — unlike the old version which
// returned 0 for both, masking silent truncation.
ssize_t read_exact(int fd, void *buf, size_t n);

// Write all n bytes to fd, retrying on EINTR.
// Returns n on success, -1 on error.
ssize_t write_all(int fd, const void *buf, size_t n);

// ============================================================================
// KEY DERIVATION   (implemented in pqc_common.c)
// ============================================================================

// Derive a fixed-length key from input key material using HKDF-SHA256
// (RFC 5869).
//
//   ikm      : input key material (e.g. ML-KEM shared secret)
//   ikm_len  : length of ikm in bytes
//   salt     : optional random salt (NULL → use zero-filled salt)
//   salt_len : length of salt (0 if salt is NULL)
//   info     : context label, e.g. "vpn-session-key"  (must not be NULL)
//   out      : output buffer
//   out_len  : desired output length in bytes (max 255 * 32 for HKDF-SHA256)
//
// Replaces the old SHA-256(secret || label) construction, which lacked a
// salt and produced the same key for identical inputs across sessions.
void hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                 const uint8_t *salt, size_t salt_len,
                 const char    *info,
                 uint8_t       *out,  size_t out_len);

// ============================================================================
// NONCE MANAGEMENT   (implemented in pqc_common.c)
// ============================================================================

// Initialise nonce state for a new session.
// Generates a cryptographically random prefix via RAND_bytes.
// Aborts (does NOT silently fall back) if RAND_bytes fails —
// unlike the old version which fell back to time(NULL).
// Returns 0 on success, -1 on failure.
int init_nonce_state(nonce_state_t *state);

// Write the next nonce into nonce[IV_LEN] and increment the counter.
// Format: [4-byte prefix (BE)][8-byte counter (BE)]
// Must only be called after a successful init_nonce_state().
// Returns 0 on success, -1 if state is uninitialised.
int generate_nonce(nonce_state_t *state, uint8_t nonce[IV_LEN]);

// ============================================================================
// REPLAY PROTECTION   (implemented in pqc_common.c)
// ============================================================================

// Check whether received_seq is acceptable (not a replay, not a duplicate).
// Implements a 64-packet sliding window based on RFC 4303.
//
//   received_seq : sequence number from the incoming packet header
//   expected_seq : pointer to the receiver's next-expected sequence number
//   seq_bitmap   : pointer to the 64-bit window bitmap
//
// Returns 1 if the packet should be accepted, 0 if it should be dropped.
//
// Key change from old version: packets arriving more than SEQUENCE_WINDOW
// ahead of expected_seq are now REJECTED (not silently accepted with a
// warning), as a large forward jump is more consistent with an attack than
// legitimate reordering.
int check_sequence(uint64_t  received_seq,
                   uint64_t *expected_seq,
                   uint64_t *seq_bitmap);

#endif // PQC_COMMON_H