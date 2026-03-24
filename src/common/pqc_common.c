// pqc_common.c
// Implementation of network I/O, HKDF key derivation,
// nonce management, and replay protection.
//
// Depends on: pqc_common.h, OpenSSL (libcrypto)

#define _POSIX_C_SOURCE 200809L

#include "pqc_common.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

// ============================================================================
// NETWORK I/O
// ============================================================================

ssize_t read_exact(int fd, void *buf, size_t n) {
    if (n == 0) return 0;

    size_t   total = 0;
    uint8_t *ptr   = (uint8_t *)buf;

    while (total < n) {
        ssize_t r = read(fd, ptr + total, n - total);

        if (r < 0) {
            if (errno == EINTR) continue;   // Signal interrupted — retry
            return -1;                       // Real error
        }

        if (r == 0) {
            // EOF mid-read: partial data received, treat as error.
            // Returns -1 (not 0) so callers can distinguish clean EOF
            // (n == 0 case above) from connection-dropped-mid-message.
            return -1;
        }

        total += (size_t)r;
    }

    return (ssize_t)total;
}

ssize_t write_all(int fd, const void *buf, size_t n) {
    if (n == 0) return 0;

    size_t         total = 0;
    const uint8_t *ptr   = (const uint8_t *)buf;

    while (total < n) {
        ssize_t w = write(fd, ptr + total, n - total);

        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }

        total += (size_t)w;
    }

    return (ssize_t)total;
}

// ============================================================================
// HKDF-SHA256   (RFC 5869)
// ============================================================================
//
// HKDF has two steps:
//   1. Extract: PRK = HMAC-SHA256(salt, IKM)
//      Produces a fixed-length pseudorandom key from raw input material.
//   2. Expand:  T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
//      Stretches PRK to the requested output length using the info label
//      as a domain separator — different labels produce independent keys
//      from the same shared secret.
//
// Why this replaces SHA-256(secret || label):
//   The old construction had no salt (same secret always → same key) and
//   no proper domain separation — concatenating secret and label is not
//   the same as using them as independent HMAC inputs.

void hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                 const uint8_t *salt, size_t salt_len,
                 const char    *info,
                 uint8_t       *out,  size_t out_len) {

    // HKDF-SHA256 output is capped at 255 * HashLen = 255 * 32 = 8160 bytes.
    // For our use (AES-256 keys = 32 bytes) this is never an issue, but
    // we guard against accidental misuse.
    if (out_len == 0 || out_len > 255 * SHA256_DIGEST_LENGTH) {
        memset(out, 0, out_len);
        return;
    }

    // -----------------------------------------------------------------------
    // Step 1: Extract
    // PRK = HMAC-SHA256(salt, IKM)
    // If no salt provided, RFC 5869 specifies a zero-filled salt of HashLen.
    // -----------------------------------------------------------------------
    uint8_t zero_salt[SHA256_DIGEST_LENGTH];
    const uint8_t *actual_salt     = salt;
    size_t         actual_salt_len = salt_len;

    if (actual_salt == NULL || actual_salt_len == 0) {
        memset(zero_salt, 0, sizeof(zero_salt));
        actual_salt     = zero_salt;
        actual_salt_len = sizeof(zero_salt);
    }

    uint8_t      prk[SHA256_DIGEST_LENGTH];
    unsigned int prk_len = 0;

    HMAC(EVP_sha256(),
         actual_salt, (int)actual_salt_len,
         ikm, ikm_len,
         prk, &prk_len);

    // -----------------------------------------------------------------------
    // Step 2: Expand
    // T(0) = empty
    // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    // OKM  = T(1) || T(2) || ... truncated to out_len
    // -----------------------------------------------------------------------
    size_t   info_len  = info ? strlen(info) : 0;
    size_t   done      = 0;
    uint8_t  t[SHA256_DIGEST_LENGTH];
    uint32_t t_len     = 0;         // 0 for first iteration (T(0) = empty)
    uint8_t  counter   = 1;

    while (done < out_len) {
        HMAC_CTX *ctx = HMAC_CTX_new();

        HMAC_Init_ex(ctx, prk, (int)prk_len, EVP_sha256(), NULL);

        if (t_len > 0)
            HMAC_Update(ctx, t, t_len);           // T(i-1)

        if (info && info_len > 0)
            HMAC_Update(ctx, (const uint8_t *)info, info_len); // info

        HMAC_Update(ctx, &counter, 1);             // counter byte

        HMAC_Final(ctx, t, &t_len);
        HMAC_CTX_free(ctx);

        size_t copy = t_len;
        if (done + copy > out_len)
            copy = out_len - done;

        memcpy(out + done, t, copy);
        done += copy;
        counter++;
    }

    // Zero intermediate values — PRK and T are sensitive
    memset(prk, 0, sizeof(prk));
    memset(t,   0, sizeof(t));
}

// ============================================================================
// NONCE MANAGEMENT
// ============================================================================

int init_nonce_state(nonce_state_t *state) {
    memset(state, 0, sizeof(*state));

    // Generate a cryptographically random 4-byte prefix.
    // We do NOT fall back to time(NULL) or any deterministic value —
    // if RAND_bytes fails the caller must abort, not continue with a
    // predictable nonce space.
    if (RAND_bytes((uint8_t *)&state->random_prefix,
                   sizeof(state->random_prefix)) != 1) {
        fprintf(stderr, "❌ RAND_bytes failed in init_nonce_state — "
                        "cannot initialise nonce state safely\n");
        return -1;
    }

    state->counter     = 0;
    state->initialised = 1;
    return 0;
}

int generate_nonce(nonce_state_t *state, uint8_t nonce[IV_LEN]) {
    if (!state->initialised) {
        fprintf(stderr, "❌ generate_nonce called on uninitialised state\n");
        memset(nonce, 0, IV_LEN);
        return -1;
    }

    // Nonce layout (12 bytes):
    //   bytes 0-3  : random_prefix in big-endian
    //   bytes 4-11 : counter in big-endian
    //
    // Big-endian for both fields ensures the nonce is comparable across
    // machines and matches what a remote peer would reconstruct if needed.
    memset(nonce, 0, IV_LEN);

    // Write prefix (big-endian, 4 bytes)
    nonce[0] = (uint8_t)(state->random_prefix >> 24);
    nonce[1] = (uint8_t)(state->random_prefix >> 16);
    nonce[2] = (uint8_t)(state->random_prefix >>  8);
    nonce[3] = (uint8_t)(state->random_prefix      );

    // Write counter (big-endian, 8 bytes)
    uint64_t ctr = state->counter;
    nonce[4]  = (uint8_t)(ctr >> 56);
    nonce[5]  = (uint8_t)(ctr >> 48);
    nonce[6]  = (uint8_t)(ctr >> 40);
    nonce[7]  = (uint8_t)(ctr >> 32);
    nonce[8]  = (uint8_t)(ctr >> 24);
    nonce[9]  = (uint8_t)(ctr >> 16);
    nonce[10] = (uint8_t)(ctr >>  8);
    nonce[11] = (uint8_t)(ctr      );

    state->counter++;

    // A 64-bit counter at 1 Gbps line rate with 1400-byte packets gives
    // ~893,000 packets/sec → counter exhausts in ~650,000 years.
    // We still warn at wrap so a caller doing re-keying can detect it,
    // but unlike the old version we do not silently continue — the
    // initialised flag is cleared, forcing re-initialisation.
    if (state->counter == 0) {
        fprintf(stderr, "❌ Nonce counter wrapped — re-keying required. "
                        "Nonce state invalidated.\n");
        state->initialised = 0;
        return -1;
    }

    return 0;
}

// ============================================================================
// REPLAY PROTECTION   (RFC 4303 sliding window)
// ============================================================================

int check_sequence(uint64_t  received_seq,
                   uint64_t *expected_seq,
                   uint64_t *seq_bitmap) {

    // -----------------------------------------------------------------------
    // Case 1: Exact match — the packet we were waiting for
    // -----------------------------------------------------------------------
    if (received_seq == *expected_seq) {
        *expected_seq = received_seq + 1;
        *seq_bitmap   = 0;
        return 1;
    }

    // -----------------------------------------------------------------------
    // Case 2: Packet is ahead of the window (future packet)
    // -----------------------------------------------------------------------
    if (received_seq > *expected_seq) {
        uint64_t diff = received_seq - *expected_seq;

        if (diff >= SEQUENCE_WINDOW) {
            // OLD behaviour: accept and jump forward with a warning.
            // NEW behaviour: reject — a jump this large is far more
            // consistent with an injection or desync attack than legitimate
            // reordering. The peer should never be this far ahead under
            // normal conditions.
            fprintf(stderr, "❌ Sequence jump too large: expected %lu, "
                            "got %lu (diff %lu >= window %d) — rejected\n",
                    (unsigned long)*expected_seq,
                    (unsigned long)received_seq,
                    (unsigned long)diff,
                    SEQUENCE_WINDOW);
            return 0;
        }

        // Within window: shift bitmap left by diff, mark new seq as seen,
        // advance the expected pointer.
        *seq_bitmap   = (*seq_bitmap << diff) | 1ULL;
        *expected_seq = received_seq + 1;
        return 1;
    }

    // -----------------------------------------------------------------------
    // Case 3: Packet is behind the window (old packet)
    // -----------------------------------------------------------------------
    // received_seq < *expected_seq here
    uint64_t diff = *expected_seq - received_seq;

    if (diff > SEQUENCE_WINDOW) {
        // Too old — definitely a replay
        fprintf(stderr, "❌ Replay detected: seq %lu is %lu packets behind "
                        "expected %lu — rejected\n",
                (unsigned long)received_seq,
                (unsigned long)diff,
                (unsigned long)*expected_seq);
        return 0;
    }

    // Within the window — check the bitmap for duplicates.
    // bit_pos 0 = expected_seq - 1, bit_pos 1 = expected_seq - 2, etc.
    uint64_t bit_pos = diff - 1;

    if (*seq_bitmap & (1ULL << bit_pos)) {
        fprintf(stderr, "❌ Duplicate packet: seq %lu already received — "
                        "rejected\n",
                (unsigned long)received_seq);
        return 0;
    }

    // First time seeing this out-of-order packet — mark and accept
    *seq_bitmap |= (1ULL << bit_pos);
    return 1;
}