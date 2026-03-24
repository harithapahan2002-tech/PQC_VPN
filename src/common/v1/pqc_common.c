// pqc_common.c
// Implementation of common utilities

#include "pqc_common.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// ============================================================================
// NETWORK I/O IMPLEMENTATION
// ============================================================================

ssize_t read_exact(int fd, void *buf, size_t n) {
    size_t offset = 0;
    uint8_t *ptr = (uint8_t*)buf;
    
    while (offset < n) {
        ssize_t r = read(fd, ptr + offset, n - offset);
        
        if (r < 0) {
            // Check if interrupted by signal - if so, retry
            if (errno == EINTR) {
                continue;
            }
            // Actual error
            return -1;
        }
        
        if (r == 0) {
            // EOF reached
            return 0;
        }
        
        offset += (size_t)r;
    }
    
    return (ssize_t)offset;
}

ssize_t write_all(int fd, const void *buf, size_t n) {
    size_t offset = 0;
    const uint8_t *ptr = (const uint8_t*)buf;
    
    while (offset < n) {
        ssize_t w = write(fd, ptr + offset, n - offset);
        
        if (w < 0) {
            // Check if interrupted by signal - if so, retry
            if (errno == EINTR) {
                continue;
            }
            // Actual error
            return -1;
        }
        
        offset += (size_t)w;
    }
    
    return (ssize_t)offset;
}

// ============================================================================
// KEY DERIVATION IMPLEMENTATION
// ============================================================================

void derive_key(const uint8_t *shared_secret, size_t ss_len,
                const char *label, uint8_t *out_key, size_t out_len) {
    // Simple key derivation using SHA-256
    // In production, use proper HKDF (RFC 5869)
    // This is sufficient for educational/research purposes
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        // Failed to create context - zero out output and return
        memset(out_key, 0, out_len);
        return;
    }
    
    // Compute: SHA-256(shared_secret || label)
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, shared_secret, ss_len);
    EVP_DigestUpdate(ctx, label, strlen(label));
    
    uint8_t hash[32];  // SHA-256 produces 32 bytes
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    
    EVP_MD_CTX_free(ctx);
    
    // Copy the required number of bytes to output
    // If we need more than 32 bytes, we'd need multiple rounds
    // For AES-256 (32 bytes), this is perfect
    size_t copy_len = (out_len < hash_len) ? out_len : hash_len;
    memcpy(out_key, hash, copy_len);
    
    // If out_len > 32, zero-fill the rest (shouldn't happen for AES-256)
    if (out_len > copy_len) {
        memset(out_key + copy_len, 0, out_len - copy_len);
    }
}
// ============================================================================
// SECURITY FUNCTIONS IMPLEMENTATION
// ============================================================================

void init_nonce_state(nonce_state_t *state) {
    state->counter = 0;
    
    // Generate random 32-bit prefix
    // This ensures even if counter resets, nonces are different
    if (RAND_bytes((uint8_t*)&state->random_prefix, 
                   sizeof(state->random_prefix)) != 1) {
        // Fallback to time-based if RAND_bytes fails
        state->random_prefix = (uint32_t)time(NULL);
    }
}

void generate_nonce(nonce_state_t *state, uint8_t nonce[IV_LEN]) {
    // Nonce format: [4 bytes random prefix][8 bytes counter]
    // This guarantees uniqueness even across sessions
    
    memset(nonce, 0, IV_LEN);
    
    // Copy random prefix (4 bytes)
    memcpy(nonce, &state->random_prefix, sizeof(state->random_prefix));
    
    // Copy counter (8 bytes) - starts at offset 4
    uint64_t counter_net = htobe64(state->counter);
    memcpy(nonce + 4, &counter_net, sizeof(uint64_t));
    
    // Increment counter for next packet
    state->counter++;
    
    // Check for counter overflow (should never happen in practice)
    if (state->counter == 0) {
        fprintf(stderr, "⚠️  Warning: Nonce counter wrapped! Re-keying recommended.\n");
    }
}

int check_sequence(uint64_t received_seq, uint64_t *expected_seq,
                   uint64_t *seq_bitmap) {
    // Replay protection using sliding window
    // Based on RFC 4303 (IPsec ESP) anti-replay algorithm
    
    // Case 1: Exact match - this is the expected packet
    if (received_seq == *expected_seq) {
        // Accept packet and advance window
        *expected_seq = received_seq + 1;
        *seq_bitmap = 0;  // Reset bitmap
        return 1;
    }
    
    // Case 2: Future packet (ahead of expected)
    if (received_seq > *expected_seq) {
        uint64_t diff = received_seq - *expected_seq;
        
        if (diff < SEQUENCE_WINDOW) {
            // Within window - shift bitmap and accept
            *seq_bitmap = (*seq_bitmap << diff) | 1;
            *expected_seq = received_seq + 1;
            return 1;
        } else {
            // Far in future - jump forward (accept but suspicious)
            fprintf(stderr, "⚠️  Warning: Sequence jump detected (%lu -> %lu)\n",
                    *expected_seq, received_seq);
            *expected_seq = received_seq + 1;
            *seq_bitmap = 0;
            return 1;
        }
    }
    
    // Case 3: Old packet (behind expected)
    if (received_seq < *expected_seq) {
        uint64_t diff = *expected_seq - received_seq;
        
        if (diff >= SEQUENCE_WINDOW) {
            // Too old - reject (replay attack!)
            fprintf(stderr, "❌ Replay detected: seq %lu (expected >= %lu)\n",
                    received_seq, *expected_seq);
            return 0;
        }
        
        // Within window - check if we've seen it before
        uint64_t bit_pos = diff - 1;
        if (*seq_bitmap & (1ULL << bit_pos)) {
            // Already received - reject (duplicate!)
            fprintf(stderr, "❌ Duplicate packet: seq %lu\n", received_seq);
            return 0;
        }
        
        // Mark as received and accept
        *seq_bitmap |= (1ULL << bit_pos);
        return 1;
    }
    
    // Should never reach here
    return 0;
}
