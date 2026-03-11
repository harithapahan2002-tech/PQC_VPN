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
