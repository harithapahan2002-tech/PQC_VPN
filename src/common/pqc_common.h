// pqc_common.h
// Common utilities, constants, and helper functions for PQ-VPN

#ifndef PQC_COMMON_H
#define PQC_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <sys/types.h>

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

#define PORT 5555
#define KEM_ALG "ML-KEM-768"
#define BUFFER_SIZE 4096
#define MAX_MESSAGE_SIZE (16 * 1024 * 1024)  // 16MB max message size

// AES-GCM parameters
#define IV_LEN 12       // GCM standard IV length
#define TAG_LEN 16      // GCM authentication tag length
#define AES_KEY_LEN 32  // AES-256 key length (256 bits)

// ============================================================================
// TIMING UTILITIES
// ============================================================================

// Calculate elapsed time in microseconds
static inline double elapsed_time_us(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e6 + 
           (end.tv_nsec - start.tv_nsec) / 1e3;
}

// Calculate elapsed time in milliseconds
static inline double elapsed_time_ms(struct timespec start, struct timespec end) {
    return elapsed_time_us(start, end) / 1000.0;
}

// ============================================================================
// NETWORK I/O HELPERS
// ============================================================================

// Read exactly n bytes from file descriptor (blocking until complete or error)
// Returns: number of bytes read, 0 on EOF, -1 on error
ssize_t read_exact(int fd, void *buf, size_t n);

// Write all n bytes to file descriptor (blocking until complete or error)
// Returns: number of bytes written, -1 on error
ssize_t write_all(int fd, const void *buf, size_t n);

// ============================================================================
// KEY DERIVATION
// ============================================================================

// Derive a key from shared secret using SHA-256
// This is a simple HKDF-like derivation (use proper HKDF in production)
//
// Parameters:
//   shared_secret: Input key material (typically from ML-KEM)
//   ss_len: Length of shared secret
//   label: Context label for key derivation (e.g., "AES-SESSION-KEY")
//   out_key: Output buffer for derived key
//   out_len: Desired length of output key (typically 32 for AES-256)
void derive_key(const uint8_t *shared_secret, size_t ss_len,
                const char *label, uint8_t *out_key, size_t out_len);

#endif // PQC_COMMON_H
