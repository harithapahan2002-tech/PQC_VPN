// bench_aead.c
// Benchmark: AES-256-GCM encryption/decryption throughput.
//
// This is identical for both PQC and classical VPN designs — the
// symmetric tunnel cipher does not change based on the key exchange
// or authentication method used. This benchmark exists to show that
// PQC adoption adds zero overhead to the data-plane (per-packet)
// cost — the entire overhead is in the handshake (KEM + signatures),
// not in ongoing tunnel traffic.
//
// Measures encryption/decryption time and throughput (MB/s) at packet
// sizes representative of real traffic: small (64B, e.g. keepalives/
// ACKs), medium (576B, typical small packet), large (1400B, our
// MAX_TUN_PAYLOAD / typical MTU-constrained packet).

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "bench_common.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define AEAD_ITERATIONS   2000
#define AEAD_WARMUP       100
#define AEAD_KEY_LEN      32   // AES-256
#define AEAD_IV_LEN       12   // GCM standard nonce length
#define AEAD_TAG_LEN      16

// Packet sizes to test — chosen to span the range seen in real VPN traffic
static const int PACKET_SIZES[] = { 64, 576, 1400 };
static const char *PACKET_SIZE_LABELS[] = {
    "64B (keepalive-sized)",
    "576B (typical small packet)",
    "1400B (MAX_TUN_PAYLOAD)"
};
#define NUM_PACKET_SIZES  3

// ============================================================================
// SINGLE SIZE BENCHMARK
// ============================================================================

static void bench_aead_size(int size, const char *size_label,
                            bench_results_t *encrypt_r,
                            bench_results_t *decrypt_r) {

    uint8_t key[AEAD_KEY_LEN];
    uint8_t iv[AEAD_IV_LEN];
    uint8_t tag[AEAD_TAG_LEN];
    uint8_t *plaintext  = malloc(size);
    uint8_t *ciphertext = malloc(size);
    uint8_t *decrypted  = malloc(size);

    RAND_bytes(key, AEAD_KEY_LEN);
    RAND_bytes(iv,  AEAD_IV_LEN);
    RAND_bytes(plaintext, size);

    double *encrypt_times = malloc(sizeof(double) * AEAD_ITERATIONS);
    double *decrypt_times = malloc(sizeof(double) * AEAD_ITERATIONS);

    printf("  Benchmarking AES-256-GCM at %s (%d iterations)...\n",
           size_label, AEAD_ITERATIONS);

    // Warmup
    for (int i = 0; i < AEAD_WARMUP; i++) {
        int outlen;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, size);
        EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AEAD_TAG_LEN, tag);
        EVP_CIPHER_CTX_free(ctx);
    }

    // Encryption timing
    for (int i = 0; i < AEAD_ITERATIONS; i++) {
        struct timespec t1, t2;
        int outlen;

        clock_gettime(CLOCK_MONOTONIC, &t1);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, size);
        EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AEAD_TAG_LEN, tag);
        EVP_CIPHER_CTX_free(ctx);

        clock_gettime(CLOCK_MONOTONIC, &t2);
        encrypt_times[i] = elapsed_us(t1, t2);
    }

    // Decryption timing (using the ciphertext+tag from the loop above)
    for (int i = 0; i < AEAD_ITERATIONS; i++) {
        struct timespec t1, t2;
        int outlen;

        clock_gettime(CLOCK_MONOTONIC, &t1);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_DecryptUpdate(ctx, decrypted, &outlen, ciphertext, size);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AEAD_TAG_LEN, tag);
        EVP_DecryptFinal_ex(ctx, decrypted + outlen, &outlen);
        EVP_CIPHER_CTX_free(ctx);

        clock_gettime(CLOCK_MONOTONIC, &t2);
        decrypt_times[i] = elapsed_us(t1, t2);
    }

    bench_compute_stats(encrypt_times, AEAD_ITERATIONS, encrypt_r);
    bench_compute_stats(decrypt_times, AEAD_ITERATIONS, decrypt_r);

    snprintf(encrypt_r->label, BENCH_LABEL_LEN, "AES-256-GCM Encrypt %dB", size);
    snprintf(decrypt_r->label, BENCH_LABEL_LEN, "AES-256-GCM Decrypt %dB", size);

    encrypt_r->data_size = size;
    decrypt_r->data_size = size;

    free(plaintext); free(ciphertext); free(decrypted);
    free(encrypt_times); free(decrypt_times);
}

// ============================================================================
// THROUGHPUT CALCULATION
// ============================================================================

static double calc_throughput_mbps(int packet_size, double mean_us) {
    // bytes per second = packet_size / (mean_us / 1,000,000)
    // MB/s = bytes_per_sec / (1024*1024)
    double bytes_per_sec = packet_size / (mean_us / 1e6);
    return bytes_per_sec / (1024.0 * 1024.0);
}

// ============================================================================
// PUBLIC ENTRY POINT
// ============================================================================

void run_aead_benchmark(bench_suite_t *suite) {
    bench_print_header("Symmetric Cipher Benchmark: AES-256-GCM Throughput");
    printf("  (Identical for PQC and classical VPNs — measures tunnel\n");
    printf("   data-plane cost, independent of key exchange method)\n");

    for (int i = 0; i < NUM_PACKET_SIZES; i++) {
        bench_results_t encrypt_r, decrypt_r;

        bench_aead_size(PACKET_SIZES[i], PACKET_SIZE_LABELS[i],
                        &encrypt_r, &decrypt_r);

        bench_suite_add(suite, &encrypt_r);
        bench_suite_add(suite, &decrypt_r);

        printf("\n");
        bench_print_result(&encrypt_r);
        bench_print_result(&decrypt_r);

        double enc_throughput = calc_throughput_mbps(PACKET_SIZES[i],
                                                      encrypt_r.mean_us);
        double dec_throughput = calc_throughput_mbps(PACKET_SIZES[i],
                                                      decrypt_r.mean_us);

        printf("  → Encrypt throughput: %8.2f MB/s\n", enc_throughput);
        printf("  → Decrypt throughput: %8.2f MB/s\n", dec_throughput);
    }

    printf("\n  ── Summary ─────────────────────────────────────────\n");
    printf("  AES-256-GCM overhead is identical regardless of whether\n");
    printf("  the key exchange uses ML-KEM-768 or classical ECDH.\n");
    printf("  Post-quantum overhead is entirely confined to the\n");
    printf("  handshake phase (see KEM and signature benchmarks).\n");
}
