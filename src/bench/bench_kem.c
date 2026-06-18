// bench_kem.c
// Benchmark: ML-KEM-768 (post-quantum) vs X25519 (classical ECDH)
//
// Measures keypair generation, encapsulation/key-agreement, and
// decapsulation/key-agreement timing for both algorithms, using
// identical methodology so the numbers are directly comparable.
//
// X25519 is used as the classical baseline because it is the most
// common ECDH curve in modern protocols (TLS 1.3, WireGuard, Signal)
// and is available directly via OpenSSL's EVP_PKEY API without any
// additional dependencies.
//
// Build: part of bench_main — see Makefile bench target.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "bench_common.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define KEM_ITERATIONS     1000
#define KEM_WARMUP         50

// ============================================================================
// ML-KEM-768 BENCHMARK
// ============================================================================

static void bench_mlkem768(bench_results_t *keypair_r,
                           bench_results_t *encap_r,
                           bench_results_t *decap_r) {

    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) {
        fprintf(stderr, "❌ ML-KEM-768 not available in liboqs\n");
        return;
    }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    double *keypair_times = malloc(sizeof(double) * KEM_ITERATIONS);
    double *encap_times    = malloc(sizeof(double) * KEM_ITERATIONS);
    double *decap_times    = malloc(sizeof(double) * KEM_ITERATIONS);

    printf("  Benchmarking ML-KEM-768 (%d iterations, %d warmup)...\n",
           KEM_ITERATIONS, KEM_WARMUP);

    // Warmup — let CPU frequency scaling and caches settle
    for (int i = 0; i < KEM_WARMUP; i++) {
        OQS_KEM_keypair(kem, pk, sk);
        OQS_KEM_encaps(kem, ct, ss_enc, pk);
        OQS_KEM_decaps(kem, ss_dec, ct, sk);
    }

    // Keypair generation
    for (int i = 0; i < KEM_ITERATIONS; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        OQS_KEM_keypair(kem, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        keypair_times[i] = elapsed_us(t1, t2);
    }

    // Encapsulation (server side: derive shared secret + ciphertext)
    for (int i = 0; i < KEM_ITERATIONS; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        OQS_KEM_encaps(kem, ct, ss_enc, pk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        encap_times[i] = elapsed_us(t1, t2);
    }

    // Decapsulation (client side: recover shared secret)
    for (int i = 0; i < KEM_ITERATIONS; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        OQS_KEM_decaps(kem, ss_dec, ct, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        decap_times[i] = elapsed_us(t1, t2);
    }

    bench_compute_stats(keypair_times, KEM_ITERATIONS, keypair_r);
    bench_compute_stats(encap_times,    KEM_ITERATIONS, encap_r);
    bench_compute_stats(decap_times,    KEM_ITERATIONS, decap_r);

    strncpy(keypair_r->label, "ML-KEM-768 Keypair",     BENCH_LABEL_LEN - 1);
    strncpy(encap_r->label,    "ML-KEM-768 Encapsulate", BENCH_LABEL_LEN - 1);
    strncpy(decap_r->label,    "ML-KEM-768 Decapsulate", BENCH_LABEL_LEN - 1);

    keypair_r->data_size = (long)kem->length_secret_key;
    encap_r->data_size    = (long)kem->length_ciphertext;
    decap_r->data_size    = (long)kem->length_shared_secret;

    memset(sk, 0, kem->length_secret_key);
    memset(ss_enc, 0, kem->length_shared_secret);
    memset(ss_dec, 0, kem->length_shared_secret);

    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    free(keypair_times); free(encap_times); free(decap_times);
    OQS_KEM_free(kem);
}

// ============================================================================
// X25519 BENCHMARK  (classical ECDH baseline)
// ============================================================================

static void bench_x25519(bench_results_t *keypair_r,
                         bench_results_t *agree_r) {

    printf("  Benchmarking X25519 (%d iterations, %d warmup)...\n",
           KEM_ITERATIONS, KEM_WARMUP);

    double *keypair_times = malloc(sizeof(double) * KEM_ITERATIONS);
    double *agree_times    = malloc(sizeof(double) * KEM_ITERATIONS);

    // Pre-generate a fixed peer keypair to agree against
    EVP_PKEY *peer = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!peer) {
        fprintf(stderr, "❌ X25519 keygen failed — OpenSSL build issue\n");
        free(keypair_times); free(agree_times);
        return;
    }

    // Warmup
    for (int i = 0; i < KEM_WARMUP; i++) {
        EVP_PKEY *kp = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
        EVP_PKEY_free(kp);
    }

    // Keypair generation
    EVP_PKEY *my_key = NULL;
    for (int i = 0; i < KEM_ITERATIONS; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        EVP_PKEY *kp = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
        clock_gettime(CLOCK_MONOTONIC, &t2);
        keypair_times[i] = elapsed_us(t1, t2);
        if (i == KEM_ITERATIONS - 1) my_key = kp;   // keep last for agreement test
        else EVP_PKEY_free(kp);
    }

    // Key agreement (ECDH derive)
    for (int i = 0; i < KEM_ITERATIONS; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, peer);
        size_t secret_len = 32;
        uint8_t secret[32];
        EVP_PKEY_derive(ctx, secret, &secret_len);
        EVP_PKEY_CTX_free(ctx);

        clock_gettime(CLOCK_MONOTONIC, &t2);
        agree_times[i] = elapsed_us(t1, t2);
    }

    bench_compute_stats(keypair_times, KEM_ITERATIONS, keypair_r);
    bench_compute_stats(agree_times,    KEM_ITERATIONS, agree_r);

    strncpy(keypair_r->label, "X25519 Keypair",  BENCH_LABEL_LEN - 1);
    strncpy(agree_r->label,    "X25519 Agree",    BENCH_LABEL_LEN - 1);

    keypair_r->data_size = 32;   // X25519 private key size
    agree_r->data_size    = 32;  // shared secret size

    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer);
    free(keypair_times); free(agree_times);
}

// ============================================================================
// PUBLIC ENTRY POINT
// ============================================================================

void run_kem_benchmark(bench_suite_t *suite) {
    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  Key Exchange Benchmark: ML-KEM-768 vs X25519\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    bench_results_t mlkem_keypair, mlkem_encap, mlkem_decap;
    bench_results_t x25519_keypair, x25519_agree;

    bench_mlkem768(&mlkem_keypair, &mlkem_encap, &mlkem_decap);
    bench_x25519(&x25519_keypair, &x25519_agree);

    bench_suite_add(suite, &mlkem_keypair);
    bench_suite_add(suite, &mlkem_encap);
    bench_suite_add(suite, &mlkem_decap);
    bench_suite_add(suite, &x25519_keypair);
    bench_suite_add(suite, &x25519_agree);

    printf("\n");
    bench_print_result(&mlkem_keypair);
    bench_print_result(&mlkem_encap);
    bench_print_result(&mlkem_decap);
    bench_print_result(&x25519_keypair);
    bench_print_result(&x25519_agree);

    // Summary comparison
    double mlkem_total  = mlkem_keypair.mean_us + mlkem_encap.mean_us;
    double x25519_total = x25519_keypair.mean_us + x25519_agree.mean_us;

    printf("\n  ── Summary ─────────────────────────────────────────\n");
    printf("  ML-KEM-768 total (keypair+encap) : %8.2f µs\n", mlkem_total);
    printf("  X25519 total (keypair+agree)     : %8.2f µs\n", x25519_total);
    printf("  Overhead factor                  : %6.2fx\n",
           mlkem_total / x25519_total);
    printf("  Public key size  : ML-KEM-768 %d B  vs  X25519 32 B\n",
           1184);
    printf("  Ciphertext size  : ML-KEM-768 %d B  vs  X25519 N/A (no ct)\n",
           1088);
}
