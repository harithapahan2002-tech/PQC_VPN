// bench_sig.c
// Benchmark: ML-DSA-65 (post-quantum) vs ECDSA P-256 (classical)
//
// Measures keypair generation, signing, and verification timing for
// both algorithms. ECDSA P-256 is used as the classical baseline —
// it is the most widely deployed signature scheme in TLS certificates
// and is directly comparable in security level intent to ML-DSA-65
// (NIST category 3 / 128-bit-equivalent classical security target).

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#include "bench_common.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define SIG_ITERATIONS    500    // Signing/verification is slower than KEM ops
#define SIG_WARMUP        20
#define MESSAGE_LEN       64     // Representative message size (cert TBS-like)

// ============================================================================
// ML-DSA-65 BENCHMARK
// ============================================================================

static void bench_mldsa65(bench_results_t *keypair_r,
                          bench_results_t *sign_r,
                          bench_results_t *verify_r) {

    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    if (!sig) {
        fprintf(stderr, "❌ ML-DSA-65 not available in liboqs\n");
        return;
    }

    uint8_t *pk  = malloc(sig->length_public_key);
    uint8_t *sk  = malloc(sig->length_secret_key);
    uint8_t *sm  = malloc(sig->length_signature);
    uint8_t message[MESSAGE_LEN];
    memset(message, 0xAB, MESSAGE_LEN);   // fixed pattern, content irrelevant

    double *keypair_times = malloc(sizeof(double) * SIG_ITERATIONS);
    double *sign_times     = malloc(sizeof(double) * SIG_ITERATIONS);
    double *verify_times   = malloc(sizeof(double) * SIG_ITERATIONS);

    printf("  Benchmarking ML-DSA-65 (%d iterations, %d warmup)...\n",
           SIG_ITERATIONS, SIG_WARMUP);

    // Generate one keypair to use for sign/verify timing
    OQS_SIG_keypair(sig, pk, sk);
    size_t sig_len = 0;

    // Warmup
    for (int i = 0; i < SIG_WARMUP; i++) {
        OQS_SIG_sign(sig, sm, &sig_len, message, MESSAGE_LEN, sk);
        OQS_SIG_verify(sig, message, MESSAGE_LEN, sm, sig_len, pk);
    }

    // Keypair generation (separate keys each iteration — this is the
    // realistic cost of issuing a new certificate)
    for (int i = 0; i < SIG_ITERATIONS; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        OQS_SIG_keypair(sig, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        keypair_times[i] = elapsed_us(t1, t2);
    }

    // Re-derive a stable keypair for sign/verify (after keypair loop
    // overwrote pk/sk repeatedly above)
    OQS_SIG_keypair(sig, pk, sk);

    // Signing
    for (int i = 0; i < SIG_ITERATIONS; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        OQS_SIG_sign(sig, sm, &sig_len, message, MESSAGE_LEN, sk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        sign_times[i] = elapsed_us(t1, t2);
    }

    // Verification (use the last signature produced above)
    for (int i = 0; i < SIG_ITERATIONS; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        OQS_SIG_verify(sig, message, MESSAGE_LEN, sm, sig_len, pk);
        clock_gettime(CLOCK_MONOTONIC, &t2);
        verify_times[i] = elapsed_us(t1, t2);
    }

    bench_compute_stats(keypair_times, SIG_ITERATIONS, keypair_r);
    bench_compute_stats(sign_times,     SIG_ITERATIONS, sign_r);
    bench_compute_stats(verify_times,   SIG_ITERATIONS, verify_r);

    strncpy(keypair_r->label, "ML-DSA-65 Keypair", BENCH_LABEL_LEN - 1);
    strncpy(sign_r->label,    "ML-DSA-65 Sign",     BENCH_LABEL_LEN - 1);
    strncpy(verify_r->label,  "ML-DSA-65 Verify",   BENCH_LABEL_LEN - 1);

    keypair_r->data_size = (long)sig->length_secret_key;
    sign_r->data_size     = (long)sig_len;
    verify_r->data_size   = (long)sig->length_public_key;

    memset(sk, 0, sig->length_secret_key);
    free(pk); free(sk); free(sm);
    free(keypair_times); free(sign_times); free(verify_times);
    OQS_SIG_free(sig);
}

// ============================================================================
// ECDSA P-256 BENCHMARK  (classical baseline)
// ============================================================================

static void bench_ecdsa_p256(bench_results_t *keypair_r,
                             bench_results_t *sign_r,
                             bench_results_t *verify_r) {

    printf("  Benchmarking ECDSA P-256 (%d iterations, %d warmup)...\n",
           SIG_ITERATIONS, SIG_WARMUP);

    double *keypair_times = malloc(sizeof(double) * SIG_ITERATIONS);
    double *sign_times     = malloc(sizeof(double) * SIG_ITERATIONS);
    double *verify_times   = malloc(sizeof(double) * SIG_ITERATIONS);

    uint8_t message[MESSAGE_LEN];
    memset(message, 0xAB, MESSAGE_LEN);

    // Warmup
    for (int i = 0; i < SIG_WARMUP; i++) {
        EVP_PKEY *kp = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        if (kp) EVP_PKEY_free(kp);
    }

    // Keypair generation
    for (int i = 0; i < SIG_ITERATIONS; i++) {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        EVP_PKEY *kp = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        clock_gettime(CLOCK_MONOTONIC, &t2);
        keypair_times[i] = elapsed_us(t1, t2);
        if (i < SIG_ITERATIONS - 1) EVP_PKEY_free(kp);
        else {
            // Keep the last keypair for sign/verify timing below
            // Sign
            uint8_t sig_buf[256];
            size_t  sig_len = sizeof(sig_buf);

            for (int j = 0; j < SIG_ITERATIONS; j++) {
                struct timespec ts1, ts2;
                EVP_MD_CTX *mctx = EVP_MD_CTX_new();
                EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, kp);

                sig_len = sizeof(sig_buf);
                clock_gettime(CLOCK_MONOTONIC, &ts1);
                EVP_DigestSign(mctx, sig_buf, &sig_len, message, MESSAGE_LEN);
                clock_gettime(CLOCK_MONOTONIC, &ts2);
                sign_times[j] = elapsed_us(ts1, ts2);
                EVP_MD_CTX_free(mctx);
            }

            // Verify (using the last signature produced above)
            for (int j = 0; j < SIG_ITERATIONS; j++) {
                struct timespec tv1, tv2;
                EVP_MD_CTX *mctx = EVP_MD_CTX_new();
                EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, kp);

                clock_gettime(CLOCK_MONOTONIC, &tv1);
                EVP_DigestVerify(mctx, sig_buf, sig_len, message, MESSAGE_LEN);
                clock_gettime(CLOCK_MONOTONIC, &tv2);
                verify_times[j] = elapsed_us(tv1, tv2);
                EVP_MD_CTX_free(mctx);
            }

            EVP_PKEY_free(kp);
        }
    }

    bench_compute_stats(keypair_times, SIG_ITERATIONS, keypair_r);
    bench_compute_stats(sign_times,     SIG_ITERATIONS, sign_r);
    bench_compute_stats(verify_times,   SIG_ITERATIONS, verify_r);

    strncpy(keypair_r->label, "ECDSA-P256 Keypair", BENCH_LABEL_LEN - 1);
    strncpy(sign_r->label,    "ECDSA-P256 Sign",     BENCH_LABEL_LEN - 1);
    strncpy(verify_r->label,  "ECDSA-P256 Verify",   BENCH_LABEL_LEN - 1);

    keypair_r->data_size = 32;    // P-256 private key size
    sign_r->data_size     = 72;   // typical DER-encoded ECDSA signature
    verify_r->data_size   = 65;   // uncompressed P-256 public key

    free(keypair_times); free(sign_times); free(verify_times);
}

// ============================================================================
// PUBLIC ENTRY POINT
// ============================================================================

void run_sig_benchmark(bench_suite_t *suite) {
    bench_print_header("Signature Benchmark: ML-DSA-65 vs ECDSA P-256");

    bench_results_t mldsa_keypair, mldsa_sign, mldsa_verify;
    bench_results_t ecdsa_keypair, ecdsa_sign, ecdsa_verify;

    bench_mldsa65(&mldsa_keypair, &mldsa_sign, &mldsa_verify);
    bench_ecdsa_p256(&ecdsa_keypair, &ecdsa_sign, &ecdsa_verify);

    bench_suite_add(suite, &mldsa_keypair);
    bench_suite_add(suite, &mldsa_sign);
    bench_suite_add(suite, &mldsa_verify);
    bench_suite_add(suite, &ecdsa_keypair);
    bench_suite_add(suite, &ecdsa_sign);
    bench_suite_add(suite, &ecdsa_verify);

    printf("\n");
    bench_print_result(&mldsa_keypair);
    bench_print_result(&mldsa_sign);
    bench_print_result(&mldsa_verify);
    bench_print_result(&ecdsa_keypair);
    bench_print_result(&ecdsa_sign);
    bench_print_result(&ecdsa_verify);

    printf("\n  ── Summary ─────────────────────────────────────────\n");
    printf("  ML-DSA-65  sign+verify : %8.2f µs\n",
           mldsa_sign.mean_us + mldsa_verify.mean_us);
    printf("  ECDSA-P256 sign+verify : %8.2f µs\n",
           ecdsa_sign.mean_us + ecdsa_verify.mean_us);
    printf("  Overhead factor        : %6.2fx\n",
           (mldsa_sign.mean_us + mldsa_verify.mean_us) /
           (ecdsa_sign.mean_us + ecdsa_verify.mean_us));
    printf("  Signature size : ML-DSA-65 3309 B  vs  ECDSA-P256 ~72 B "
           "(%.0fx larger)\n", 3309.0 / 72.0);
    printf("  Public key size: ML-DSA-65 1952 B  vs  ECDSA-P256 65 B "
           "(%.0fx larger)\n", 1952.0 / 65.0);
}
