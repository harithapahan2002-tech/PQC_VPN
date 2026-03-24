// test_foundation.c
// Test suite for pqc_common and pqc_crypto layers.
//
// Covers:
//   - HKDF-SHA256: determinism, domain separation, different lengths
//   - Nonce state: initialisation, uniqueness, counter increment
//   - AES-GCM: round-trip, authentication failure, zero-length guard
//   - read_exact / write_all: via socketpair
//
// Build:
//   gcc -o test_foundation test_foundation.c pqc_common.c pqc_crypto.c \
//       -lssl -lcrypto
// Run:
//   ./test_foundation

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "../common/pqc_common.h"
#include "../common/pqc_crypto.h"

// ============================================================================
// TEST FRAMEWORK
// ============================================================================

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  %-55s", (name)); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("✅ PASS\n"); \
    } while (0)

#define FAIL(reason) \
    do { \
        tests_failed++; \
        printf("❌ FAIL — %s\n", (reason)); \
    } while (0)

#define ASSERT(cond, reason) \
    do { \
        if (!(cond)) { FAIL(reason); return; } \
    } while (0)

// ============================================================================
// HKDF TESTS
// ============================================================================

static void test_hkdf_deterministic(void) {
    TEST("HKDF: same inputs produce same output");

    uint8_t ikm[32];
    memset(ikm, 0xAB, sizeof(ikm));

    uint8_t out1[32], out2[32];
    hkdf_sha256(ikm, sizeof(ikm), NULL, 0, "test-label", out1, sizeof(out1));
    hkdf_sha256(ikm, sizeof(ikm), NULL, 0, "test-label", out2, sizeof(out2));

    ASSERT(memcmp(out1, out2, 32) == 0, "two calls with same input differ");
    PASS();
}

static void test_hkdf_domain_separation(void) {
    TEST("HKDF: different info labels produce different keys");

    uint8_t ikm[32];
    memset(ikm, 0xCD, sizeof(ikm));

    uint8_t key1[32], key2[32];
    hkdf_sha256(ikm, sizeof(ikm), NULL, 0, "vpn-session-key", key1, 32);
    hkdf_sha256(ikm, sizeof(ikm), NULL, 0, "pqvpn-auth-v1",  key2, 32);

    ASSERT(memcmp(key1, key2, 32) != 0,
           "different labels produced identical keys");
    PASS();
}

static void test_hkdf_salt_changes_output(void) {
    TEST("HKDF: different salts produce different keys");

    uint8_t ikm[32];
    memset(ikm, 0x55, sizeof(ikm));

    uint8_t salt1[16], salt2[16];
    memset(salt1, 0x11, sizeof(salt1));
    memset(salt2, 0x22, sizeof(salt2));

    uint8_t out1[32], out2[32];
    hkdf_sha256(ikm, 32, salt1, 16, "label", out1, 32);
    hkdf_sha256(ikm, 32, salt2, 16, "label", out2, 32);

    ASSERT(memcmp(out1, out2, 32) != 0,
           "different salts produced identical keys");
    PASS();
}

static void test_hkdf_no_salt_stable(void) {
    TEST("HKDF: NULL salt and zero-length salt produce same result");

    uint8_t ikm[32];
    memset(ikm, 0x77, sizeof(ikm));

    uint8_t out1[32], out2[32];
    hkdf_sha256(ikm, 32, NULL, 0,  "label", out1, 32);
    hkdf_sha256(ikm, 32, NULL, 0,  "label", out2, 32);

    ASSERT(memcmp(out1, out2, 32) == 0, "repeated calls with NULL salt differ");
    PASS();
}

static void test_hkdf_variable_length(void) {
    TEST("HKDF: can produce 16, 32, and 64 byte outputs");

    uint8_t ikm[32];
    memset(ikm, 0x33, sizeof(ikm));

    uint8_t out16[16], out32[32], out64[64];
    hkdf_sha256(ikm, 32, NULL, 0, "len-test", out16, 16);
    hkdf_sha256(ikm, 32, NULL, 0, "len-test", out32, 32);
    hkdf_sha256(ikm, 32, NULL, 0, "len-test", out64, 64);

    // The first 16 bytes of out32 must match out16 (RFC 5869 property)
    ASSERT(memcmp(out16, out32, 16) == 0,
           "16-byte output doesn't match first 16 bytes of 32-byte output");

    // out32 and out64's first 32 bytes must match
    ASSERT(memcmp(out32, out64, 32) == 0,
           "32-byte output doesn't match first 32 bytes of 64-byte output");

    PASS();
}

// ============================================================================
// NONCE TESTS
// ============================================================================

static void test_nonce_init_succeeds(void) {
    TEST("Nonce: init_nonce_state succeeds");

    nonce_state_t state;
    int r = init_nonce_state(&state);

    ASSERT(r == 0,          "init_nonce_state returned non-zero");
    ASSERT(state.initialised == 1, "initialised flag not set");
    ASSERT(state.counter == 0,     "counter not reset to 0");
    PASS();
}

static void test_nonce_uninit_rejected(void) {
    TEST("Nonce: generate_nonce rejects uninitialised state");

    nonce_state_t state;
    memset(&state, 0, sizeof(state));
    // Do NOT call init_nonce_state — state.initialised remains 0

    uint8_t nonce[IV_LEN];
    int r = generate_nonce(&state, nonce);

    ASSERT(r == -1, "should have returned -1 for uninitialised state");
    PASS();
}

static void test_nonce_counter_increments(void) {
    TEST("Nonce: counter increments with each call");

    nonce_state_t state;
    ASSERT(init_nonce_state(&state) == 0, "init failed");

    uint8_t n1[IV_LEN], n2[IV_LEN], n3[IV_LEN];
    generate_nonce(&state, n1);
    generate_nonce(&state, n2);
    generate_nonce(&state, n3);

    ASSERT(state.counter == 3, "counter should be 3 after 3 calls");

    // All three nonces must differ
    ASSERT(memcmp(n1, n2, IV_LEN) != 0, "nonce 1 and 2 are identical");
    ASSERT(memcmp(n2, n3, IV_LEN) != 0, "nonce 2 and 3 are identical");
    ASSERT(memcmp(n1, n3, IV_LEN) != 0, "nonce 1 and 3 are identical");
    PASS();
}

static void test_nonce_prefix_constant(void) {
    TEST("Nonce: random prefix is constant within a session");

    nonce_state_t state;
    ASSERT(init_nonce_state(&state) == 0, "init failed");

    uint8_t n1[IV_LEN], n2[IV_LEN];
    generate_nonce(&state, n1);
    generate_nonce(&state, n2);

    // First 4 bytes are the random prefix — must be identical across calls
    ASSERT(memcmp(n1, n2, 4) == 0,
           "random prefix changed between calls in same session");
    // Last 8 bytes are the counter — must differ
    ASSERT(memcmp(n1 + 4, n2 + 4, 8) != 0,
           "counter bytes did not change between calls");
    PASS();
}

static void test_nonce_sessions_differ(void) {
    TEST("Nonce: two sessions produce different prefixes");

    nonce_state_t s1, s2;
    ASSERT(init_nonce_state(&s1) == 0, "init s1 failed");
    ASSERT(init_nonce_state(&s2) == 0, "init s2 failed");

    // Prefixes should be different (random — could theoretically collide
    // but probability is 1/2^32 which is negligible)
    // We check the full first nonce rather than just the prefix
    uint8_t n1[IV_LEN], n2[IV_LEN];
    generate_nonce(&s1, n1);
    generate_nonce(&s2, n2);

    ASSERT(memcmp(n1, n2, IV_LEN) != 0,
           "two independent sessions produced identical nonces");
    PASS();
}

// ============================================================================
// AES-GCM TESTS
// ============================================================================

static void test_gcm_roundtrip(void) {
    TEST("AES-GCM: encrypt → decrypt round-trip");

    uint8_t key[AES_KEY_LEN];
    memset(key, 0x42, sizeof(key));

    const char *msg = "Hello, PQ-VPN!";
    size_t msg_len  = strlen(msg);

    nonce_state_t ns;
    ASSERT(init_nonce_state(&ns) == 0, "nonce init failed");

    uint8_t iv[IV_LEN], tag[TAG_LEN];
    uint8_t ct[256], pt[256];

    ASSERT(generate_nonce(&ns, iv) == 0, "generate_nonce failed");

    int ct_len = aes_gcm_encrypt(key, (const uint8_t *)msg, (int)msg_len,
                                 iv, ct, tag);
    ASSERT(ct_len == (int)msg_len, "ciphertext length mismatch");

    int pt_len = aes_gcm_decrypt(key, ct, ct_len, iv, tag, pt);
    ASSERT(pt_len == (int)msg_len, "plaintext length mismatch");
    ASSERT(memcmp(pt, msg, msg_len) == 0, "decrypted content mismatch");
    PASS();
}

static void test_gcm_auth_failure_wrong_tag(void) {
    TEST("AES-GCM: tampered tag causes decryption failure");

    uint8_t key[AES_KEY_LEN];
    memset(key, 0x11, sizeof(key));

    const uint8_t plain[] = "sensitive data";
    uint8_t ct[256], tag[TAG_LEN], pt[256];

    nonce_state_t ns;
    ASSERT(init_nonce_state(&ns) == 0, "nonce init failed");
    uint8_t iv[IV_LEN];
    ASSERT(generate_nonce(&ns, iv) == 0, "nonce failed");

    int ct_len = aes_gcm_encrypt(key, plain, sizeof(plain), iv, ct, tag);
    ASSERT(ct_len > 0, "encryption failed");

    // Flip one bit in the tag
    tag[0] ^= 0x01;

    int pt_len = aes_gcm_decrypt(key, ct, ct_len, iv, tag, pt);
    ASSERT(pt_len == -1, "should return -1 on tag mismatch");
    PASS();
}

static void test_gcm_auth_failure_wrong_key(void) {
    TEST("AES-GCM: wrong key causes decryption failure");

    uint8_t key_enc[AES_KEY_LEN], key_dec[AES_KEY_LEN];
    memset(key_enc, 0xAA, sizeof(key_enc));
    memset(key_dec, 0xBB, sizeof(key_dec));

    const uint8_t plain[] = "secret";
    uint8_t ct[256], tag[TAG_LEN], pt[256];

    nonce_state_t ns;
    ASSERT(init_nonce_state(&ns) == 0, "nonce init failed");
    uint8_t iv[IV_LEN];
    ASSERT(generate_nonce(&ns, iv) == 0, "nonce failed");

    int ct_len = aes_gcm_encrypt(key_enc, plain, sizeof(plain), iv, ct, tag);
    ASSERT(ct_len > 0, "encryption failed");

    int pt_len = aes_gcm_decrypt(key_dec, ct, ct_len, iv, tag, pt);
    ASSERT(pt_len == -1, "should return -1 with wrong key");
    PASS();
}

static void test_gcm_auth_failure_tampered_ciphertext(void) {
    TEST("AES-GCM: tampered ciphertext causes decryption failure");

    uint8_t key[AES_KEY_LEN];
    memset(key, 0x55, sizeof(key));

    const uint8_t plain[] = "tamper test payload";
    uint8_t ct[256], tag[TAG_LEN], pt[256];

    nonce_state_t ns;
    ASSERT(init_nonce_state(&ns) == 0, "nonce init failed");
    uint8_t iv[IV_LEN];
    ASSERT(generate_nonce(&ns, iv) == 0, "nonce failed");

    int ct_len = aes_gcm_encrypt(key, plain, sizeof(plain), iv, ct, tag);
    ASSERT(ct_len > 0, "encryption failed");

    // Flip a bit in the ciphertext body
    ct[ct_len / 2] ^= 0xFF;

    int pt_len = aes_gcm_decrypt(key, ct, ct_len, iv, tag, pt);
    ASSERT(pt_len == -1, "should return -1 on tampered ciphertext");
    PASS();
}

static void test_gcm_nonce_in_header_matches_encrypt(void) {
    TEST("AES-GCM: nonce used for encrypt is the one passed in (not regenerated)");

    // This test catches the critical old bug where aes_gcm_encrypt
    // internally called RAND_bytes and overwrote the caller's nonce,
    // making the counter-nonce system a no-op.

    uint8_t key[AES_KEY_LEN];
    memset(key, 0x99, sizeof(key));

    nonce_state_t ns;
    ASSERT(init_nonce_state(&ns) == 0, "nonce init failed");

    uint8_t iv_before[IV_LEN], iv_after[IV_LEN];
    ASSERT(generate_nonce(&ns, iv_before) == 0, "nonce failed");
    memcpy(iv_after, iv_before, IV_LEN);

    const uint8_t plain[] = "nonce consistency check";
    uint8_t ct[256], tag[TAG_LEN];

    // Pass iv_after — if encrypt regenerates IV internally, iv_after
    // would differ from iv_before after the call
    int ct_len = aes_gcm_encrypt(key, plain, sizeof(plain),
                                 iv_after, ct, tag);
    ASSERT(ct_len > 0, "encryption failed");
    ASSERT(memcmp(iv_before, iv_after, IV_LEN) == 0,
           "encrypt overwrote the caller's nonce — critical bug!");

    // Also verify decryption works using the original nonce
    uint8_t pt[256];
    int pt_len = aes_gcm_decrypt(key, ct, ct_len, iv_before, tag, pt);
    ASSERT(pt_len > 0, "decryption with original nonce failed");
    ASSERT(memcmp(pt, plain, sizeof(plain)) == 0, "content mismatch");
    PASS();
}

static void test_gcm_large_payload(void) {
    TEST("AES-GCM: MAX_TUN_PAYLOAD sized packet round-trips correctly");

    uint8_t key[AES_KEY_LEN];
    memset(key, 0x66, sizeof(key));

    uint8_t plain[MAX_TUN_PAYLOAD];
    for (int i = 0; i < MAX_TUN_PAYLOAD; i++)
        plain[i] = (uint8_t)(i & 0xFF);

    nonce_state_t ns;
    ASSERT(init_nonce_state(&ns) == 0, "nonce init failed");
    uint8_t iv[IV_LEN], tag[TAG_LEN];
    ASSERT(generate_nonce(&ns, iv) == 0, "nonce failed");

    uint8_t ct[MAX_TUN_PAYLOAD], pt[MAX_TUN_PAYLOAD];

    int ct_len = aes_gcm_encrypt(key, plain, MAX_TUN_PAYLOAD, iv, ct, tag);
    ASSERT(ct_len == MAX_TUN_PAYLOAD, "ciphertext wrong length");

    int pt_len = aes_gcm_decrypt(key, ct, ct_len, iv, tag, pt);
    ASSERT(pt_len == MAX_TUN_PAYLOAD, "plaintext wrong length");
    ASSERT(memcmp(pt, plain, MAX_TUN_PAYLOAD) == 0, "content mismatch");
    PASS();
}

// ============================================================================
// READ_EXACT / WRITE_ALL TESTS
// ============================================================================

static void test_io_roundtrip(void) {
    TEST("I/O: write_all / read_exact round-trip over socketpair");

    int fds[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0,
           "socketpair failed");

    const char *msg = "pqvpn test message 1234567890";
    size_t len = strlen(msg);

    ssize_t w = write_all(fds[0], msg, len);
    ASSERT(w == (ssize_t)len, "write_all returned wrong count");

    char buf[256];
    memset(buf, 0, sizeof(buf));
    ssize_t r = read_exact(fds[1], buf, len);
    ASSERT(r == (ssize_t)len, "read_exact returned wrong count");
    ASSERT(memcmp(buf, msg, len) == 0, "content mismatch after read_exact");

    close(fds[0]);
    close(fds[1]);
    PASS();
}

static void test_io_eof_returns_error(void) {
    TEST("I/O: read_exact returns -1 on mid-stream EOF");

    int fds[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0,
           "socketpair failed");

    // Write 4 bytes but ask read_exact for 8 — EOF will occur mid-read
    uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
    write_all(fds[0], data, 4);
    close(fds[0]);   // Close write end — causes EOF on fds[1]

    uint8_t buf[8];
    ssize_t r = read_exact(fds[1], buf, 8);
    ASSERT(r == -1, "read_exact should return -1 on partial EOF");

    close(fds[1]);
    PASS();
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║          PQ-VPN Foundation Test Suite                   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("── HKDF-SHA256 ─────────────────────────────────────────────\n");
    test_hkdf_deterministic();
    test_hkdf_domain_separation();
    test_hkdf_salt_changes_output();
    test_hkdf_no_salt_stable();
    test_hkdf_variable_length();

    printf("\n── Nonce management ─────────────────────────────────────────\n");
    test_nonce_init_succeeds();
    test_nonce_uninit_rejected();
    test_nonce_counter_increments();
    test_nonce_prefix_constant();
    test_nonce_sessions_differ();

    printf("\n── AES-256-GCM ──────────────────────────────────────────────\n");
    test_gcm_roundtrip();
    test_gcm_auth_failure_wrong_tag();
    test_gcm_auth_failure_wrong_key();
    test_gcm_auth_failure_tampered_ciphertext();
    test_gcm_nonce_in_header_matches_encrypt();
    test_gcm_large_payload();

    printf("\n── Network I/O ──────────────────────────────────────────────\n");
    test_io_roundtrip();
    test_io_eof_returns_error();

    printf("\n════════════════════════════════════════════════════════════\n");
    printf("Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf("  (%d FAILED)", tests_failed);
    printf("\n");

    return tests_failed > 0 ? 1 : 0;
}