// test_auth.c
// Test suite for the PSK authentication layer (pqc_auth).
//
// These tests exercise auth_load_psk and the MAC computation logic
// directly. The full network handshake (auth_server / auth_client)
// requires two processes and a live socket, so that is covered by
// the integration test in test_udp.c rather than here.
//
// Build:
//   gcc -o test_auth test_auth.c pqc_common.c pqc_auth.c \
//       -lssl -lcrypto
// Run:
//   ./test_auth

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/pqc_common.h"
#include "../common/pqc_auth.h"

#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// ============================================================================
// TEST FRAMEWORK  (same pattern as test_foundation.c)
// ============================================================================

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { tests_run++; printf("  %-55s", (name)); } while (0)

#define PASS() \
    do { tests_passed++; printf("✅ PASS\n"); } while (0)

#define FAIL(reason) \
    do { tests_failed++; printf("❌ FAIL — %s\n", (reason)); } while (0)

#define ASSERT(cond, reason) \
    do { if (!(cond)) { FAIL(reason); return; } } while (0)

// ============================================================================
// HELPERS
// ============================================================================

// Write a temporary psk.conf containing the given hex string.
// Returns the filename (static buffer — use immediately).
static const char *write_temp_psk(const char *hex_content) {
    static const char path[] = "/tmp/test_psk_tmp.conf";
    FILE *f = fopen(path, "w");
    if (!f) return NULL;
    fprintf(f, "%s\n", hex_content);
    fclose(f);
    return path;
}

// A valid 64-character hex PSK for testing
static const char *valid_psk_hex =
    "a3f1c2e4b5d6789012345678abcdef01"
    "a3f1c2e4b5d6789012345678abcdef01";

// A different valid PSK
static const char *other_psk_hex =
    "deadbeefcafebabe0102030405060708"
    "090a0b0c0d0e0f101112131415161718";

// ============================================================================
// PSK LOADING TESTS
// ============================================================================

static void test_load_valid_psk(void) {
    TEST("PSK load: valid 64-char hex file loads successfully");

    const char *path = write_temp_psk(valid_psk_hex);
    ASSERT(path != NULL, "could not write temp PSK file");

    auth_context_t ctx;
    int r = auth_load_psk(&ctx, path);

    ASSERT(r == 0,       "auth_load_psk returned non-zero");
    ASSERT(ctx.loaded == 1, "loaded flag not set");

    // Auth key must be non-zero (HKDF of a non-zero PSK is non-zero)
    uint8_t zero[AUTH_KEY_LEN];
    memset(zero, 0, sizeof(zero));
    ASSERT(memcmp(ctx.auth_key, zero, AUTH_KEY_LEN) != 0,
           "auth_key is all zeros after load");

    unlink(path);
    PASS();
}

static void test_load_missing_file(void) {
    TEST("PSK load: missing file returns -1");

    auth_context_t ctx;
    int r = auth_load_psk(&ctx, "/tmp/no_such_file_pqvpn.conf");

    ASSERT(r == -1,      "should return -1 for missing file");
    ASSERT(ctx.loaded == 0, "loaded flag should remain 0");
    PASS();
}

static void test_load_wrong_length(void) {
    TEST("PSK load: wrong length hex string returns -1");

    // 62 chars — one byte short
    const char *path = write_temp_psk(
        "a3f1c2e4b5d6789012345678abcdef01"
        "a3f1c2e4b5d6789012345678abcdef");   // 62 chars

    ASSERT(path != NULL, "could not write temp PSK file");

    auth_context_t ctx;
    int r = auth_load_psk(&ctx, path);

    ASSERT(r == -1, "should return -1 for short PSK");
    ASSERT(ctx.loaded == 0, "loaded flag should remain 0");

    unlink(path);
    PASS();
}

static void test_load_invalid_hex(void) {
    TEST("PSK load: non-hex characters return -1");

    // 64 chars but contains 'z' which is not valid hex
    const char *path = write_temp_psk(
        "a3f1c2e4b5d6789012345678abcdef01"
        "a3f1c2e4b5d678901234567zabcdef0");

    ASSERT(path != NULL, "could not write temp PSK file");

    auth_context_t ctx;
    int r = auth_load_psk(&ctx, path);

    ASSERT(r == -1, "should return -1 for invalid hex");

    unlink(path);
    PASS();
}

static void test_load_deterministic(void) {
    TEST("PSK load: same PSK file always produces same auth_key");

    const char *path = write_temp_psk(valid_psk_hex);
    ASSERT(path != NULL, "could not write temp PSK file");

    auth_context_t ctx1, ctx2;
    ASSERT(auth_load_psk(&ctx1, path) == 0, "first load failed");
    ASSERT(auth_load_psk(&ctx2, path) == 0, "second load failed");

    ASSERT(memcmp(ctx1.auth_key, ctx2.auth_key, AUTH_KEY_LEN) == 0,
           "two loads of same PSK produced different auth keys");

    unlink(path);
    PASS();
}

static void test_load_different_psks_differ(void) {
    TEST("PSK load: different PSKs produce different auth keys");

    const char *path1 = "/tmp/test_psk_a.conf";
    const char *path2 = "/tmp/test_psk_b.conf";

    FILE *f1 = fopen(path1, "w"); fprintf(f1, "%s\n", valid_psk_hex); fclose(f1);
    FILE *f2 = fopen(path2, "w"); fprintf(f2, "%s\n", other_psk_hex); fclose(f2);

    auth_context_t ctx1, ctx2;
    ASSERT(auth_load_psk(&ctx1, path1) == 0, "load ctx1 failed");
    ASSERT(auth_load_psk(&ctx2, path2) == 0, "load ctx2 failed");

    ASSERT(memcmp(ctx1.auth_key, ctx2.auth_key, AUTH_KEY_LEN) != 0,
           "different PSKs produced identical auth keys");

    unlink(path1);
    unlink(path2);
    PASS();
}

// ============================================================================
// AUTH KEY DERIVATION TESTS
// ============================================================================

static void test_auth_key_differs_from_session_key(void) {
    TEST("PSK: auth key (pqvpn-auth-v1) differs from session key label");

    const char *path = write_temp_psk(valid_psk_hex);
    ASSERT(path != NULL, "could not write temp PSK file");

    auth_context_t ctx;
    ASSERT(auth_load_psk(&ctx, path) == 0, "load failed");

    // Derive what a "vpn-session-key" label would produce from the same PSK
    uint8_t raw_psk[PSK_BYTES];
    // Decode the hex PSK manually for comparison
    const char *hex = valid_psk_hex;
    for (int i = 0; i < PSK_BYTES; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%02x", &byte);
        raw_psk[i] = (uint8_t)byte;
    }

    uint8_t session_key[AUTH_KEY_LEN];
    hkdf_sha256(raw_psk, PSK_BYTES, NULL, 0,
                "vpn-session-key", session_key, AUTH_KEY_LEN);

    ASSERT(memcmp(ctx.auth_key, session_key, AUTH_KEY_LEN) != 0,
           "auth key and session key label produced identical keys — "
           "domain separation failure");

    memset(raw_psk,     0, sizeof(raw_psk));
    memset(session_key, 0, sizeof(session_key));
    unlink(path);
    PASS();
}

// ============================================================================
// MAC COMPUTATION TESTS
// ============================================================================
// We test the MAC logic indirectly by verifying that auth keys from
// different PSKs produce different HMAC outputs over the same challenge,
// and that domain prefixes ("server" vs "client") produce different MACs.

static void compute_test_mac(const uint8_t  auth_key[AUTH_KEY_LEN],
                              const char    *prefix,
                              const uint8_t  challenge[CHALLENGE_LEN],
                              uint8_t        mac_out[HMAC_LEN]) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, auth_key, AUTH_KEY_LEN, EVP_sha256(), NULL);
    HMAC_Update(ctx, (const uint8_t *)prefix, strlen(prefix));
    HMAC_Update(ctx, challenge, CHALLENGE_LEN);
    unsigned int len = 0;
    HMAC_Final(ctx, mac_out, &len);
    HMAC_CTX_free(ctx);
}

static void test_mac_domain_separation(void) {
    TEST("MAC: 'server' and 'client' prefixes produce different MACs");

    const char *path = write_temp_psk(valid_psk_hex);
    ASSERT(path != NULL, "could not write temp PSK file");

    auth_context_t ctx;
    ASSERT(auth_load_psk(&ctx, path) == 0, "load failed");

    uint8_t challenge[CHALLENGE_LEN];
    memset(challenge, 0xAB, CHALLENGE_LEN);

    uint8_t mac_server[HMAC_LEN], mac_client[HMAC_LEN];
    compute_test_mac(ctx.auth_key, "server", challenge, mac_server);
    compute_test_mac(ctx.auth_key, "client", challenge, mac_client);

    ASSERT(memcmp(mac_server, mac_client, HMAC_LEN) != 0,
           "server and client MACs are identical — domain separation failure");

    unlink(path);
    PASS();
}

static void test_mac_wrong_key_differs(void) {
    TEST("MAC: different PSK produces different MAC over same challenge");

    const char *path1 = "/tmp/test_mac_a.conf";
    const char *path2 = "/tmp/test_mac_b.conf";

    FILE *f1 = fopen(path1, "w"); fprintf(f1, "%s\n", valid_psk_hex); fclose(f1);
    FILE *f2 = fopen(path2, "w"); fprintf(f2, "%s\n", other_psk_hex); fclose(f2);

    auth_context_t ctx1, ctx2;
    ASSERT(auth_load_psk(&ctx1, path1) == 0, "load ctx1 failed");
    ASSERT(auth_load_psk(&ctx2, path2) == 0, "load ctx2 failed");

    uint8_t challenge[CHALLENGE_LEN];
    memset(challenge, 0x55, CHALLENGE_LEN);

    uint8_t mac1[HMAC_LEN], mac2[HMAC_LEN];
    compute_test_mac(ctx1.auth_key, "server", challenge, mac1);
    compute_test_mac(ctx2.auth_key, "server", challenge, mac2);

    ASSERT(memcmp(mac1, mac2, HMAC_LEN) != 0,
           "different PSKs produced same MAC — auth broken");

    unlink(path1);
    unlink(path2);
    PASS();
}

static void test_mac_different_challenge_differs(void) {
    TEST("MAC: same PSK, different challenge produces different MAC");

    const char *path = write_temp_psk(valid_psk_hex);
    ASSERT(path != NULL, "could not write temp PSK file");

    auth_context_t ctx;
    ASSERT(auth_load_psk(&ctx, path) == 0, "load failed");

    uint8_t ch1[CHALLENGE_LEN], ch2[CHALLENGE_LEN];
    memset(ch1, 0x11, CHALLENGE_LEN);
    memset(ch2, 0x22, CHALLENGE_LEN);

    uint8_t mac1[HMAC_LEN], mac2[HMAC_LEN];
    compute_test_mac(ctx.auth_key, "server", ch1, mac1);
    compute_test_mac(ctx.auth_key, "server", ch2, mac2);

    ASSERT(memcmp(mac1, mac2, HMAC_LEN) != 0,
           "different challenges produced same MAC");

    unlink(path);
    PASS();
}

// ============================================================================
// PSK FILE GENERATION TEST
// ============================================================================

static void test_generate_psk_file(void) {
    TEST("PSK generate: auth_generate_psk_file creates a loadable PSK");

    const char *path = "/tmp/test_generated_psk.conf";
    unlink(path);   // Ensure clean state

    int r = auth_generate_psk_file(path);
    ASSERT(r == 0, "auth_generate_psk_file returned non-zero");

    // Verify the generated file can be loaded
    auth_context_t ctx;
    ASSERT(auth_load_psk(&ctx, path) == 0,
           "generated PSK file failed to load");
    ASSERT(ctx.loaded == 1, "loaded flag not set after loading generated PSK");

    // Two generated files must differ
    const char *path2 = "/tmp/test_generated_psk2.conf";
    ASSERT(auth_generate_psk_file(path2) == 0, "second generate failed");

    auth_context_t ctx2;
    ASSERT(auth_load_psk(&ctx2, path2) == 0, "second generated PSK load failed");

    ASSERT(memcmp(ctx.auth_key, ctx2.auth_key, AUTH_KEY_LEN) != 0,
           "two generated PSK files produced identical auth keys");

    unlink(path);
    unlink(path2);
    PASS();
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║          PQ-VPN Authentication Test Suite               ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("── PSK file loading ─────────────────────────────────────────\n");
    test_load_valid_psk();
    test_load_missing_file();
    test_load_wrong_length();
    test_load_invalid_hex();
    test_load_deterministic();
    test_load_different_psks_differ();

    printf("\n── Auth key derivation ───────────────────────────────────────\n");
    test_auth_key_differs_from_session_key();

    printf("\n── MAC computation ───────────────────────────────────────────\n");
    test_mac_domain_separation();
    test_mac_wrong_key_differs();
    test_mac_different_challenge_differs();

    printf("\n── PSK generation ────────────────────────────────────────────\n");
    test_generate_psk_file();

    printf("\n════════════════════════════════════════════════════════════\n");
    printf("Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf("  (%d FAILED)", tests_failed);
    printf("\n");

    return tests_failed > 0 ? 1 : 0;
}