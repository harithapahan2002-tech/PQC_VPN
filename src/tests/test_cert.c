#define _GNU_SOURCE
// test_cert.c
// Test suite for pqc_cert — ML-DSA-65 certificate system.
//
// Covers:
//   - CA keypair generation
//   - Certificate issuance and loading
//   - Certificate verification (valid, tampered, expired, wrong CA)
//   - Handshake simulation (server and client exchange)
//
// Build:
//   make test_cert
// Run:
//   ./bin/test_cert

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "../common/pqc_common.h"
#include "../common/pqc_cert.h"

// ============================================================================
// TEST FRAMEWORK
// ============================================================================

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { tests_run++; printf("  %-60s", (name)); } while (0)

#define PASS() \
    do { tests_passed++; printf("✅ PASS\n"); } while (0)

#define FAIL(reason) \
    do { tests_failed++; printf("❌ FAIL — %s\n", (reason)); } while (0)

#define ASSERT(cond, reason) \
    do { if (!(cond)) { FAIL(reason); return; } } while (0)

// ============================================================================
// TEMP FILE PATHS  (cleaned up after each test)
// ============================================================================

#define TEST_CA_KEY    "/tmp/test_ca_key.priv"
#define TEST_CA_CERT   "/tmp/test_ca_cert.pub"
#define TEST_SRV_CERT  "/tmp/test_server_cert.bin"
#define TEST_SRV_KEY   "/tmp/test_server_key.priv"
#define TEST_CLI_CERT  "/tmp/test_client_cert.bin"
#define TEST_CLI_KEY   "/tmp/test_client_key.priv"
#define TEST_CA2_KEY   "/tmp/test_ca2_key.priv"
#define TEST_CA2_CERT  "/tmp/test_ca2_cert.pub"

// Override the file path constants for testing by using direct file ops
// The cert functions use the path constants from pqc_cert.h — we work
// around this by calling the lower-level functions directly with
// test paths, or by symlinking. For simplicity we use the real paths
// in /tmp and call cert_issue / cert_load directly.

static void cleanup_test_files(void) {
    unlink(TEST_CA_KEY);
    unlink(TEST_CA_CERT);
    unlink(TEST_SRV_CERT);
    unlink(TEST_SRV_KEY);
    unlink(TEST_CLI_CERT);
    unlink(TEST_CLI_KEY);
    unlink(TEST_CA2_KEY);
    unlink(TEST_CA2_CERT);
    // Also clean up any files written to working directory by gen functions
    unlink(CA_KEY_PATH);
    unlink(CA_CERT_PATH);
    unlink(SERVER_CERT_PATH);
    unlink(SERVER_KEY_PATH);
    unlink(CLIENT_CERT_PATH);
    unlink(CLIENT_KEY_PATH);
}

// ============================================================================
// CA GENERATION TESTS
// ============================================================================

static void test_ca_generation(void) {
    TEST("CA: cert_generate_ca creates ca_key.priv and ca_cert.pub");

    cleanup_test_files();

    int r = cert_generate_ca();
    ASSERT(r == 0, "cert_generate_ca returned non-zero");

    // Both files must exist and be the right size
    FILE *f;

    f = fopen(CA_KEY_PATH, "rb");
    ASSERT(f != NULL, "ca_key.priv not created");
    fseek(f, 0, SEEK_END);
    long key_size = ftell(f);
    fclose(f);
    ASSERT(key_size == CERT_PRIVKEY_LEN,
           "ca_key.priv wrong size");

    f = fopen(CA_CERT_PATH, "rb");
    ASSERT(f != NULL, "ca_cert.pub not created");
    fseek(f, 0, SEEK_END);
    long pub_size = ftell(f);
    fclose(f);
    ASSERT(pub_size == CERT_PUBKEY_LEN,
           "ca_cert.pub wrong size");

    PASS();
}

static void test_ca_pubkey_load(void) {
    TEST("CA: cert_load_ca_pubkey loads ca_cert.pub correctly");

    uint8_t pubkey[CERT_PUBKEY_LEN];
    int r = cert_load_ca_pubkey(pubkey);
    ASSERT(r == 0, "cert_load_ca_pubkey returned non-zero");

    // Key must be non-zero
    int all_zero = 1;
    for (int i = 0; i < CERT_PUBKEY_LEN; i++)
        if (pubkey[i] != 0) { all_zero = 0; break; }
    ASSERT(!all_zero, "loaded CA public key is all zeros");

    PASS();
}

// ============================================================================
// CERTIFICATE ISSUANCE TESTS
// ============================================================================

static void test_cert_issue_server(void) {
    TEST("Cert: cert_issue creates valid server certificate");

    int r = cert_issue("vpn-server", SERVER_CERT_PATH, SERVER_KEY_PATH);
    ASSERT(r == 0, "cert_issue returned non-zero for server");

    // Certificate file must be exactly sizeof(pqc_cert_t)
    FILE *f = fopen(SERVER_CERT_PATH, "rb");
    ASSERT(f != NULL, "server_cert.bin not created");
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);
    ASSERT((size_t)size == sizeof(pqc_cert_t),
           "server_cert.bin wrong size");

    PASS();
}

static void test_cert_issue_client(void) {
    TEST("Cert: cert_issue creates valid client certificate");

    int r = cert_issue("vpn-client", CLIENT_CERT_PATH, CLIENT_KEY_PATH);
    ASSERT(r == 0, "cert_issue returned non-zero for client");

    FILE *f = fopen(CLIENT_CERT_PATH, "rb");
    ASSERT(f != NULL, "client_cert.bin not created");
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);
    ASSERT((size_t)size == sizeof(pqc_cert_t),
           "client_cert.bin wrong size");

    PASS();
}

static void test_cert_load(void) {
    TEST("Cert: cert_load reads certificate fields correctly");

    pqc_cert_t cert;
    int r = cert_load(SERVER_CERT_PATH, &cert);
    ASSERT(r == 0, "cert_load returned non-zero");

    // Identity must match
    ASSERT(strcmp(cert.identity, "vpn-server") == 0,
           "identity field mismatch");

    // Timestamps must be reasonable
    uint64_t issued_be, expires_be;
    memcpy(&issued_be,  &cert.issued_at,  8);
    memcpy(&expires_be, &cert.expires_at, 8);
    uint64_t issued  = be64toh(issued_be);
    uint64_t expires = be64toh(expires_be);

    time_t now = time(NULL);
    ASSERT(issued  <= (uint64_t)now + 5,  "issued_at is in the future");
    ASSERT(expires >  (uint64_t)now,      "expires_at is already past");
    ASSERT(expires == issued + CERT_VALIDITY_SEC,
           "validity window is wrong");

    // Public key must be non-zero
    int all_zero = 1;
    for (int i = 0; i < CERT_PUBKEY_LEN; i++)
        if (cert.public_key[i] != 0) { all_zero = 0; break; }
    ASSERT(!all_zero, "public key in certificate is all zeros");

    PASS();
}

static void test_two_certs_differ(void) {
    TEST("Cert: two certificates have different public keys");

    pqc_cert_t srv, cli;
    ASSERT(cert_load(SERVER_CERT_PATH, &srv) == 0, "server cert load failed");
    ASSERT(cert_load(CLIENT_CERT_PATH, &cli) == 0, "client cert load failed");

    ASSERT(memcmp(srv.public_key, cli.public_key, CERT_PUBKEY_LEN) != 0,
           "server and client have identical public keys");
    ASSERT(strcmp(srv.identity, cli.identity) != 0,
           "server and client have identical identities");

    PASS();
}

// ============================================================================
// CERTIFICATE VERIFICATION TESTS
// ============================================================================

static void test_verify_valid_cert(void) {
    TEST("Verify: valid certificate passes verification");

    uint8_t ca_pubkey[CERT_PUBKEY_LEN];
    ASSERT(cert_load_ca_pubkey(ca_pubkey) == 0, "CA pubkey load failed");

    pqc_cert_t cert;
    ASSERT(cert_load(SERVER_CERT_PATH, &cert) == 0, "cert load failed");

    int r = cert_verify(&cert, ca_pubkey);
    ASSERT(r == 0, "valid certificate failed verification");

    PASS();
}

static void test_verify_tampered_identity(void) {
    TEST("Verify: tampered identity field fails verification");

    uint8_t ca_pubkey[CERT_PUBKEY_LEN];
    ASSERT(cert_load_ca_pubkey(ca_pubkey) == 0, "CA pubkey load failed");

    pqc_cert_t cert;
    ASSERT(cert_load(SERVER_CERT_PATH, &cert) == 0, "cert load failed");

    // Modify the identity — the CA signature no longer covers this content
    cert.identity[0] ^= 0xFF;

    int r = cert_verify(&cert, ca_pubkey);
    ASSERT(r == -1, "tampered identity should fail verification");

    PASS();
}

static void test_verify_tampered_pubkey(void) {
    TEST("Verify: tampered public key field fails verification");

    uint8_t ca_pubkey[CERT_PUBKEY_LEN];
    ASSERT(cert_load_ca_pubkey(ca_pubkey) == 0, "CA pubkey load failed");

    pqc_cert_t cert;
    ASSERT(cert_load(SERVER_CERT_PATH, &cert) == 0, "cert load failed");

    // Flip a byte in the public key
    cert.public_key[100] ^= 0x01;

    int r = cert_verify(&cert, ca_pubkey);
    ASSERT(r == -1, "tampered public key should fail verification");

    PASS();
}

static void test_verify_tampered_signature(void) {
    TEST("Verify: tampered signature field fails verification");

    uint8_t ca_pubkey[CERT_PUBKEY_LEN];
    ASSERT(cert_load_ca_pubkey(ca_pubkey) == 0, "CA pubkey load failed");

    pqc_cert_t cert;
    ASSERT(cert_load(SERVER_CERT_PATH, &cert) == 0, "cert load failed");

    // Corrupt the signature
    cert.signature[0] ^= 0xFF;
    cert.signature[1] ^= 0xFF;

    int r = cert_verify(&cert, ca_pubkey);
    ASSERT(r == -1, "tampered signature should fail verification");

    PASS();
}

static void test_verify_wrong_ca(void) {
    TEST("Verify: certificate signed by different CA fails verification");

    // Generate a second CA
    // We do this by temporarily swapping the CA paths — save originals,
    // generate new CA, verify with new CA pubkey, then restore.
    // Simpler: just generate a fresh CA pubkey and try to verify with it.

    // Rename existing CA files out of the way
    rename(CA_KEY_PATH,  TEST_CA_KEY);
    rename(CA_CERT_PATH, TEST_CA_CERT);

    // Generate a second CA
    int r = cert_generate_ca();
    ASSERT(r == 0, "second CA generation failed");

    // Load the second CA's public key
    uint8_t ca2_pubkey[CERT_PUBKEY_LEN];
    ASSERT(cert_load_ca_pubkey(ca2_pubkey) == 0, "CA2 pubkey load failed");

    // Restore original CA files
    rename(TEST_CA_KEY,  CA_KEY_PATH);
    rename(TEST_CA_CERT, CA_CERT_PATH);

    // The server cert was signed by CA1 — verifying with CA2 must fail
    pqc_cert_t cert;
    ASSERT(cert_load(SERVER_CERT_PATH, &cert) == 0, "cert load failed");

    int vr = cert_verify(&cert, ca2_pubkey);
    ASSERT(vr == -1, "cert signed by different CA should fail verification");

    PASS();
}

static void test_verify_expired_cert(void) {
    TEST("Verify: expired certificate fails verification");

    uint8_t ca_pubkey[CERT_PUBKEY_LEN];
    ASSERT(cert_load_ca_pubkey(ca_pubkey) == 0, "CA pubkey load failed");

    pqc_cert_t cert;
    ASSERT(cert_load(SERVER_CERT_PATH, &cert) == 0, "cert load failed");

    // Manually set expires_at to the past
    // We need to re-sign this to make it a valid-but-expired cert,
    // OR we just manipulate the timestamp and confirm the expiry check
    // catches it before the signature check.
    // Since cert_verify checks expiry FIRST, we just set the timestamp.
    uint64_t past = htobe64((uint64_t)(time(NULL) - 3600)); // 1 hour ago
    memcpy(&cert.expires_at, &past, 8);

    int r = cert_verify(&cert, ca_pubkey);
    ASSERT(r == -1, "expired certificate should fail verification");

    PASS();
}

static void test_client_cert_also_verifies(void) {
    TEST("Verify: client certificate also passes with same CA");

    uint8_t ca_pubkey[CERT_PUBKEY_LEN];
    ASSERT(cert_load_ca_pubkey(ca_pubkey) == 0, "CA pubkey load failed");

    pqc_cert_t cert;
    ASSERT(cert_load(CLIENT_CERT_PATH, &cert) == 0, "cert load failed");

    int r = cert_verify(&cert, ca_pubkey);
    ASSERT(r == 0, "valid client certificate failed verification");

    PASS();
}

// ============================================================================
// HANDSHAKE SIMULATION
// ============================================================================

// We simulate the cert handshake using a socketpair (two connected sockets).
// This avoids needing a real network and lets us test the handshake
// functions directly without spinning up threads.
//
// However cert_handshake_server and cert_handshake_client both block
// waiting for the peer, so we need two threads.

typedef struct {
    int        sock;
    int        result;
    int        is_server;
    uint8_t    ca_pubkey[CERT_PUBKEY_LEN];
} handshake_arg_t;

static void *run_server_handshake(void *arg) {
    handshake_arg_t *a = (handshake_arg_t *)arg;
    pqc_cert_t server_cert;
    if (cert_load(SERVER_CERT_PATH, &server_cert) != 0) {
        a->result = -1; return NULL;
    }
    struct sockaddr_in client_addr;
    a->result = cert_handshake_server(a->ca_pubkey, &server_cert,
                                      a->sock, &client_addr);
    return NULL;
}

static void *run_client_handshake(void *arg) {
    handshake_arg_t *a = (handshake_arg_t *)arg;
    pqc_cert_t client_cert;
    if (cert_load(CLIENT_CERT_PATH, &client_cert) != 0) {
        a->result = -1; return NULL;
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(15555);
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    a->result = cert_handshake_client(a->ca_pubkey, &client_cert,
                                      a->sock, &server_addr);
    return NULL;
}

static void test_handshake_valid(void) {
    TEST("Handshake: valid mutual cert exchange succeeds");

    uint8_t ca_pubkey[CERT_PUBKEY_LEN];
    ASSERT(cert_load_ca_pubkey(ca_pubkey) == 0, "CA pubkey load failed");

    // Create server UDP socket
    int srv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(srv_sock >= 0, "server socket creation failed");

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family      = AF_INET;
    srv_addr.sin_port        = htons(15555);
    srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int opt = 1;
    setsockopt(srv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    ASSERT(bind(srv_sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == 0,
           "server bind failed");

    // Create client UDP socket
    int cli_sock = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(cli_sock >= 0, "client socket creation failed");

    struct sockaddr_in cli_bind;
    memset(&cli_bind, 0, sizeof(cli_bind));
    cli_bind.sin_family      = AF_INET;
    cli_bind.sin_addr.s_addr = INADDR_ANY;
    cli_bind.sin_port        = 0;
    ASSERT(bind(cli_sock, (struct sockaddr *)&cli_bind, sizeof(cli_bind)) == 0,
           "client bind failed");

    handshake_arg_t srv_arg = { .sock = srv_sock, .result = 0 };
    handshake_arg_t cli_arg = { .sock = cli_sock, .result = 0 };
    memcpy(srv_arg.ca_pubkey, ca_pubkey, CERT_PUBKEY_LEN);
    memcpy(cli_arg.ca_pubkey, ca_pubkey, CERT_PUBKEY_LEN);

    pthread_t srv_thread, cli_thread;
    pthread_create(&srv_thread, NULL, run_server_handshake, &srv_arg);
    pthread_create(&cli_thread, NULL, run_client_handshake, &cli_arg);

    pthread_join(srv_thread, NULL);
    pthread_join(cli_thread, NULL);

    close(srv_sock);
    close(cli_sock);

    ASSERT(srv_arg.result == 0, "server handshake returned non-zero");
    ASSERT(cli_arg.result == 0, "client handshake returned non-zero");

    PASS();
}

// ============================================================================
// CERT PRINT TEST
// ============================================================================

static void test_cert_print(void) {
    TEST("Cert: cert_print runs without crash");

    pqc_cert_t cert;
    ASSERT(cert_load(SERVER_CERT_PATH, &cert) == 0, "cert load failed");

    printf("\n");
    cert_print(&cert);    // Just verify it doesn't crash
    printf("  %-60s", ""); // Re-align for PASS marker

    PASS();
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║          PQ-VPN Certificate Test Suite (ML-DSA-65)         ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Clean slate
    cleanup_test_files();

    printf("── CA generation ────────────────────────────────────────────────\n");
    test_ca_generation();
    test_ca_pubkey_load();

    printf("\n── Certificate issuance ─────────────────────────────────────────\n");
    test_cert_issue_server();
    test_cert_issue_client();
    test_cert_load();
    test_two_certs_differ();

    printf("\n── Certificate verification ─────────────────────────────────────\n");
    test_verify_valid_cert();
    test_verify_tampered_identity();
    test_verify_tampered_pubkey();
    test_verify_tampered_signature();
    test_verify_wrong_ca();
    test_verify_expired_cert();
    test_client_cert_also_verifies();

    printf("\n── Handshake simulation ─────────────────────────────────────────\n");
    test_handshake_valid();

    printf("\n── Utility ──────────────────────────────────────────────────────\n");
    test_cert_print();

    // Clean up temp files
    cleanup_test_files();

    printf("\n════════════════════════════════════════════════════════════════\n");
    printf("Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf("  (%d FAILED)", tests_failed);
    printf("\n");

    return tests_failed > 0 ? 1 : 0;
}