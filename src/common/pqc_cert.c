// pqc_cert.c
// ML-DSA-65 certificate implementation (NIST FIPS 204).
//
// Depends on: pqc_cert.h, pqc_common.h, liboqs, OpenSSL (for SHA-256)

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "pqc_cert.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

// Write exactly len bytes to a file.
// Returns 0 on success, -1 on failure.
static int write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "❌ cert: cannot open '%s' for writing: %s\n",
                path, strerror(errno));
        return -1;
    }
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    if (written != len) {
        fprintf(stderr, "❌ cert: short write to '%s'\n", path);
        return -1;
    }
    return 0;
}

// Read exactly expected_len bytes from a file.
// Returns 0 on success, -1 on failure.
static int read_file(const char *path, void *buf, size_t expected_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "❌ cert: cannot open '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    size_t n = fread(buf, 1, expected_len, f);
    fclose(f);

    if (n != expected_len) {
        fprintf(stderr, "❌ cert: '%s' wrong size (got %zu, expected %zu)\n",
                path, n, expected_len);
        return -1;
    }
    return 0;
}

// Get a new OQS_SIG context for ML-DSA-65.
// Caller must call OQS_SIG_free() when done.
static OQS_SIG *get_sig(void) {
    OQS_SIG *sig = OQS_SIG_new(CERT_ALG);
    if (!sig)
        fprintf(stderr, "❌ cert: OQS_SIG_new(%s) failed — "
                        "is liboqs built with ML-DSA support?\n", CERT_ALG);
    return sig;
}

// Print a short hex fingerprint (first 8 bytes of SHA-256 of the public key).
// Used in cert_print() for human-readable key identification.
static void print_fingerprint(const uint8_t *pubkey, size_t len) {
    uint8_t digest[32];
    unsigned int dlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, pubkey, len);
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);

    printf("   Fingerprint : ");
    for (int i = 0; i < 8; i++) printf("%02x", digest[i]);
    printf("...\n");
}

// ============================================================================
// CA OPERATIONS
// ============================================================================

int cert_generate_ca(void) {
    printf("🔑 Generating CA keypair (%s)...\n", CERT_ALG);

    OQS_SIG *sig = get_sig();
    if (!sig) return -1;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);

    if (!pk || !sk) {
        fprintf(stderr, "❌ cert: alloc failed\n");
        OQS_SIG_free(sig);
        free(pk); free(sk);
        return -1;
    }

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "❌ cert: keypair generation failed\n");
        goto ca_error;
    }

    printf("   ✅ Keypair generated\n");
    printf("   Public key  : %zu bytes\n", sig->length_public_key);
    printf("   Private key : %zu bytes\n", sig->length_secret_key);

    // Write CA private key
    if (write_file(CA_KEY_PATH, sk, sig->length_secret_key) != 0)
        goto ca_error;
    printf("   ✅ CA private key → %s  (keep secret!)\n", CA_KEY_PATH);

    // Write CA public key
    if (write_file(CA_CERT_PATH, pk, sig->length_public_key) != 0)
        goto ca_error;
    printf("   ✅ CA public key  → %s  (distribute to all peers)\n",
           CA_CERT_PATH);

    // Zero private key before freeing
    memset(sk, 0, sig->length_secret_key);
    free(pk); free(sk);
    OQS_SIG_free(sig);

    printf("\n⚠️  Keep %s secret — it can sign certificates for any identity.\n",
           CA_KEY_PATH);
    printf("   Copy %s to both server and client.\n\n", CA_CERT_PATH);
    return 0;

ca_error:
    memset(sk, 0, sig->length_secret_key);
    free(pk); free(sk);
    OQS_SIG_free(sig);
    return -1;
}

int cert_load_ca_pubkey(uint8_t ca_pubkey[CERT_PUBKEY_LEN]) {
    return read_file(CA_CERT_PATH, ca_pubkey, CERT_PUBKEY_LEN);
}

// ============================================================================
// CERTIFICATE ISSUANCE
// ============================================================================

int cert_issue(const char *identity,
               const char *cert_out_path,
               const char *key_out_path) {

    if (!identity || strlen(identity) == 0 ||
        strlen(identity) >= CERT_IDENTITY_LEN) {
        fprintf(stderr, "❌ cert: identity must be 1-%d characters\n",
                CERT_IDENTITY_LEN - 1);
        return -1;
    }

    printf("📜 Issuing certificate for '%s'...\n", identity);

    OQS_SIG *sig = get_sig();
    if (!sig) return -1;

    // Allocate buffers
    uint8_t *entity_pk = malloc(sig->length_public_key);
    uint8_t *entity_sk = malloc(sig->length_secret_key);
    uint8_t *ca_sk     = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    if (!entity_pk || !entity_sk || !ca_sk || !signature) {
        fprintf(stderr, "❌ cert: alloc failed\n");
        goto issue_error;
    }

    // Generate keypair for this entity
    printf("1️⃣  Generating entity keypair...\n");
    if (OQS_SIG_keypair(sig, entity_pk, entity_sk) != OQS_SUCCESS) {
        fprintf(stderr, "❌ cert: entity keypair generation failed\n");
        goto issue_error;
    }
    printf("   ✅ Keypair generated\n");

    // Load CA private key for signing
    printf("2️⃣  Loading CA private key from '%s'...\n", CA_KEY_PATH);
    if (read_file(CA_KEY_PATH, ca_sk, sig->length_secret_key) != 0)
        goto issue_error;
    printf("   ✅ CA key loaded\n");

    // Build the to-be-signed certificate (all fields except signature)
    pqc_cert_t cert;
    memset(&cert, 0, sizeof(cert));

    strncpy(cert.identity, identity, CERT_IDENTITY_LEN - 1);

    memcpy(cert.public_key, entity_pk, CERT_PUBKEY_LEN);

    // Timestamps in network byte order (big-endian)
    time_t now = time(NULL);
    uint64_t issued_be  = htobe64((uint64_t)now);
    uint64_t expires_be = htobe64((uint64_t)(now + CERT_VALIDITY_SEC));
    memcpy(&cert.issued_at,  &issued_be,  8);
    memcpy(&cert.expires_at, &expires_be, 8);

    // Sign the TBS region:  identity + public_key + issued_at + expires_at
    // The signature field in cert is NOT included.
    printf("3️⃣  Signing certificate with CA key...\n");
    size_t sig_len = 0;

    if (OQS_SIG_sign(sig,
                     cert.signature, &sig_len,
                     (const uint8_t *)&cert, CERT_TBS_SIZE,
                     ca_sk) != OQS_SUCCESS) {
        fprintf(stderr, "❌ cert: signing failed\n");
        goto issue_error;
    }

    if (sig_len != CERT_SIG_LEN) {
        fprintf(stderr, "❌ cert: unexpected signature length "
                        "(got %zu, expected %d)\n", sig_len, CERT_SIG_LEN);
        goto issue_error;
    }
    printf("   ✅ Signed (%zu bytes)\n", sig_len);

    // Zero CA private key immediately — no longer needed
    memset(ca_sk, 0, sig->length_secret_key);

    // Write certificate
    printf("4️⃣  Writing certificate and private key...\n");
    if (write_file(cert_out_path, &cert, sizeof(cert)) != 0)
        goto issue_error;
    printf("   ✅ Certificate → %s\n", cert_out_path);

    // Write entity private key
    if (write_file(key_out_path, entity_sk, sig->length_secret_key) != 0)
        goto issue_error;
    printf("   ✅ Private key  → %s  (keep secret!)\n", key_out_path);

    // Zero entity private key before freeing
    memset(entity_sk, 0, sig->length_secret_key);

    free(entity_pk); free(entity_sk); free(ca_sk); free(signature);
    OQS_SIG_free(sig);

    // Print summary
    printf("\n✅ Certificate issued for '%s'\n", identity);
    cert_print(&cert);
    return 0;

issue_error:
    if (ca_sk)     memset(ca_sk,     0, sig->length_secret_key);
    if (entity_sk) memset(entity_sk, 0, sig->length_secret_key);
    free(entity_pk); free(entity_sk); free(ca_sk); free(signature);
    OQS_SIG_free(sig);
    return -1;
}

// ============================================================================
// CERTIFICATE LOADING AND VERIFICATION
// ============================================================================

int cert_load(const char *cert_path, pqc_cert_t *cert) {
    return read_file(cert_path, cert, sizeof(pqc_cert_t));
}

int cert_load_privkey(const char *key_path,
                      uint8_t privkey[CERT_PRIVKEY_LEN]) {
    return read_file(key_path, privkey, CERT_PRIVKEY_LEN);
}

int cert_verify(const pqc_cert_t         *cert,
                const uint8_t ca_pubkey[CERT_PUBKEY_LEN]) {

    // -----------------------------------------------------------------------
    // Check 1: Expiry
    // Compare current time against expires_at (stored big-endian).
    // Do this first — it's cheap and avoids loading OQS for expired certs.
    // -----------------------------------------------------------------------
    uint64_t expires_be;
    memcpy(&expires_be, &cert->expires_at, 8);
    uint64_t expires_at = be64toh(expires_be);
    uint64_t now        = (uint64_t)time(NULL);

    if (now > expires_at) {
        fprintf(stderr, "❌ cert: certificate for '%s' has expired\n",
                cert->identity);
        return -1;
    }

    // -----------------------------------------------------------------------
    // Check 2: CA signature over TBS region
    // Verify that CA signed (identity + public_key + issued_at + expires_at).
    // -----------------------------------------------------------------------
    OQS_SIG *sig = get_sig();
    if (!sig) return -1;

    int result = OQS_SIG_verify(sig,
                                (const uint8_t *)cert, CERT_TBS_SIZE,
                                cert->signature, CERT_SIG_LEN,
                                ca_pubkey);
    OQS_SIG_free(sig);

    if (result != OQS_SUCCESS) {
        fprintf(stderr, "❌ cert: signature verification FAILED for '%s' — "
                        "invalid certificate or wrong CA\n", cert->identity);
        return -1;
    }

    return 0;
}

// ============================================================================
// HANDSHAKE FUNCTIONS
// ============================================================================

// recv_cert_with_timeout: receive exactly sizeof(pqc_cert_t) bytes.
// Skips packets of wrong size (stale tunnel data, etc.).
// Returns 0 on success, -1 on timeout or error.
static int recv_cert_with_timeout(int                 udp_sock,
                                  pqc_cert_t         *cert_out,
                                  struct sockaddr_in *src_out,
                                  int                 timeout_ms) {
    uint8_t buf[sizeof(pqc_cert_t) + 64];   // +64 safety margin
    struct  timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000;

    while (1) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int remaining = (int)((deadline.tv_sec  - now.tv_sec)  * 1000 +
                              (deadline.tv_nsec - now.tv_nsec) / 1000000);
        if (remaining <= 0) break;

        struct pollfd pfd = { .fd = udp_sock, .events = POLLIN };
        int r = poll(&pfd, 1, remaining);
        if (r <= 0) break;

        struct sockaddr_in src;
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(udp_sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &src_len);
        if (n < 0) break;

        if ((size_t)n == sizeof(pqc_cert_t)) {
            memcpy(cert_out, buf, sizeof(pqc_cert_t));
            if (src_out) *src_out = src;
            return 0;
        }

        // Wrong size — stale packet, skip silently
        fprintf(stderr, "   🧹 Skipped %zd-byte packet during cert exchange\n",
                n);
    }

    fprintf(stderr, "❌ cert: timeout waiting for certificate\n");
    return -1;
}

int cert_handshake_server(const uint8_t      ca_pubkey[CERT_PUBKEY_LEN],
                          const pqc_cert_t   *server_cert,
                          int                 udp_sock,
                          struct sockaddr_in *client_addr) {

    printf("🔑 Cert auth: waiting for client certificate...\n");

    // -----------------------------------------------------------------------
    // Step 1: Receive client certificate
    // -----------------------------------------------------------------------
    pqc_cert_t client_cert;
    memset(&client_cert, 0, sizeof(client_cert));

    if (recv_cert_with_timeout(udp_sock, &client_cert, client_addr,
                               15000) != 0) {
        fprintf(stderr, "❌ cert: failed to receive client certificate\n");
        return -1;
    }

    printf("   ✅ Received certificate from %s:%d (identity: '%s')\n",
           inet_ntoa(client_addr->sin_addr),
           ntohs(client_addr->sin_port),
           client_cert.identity);

    // -----------------------------------------------------------------------
    // Step 2: Verify client certificate against CA
    // -----------------------------------------------------------------------
    if (cert_verify(&client_cert, ca_pubkey) != 0) {
        fprintf(stderr, "❌ cert: client certificate verification failed\n");
        return -1;
    }
    printf("   ✅ Client certificate valid (identity: '%s')\n",
           client_cert.identity);

    // -----------------------------------------------------------------------
    // Step 3: Send server certificate to client
    // -----------------------------------------------------------------------
    ssize_t sent = sendto(udp_sock, server_cert, sizeof(pqc_cert_t), 0,
                          (const struct sockaddr *)client_addr,
                          sizeof(*client_addr));
    if (sent != (ssize_t)sizeof(pqc_cert_t)) {
        fprintf(stderr, "❌ cert: failed to send server certificate\n");
        return -1;
    }
    printf("   ✅ Server certificate sent\n");

    return 0;
}

int cert_handshake_client(const uint8_t            ca_pubkey[CERT_PUBKEY_LEN],
                          const pqc_cert_t         *client_cert,
                          int                       udp_sock,
                          const struct sockaddr_in *server_addr) {

    printf("🔑 Cert auth: sending client certificate...\n");

    // -----------------------------------------------------------------------
    // Step 1: Send client certificate to server
    // -----------------------------------------------------------------------
    ssize_t sent = sendto(udp_sock, client_cert, sizeof(pqc_cert_t), 0,
                          (const struct sockaddr *)server_addr,
                          sizeof(*server_addr));
    if (sent != (ssize_t)sizeof(pqc_cert_t)) {
        fprintf(stderr, "❌ cert: failed to send client certificate\n");
        return -1;
    }
    printf("   ✅ Client certificate sent (identity: '%s')\n",
           client_cert->identity);

    // -----------------------------------------------------------------------
    // Step 2: Receive and verify server certificate
    // -----------------------------------------------------------------------
    pqc_cert_t server_cert;
    memset(&server_cert, 0, sizeof(server_cert));

    if (recv_cert_with_timeout(udp_sock, &server_cert, NULL,
                               15000) != 0) {
        fprintf(stderr, "❌ cert: failed to receive server certificate\n");
        return -1;
    }
    printf("   ✅ Server certificate received (identity: '%s')\n",
           server_cert.identity);

    // -----------------------------------------------------------------------
    // Step 3: Verify server certificate against CA
    // -----------------------------------------------------------------------
    if (cert_verify(&server_cert, ca_pubkey) != 0) {
        fprintf(stderr, "❌ cert: server certificate verification FAILED — "
                        "possible MITM attack or wrong CA\n");
        return -1;
    }
    printf("   ✅ Server certificate valid\n");

    return 0;
}

// ============================================================================
// UTILITY
// ============================================================================

void cert_print(const pqc_cert_t *cert) {
    // Decode timestamps from big-endian
    uint64_t issued_be, expires_be;
    memcpy(&issued_be,  &cert->issued_at,  8);
    memcpy(&expires_be, &cert->expires_at, 8);
    time_t issued  = (time_t)be64toh(issued_be);
    time_t expires = (time_t)be64toh(expires_be);

    char issued_str[32], expires_str[32];
    strftime(issued_str,  sizeof(issued_str),  "%Y-%m-%d %H:%M:%S",
             gmtime(&issued));
    strftime(expires_str, sizeof(expires_str), "%Y-%m-%d %H:%M:%S",
             gmtime(&expires));

    printf("   Identity    : %s\n", cert->identity);
    printf("   Issued      : %s UTC\n", issued_str);
    printf("   Expires     : %s UTC\n", expires_str);
    printf("   Algorithm   : %s\n",     CERT_ALG);
    printf("   Cert size   : %zu bytes\n", sizeof(pqc_cert_t));
    print_fingerprint(cert->public_key, CERT_PUBKEY_LEN);
}

void cert_ca_free(cert_ca_t *ca) {
    memset(ca, 0, sizeof(*ca));
}