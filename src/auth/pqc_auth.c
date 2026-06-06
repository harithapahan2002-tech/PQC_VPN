// pqc_auth.c
// PSK mutual authentication implementation.
//
// Depends on: pqc_auth.h, pqc_common.h, OpenSSL (libcrypto)

#define _POSIX_C_SOURCE 200809L

#include "pqc_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

// Decode a lowercase hex string into bytes.
// hex must be exactly hex_len chars (= 2 * out_len).
// Returns 0 on success, -1 on invalid characters.
static int hex_decode(const char *hex, size_t hex_len,
                      uint8_t *out, size_t out_len) {
    if (hex_len != out_len * 2) return -1;

    for (size_t i = 0; i < out_len; i++) {
        uint8_t hi, lo;
        char h = hex[i * 2];
        char l = hex[i * 2 + 1];

        if      (h >= '0' && h <= '9') hi = (uint8_t)(h - '0');
        else if (h >= 'a' && h <= 'f') hi = (uint8_t)(h - 'a' + 10);
        else if (h >= 'A' && h <= 'F') hi = (uint8_t)(h - 'A' + 10);
        else return -1;

        if      (l >= '0' && l <= '9') lo = (uint8_t)(l - '0');
        else if (l >= 'a' && l <= 'f') lo = (uint8_t)(l - 'a' + 10);
        else if (l >= 'A' && l <= 'F') lo = (uint8_t)(l - 'A' + 10);
        else return -1;

        out[i] = (hi << 4) | lo;
    }
    return 0;
}

// Encode bytes as a lowercase hex string.
// out must be at least in_len * 2 + 1 bytes.
static void hex_encode(const uint8_t *in, size_t in_len, char *out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hex_chars[in[i] >> 4];
        out[i * 2 + 1] = hex_chars[in[i] & 0x0f];
    }
    out[in_len * 2] = '\0';
}

// Compute HMAC-SHA256(key, domain_prefix || data).
// domain_prefix provides separation between server and client MACs,
// preventing the server's response from being replayed as the client's.
static int compute_mac(const uint8_t  auth_key[AUTH_KEY_LEN],
                       const char    *domain_prefix,
                       const uint8_t *data, size_t data_len,
                       uint8_t        mac_out[HMAC_LEN]) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) return -1;

    int ok = 1;
    unsigned int mac_len = 0;

    ok &= HMAC_Init_ex(ctx, auth_key, AUTH_KEY_LEN, EVP_sha256(), NULL);
    ok &= HMAC_Update(ctx, (const uint8_t *)domain_prefix,
                      strlen(domain_prefix));
    ok &= HMAC_Update(ctx, data, data_len);
    ok &= HMAC_Final(ctx, mac_out, &mac_len);

    HMAC_CTX_free(ctx);

    if (!ok || mac_len != HMAC_LEN) return -1;
    return 0;
}

// Constant-time comparison for MACs — prevents timing side-channel attacks
// where an attacker measures how long the comparison takes to determine
// how many bytes of a forged MAC are correct.
static int mac_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}

// Send a fixed-size buffer as a single UDP datagram.
static int udp_send(int sock, const void *data, size_t len,
                    const struct sockaddr_in *dest) {
    ssize_t s = sendto(sock, data, len, 0,
                       (const struct sockaddr *)dest, sizeof(*dest));
    return (s == (ssize_t)len) ? 0 : -1;
}

// Receive exactly expected_len bytes from sock into buf, with timeout.
// Also populates src_addr if non-NULL.
// Returns 0 on success, -1 on timeout or error.
static int udp_recv_exact(int sock, void *buf, size_t expected_len,
                          struct sockaddr_in *src_addr, int timeout_ms) {
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    int r = poll(&pfd, 1, timeout_ms);

    if (r <= 0) {
        if (r == 0)
            fprintf(stderr, "❌ Auth timeout waiting for peer\n");
        return -1;
    }

    socklen_t src_len = sizeof(*src_addr);
    struct sockaddr_in tmp;
    struct sockaddr_in *sptr = src_addr ? src_addr : &tmp;

    ssize_t n = recvfrom(sock, buf, expected_len, 0,
                         (struct sockaddr *)sptr, &src_len);

    if (n != (ssize_t)expected_len) {
        fprintf(stderr, "❌ Auth: unexpected datagram size "
                        "(got %zd, expected %zu)\n", n, expected_len);
        return -1;
    }
    return 0;
}

// ============================================================================
// PSK LOADING
// ============================================================================

int auth_load_psk(auth_context_t *ctx, const char *psk_path) {
    memset(ctx, 0, sizeof(*ctx));

    FILE *f = fopen(psk_path, "r");
    if (!f) {
        fprintf(stderr, "❌ Cannot open PSK file '%s': %s\n",
                psk_path, strerror(errno));
        fprintf(stderr,
                "   Run: ./bin/gen_psk to generate a new psk.conf\n");
        return -1;
    }

    // Read exactly PSK_HEX_LEN hex characters from the first line
    char line[PSK_HEX_LEN + 4];   // +4 for newline, CR, null, safety
    if (!fgets(line, sizeof(line), f)) {
        fprintf(stderr, "❌ PSK file '%s' is empty\n", psk_path);
        fclose(f);
        return -1;
    }
    fclose(f);

    // Strip trailing newline / carriage return
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
        line[--len] = '\0';

    if (len != PSK_HEX_LEN) {
        fprintf(stderr, "❌ PSK file must contain exactly %d hex characters "
                        "(got %zu)\n", PSK_HEX_LEN, len);
        return -1;
    }

    // Decode hex → raw PSK bytes
    uint8_t raw_psk[PSK_BYTES];
    if (hex_decode(line, PSK_HEX_LEN, raw_psk, PSK_BYTES) != 0) {
        fprintf(stderr, "❌ PSK file contains non-hex characters\n");
        memset(raw_psk, 0, sizeof(raw_psk));
        return -1;
    }

    // Derive auth key from raw PSK via HKDF.
    // Using a fixed info label "pqvpn-auth-v1" domain-separates this key
    // from any session keys derived from the KEM shared secret, even if
    // the same PSK were somehow used as IKM there too.
    hkdf_sha256(raw_psk, PSK_BYTES,
                NULL, 0,
                "pqvpn-auth-v1",
                ctx->auth_key, AUTH_KEY_LEN);

    // Zero the raw PSK — we only keep the derived auth key
    memset(raw_psk, 0, sizeof(raw_psk));
    memset(line,    0, sizeof(line));

    ctx->loaded = 1;
    return 0;
}

// ============================================================================
// SERVER-SIDE HANDSHAKE
// ============================================================================

int auth_server(const auth_context_t *ctx,
                int                   udp_sock,
                struct sockaddr_in   *client_addr) {

    if (!ctx->loaded) {
        fprintf(stderr, "❌ auth_server: PSK not loaded\n");
        return -1;
    }

    printf("🔑 Auth: waiting for client challenge...\n");

    // ------------------------------------------------------------------
    // Step 1: Receive client_challenge (32 bytes)
    //
    // Loop until we receive a packet of exactly CHALLENGE_LEN bytes or
    // the timeout expires. This skips stale tunnel packets left in the
    // socket buffer from a previous session — they are larger than 32
    // bytes and can be safely discarded here.
    // ------------------------------------------------------------------
    uint8_t client_challenge[CHALLENGE_LEN];
    uint8_t discard_buf[UDP_RECV_BUFSIZE];
    int     got_challenge = 0;
    struct  timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += AUTH_TIMEOUT_MS / 1000;

    while (!got_challenge) {
        // Check if we've exceeded the overall timeout
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int remaining_ms = (int)((deadline.tv_sec  - now.tv_sec)  * 1000 +
                                 (deadline.tv_nsec - now.tv_nsec) / 1000000);
        if (remaining_ms <= 0) break;

        // Poll with remaining time
        struct pollfd pfd = { .fd = udp_sock, .events = POLLIN };
        int r = poll(&pfd, 1, remaining_ms);
        if (r <= 0) break;

        // Peek at the packet size before committing
        struct sockaddr_in src;
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(udp_sock, discard_buf, sizeof(discard_buf), 0,
                             (struct sockaddr *)&src, &src_len);
        if (n < 0) break;

        if (n == CHALLENGE_LEN) {
            // Right size — this is the client challenge
            memcpy(client_challenge, discard_buf, CHALLENGE_LEN);
            *client_addr = src;
            got_challenge = 1;
        } else {
            // Wrong size — stale packet, discard silently
            fprintf(stderr, "   🧹 Skipped %zd-byte stale packet during "
                            "auth wait\n", n);
        }
    }

    if (!got_challenge) {
        fprintf(stderr, "❌ Auth timeout waiting for peer\n");
        fprintf(stderr, "❌ Auth: failed to receive client challenge\n");
        return -1;
    }

    printf("   ✅ Received client challenge from %s:%d\n",
           inet_ntoa(client_addr->sin_addr),
           ntohs(client_addr->sin_port));

    // ------------------------------------------------------------------
    // Step 2: Compute server_mac = HMAC(auth_key, "server" || client_challenge)
    // ------------------------------------------------------------------
    uint8_t server_mac[HMAC_LEN];
    if (compute_mac(ctx->auth_key, "server",
                    client_challenge, CHALLENGE_LEN, server_mac) != 0) {
        fprintf(stderr, "❌ Auth: MAC computation failed\n");
        return -1;
    }

    // ------------------------------------------------------------------
    // Step 3: Generate server_challenge (32 bytes random)
    // ------------------------------------------------------------------
    uint8_t server_challenge[CHALLENGE_LEN];
    if (RAND_bytes(server_challenge, CHALLENGE_LEN) != 1) {
        fprintf(stderr, "❌ Auth: RAND_bytes failed for server challenge\n");
        return -1;
    }

    // ------------------------------------------------------------------
    // Step 4: Send server_mac || server_challenge  (64 bytes total)
    // ------------------------------------------------------------------
    uint8_t response[HMAC_LEN + CHALLENGE_LEN];
    memcpy(response,             server_mac,       HMAC_LEN);
    memcpy(response + HMAC_LEN,  server_challenge, CHALLENGE_LEN);

    if (udp_send(udp_sock, response, sizeof(response), client_addr) != 0) {
        fprintf(stderr, "❌ Auth: failed to send server response\n");
        return -1;
    }
    printf("   ✅ Sent server MAC + challenge\n");

    // ------------------------------------------------------------------
    // Step 5: Receive client_mac (32 bytes)
    // ------------------------------------------------------------------
    uint8_t received_client_mac[HMAC_LEN];
    struct sockaddr_in from_addr;

    if (udp_recv_exact(udp_sock, received_client_mac, HMAC_LEN,
                       &from_addr, AUTH_TIMEOUT_MS) != 0) {
        fprintf(stderr, "❌ Auth: failed to receive client MAC\n");
        return -1;
    }

    // Verify the response came from the same client address
    if (from_addr.sin_addr.s_addr != client_addr->sin_addr.s_addr ||
        from_addr.sin_port        != client_addr->sin_port) {
        fprintf(stderr, "❌ Auth: client MAC arrived from unexpected address\n");
        return -1;
    }

    // ------------------------------------------------------------------
    // Step 6: Verify client_mac == HMAC(auth_key, "client" || server_challenge)
    // ------------------------------------------------------------------
    uint8_t expected_client_mac[HMAC_LEN];
    if (compute_mac(ctx->auth_key, "client",
                    server_challenge, CHALLENGE_LEN,
                    expected_client_mac) != 0) {
        fprintf(stderr, "❌ Auth: MAC computation failed\n");
        return -1;
    }

    if (!mac_equal(received_client_mac, expected_client_mac, HMAC_LEN)) {
        fprintf(stderr, "❌ Auth: client MAC verification FAILED — "
                        "wrong PSK or replay attack\n");
        // Zero sensitive values before returning
        memset(expected_client_mac, 0, HMAC_LEN);
        memset(server_challenge,    0, CHALLENGE_LEN);
        return -1;
    }

    // Zero sensitive values after use
    memset(expected_client_mac, 0, HMAC_LEN);
    memset(server_challenge,    0, CHALLENGE_LEN);
    memset(client_challenge,    0, CHALLENGE_LEN);
    memset(server_mac,          0, HMAC_LEN);

    printf("   ✅ Client authenticated successfully\n");
    return 0;
}

// ============================================================================
// CLIENT-SIDE HANDSHAKE
// ============================================================================

int auth_client(const auth_context_t     *ctx,
                int                       udp_sock,
                const struct sockaddr_in *server_addr) {

    if (!ctx->loaded) {
        fprintf(stderr, "❌ auth_client: PSK not loaded\n");
        return -1;
    }

    printf("🔑 Auth: starting mutual authentication...\n");

    // ------------------------------------------------------------------
    // Step 1: Generate and send client_challenge (32 bytes)
    // ------------------------------------------------------------------
    uint8_t client_challenge[CHALLENGE_LEN];
    if (RAND_bytes(client_challenge, CHALLENGE_LEN) != 1) {
        fprintf(stderr, "❌ Auth: RAND_bytes failed for client challenge\n");
        return -1;
    }

    if (udp_send(udp_sock, client_challenge, CHALLENGE_LEN,
                 server_addr) != 0) {
        fprintf(stderr, "❌ Auth: failed to send client challenge\n");
        return -1;
    }
    printf("   ✅ Sent client challenge\n");

    // ------------------------------------------------------------------
    // Step 2: Receive server_mac || server_challenge (64 bytes)
    // ------------------------------------------------------------------
    uint8_t server_response[HMAC_LEN + CHALLENGE_LEN];
    struct sockaddr_in from_addr;

    if (udp_recv_exact(udp_sock, server_response, sizeof(server_response),
                       &from_addr, AUTH_TIMEOUT_MS) != 0) {
        fprintf(stderr, "❌ Auth: failed to receive server response\n");
        return -1;
    }

    const uint8_t *received_server_mac  = server_response;
    const uint8_t *server_challenge     = server_response + HMAC_LEN;

    // ------------------------------------------------------------------
    // Step 3: Verify server_mac == HMAC(auth_key, "server" || client_challenge)
    // ------------------------------------------------------------------
    uint8_t expected_server_mac[HMAC_LEN];
    if (compute_mac(ctx->auth_key, "server",
                    client_challenge, CHALLENGE_LEN,
                    expected_server_mac) != 0) {
        fprintf(stderr, "❌ Auth: MAC computation failed\n");
        return -1;
    }

    if (!mac_equal(received_server_mac, expected_server_mac, HMAC_LEN)) {
        fprintf(stderr, "❌ Auth: server MAC verification FAILED — "
                        "wrong PSK, wrong server, or MITM attack\n");
        memset(expected_server_mac, 0, HMAC_LEN);
        memset(client_challenge,    0, CHALLENGE_LEN);
        return -1;
    }

    printf("   ✅ Server authenticated successfully\n");
    memset(expected_server_mac, 0, HMAC_LEN);

    // ------------------------------------------------------------------
    // Step 4: Compute and send client_mac =
    //         HMAC(auth_key, "client" || server_challenge)
    // ------------------------------------------------------------------
    uint8_t client_mac[HMAC_LEN];
    if (compute_mac(ctx->auth_key, "client",
                    server_challenge, CHALLENGE_LEN, client_mac) != 0) {
        fprintf(stderr, "❌ Auth: MAC computation failed\n");
        return -1;
    }

    if (udp_send(udp_sock, client_mac, HMAC_LEN, server_addr) != 0) {
        fprintf(stderr, "❌ Auth: failed to send client MAC\n");
        memset(client_mac, 0, HMAC_LEN);
        return -1;
    }

    memset(client_mac,       0, HMAC_LEN);
    memset(client_challenge, 0, CHALLENGE_LEN);

    printf("   ✅ Mutual authentication complete\n");
    return 0;
}

// ============================================================================
// PSK FILE GENERATION UTILITY
// ============================================================================

int auth_generate_psk_file(const char *psk_path) {
    uint8_t raw[PSK_BYTES];

    if (RAND_bytes(raw, PSK_BYTES) != 1) {
        fprintf(stderr, "❌ RAND_bytes failed — cannot generate PSK\n");
        return -1;
    }

    char hex[PSK_HEX_LEN + 1];
    hex_encode(raw, PSK_BYTES, hex);
    memset(raw, 0, sizeof(raw));

    FILE *f = fopen(psk_path, "w");
    if (!f) {
        fprintf(stderr, "❌ Cannot write PSK file '%s': %s\n",
                psk_path, strerror(errno));
        memset(hex, 0, sizeof(hex));
        return -1;
    }

    fprintf(f, "%s\n", hex);
    fclose(f);
    memset(hex, 0, sizeof(hex));

    printf("✅ PSK written to '%s' — copy this file to both peers before "
           "starting the VPN\n", psk_path);
    return 0;
}