// vpn_server.c
// Post-Quantum VPN Server
// ML-KEM-768 key exchange + PSK mutual authentication + AES-256-GCM tunnel
//
// Handshake sequence:
//   1. PSK mutual authentication  (pqc_auth)
//   2. ML-KEM-768 key exchange    (liboqs)
//   3. HKDF session key derivation
//   4. AES-256-GCM encrypted tunnel with counter nonces + replay protection
//
// Usage:
//   sudo ./bin/vpn_server
//   (psk.conf must exist in the working directory)
//
// Depends on: pqc_common, pqc_crypto, pqc_auth, tun, udp_support, liboqs

// _GNU_SOURCE exposes htobe64/be64toh from <endian.h>, which are glibc
// extensions not available under _POSIX_C_SOURCE alone.
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <arpa/inet.h>
#include <endian.h>

#include <oqs/oqs.h>

#include "../common/pqc_common.h"
#include "../common/pqc_crypto.h"
#include "../common/pqc_auth.h"
#include "tun.h"
#include "udp_support.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define SERVER_TUN_IP   "10.8.0.1"
#define CLIENT_TUN_IP   "10.8.0.2"
#define NETMASK         "255.255.255.0"
#define TUN_NAME        "tun0"

// ============================================================================
// GLOBAL SIGNAL STATE
// ============================================================================

static volatile sig_atomic_t running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

// ============================================================================
// HANDSHAKE
// ============================================================================

// perform_handshake:
//   Runs PSK mutual auth then ML-KEM-768 encapsulation.
//   On success, session_key contains the derived AES-256 key.
//   client_addr is populated with the authenticated client's address.
//
// Returns 0 on success, -1 on failure.
static int perform_handshake(int                 udp_sock,
                             struct sockaddr_in *client_addr,
                             uint8_t             session_key[AES_KEY_LEN],
                             const auth_context_t *auth_ctx) {

    printf("\n🔐 Starting handshake...\n");

    // ------------------------------------------------------------------
    // Phase 1: PSK mutual authentication
    // Must complete before any key material is exchanged. If this fails,
    // the peer does not know the PSK and we abort immediately.
    // ------------------------------------------------------------------
    printf("\n── Phase 1: Mutual authentication ───────────────────────\n");
    if (auth_server(auth_ctx, udp_sock, client_addr) != 0) {
        fprintf(stderr, "❌ Authentication failed — aborting handshake\n");
        return -1;
    }
    printf("✅ Peer authenticated\n");

    // ------------------------------------------------------------------
    // Phase 2: ML-KEM-768 key exchange
    // Now that the peer is authenticated, we proceed with the KEM.
    // The client sends its public key; we encapsulate and send back
    // the ciphertext; both sides derive the same shared secret.
    // ------------------------------------------------------------------
    printf("\n── Phase 2: ML-KEM-768 key exchange ─────────────────────\n");

    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) {
        fprintf(stderr, "❌ Failed to initialise %s\n", KEM_ALG);
        return -1;
    }

    printf("   Algorithm  : %s\n", KEM_ALG);
    printf("   Public key : %zu bytes\n", kem->length_public_key);
    printf("   Ciphertext : %zu bytes\n", kem->length_ciphertext);
    printf("   Shared sec : %zu bytes\n\n", kem->length_shared_secret);

    uint8_t *client_pk    = malloc(kem->length_public_key);
    uint8_t *ciphertext   = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    if (!client_pk || !ciphertext || !shared_secret) {
        fprintf(stderr, "❌ Memory allocation failed\n");
        goto kem_error;
    }

    // Receive client public key
    printf("1️⃣  Waiting for client public key...\n");
    struct sockaddr_in from_addr;
    ssize_t nrecv = recv_udp(udp_sock, client_pk, kem->length_public_key,
                             &from_addr, 15000);

    if (nrecv != (ssize_t)kem->length_public_key) {
        fprintf(stderr, "❌ Failed to receive client public key "
                        "(got %zd, expected %zu)\n",
                nrecv, kem->length_public_key);
        goto kem_error;
    }

    // Verify it came from the authenticated client
    if (from_addr.sin_addr.s_addr != client_addr->sin_addr.s_addr ||
        from_addr.sin_port        != client_addr->sin_port) {
        fprintf(stderr, "❌ Public key arrived from unexpected address\n");
        goto kem_error;
    }
    printf("   ✅ Received %zu bytes\n", kem->length_public_key);

    // Encapsulate: derive shared secret, produce ciphertext for client
    printf("\n2️⃣  Encapsulating shared secret...\n");
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, client_pk)
            != OQS_SUCCESS) {
        fprintf(stderr, "❌ Encapsulation failed\n");
        goto kem_error;
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);
    printf("   ✅ Encapsulation: %.2f µs\n", elapsed_us(t1, t2));

    // Send ciphertext to client
    printf("\n3️⃣  Sending ciphertext to client...\n");
    if (send_udp(udp_sock, ciphertext, kem->length_ciphertext,
                 client_addr) < 0) {
        fprintf(stderr, "❌ Failed to send ciphertext\n");
        goto kem_error;
    }
    printf("   ✅ Sent %zu bytes\n", kem->length_ciphertext);

    // ------------------------------------------------------------------
    // Phase 3: Session key derivation
    // HKDF(shared_secret, info="vpn-session-key") → AES-256 key
    // The HKDF info label domain-separates this key from the auth key
    // derived in pqc_auth (which uses "pqvpn-auth-v1").
    // ------------------------------------------------------------------
    printf("\n── Phase 3: Session key derivation ──────────────────────\n");
    hkdf_sha256(shared_secret, kem->length_shared_secret,
                NULL, 0,
                "vpn-session-key",
                session_key, AES_KEY_LEN);
    printf("   ✅ Session key derived (AES-256, 32 bytes)\n");

    // Zero shared secret — no longer needed after key derivation
    memset(shared_secret, 0, kem->length_shared_secret);

    free(client_pk);
    free(ciphertext);
    free(shared_secret);
    OQS_KEM_free(kem);

    printf("\n✅ Handshake complete\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    return 0;

kem_error:
    if (shared_secret) { memset(shared_secret, 0, kem->length_shared_secret); }
    free(client_pk);
    free(ciphertext);
    free(shared_secret);
    OQS_KEM_free(kem);
    return -1;
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║        Post-Quantum VPN Server (ML-KEM-768)              ║\n");
    printf("║        PSK Auth + AES-256-GCM + Replay Protection       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    // Signal handler using sigaction (replaces old signal() call)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;    // Do not restart syscalls — lets poll() return EINTR
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // State
    tun_device_t       tun;
    int                udp_sock    = -1;
    struct sockaddr_in client_addr;
    uint8_t            session_key[AES_KEY_LEN];
    auth_context_t     auth_ctx;

    // Security state — TX (outgoing) and RX (incoming) are independent
    nonce_state_t tx_nonce;
    uint64_t      tx_sequence   = 0;
    uint64_t      rx_expected   = 0;
    uint64_t      rx_bitmap     = 0;

    // Statistics
    uint64_t pkts_sent     = 0;
    uint64_t pkts_recv     = 0;
    uint64_t bytes_sent    = 0;
    uint64_t bytes_recv    = 0;
    uint64_t replays_blocked = 0;

    memset(&tun,         0, sizeof(tun));
    memset(&client_addr, 0, sizeof(client_addr));
    memset(session_key,  0, sizeof(session_key));
    tun.fd = -1;

    // -----------------------------------------------------------------------
    // 1. Load PSK
    // -----------------------------------------------------------------------
    printf("1️⃣  Loading PSK from '%s'...\n", PSK_FILE_PATH);
    if (auth_load_psk(&auth_ctx, PSK_FILE_PATH) != 0) {
        fprintf(stderr, "❌ Failed to load PSK — run ./bin/gen_psk first\n");
        return 1;
    }
    printf("   ✅ PSK loaded\n\n");

    // -----------------------------------------------------------------------
    // 2. Create TUN interface
    // -----------------------------------------------------------------------
    printf("2️⃣  Creating TUN interface '%s'...\n", TUN_NAME);
    if (tun_create(&tun, TUN_NAME) != 0) {
        fprintf(stderr, "❌ Failed to create TUN "
                        "(run as root: sudo ./bin/vpn_server)\n");
        goto cleanup;
    }
    if (tun_set_ip(&tun, SERVER_TUN_IP, CLIENT_TUN_IP, NETMASK) != 0)
        goto cleanup;
    if (tun_up(&tun) != 0)
        goto cleanup;
    printf("\n");

    // -----------------------------------------------------------------------
    // 3. Create UDP socket
    // -----------------------------------------------------------------------
    printf("3️⃣  Binding UDP socket on port %d...\n", VPN_PORT);
    udp_sock = create_udp_socket(VPN_PORT);
    if (udp_sock < 0) {
        fprintf(stderr, "❌ Failed to create UDP socket\n");
        goto cleanup;
    }
    printf("   ✅ Listening on 0.0.0.0:%d\n\n", VPN_PORT);

    // -----------------------------------------------------------------------
    // 4. Handshake
    // -----------------------------------------------------------------------
    printf("4️⃣  Waiting for client connection...\n\n");
    if (perform_handshake(udp_sock, &client_addr,
                          session_key, &auth_ctx) != 0) {
        fprintf(stderr, "❌ Handshake failed\n");
        goto cleanup;
    }

    // Initialise nonce state — must succeed or we cannot send safely
    if (init_nonce_state(&tx_nonce) != 0) {
        fprintf(stderr, "❌ Failed to initialise nonce state\n");
        goto cleanup;
    }
    printf("🔒 Security initialised:\n");
    printf("   Counter-based nonces  : enabled\n");
    printf("   Replay protection     : enabled (window=%d)\n", SEQUENCE_WINDOW);
    printf("   Session key           : AES-256-GCM\n\n");

    // -----------------------------------------------------------------------
    // 5. Tunnel loop
    // -----------------------------------------------------------------------
    printf("5️⃣  VPN tunnel active!\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("   Server TUN : %s (%s)\n", SERVER_TUN_IP, TUN_NAME);
    printf("   Client TUN : %s (virtual)\n", CLIENT_TUN_IP);
    printf("   Client IP  : %s:%d\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    printf("\n   Try from client: ping %s\n", SERVER_TUN_IP);
    printf("   Press Ctrl+C to stop\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    // Buffers — sized from constants, not hardcoded
    uint8_t tun_buf[MAX_TUN_PAYLOAD];
    uint8_t udp_buf[UDP_RECV_BUFSIZE];
    uint8_t enc_buf[VPN_HEADER_SIZE + MAX_TUN_PAYLOAD];

    struct pollfd fds[2];
    fds[0].fd     = tun.fd;
    fds[0].events = POLLIN;
    fds[1].fd     = udp_sock;
    fds[1].events = POLLIN;

    while (running) {
        int ret = poll(fds, 2, 1000);

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (ret == 0) continue;     // Timeout — re-check running flag

        // ==================================================================
        // OUTGOING: TUN → encrypt → UDP
        // ==================================================================
        if (fds[0].revents & POLLIN) {
            ssize_t nread = tun_read(&tun, tun_buf, sizeof(tun_buf));
            if (nread <= 0) continue;

            // Generate next counter nonce
            uint8_t nonce[IV_LEN];
            if (generate_nonce(&tx_nonce, nonce) != 0) {
                fprintf(stderr, "❌ Nonce generation failed — stopping\n");
                running = 0;
                break;
            }

            // Build packet header
            vpn_packet_header_t *hdr = (vpn_packet_header_t *)enc_buf;
            hdr->sequence = htobe64(tx_sequence);
            memcpy(hdr->iv, nonce, IV_LEN);

            // Encrypt using the counter nonce — not regenerated internally
            uint8_t *ct_ptr = enc_buf + VPN_HEADER_SIZE;
            uint8_t  tag[TAG_LEN];

            int ct_len = aes_gcm_encrypt(session_key,
                                         tun_buf, (int)nread,
                                         nonce,
                                         ct_ptr, tag);
            if (ct_len < 0) {
                fprintf(stderr, "❌ Encryption failed\n");
                continue;
            }

            // Store tag in header now that we have it
            memcpy(hdr->tag, tag, TAG_LEN);

            size_t total = VPN_HEADER_SIZE + (size_t)ct_len;
            if (send_udp(udp_sock, enc_buf, total, &client_addr) < 0) {
                fprintf(stderr, "❌ UDP send failed\n");
                continue;
            }

            bytes_sent += total;
            pkts_sent++;
            tx_sequence++;

            printf("📤 #%lu seq=%lu %zd→%zu bytes | ",
                   pkts_sent, tx_sequence - 1, nread, total);
            print_ip_packet(tun_buf, (size_t)nread);
        }

        // ==================================================================
        // INCOMING: UDP → verify → decrypt → TUN
        // ==================================================================
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            ssize_t nrecv = recv_udp(udp_sock, udp_buf, sizeof(udp_buf),
                                     &from, 0);

            if (nrecv < (ssize_t)VPN_HEADER_SIZE) continue;

            // Drop packets from unknown sources
            if (from.sin_addr.s_addr != client_addr.sin_addr.s_addr ||
                from.sin_port        != client_addr.sin_port) {
                fprintf(stderr, "⚠️  Packet from unknown source — dropped\n");
                continue;
            }

            // Parse header
            vpn_packet_header_t *hdr = (vpn_packet_header_t *)udp_buf;
            uint64_t recv_seq = be64toh(hdr->sequence);

            // Replay check — before decryption
            if (!check_sequence(recv_seq, &rx_expected, &rx_bitmap)) {
                replays_blocked++;
                continue;
            }

            // Decrypt and authenticate
            uint8_t *ct  = udp_buf + VPN_HEADER_SIZE;
            int      ct_len = (int)(nrecv - VPN_HEADER_SIZE);

            uint8_t plaintext[MAX_TUN_PAYLOAD];
            int pt_len = aes_gcm_decrypt(session_key,
                                         ct, ct_len,
                                         hdr->iv, hdr->tag,
                                         plaintext);
            if (pt_len < 0) {
                fprintf(stderr, "❌ Decryption/auth failed for seq %lu\n",
                        (unsigned long)recv_seq);
                continue;
            }

            // Deliver to kernel
            if (tun_write(&tun, plaintext, (size_t)pt_len) < 0) {
                fprintf(stderr, "❌ tun_write failed\n");
                continue;
            }

            bytes_recv += (size_t)nrecv;
            pkts_recv++;

            printf("📥 #%lu seq=%lu %d bytes | ",
                   pkts_recv, (unsigned long)recv_seq, pt_len);
            print_ip_packet(plaintext, (size_t)pt_len);
        }
    }

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------
cleanup:
    printf("\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("📊 Session statistics:\n");
    printf("   Packets sent     : %lu\n",     (unsigned long)pkts_sent);
    printf("   Packets received : %lu\n",     (unsigned long)pkts_recv);
    printf("   Bytes sent       : %lu (%.2f KB)\n",
           (unsigned long)bytes_sent, bytes_sent / 1024.0);
    printf("   Bytes received   : %lu (%.2f KB)\n",
           (unsigned long)bytes_recv, bytes_recv / 1024.0);
    printf("   Replays blocked  : %lu\n",     (unsigned long)replays_blocked);
    printf("   Header overhead  : %zu bytes per packet\n", VPN_HEADER_SIZE);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    printf("🧹 Cleaning up...\n");

    // Zero session key before freeing — it must not linger in memory
    memset(session_key, 0, sizeof(session_key));
    memset(&auth_ctx,   0, sizeof(auth_ctx));
    memset(&tx_nonce,   0, sizeof(tx_nonce));

    if (tun.fd >= 0) {
        tun_down(&tun);
        tun_close(&tun);
    }
    if (udp_sock >= 0) close(udp_sock);

    printf("✅ Server stopped\n");
    return 0;
}