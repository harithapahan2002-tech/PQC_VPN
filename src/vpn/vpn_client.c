// vpn_client.c
// Post-Quantum VPN Client
// ML-KEM-768 key exchange + PSK mutual authentication + AES-256-GCM tunnel
//
// Handshake sequence (mirrors server, opposite roles):
//   1. PSK mutual authentication  (pqc_auth)
//   2. ML-KEM-768 key exchange    (liboqs)
//   3. HKDF session key derivation
//   4. AES-256-GCM encrypted tunnel with counter nonces + replay protection
//
// Usage:
//   sudo ./bin/vpn_client
//   (psk.conf must exist in the working directory — same file as server)
//
// Depends on: pqc_common, pqc_crypto, pqc_auth, tun, udp_support, liboqs

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

#define SERVER_IP       "127.0.0.1"     // Change to server's real IP
#define CLIENT_TUN_IP   "10.8.0.2"
#define SERVER_TUN_IP   "10.8.0.1"
#define NETMASK         "255.255.255.0"
#define TUN_NAME        "tun1"

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
//   Runs PSK mutual auth then ML-KEM-768 decapsulation.
//   On success, session_key contains the derived AES-256 key.
//
// Returns 0 on success, -1 on failure.
static int perform_handshake(int                      udp_sock,
                             const struct sockaddr_in *server_addr,
                             uint8_t                   session_key[AES_KEY_LEN],
                             const auth_context_t     *auth_ctx) {

    printf("\n🔐 Starting handshake...\n");

    // ------------------------------------------------------------------
    // Phase 1: PSK mutual authentication
    // Client initiates — sends challenge, verifies server, sends response.
    // ------------------------------------------------------------------
    printf("\n── Phase 1: Mutual authentication ───────────────────────\n");
    if (auth_client(auth_ctx, udp_sock, server_addr) != 0) {
        fprintf(stderr, "❌ Authentication failed — aborting handshake\n");
        return -1;
    }
    printf("✅ Peer authenticated\n");

    // ------------------------------------------------------------------
    // Phase 2: ML-KEM-768 key exchange
    // Client generates a keypair, sends the public key to the server,
    // receives the ciphertext, and decapsulates to recover the shared secret.
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

    uint8_t *client_pk     = malloc(kem->length_public_key);
    uint8_t *client_sk     = malloc(kem->length_secret_key);
    uint8_t *ciphertext    = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    if (!client_pk || !client_sk || !ciphertext || !shared_secret) {
        fprintf(stderr, "❌ Memory allocation failed\n");
        goto kem_error;
    }

    // Generate client keypair
    printf("1️⃣  Generating ML-KEM-768 keypair...\n");
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (OQS_KEM_keypair(kem, client_pk, client_sk) != OQS_SUCCESS) {
        fprintf(stderr, "❌ Keypair generation failed\n");
        goto kem_error;
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);
    printf("   ✅ Keypair generation: %.2f µs\n", elapsed_us(t1, t2));

    // Send public key to server
    printf("\n2️⃣  Sending public key to server...\n");
    if (send_udp(udp_sock, client_pk, kem->length_public_key,
                 server_addr) < 0) {
        fprintf(stderr, "❌ Failed to send public key\n");
        goto kem_error;
    }
    printf("   ✅ Sent %zu bytes to %s:%d\n",
           kem->length_public_key, SERVER_IP, VPN_PORT);

    // Receive ciphertext from server
    printf("\n3️⃣  Waiting for server ciphertext...\n");
    struct sockaddr_in from_addr;
    ssize_t nrecv = recv_udp(udp_sock, ciphertext, kem->length_ciphertext,
                             &from_addr, 15000);

    if (nrecv != (ssize_t)kem->length_ciphertext) {
        fprintf(stderr, "❌ Failed to receive ciphertext "
                        "(got %zd, expected %zu)\n",
                nrecv, kem->length_ciphertext);
        goto kem_error;
    }
    printf("   ✅ Received %zu bytes\n", kem->length_ciphertext);

    // Decapsulate to recover shared secret
    printf("\n4️⃣  Decapsulating shared secret...\n");
    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, client_sk)
            != OQS_SUCCESS) {
        fprintf(stderr, "❌ Decapsulation failed\n");
        goto kem_error;
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);
    printf("   ✅ Decapsulation: %.2f µs\n", elapsed_us(t1, t2));

    // ------------------------------------------------------------------
    // Phase 3: Session key derivation
    // Must use the same info label as the server — "vpn-session-key"
    // Both sides derive the same key from the same shared secret.
    // ------------------------------------------------------------------
    printf("\n── Phase 3: Session key derivation ──────────────────────\n");
    hkdf_sha256(shared_secret, kem->length_shared_secret,
                NULL, 0,
                "vpn-session-key",
                session_key, AES_KEY_LEN);
    printf("   ✅ Session key derived (AES-256, 32 bytes)\n");

    // Zero all private key material immediately after use
    memset(client_sk,     0, kem->length_secret_key);
    memset(shared_secret, 0, kem->length_shared_secret);

    free(client_pk);
    free(client_sk);
    free(ciphertext);
    free(shared_secret);
    OQS_KEM_free(kem);

    printf("\n✅ Handshake complete\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    return 0;

kem_error:
    // Zero any sensitive material before freeing
    if (client_sk)     memset(client_sk,     0, kem->length_secret_key);
    if (shared_secret) memset(shared_secret, 0, kem->length_shared_secret);
    free(client_pk);
    free(client_sk);
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
    printf("║        Post-Quantum VPN Client (ML-KEM-768)              ║\n");
    printf("║        PSK Auth + AES-256-GCM + Replay Protection       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    // sigaction replaces old signal() — correctly handles SA_RESTART
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // State
    tun_device_t       tun;
    int                udp_sock = -1;
    struct sockaddr_in server_addr;
    uint8_t            session_key[AES_KEY_LEN];
    auth_context_t     auth_ctx;

    // Security state
    nonce_state_t tx_nonce;
    uint64_t      tx_sequence = 0;
    uint64_t      rx_expected = 0;
    uint64_t      rx_bitmap   = 0;

    // Statistics
    uint64_t pkts_sent      = 0;
    uint64_t pkts_recv      = 0;
    uint64_t bytes_sent     = 0;
    uint64_t bytes_recv     = 0;
    uint64_t replays_blocked = 0;

    memset(&tun,         0, sizeof(tun));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(session_key,  0, sizeof(session_key));
    tun.fd = -1;

    // -----------------------------------------------------------------------
    // 1. Load PSK
    // -----------------------------------------------------------------------
    printf("1️⃣  Loading PSK from '%s'...\n", PSK_FILE_PATH);
    if (auth_load_psk(&auth_ctx, PSK_FILE_PATH) != 0) {
        fprintf(stderr, "❌ Failed to load PSK — copy psk.conf from server\n");
        return 1;
    }
    printf("   ✅ PSK loaded\n\n");

    // -----------------------------------------------------------------------
    // 2. Create TUN interface
    // -----------------------------------------------------------------------
    printf("2️⃣  Creating TUN interface '%s'...\n", TUN_NAME);
    if (tun_create(&tun, TUN_NAME) != 0) {
        fprintf(stderr, "❌ Failed to create TUN "
                        "(run as root: sudo ./bin/vpn_client)\n");
        goto cleanup;
    }
    if (tun_set_ip(&tun, CLIENT_TUN_IP, SERVER_TUN_IP, NETMASK) != 0)
        goto cleanup;
    if (tun_up(&tun) != 0)
        goto cleanup;
    printf("\n");

    // -----------------------------------------------------------------------
    // 3. Create UDP socket (ephemeral port)
    // -----------------------------------------------------------------------
    printf("3️⃣  Creating UDP socket...\n");
    udp_sock = create_udp_socket(0);
    if (udp_sock < 0) {
        fprintf(stderr, "❌ Failed to create UDP socket\n");
        goto cleanup;
    }
    printf("   ✅ Bound on port %d\n\n", get_socket_port(udp_sock));

    // -----------------------------------------------------------------------
    // 4. Resolve server address
    // -----------------------------------------------------------------------
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(VPN_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "❌ Invalid server IP: %s\n", SERVER_IP);
        goto cleanup;
    }

    // -----------------------------------------------------------------------
    // 5. Handshake
    // -----------------------------------------------------------------------
    printf("4️⃣  Connecting to server %s:%d...\n", SERVER_IP, VPN_PORT);
    if (perform_handshake(udp_sock, &server_addr,
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
    // 6. Tunnel loop
    // -----------------------------------------------------------------------
    printf("5️⃣  VPN tunnel active!\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("   Client TUN : %s (%s)\n", CLIENT_TUN_IP, TUN_NAME);
    printf("   Server TUN : %s (virtual)\n", SERVER_TUN_IP);
    printf("   Server     : %s:%d\n", SERVER_IP, VPN_PORT);
    printf("\n   Try: ping %s\n", SERVER_TUN_IP);
    printf("   Press Ctrl+C to disconnect\n");
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

        if (ret == 0) continue;

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

            // Build header — nonce written here is the one used for encryption
            vpn_packet_header_t *hdr = (vpn_packet_header_t *)enc_buf;
            hdr->sequence = htobe64(tx_sequence);
            memcpy(hdr->iv, nonce, IV_LEN);

            // Encrypt with the counter nonce
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

            memcpy(hdr->tag, tag, TAG_LEN);

            size_t total = VPN_HEADER_SIZE + (size_t)ct_len;
            if (send_udp(udp_sock, enc_buf, total, &server_addr) < 0) {
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

            // Only accept packets from our known server
            if (from.sin_addr.s_addr != server_addr.sin_addr.s_addr ||
                from.sin_port        != server_addr.sin_port) {
                fprintf(stderr, "⚠️  Packet from unknown source — dropped\n");
                continue;
            }

            // Parse header
            vpn_packet_header_t *hdr = (vpn_packet_header_t *)udp_buf;
            uint64_t recv_seq = be64toh(hdr->sequence);

            // Replay check before decryption
            if (!check_sequence(recv_seq, &rx_expected, &rx_bitmap)) {
                replays_blocked++;
                continue;
            }

            // Decrypt and authenticate
            uint8_t *ct     = udp_buf + VPN_HEADER_SIZE;
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

    // Zero all sensitive state
    memset(session_key, 0, sizeof(session_key));
    memset(&auth_ctx,   0, sizeof(auth_ctx));
    memset(&tx_nonce,   0, sizeof(tx_nonce));

    if (tun.fd >= 0) {
        tun_down(&tun);
        tun_close(&tun);
    }
    if (udp_sock >= 0) close(udp_sock);

    printf("✅ Client stopped\n");
    return 0;
}