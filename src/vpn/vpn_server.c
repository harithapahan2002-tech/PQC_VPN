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
// The server runs in a persistent loop — after one client disconnects,
// it resets all session state and waits for the next client.
//
// Usage:
//   sudo ./bin/vpn_server
//   (psk.conf must exist in the working directory)

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

// How long to wait between sessions (seconds).
// Gives the OS time to clean up routes/state before the next client.
#define RECONNECT_DELAY_SEC  2

// ============================================================================
// GLOBAL SIGNAL STATE
// ============================================================================

static volatile sig_atomic_t running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
    printf("\n🛑 Shutting down server...\n");
}

// ============================================================================
// SESSION STATE
// ============================================================================

// All per-session state in one struct so it's easy to reset between clients.
typedef struct {
    struct sockaddr_in client_addr;
    uint8_t            session_key[AES_KEY_LEN];
    nonce_state_t      tx_nonce;
    uint64_t           tx_sequence;
    uint64_t           rx_expected;
    uint64_t           rx_bitmap;
    uint64_t           pkts_sent;
    uint64_t           pkts_recv;
    uint64_t           bytes_sent;
    uint64_t           bytes_recv;
    uint64_t           replays_blocked;
} session_t;

static void session_reset(session_t *s) {
    // Zero everything — especially session_key which is sensitive
    memset(s, 0, sizeof(*s));
}

static void session_print_stats(const session_t *s) {
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("📊 Session statistics:\n");
    printf("   Packets sent     : %lu\n",   (unsigned long)s->pkts_sent);
    printf("   Packets received : %lu\n",   (unsigned long)s->pkts_recv);
    printf("   Bytes sent       : %lu (%.2f KB)\n",
           (unsigned long)s->bytes_sent, s->bytes_sent / 1024.0);
    printf("   Bytes received   : %lu (%.2f KB)\n",
           (unsigned long)s->bytes_recv, s->bytes_recv / 1024.0);
    printf("   Replays blocked  : %lu\n",   (unsigned long)s->replays_blocked);
    printf("   Header overhead  : %zu bytes per packet\n", VPN_HEADER_SIZE);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
}

// ============================================================================
// HANDSHAKE
// ============================================================================

static int perform_handshake(int                   udp_sock,
                             session_t             *s,
                             const auth_context_t  *auth_ctx) {

    printf("\n🔐 Starting handshake...\n");

    // Phase 1: PSK mutual authentication
    printf("\n── Phase 1: Mutual authentication ───────────────────────\n");
    if (auth_server(auth_ctx, udp_sock, &s->client_addr) != 0) {
        fprintf(stderr, "❌ Authentication failed\n");
        return -1;
    }
    printf("✅ Client authenticated: %s:%d\n",
           inet_ntoa(s->client_addr.sin_addr),
           ntohs(s->client_addr.sin_port));

    // Phase 2: ML-KEM-768 key exchange
    printf("\n── Phase 2: ML-KEM-768 key exchange ─────────────────────\n");

    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) {
        fprintf(stderr, "❌ Failed to initialise %s\n", KEM_ALG);
        return -1;
    }

    printf("   Algorithm  : %s\n",   KEM_ALG);
    printf("   Public key : %zu bytes\n", kem->length_public_key);
    printf("   Ciphertext : %zu bytes\n", kem->length_ciphertext);
    printf("   Shared sec : %zu bytes\n\n", kem->length_shared_secret);

    uint8_t *client_pk     = malloc(kem->length_public_key);
    uint8_t *ciphertext    = malloc(kem->length_ciphertext);
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
    if (from_addr.sin_addr.s_addr != s->client_addr.sin_addr.s_addr ||
        from_addr.sin_port        != s->client_addr.sin_port) {
        fprintf(stderr, "❌ Public key from unexpected address\n");
        goto kem_error;
    }
    printf("   ✅ Received %zu bytes\n", kem->length_public_key);

    // Encapsulate
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

    // Send ciphertext
    printf("\n3️⃣  Sending ciphertext to client...\n");
    if (send_udp(udp_sock, ciphertext, kem->length_ciphertext,
                 &s->client_addr) < 0) {
        fprintf(stderr, "❌ Failed to send ciphertext\n");
        goto kem_error;
    }
    printf("   ✅ Sent %zu bytes\n", kem->length_ciphertext);

    // Phase 3: Session key derivation
    printf("\n── Phase 3: Session key derivation ──────────────────────\n");
    hkdf_sha256(shared_secret, kem->length_shared_secret,
                NULL, 0, "vpn-session-key",
                s->session_key, AES_KEY_LEN);
    printf("   ✅ Session key derived (AES-256, 32 bytes)\n");

    memset(shared_secret, 0, kem->length_shared_secret);
    free(client_pk);
    free(ciphertext);
    free(shared_secret);
    OQS_KEM_free(kem);

    printf("\n✅ Handshake complete\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    return 0;

kem_error:
    if (shared_secret) memset(shared_secret, 0, kem->length_shared_secret);
    free(client_pk);
    free(ciphertext);
    free(shared_secret);
    OQS_KEM_free(kem);
    return -1;
}

// ============================================================================
// TUNNEL LOOP  (one session)
// ============================================================================

// run_tunnel: handle one connected client until they disconnect or an
// error occurs. Returns when the session ends — the outer loop in main()
// then resets state and waits for the next client.
static void run_tunnel(int udp_sock, tun_device_t *tun, session_t *s) {

    printf("4️⃣  VPN tunnel active!\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("   Server TUN : %s (%s)\n", SERVER_TUN_IP, TUN_NAME);
    printf("   Client     : %s:%d\n",
           inet_ntoa(s->client_addr.sin_addr),
           ntohs(s->client_addr.sin_port));
    printf("   Security   : ML-KEM-768 + AES-256-GCM\n");
    printf("   Press Ctrl+C to stop server\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    uint8_t tun_buf[MAX_TUN_PAYLOAD];
    uint8_t udp_buf[UDP_RECV_BUFSIZE];
    uint8_t enc_buf[VPN_HEADER_SIZE + MAX_TUN_PAYLOAD];

    struct pollfd fds[2];
    fds[0].fd     = tun->fd;
    fds[0].events = POLLIN;
    fds[1].fd     = udp_sock;
    fds[1].events = POLLIN;

    // Track idle time — if no packets for 30 seconds, consider client gone
    int idle_seconds = 0;

    while (running) {
        int ret = poll(fds, 2, 1000);

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        if (ret == 0) {
            // 1-second timeout
            idle_seconds++;
            if (idle_seconds >= 30) {
                printf("\n⏱️  Client idle for 30 seconds — ending session\n");
                break;
            }
            continue;
        }

        idle_seconds = 0;   // Reset on any activity

        // OUTGOING: TUN → encrypt → UDP
        if (fds[0].revents & POLLIN) {
            ssize_t nread = tun_read(tun, tun_buf, sizeof(tun_buf));
            if (nread <= 0) continue;

            uint8_t nonce[IV_LEN];
            if (generate_nonce(&s->tx_nonce, nonce) != 0) {
                fprintf(stderr, "❌ Nonce generation failed\n");
                running = 0;
                break;
            }

            vpn_packet_header_t *hdr = (vpn_packet_header_t *)enc_buf;
            hdr->sequence = htobe64(s->tx_sequence);
            memcpy(hdr->iv, nonce, IV_LEN);

            uint8_t tag[TAG_LEN];
            int ct_len = aes_gcm_encrypt(s->session_key,
                                         tun_buf, (int)nread,
                                         nonce,
                                         enc_buf + VPN_HEADER_SIZE, tag);
            if (ct_len < 0) {
                fprintf(stderr, "❌ Encryption failed\n");
                continue;
            }

            memcpy(hdr->tag, tag, TAG_LEN);
            size_t total = VPN_HEADER_SIZE + (size_t)ct_len;

            if (send_udp(udp_sock, enc_buf, total, &s->client_addr) < 0) {
                fprintf(stderr, "❌ UDP send failed\n");
                continue;
            }

            s->bytes_sent += total;
            s->pkts_sent++;
            s->tx_sequence++;

            printf("📤 #%lu seq=%lu %zd→%zu bytes | ",
                   s->pkts_sent, s->tx_sequence - 1, nread, total);
            print_ip_packet(tun_buf, (size_t)nread);
        }

        // INCOMING: UDP → verify → decrypt → TUN
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            ssize_t nrecv = recv_udp(udp_sock, udp_buf, sizeof(udp_buf),
                                     &from, 0);

            if (nrecv < (ssize_t)VPN_HEADER_SIZE) continue;

            // Drop packets from unknown sources
            if (from.sin_addr.s_addr != s->client_addr.sin_addr.s_addr ||
                from.sin_port        != s->client_addr.sin_port) {
                fprintf(stderr, "⚠️  Packet from unknown source — dropped\n");
                continue;
            }

            vpn_packet_header_t *hdr = (vpn_packet_header_t *)udp_buf;
            uint64_t recv_seq = be64toh(hdr->sequence);

            if (!check_sequence(recv_seq, &s->rx_expected, &s->rx_bitmap)) {
                s->replays_blocked++;
                continue;
            }

            uint8_t *ct     = udp_buf + VPN_HEADER_SIZE;
            int      ct_len = (int)(nrecv - VPN_HEADER_SIZE);

            uint8_t plaintext[MAX_TUN_PAYLOAD];
            int pt_len = aes_gcm_decrypt(s->session_key,
                                         ct, ct_len,
                                         hdr->iv, hdr->tag,
                                         plaintext);
            if (pt_len < 0) {
                fprintf(stderr, "❌ Decrypt failed seq %lu\n",
                        (unsigned long)recv_seq);
                continue;
            }

            if (tun_write(tun, plaintext, (size_t)pt_len) < 0) {
                fprintf(stderr, "❌ tun_write failed\n");
                continue;
            }

            s->bytes_recv += (size_t)nrecv;
            s->pkts_recv++;

            printf("📥 #%lu seq=%lu %d bytes | ",
                   s->pkts_recv, (unsigned long)recv_seq, pt_len);
            print_ip_packet(plaintext, (size_t)pt_len);
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║        Post-Quantum VPN Server (ML-KEM-768)              ║\n");
    printf("║        PSK Auth + AES-256-GCM + Replay Protection       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    tun_device_t   tun;
    int            udp_sock = -1;
    auth_context_t auth_ctx;
    session_t      session;

    memset(&tun,     0, sizeof(tun));
    memset(&auth_ctx, 0, sizeof(auth_ctx));
    session_reset(&session);
    tun.fd = -1;

    // -----------------------------------------------------------------------
    // 1. Load PSK — once, before the session loop
    // -----------------------------------------------------------------------
    printf("1️⃣  Loading PSK from '%s'...\n", PSK_FILE_PATH);
    if (auth_load_psk(&auth_ctx, PSK_FILE_PATH) != 0) {
        fprintf(stderr, "❌ Failed to load PSK — run ./bin/gen_psk first\n");
        return 1;
    }
    printf("   ✅ PSK loaded\n\n");

    // -----------------------------------------------------------------------
    // 2. Create TUN interface — once, persists across sessions
    // -----------------------------------------------------------------------
    printf("2️⃣  Creating TUN interface '%s'...\n", TUN_NAME);
    if (tun_create(&tun, TUN_NAME) != 0) {
        fprintf(stderr, "❌ Failed to create TUN "
                        "(run as root: sudo ./bin/vpn_server)\n");
        goto shutdown;
    }
    if (tun_set_ip(&tun, SERVER_TUN_IP, CLIENT_TUN_IP, NETMASK) != 0)
        goto shutdown;
    if (tun_up(&tun) != 0)
        goto shutdown;
    printf("\n");

    // -----------------------------------------------------------------------
    // 3. Create UDP socket — once, persists across sessions
    // -----------------------------------------------------------------------
    printf("3️⃣  Binding UDP socket on port %d...\n", VPN_PORT);
    udp_sock = create_udp_socket(VPN_PORT);
    if (udp_sock < 0) {
        fprintf(stderr, "❌ Failed to bind UDP socket\n");
        goto shutdown;
    }
    printf("   ✅ Listening on 0.0.0.0:%d\n\n", VPN_PORT);

    // -----------------------------------------------------------------------
    // 4. Session loop — accept a client, run tunnel, repeat
    //
    // The TUN interface and UDP socket are created once above and reused
    // across sessions. Only per-session cryptographic state is reset
    // between clients — keys, nonces, sequence numbers, statistics.
    // -----------------------------------------------------------------------
    int session_count = 0;

    while (running) {

        session_count++;
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        printf("🔵 Session #%d — waiting for client...\n\n", session_count);

        // Reset all per-session state before each new client
        session_reset(&session);

        // Handshake — blocks until a client authenticates and completes KEM
        if (perform_handshake(udp_sock, &session, &auth_ctx) != 0) {
            fprintf(stderr, "⚠️  Handshake failed — waiting for next client\n\n");

            // Don't spin on repeated failures
            sleep(RECONNECT_DELAY_SEC);
            continue;
        }

        // Initialise per-session nonce state
        if (init_nonce_state(&session.tx_nonce) != 0) {
            fprintf(stderr, "❌ Nonce init failed — aborting session\n\n");
            session_reset(&session);
            sleep(RECONNECT_DELAY_SEC);
            continue;
        }

        printf("🔒 Security initialised:\n");
        printf("   Nonces        : counter-based\n");
        printf("   Replay window : %d packets\n", SEQUENCE_WINDOW);
        printf("   Cipher        : AES-256-GCM\n\n");

        // Run the tunnel until the client disconnects or server stops
        run_tunnel(udp_sock, &tun, &session);

        // Session ended — print stats and zero sensitive state
        printf("\n🔴 Session #%d ended\n", session_count);
        session_print_stats(&session);
        session_reset(&session);    // zeros session_key, nonce, etc.

        if (!running) break;

        printf("⏳ Waiting %d seconds before accepting next client...\n\n",
               RECONNECT_DELAY_SEC);
        sleep(RECONNECT_DELAY_SEC);
    }

    // -----------------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------------
shutdown:
    printf("\n🧹 Shutting down server...\n");

    memset(&auth_ctx, 0, sizeof(auth_ctx));
    session_reset(&session);

    if (tun.fd >= 0) {
        tun_down(&tun);
        tun_close(&tun);
    }
    if (udp_sock >= 0) close(udp_sock);

    printf("✅ Server stopped after %d session(s)\n", session_count);
    return 0;
}