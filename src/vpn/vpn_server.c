// vpn_server.c
// Post-Quantum VPN Server
// ML-KEM-768 + ML-DSA-65 cert auth + AES-256-GCM + keepalive
//
// Handshake sequence:
//   1. ML-DSA-65 certificate exchange  (pqc_cert)
//   2. ML-KEM-768 key exchange         (liboqs)
//   3. HKDF-SHA256 session key         (pqc_common)
//   4. AES-256-GCM tunnel              (pqc_crypto)
//
// Setup (run once):
//   sudo ./bin/gen_ca
//   sudo ./bin/gen_cert server
//   sudo ./bin/gen_cert client
//   # copy ca_cert.pub to client machine

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>
#include <endian.h>
#include <oqs/oqs.h>

#include "../common/pqc_common.h"
#include "../common/pqc_crypto.h"
#include "../common/pqc_cert.h"
#include "tun.h"
#include "udp_support.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define SERVER_TUN_IP        "10.8.0.1"
#define CLIENT_TUN_IP        "10.8.0.2"
#define NETMASK              "255.255.255.0"
#define TUN_NAME             "tun0"
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

typedef struct {
    struct sockaddr_in client_addr;
    uint8_t            session_key[AES_KEY_LEN];
    nonce_state_t      tx_nonce;
    uint64_t           tx_sequence;
    uint64_t           rx_expected;
    uint64_t           rx_bitmap;
    uint64_t           pkts_sent;
    uint64_t           pkts_recv;
    uint64_t           keepalives_recv;
    uint64_t           bytes_sent;
    uint64_t           bytes_recv;
    uint64_t           replays_blocked;
} session_t;

static void session_reset(session_t *s) {
    memset(s, 0, sizeof(*s));
}

static void session_print_stats(const session_t *s) {
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("📊 Session statistics:\n");
    printf("   Packets sent      : %lu\n",   (unsigned long)s->pkts_sent);
    printf("   Packets received  : %lu\n",   (unsigned long)s->pkts_recv);
    printf("   Keepalives recv   : %lu\n",   (unsigned long)s->keepalives_recv);
    printf("   Bytes sent        : %lu (%.2f KB)\n",
           (unsigned long)s->bytes_sent, s->bytes_sent / 1024.0);
    printf("   Bytes received    : %lu (%.2f KB)\n",
           (unsigned long)s->bytes_recv, s->bytes_recv / 1024.0);
    printf("   Replays blocked   : %lu\n",   (unsigned long)s->replays_blocked);
    printf("   Header overhead   : %zu bytes per packet\n", VPN_HEADER_SIZE);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
}

// ============================================================================
// SOCKET FLUSH
// ============================================================================

static void flush_udp_socket(int sock) {
    uint8_t discard[UDP_RECV_BUFSIZE];
    struct sockaddr_in src;
    int flushed = 0;
    while (1) {
        ssize_t n = recv_udp(sock, discard, sizeof(discard), &src, 0);
        if (n <= 0) break;
        flushed++;
    }
    if (flushed > 0)
        printf("   🧹 Flushed %d stale packet(s)\n", flushed);
}

// ============================================================================
// HANDSHAKE
// ============================================================================

static int perform_handshake(int                  udp_sock,
                             session_t            *s,
                             const uint8_t         ca_pubkey[CERT_PUBKEY_LEN],
                             const pqc_cert_t     *server_cert) {

    printf("\n🔐 Starting handshake...\n");

    // ------------------------------------------------------------------
    // Phase 1: ML-DSA-65 certificate exchange
    // Both sides prove identity via CA-signed certificates.
    // No shared secret needed — only the CA public key.
    // ------------------------------------------------------------------
    printf("\n── Phase 1: Certificate authentication (ML-DSA-65) ──────\n");

    if (cert_handshake_server(ca_pubkey, server_cert,
                              udp_sock, &s->client_addr) != 0) {
        fprintf(stderr, "❌ Certificate authentication failed\n");
        return -1;
    }
    printf("✅ Client authenticated via ML-DSA-65 certificate\n");
    printf("   Client: %s:%d\n",
           inet_ntoa(s->client_addr.sin_addr),
           ntohs(s->client_addr.sin_port));

    // ------------------------------------------------------------------
    // Phase 2: ML-KEM-768 key exchange
    // ------------------------------------------------------------------
    printf("\n── Phase 2: ML-KEM-768 key exchange ─────────────────────\n");

    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) { fprintf(stderr, "❌ KEM init failed\n"); return -1; }

    uint8_t *client_pk     = malloc(kem->length_public_key);
    uint8_t *ciphertext    = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    if (!client_pk || !ciphertext || !shared_secret) {
        fprintf(stderr, "❌ Alloc failed\n"); goto kem_error;
    }

    printf("   Algorithm  : %s\n",      KEM_ALG);
    printf("   Public key : %zu bytes\n", kem->length_public_key);
    printf("   Ciphertext : %zu bytes\n", kem->length_ciphertext);

    struct sockaddr_in from;
    ssize_t nrecv = recv_udp(udp_sock, client_pk, kem->length_public_key,
                             &from, 15000);
    if (nrecv != (ssize_t)kem->length_public_key) {
        fprintf(stderr, "❌ Client public key recv failed\n"); goto kem_error;
    }
    if (from.sin_addr.s_addr != s->client_addr.sin_addr.s_addr ||
        from.sin_port        != s->client_addr.sin_port) {
        fprintf(stderr, "❌ Public key from wrong address\n"); goto kem_error;
    }
    printf("   ✅ Public key received\n");

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, client_pk)
            != OQS_SUCCESS) {
        fprintf(stderr, "❌ Encapsulation failed\n"); goto kem_error;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);
    printf("   ✅ Encapsulation: %.2f µs\n", elapsed_us(t1, t2));

    if (send_udp(udp_sock, ciphertext, kem->length_ciphertext,
                 &s->client_addr) < 0) {
        fprintf(stderr, "❌ Ciphertext send failed\n"); goto kem_error;
    }
    printf("   ✅ Ciphertext sent (%zu bytes)\n", kem->length_ciphertext);

    // ------------------------------------------------------------------
    // Phase 3: Session key derivation
    // ------------------------------------------------------------------
    printf("\n── Phase 3: Session key derivation ──────────────────────\n");
    hkdf_sha256(shared_secret, kem->length_shared_secret,
                NULL, 0, "vpn-session-key",
                s->session_key, AES_KEY_LEN);
    printf("   ✅ Session key derived (AES-256)\n");

    memset(shared_secret, 0, kem->length_shared_secret);
    free(client_pk); free(ciphertext); free(shared_secret);
    OQS_KEM_free(kem);

    printf("\n✅ Handshake complete\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    return 0;

kem_error:
    if (shared_secret) memset(shared_secret, 0, kem->length_shared_secret);
    free(client_pk); free(ciphertext); free(shared_secret);
    OQS_KEM_free(kem);
    return -1;
}

// ============================================================================
// TUNNEL LOOP
// ============================================================================

static void run_tunnel(int udp_sock, tun_device_t *tun, session_t *s) {

    printf("4️⃣  VPN tunnel active!\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("   Server TUN : %s (%s)\n", SERVER_TUN_IP, TUN_NAME);
    printf("   Client     : %s:%d\n",
           inet_ntoa(s->client_addr.sin_addr),
           ntohs(s->client_addr.sin_port));
    printf("   Security   : ML-DSA-65 + ML-KEM-768 + AES-256-GCM\n");
    printf("   Keepalive  : %ds interval / %ds idle timeout\n",
           KEEPALIVE_INTERVAL_SEC, KEEPALIVE_IDLE_SEC);
    printf("   Ctrl+C to stop\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    uint8_t tun_buf[MAX_TUN_PAYLOAD];
    uint8_t udp_buf[UDP_RECV_BUFSIZE];
    uint8_t enc_buf[VPN_HEADER_SIZE + MAX_TUN_PAYLOAD];

    struct pollfd fds[2];
    fds[0].fd = tun->fd;   fds[0].events = POLLIN;
    fds[1].fd = udp_sock;  fds[1].events = POLLIN;

    time_t last_rx_time = time(NULL);

    while (running) {
        int ret = poll(fds, 2, 1000);
        if (ret < 0) { if (errno == EINTR) continue; perror("poll"); break; }

        if (time(NULL) - last_rx_time >= KEEPALIVE_IDLE_SEC) {
            printf("\n⏱️  No client packets for %d seconds — ending session\n",
                   KEEPALIVE_IDLE_SEC);
            break;
        }

        if (ret == 0) continue;

        // OUTGOING: TUN → encrypt → UDP
        if (fds[0].revents & POLLIN) {
            ssize_t nread = tun_read(tun, tun_buf, sizeof(tun_buf));
            if (nread <= 0) continue;

            uint8_t nonce[IV_LEN];
            if (generate_nonce(&s->tx_nonce, nonce) != 0) {
                fprintf(stderr, "❌ Nonce failed\n"); running = 0; break;
            }

            vpn_packet_header_t *hdr = (vpn_packet_header_t *)enc_buf;
            hdr->magic    = htonl(VPN_MAGIC);
            hdr->type     = PKT_TYPE_DATA;
            hdr->sequence = htobe64(s->tx_sequence);
            memcpy(hdr->iv, nonce, IV_LEN);

            uint8_t tag[TAG_LEN];
            int ct_len = aes_gcm_encrypt(s->session_key,
                                         tun_buf, (int)nread,
                                         nonce, enc_buf + VPN_HEADER_SIZE, tag);
            if (ct_len < 0) { fprintf(stderr, "❌ Encrypt\n"); continue; }
            memcpy(hdr->tag, tag, TAG_LEN);

            size_t total = VPN_HEADER_SIZE + (size_t)ct_len;
            if (send_udp(udp_sock, enc_buf, total, &s->client_addr) < 0)
                continue;

            s->bytes_sent += total;
            s->pkts_sent++;
            s->tx_sequence++;
            printf("📤 #%lu seq=%lu %zd→%zu | ",
                   s->pkts_sent, s->tx_sequence - 1, nread, total);
            print_ip_packet(tun_buf, (size_t)nread);
        }

        // INCOMING: UDP → verify → decrypt → TUN
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            ssize_t nrecv = recv_udp(udp_sock, udp_buf, sizeof(udp_buf),
                                     &from, 0);
            if (nrecv < (ssize_t)VPN_HEADER_SIZE) continue;

            if (from.sin_addr.s_addr != s->client_addr.sin_addr.s_addr ||
                from.sin_port        != s->client_addr.sin_port) {
                fprintf(stderr, "⚠️  Unknown source — dropped\n"); continue;
            }

            vpn_packet_header_t *hdr = (vpn_packet_header_t *)udp_buf;
            if (ntohl(hdr->magic) != VPN_MAGIC) {
                fprintf(stderr, "⚠️  Bad magic — discarded\n"); continue;
            }

            last_rx_time = time(NULL);

            uint64_t recv_seq = be64toh(hdr->sequence);

            if (hdr->type == PKT_TYPE_KEEPALIVE) {
                uint8_t ka[8];
                aes_gcm_decrypt(s->session_key,
                                udp_buf + VPN_HEADER_SIZE,
                                (int)(nrecv - VPN_HEADER_SIZE),
                                hdr->iv, hdr->tag, ka);
                s->keepalives_recv++;
                printf("💓 Keepalive seq=%lu\n", (unsigned long)recv_seq);
                continue;
            }

            if (!check_sequence(recv_seq, &s->rx_expected, &s->rx_bitmap)) {
                s->replays_blocked++; continue;
            }

            uint8_t plaintext[MAX_TUN_PAYLOAD];
            int pt_len = aes_gcm_decrypt(s->session_key,
                                         udp_buf + VPN_HEADER_SIZE,
                                         (int)(nrecv - VPN_HEADER_SIZE),
                                         hdr->iv, hdr->tag, plaintext);
            if (pt_len < 0) {
                fprintf(stderr, "❌ Decrypt failed seq %lu\n",
                        (unsigned long)recv_seq);
                continue;
            }

            if (tun_write(tun, plaintext, (size_t)pt_len) < 0) continue;

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
    printf("║        ML-DSA-65 Cert Auth + AES-256-GCM + Keepalive    ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    tun_device_t  tun;
    int           udp_sock = -1;
    session_t     session;
    uint8_t       ca_pubkey[CERT_PUBKEY_LEN];
    pqc_cert_t    server_cert;

    memset(&tun,     0, sizeof(tun));
    session_reset(&session);
    tun.fd = -1;

    // 1. Load CA public key
    printf("1️⃣  Loading CA public key from '%s'...\n", CA_CERT_PATH);
    if (cert_load_ca_pubkey(ca_pubkey) != 0) {
        fprintf(stderr, "❌ Failed — run ./bin/gen_ca first\n");
        return 1;
    }
    printf("   ✅ CA public key loaded\n\n");

    // 2. Load server certificate
    printf("2️⃣  Loading server certificate from '%s'...\n", SERVER_CERT_PATH);
    if (cert_load(SERVER_CERT_PATH, &server_cert) != 0) {
        fprintf(stderr, "❌ Failed — run ./bin/gen_cert server first\n");
        return 1;
    }
    // Verify our own cert is still valid
    if (cert_verify(&server_cert, ca_pubkey) != 0) {
        fprintf(stderr, "❌ Server certificate is invalid or expired\n");
        return 1;
    }
    printf("   ✅ Server certificate valid\n");
    cert_print(&server_cert);
    printf("\n");

    // 3. TUN interface
    printf("3️⃣  Creating TUN '%s'...\n", TUN_NAME);
    if (tun_create(&tun, TUN_NAME) != 0) {
        fprintf(stderr, "❌ TUN failed (run as root)\n"); goto shutdown;
    }
    if (tun_set_ip(&tun, SERVER_TUN_IP, CLIENT_TUN_IP, NETMASK) != 0)
        goto shutdown;
    if (tun_up(&tun) != 0) goto shutdown;
    printf("\n");

    // 4. UDP socket
    printf("4️⃣  Binding UDP on port %d...\n", VPN_PORT);
    udp_sock = create_udp_socket(VPN_PORT);
    if (udp_sock < 0) {
        fprintf(stderr, "❌ UDP socket failed\n"); goto shutdown;
    }
    printf("   ✅ Listening on 0.0.0.0:%d\n\n", VPN_PORT);

    // 5. Session loop
    int session_count = 0;

    while (running) {
        session_count++;
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        printf("🔵 Session #%d — waiting for client...\n\n", session_count);

        session_reset(&session);
        flush_udp_socket(udp_sock);

        if (perform_handshake(udp_sock, &session,
                              ca_pubkey, &server_cert) != 0) {
            fprintf(stderr, "⚠️  Handshake failed — waiting for next client\n\n");
            sleep(RECONNECT_DELAY_SEC);
            continue;
        }

        if (init_nonce_state(&session.tx_nonce) != 0) {
            fprintf(stderr, "❌ Nonce init failed\n");
            session_reset(&session);
            sleep(RECONNECT_DELAY_SEC);
            continue;
        }

        printf("🔒 Security:\n");
        printf("   Auth    : ML-DSA-65 certificates\n");
        printf("   KEM     : ML-KEM-768\n");
        printf("   Cipher  : AES-256-GCM\n");
        printf("   Replay  : %d-packet window\n\n", SEQUENCE_WINDOW);

        run_tunnel(udp_sock, &tun, &session);

        printf("\n🔴 Session #%d ended\n", session_count);
        session_print_stats(&session);
        session_reset(&session);

        if (!running) break;
        printf("⏳ %ds before next client...\n\n", RECONNECT_DELAY_SEC);
        sleep(RECONNECT_DELAY_SEC);
    }

shutdown:
    printf("\n🧹 Shutting down...\n");
    session_reset(&session);
    if (tun.fd >= 0) { tun_down(&tun); tun_close(&tun); }
    if (udp_sock >= 0) close(udp_sock);
    printf("✅ Server stopped after %d session(s)\n", session_count);
    return 0;
}