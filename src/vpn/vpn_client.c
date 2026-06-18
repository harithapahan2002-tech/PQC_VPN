// vpn_client.c
// Post-Quantum VPN Client
// ML-KEM-768 + ML-DSA-65 cert auth + AES-256-GCM + keepalive

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
// CONFIGURATION DEFAULTS  (overridable via command-line arguments)
// ============================================================================

// SERVER_IP: 127.0.0.1  for local testing
//            10.0.5.1   for namespace testing
//            <VM IP>    for cloud deployment
#define DEFAULT_SERVER_IP    "127.0.0.1"
#define DEFAULT_TUN_NAME     "tun1"
#define DEFAULT_CLIENT_IP    "10.8.0.2"
#define DEFAULT_SERVER_TUN   "10.8.0.1"
#define DEFAULT_NETMASK      "255.255.255.0"
#define DEFAULT_CERT_PATH    CLIENT_CERT_PATH
#define DEFAULT_KEY_PATH     CLIENT_KEY_PATH

#define VPN_DNS_SERVER   "8.8.8.8"
#define RESOLV_CONF      "/etc/resolv.conf"
#define RESOLV_CONF_BAK  "/etc/resolv.conf.vpn_backup"

// ============================================================================
// GLOBAL STATE
// ============================================================================

static volatile sig_atomic_t running = 1;
static int route_applied = 0;
static int dns_applied   = 0;

static void handle_sigint(int sig) { (void)sig; running = 0; }

// ============================================================================
// ROUTING HELPERS
// ============================================================================

static int run_cmd(const char *cmd) {
    int ret = system(cmd);
    if (ret != 0) fprintf(stderr, "   ⚠️  Command failed: %s\n", cmd);
    return (ret == 0) ? 0 : -1;
}

static int save_default_route(char *buf, size_t len) {
    FILE *f = popen("ip route show default 2>/dev/null", "r");
    if (!f) return -1;
    int found = (fgets(buf, (int)len, f) != NULL);
    pclose(f);
    if (!found || strlen(buf) == 0) return -1;
    // Strip trailing newline
    size_t l = strlen(buf);
    if (l > 0 && buf[l-1] == '\n') buf[l-1] = '\0';
    return 0;
}

static int extract_gateway(const char *route, char *gw, size_t gw_len) {
    // Parse "default via X.X.X.X dev ..." — extract X.X.X.X
    const char *via = strstr(route, " via ");
    if (!via) return -1;
    via += 5;   // " via " is 5 characters: space-v-i-a-space
    size_t i = 0;
    // NOTE: 'gw[i] = via[i++]' was used previously — this is undefined
    // behaviour in C because the order of evaluation between the
    // assignment's left side and the increment in via[i++] is
    // unspecified by the standard. On this compiler it silently
    // produced an empty string. Incrementing on a separate line
    // removes the ambiguity entirely.
    while (via[i] && via[i] != ' ' && via[i] != '\n' && i < gw_len - 1) {
        gw[i] = via[i];
        i++;
    }
    gw[i] = '\0';
    if (i == 0) return -1;
    printf("   ✅ Detected gateway: %s\n", gw);
    return 0;
}

static int route_add_vpn(const char *server_ip,  const char *orig_gw,
                         const char *server_tun,  const char *tun_name) {
    char cmd[512];

    // CRITICAL: this host route MUST succeed before the default route
    // is changed, or all traffic — including the client's own handshake
    // and tunnel UDP packets to server_ip — gets routed back into the
    // tunnel, creating an infinite encrypt-and-resend loop.
    //
    // Use 'replace' instead of 'add': 'add' fails silently (suppressed
    // by 2>/dev/null) if a route to server_ip already exists from a
    // previous run, leaving stale state. 'replace' always succeeds in
    // setting the correct gateway, whether or not a route pre-exists.
    snprintf(cmd, sizeof(cmd),
             "ip route replace %s via %s", server_ip, orig_gw);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "   ❌ CRITICAL: failed to add host route for %s — "
                        "aborting to prevent routing loop\n", server_ip);
        return -1;
    }

    // Verify the host route actually points where we expect before
    // proceeding. This catches cases where 'ip route replace' succeeded
    // but the kernel resolved it differently than intended.
    snprintf(cmd, sizeof(cmd),
             "ip route get %s | grep -q 'via %s'", server_ip, orig_gw);
    if (run_cmd(cmd) != 0) {
        fprintf(stderr, "   ❌ CRITICAL: host route verification failed — "
                        "aborting to prevent routing loop\n");
        return -1;
    }
    printf("   ✅ Host route confirmed: %s via %s (bypasses tunnel)\n",
           server_ip, orig_gw);

    // Only now is it safe to make the tunnel the default route
    snprintf(cmd, sizeof(cmd),
             "ip route replace default via %s dev %s metric 50",
             server_tun, tun_name);
    if (run_cmd(cmd) != 0) return -1;
    printf("   ✅ Default route → tunnel (%s via %s)\n", tun_name, server_tun);
    return 0;
}

static void route_remove_vpn(const char *server_ip,  const char *server_tun,
                              const char *tun_name) {
    char cmd[512];
    // Remove tunnel default route FIRST — restores normal routing
    // immediately, before we touch the host route exception.
    snprintf(cmd, sizeof(cmd),
             "ip route del default via %s dev %s metric 50 2>/dev/null || true",
             server_tun, tun_name);
    run_cmd(cmd);

    // Remove the host route exception for the server IP
    snprintf(cmd, sizeof(cmd),
             "ip route del %s 2>/dev/null || true", server_ip);
    run_cmd(cmd);

    printf("   ✅ Original routing restored\n");
}

// ============================================================================
// DNS HELPERS
// ============================================================================

static int dns_apply(void) {
    if (run_cmd("cp " RESOLV_CONF " " RESOLV_CONF_BAK " 2>/dev/null") != 0)
        return -1;
    FILE *f = fopen(RESOLV_CONF, "w");
    if (!f) return -1;
    fprintf(f, "# vpn_client — original at %s\nnameserver %s\n",
            RESOLV_CONF_BAK, VPN_DNS_SERVER);
    fclose(f);
    printf("   ✅ DNS → %s\n", VPN_DNS_SERVER);
    return 0;
}

static void dns_restore(void) {
    if (run_cmd("mv " RESOLV_CONF_BAK " " RESOLV_CONF " 2>/dev/null") == 0)
        printf("   ✅ DNS restored\n");
    else
        fprintf(stderr, "   ⚠️  DNS restore failed — check %s\n",
                RESOLV_CONF_BAK);
}

// ============================================================================
// KEEPALIVE
// ============================================================================

static int send_keepalive(int                      udp_sock,
                          const struct sockaddr_in *server_addr,
                          uint8_t                   session_key[AES_KEY_LEN],
                          nonce_state_t             *tx_nonce,
                          uint64_t                 *tx_sequence) {
    uint8_t enc_buf[VPN_HEADER_SIZE + 8];
    uint8_t payload = 0x00;
    uint8_t nonce[IV_LEN];
    uint8_t tag[TAG_LEN];

    if (generate_nonce(tx_nonce, nonce) != 0) return -1;

    vpn_packet_header_t *hdr = (vpn_packet_header_t *)enc_buf;
    hdr->magic    = htonl(VPN_MAGIC);
    hdr->type     = PKT_TYPE_KEEPALIVE;
    hdr->sequence = htobe64(*tx_sequence);
    memcpy(hdr->iv, nonce, IV_LEN);

    int ct_len = aes_gcm_encrypt(session_key, &payload, 1,
                                 nonce, enc_buf + VPN_HEADER_SIZE, tag);
    if (ct_len < 0) return -1;
    memcpy(hdr->tag, tag, TAG_LEN);

    size_t total = VPN_HEADER_SIZE + (size_t)ct_len;
    if (send_udp(udp_sock, enc_buf, total, server_addr) < 0) return -1;

    (*tx_sequence)++;
    return 0;
}

// ============================================================================
// HANDSHAKE
// ============================================================================

static int perform_handshake(int                      udp_sock,
                             const struct sockaddr_in *server_addr,
                             uint8_t                   session_key[AES_KEY_LEN],
                             const uint8_t             ca_pubkey[CERT_PUBKEY_LEN],
                             const pqc_cert_t         *client_cert) {

    printf("\n🔐 Starting handshake...\n");

    // ------------------------------------------------------------------
    // Phase 1: ML-DSA-65 certificate exchange
    // ------------------------------------------------------------------
    printf("\n── Phase 1: Certificate authentication (ML-DSA-65) ──────\n");

    if (cert_handshake_client(ca_pubkey, client_cert,
                              udp_sock, server_addr) != 0) {
        fprintf(stderr, "❌ Certificate authentication failed\n");
        return -1;
    }
    printf("✅ Server authenticated via ML-DSA-65 certificate\n");

    // ------------------------------------------------------------------
    // Phase 2: ML-KEM-768 key exchange
    // ------------------------------------------------------------------
    printf("\n── Phase 2: ML-KEM-768 key exchange ─────────────────────\n");

    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) { fprintf(stderr, "❌ KEM init failed\n"); return -1; }

    uint8_t *client_pk     = malloc(kem->length_public_key);
    uint8_t *client_sk     = malloc(kem->length_secret_key);
    uint8_t *ciphertext    = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    if (!client_pk || !client_sk || !ciphertext || !shared_secret) {
        fprintf(stderr, "❌ Alloc failed\n"); goto kem_error;
    }

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (OQS_KEM_keypair(kem, client_pk, client_sk) != OQS_SUCCESS) {
        fprintf(stderr, "❌ Keypair failed\n"); goto kem_error;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);
    printf("   ✅ Keypair: %.2f µs\n", elapsed_us(t1, t2));

    if (send_udp(udp_sock, client_pk, kem->length_public_key,
                 server_addr) < 0) {
        fprintf(stderr, "❌ Public key send failed\n"); goto kem_error;
    }
    printf("   ✅ Public key sent (%zu bytes)\n", kem->length_public_key);

    struct sockaddr_in from;
    ssize_t nrecv = recv_udp(udp_sock, ciphertext, kem->length_ciphertext,
                             &from, 15000);
    if (nrecv != (ssize_t)kem->length_ciphertext) {
        fprintf(stderr, "❌ Ciphertext recv failed\n"); goto kem_error;
    }
    printf("   ✅ Ciphertext received (%zu bytes)\n", kem->length_ciphertext);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, client_sk)
            != OQS_SUCCESS) {
        fprintf(stderr, "❌ Decapsulation failed\n"); goto kem_error;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);
    printf("   ✅ Decapsulation: %.2f µs\n", elapsed_us(t1, t2));

    // ------------------------------------------------------------------
    // Phase 3: Session key derivation
    // ------------------------------------------------------------------
    printf("\n── Phase 3: Session key derivation ──────────────────────\n");
    hkdf_sha256(shared_secret, kem->length_shared_secret,
                NULL, 0, "vpn-session-key", session_key, AES_KEY_LEN);
    printf("   ✅ Session key derived (AES-256)\n");

    memset(client_sk,     0, kem->length_secret_key);
    memset(shared_secret, 0, kem->length_shared_secret);
    free(client_pk); free(client_sk); free(ciphertext); free(shared_secret);
    OQS_KEM_free(kem);

    printf("\n✅ Handshake complete\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    return 0;

kem_error:
    if (client_sk)     memset(client_sk,     0, kem->length_secret_key);
    if (shared_secret) memset(shared_secret, 0, kem->length_shared_secret);
    free(client_pk); free(client_sk); free(ciphertext); free(shared_secret);
    OQS_KEM_free(kem);
    return -1;
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    // Runtime configuration — can be overridden via command-line
    const char *server_ip   = DEFAULT_SERVER_IP;
    const char *tun_name    = DEFAULT_TUN_NAME;
    const char *client_ip   = DEFAULT_CLIENT_IP;
    const char *server_tun  = DEFAULT_SERVER_TUN;
    const char *netmask     = DEFAULT_NETMASK;
    const char *cert_path   = DEFAULT_CERT_PATH;
    const char *key_path    = DEFAULT_KEY_PATH;
    (void)key_path;  // reserved for future private key use

    // Parse command-line arguments
    // Usage: vpn_client [--server IP] [--tun NAME] [--ip CLIENT_IP]
    //                   [--cert PATH]
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc)
            server_ip  = argv[++i];
        else if (strcmp(argv[i], "--tun") == 0 && i + 1 < argc)
            tun_name   = argv[++i];
        else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc)
            client_ip  = argv[++i];
        else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc)
            cert_path  = argv[++i];
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("  --server IP    VPN server IP (default: %s)\n",
                   DEFAULT_SERVER_IP);
            printf("  --tun NAME     TUN interface name (default: %s)\n",
                   DEFAULT_TUN_NAME);
            printf("  --ip IP        Client TUN IP (default: %s)\n",
                   DEFAULT_CLIENT_IP);
            printf("  --cert PATH    Client certificate (default: %s)\n",
                   DEFAULT_CERT_PATH);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s (try --help)\n", argv[i]);
            return 1;
        }
    }

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║        Post-Quantum VPN Client (ML-KEM-768)              ║\n");
    printf("║        ML-DSA-65 Cert Auth + AES-256-GCM + Keepalive    ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    tun_device_t       tun;
    int                udp_sock = -1;
    struct sockaddr_in server_addr;
    uint8_t            session_key[AES_KEY_LEN];
    uint8_t            ca_pubkey[CERT_PUBKEY_LEN];
    pqc_cert_t         client_cert;
    char               saved_route[256];
    char               saved_gateway[64];
    nonce_state_t      tx_nonce;
    uint64_t tx_sequence = 0, rx_expected = 0, rx_bitmap = 0;
    uint64_t pkts_sent = 0, pkts_recv = 0, keepalives_sent = 0;
    uint64_t bytes_sent = 0, bytes_recv = 0, replays_blocked = 0;

    memset(&tun, 0, sizeof(tun));
    memset(&server_addr, 0, sizeof(server_addr));
    memset(session_key,  0, sizeof(session_key));
    memset(saved_route,  0, sizeof(saved_route));
    memset(saved_gateway,0, sizeof(saved_gateway));
    tun.fd = -1;

    // 1. Load CA public key
    printf("1️⃣  Loading CA public key from '%s'...\n", CA_CERT_PATH);
    if (cert_load_ca_pubkey(ca_pubkey) != 0) {
        fprintf(stderr, "❌ Failed — copy ca_cert.pub from server\n");
        return 1;
    }
    printf("   ✅ CA public key loaded\n\n");

    // 2. Load client certificate and private key
    printf("2️⃣  Loading client certificate from '%s'...\n", cert_path);
    if (cert_load(cert_path, &client_cert) != 0) {
        fprintf(stderr, "❌ Failed — run ./bin/gen_cert client\n");
        return 1;
    }
    if (cert_verify(&client_cert, ca_pubkey) != 0) {
        fprintf(stderr, "❌ Client certificate is invalid or expired\n");
        return 1;
    }
    printf("   ✅ Client certificate valid\n");
    cert_print(&client_cert);
    printf("\n");

    // 3. Save network state
    printf("3️⃣  Saving network state...\n");
    if (save_default_route(saved_route, sizeof(saved_route)) == 0) {
        extract_gateway(saved_route, saved_gateway, sizeof(saved_gateway));
        if (saved_gateway[0])
            printf("   ✅ Gateway: %s\n", saved_gateway);
    }
    printf("\n");

    // 4. TUN interface
    printf("4️⃣  Creating TUN '%s'...\n", tun_name);
    if (tun_create(&tun, tun_name) != 0) {
        fprintf(stderr, "❌ TUN failed (run as root)\n"); goto cleanup;
    }
    if (tun_set_ip(&tun, client_ip, server_tun, netmask) != 0)
        goto cleanup;
    if (tun_up(&tun) != 0) goto cleanup;
    printf("\n");

    // 5. UDP socket
    printf("5️⃣  UDP socket...\n");
    udp_sock = create_udp_socket(0);
    if (udp_sock < 0) {
        fprintf(stderr, "❌ Socket failed\n"); goto cleanup;
    }
    printf("   ✅ Port %d\n\n", get_socket_port(udp_sock));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(VPN_PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "❌ Invalid server IP: %s\n", server_ip);
        goto cleanup;
    }

    // 6. Handshake
    printf("6️⃣  Connecting to %s:%d...\n", server_ip, VPN_PORT);
    if (perform_handshake(udp_sock, &server_addr, session_key,
                          ca_pubkey, &client_cert) != 0) {
        fprintf(stderr, "❌ Handshake failed\n"); goto cleanup;
    }
    if (init_nonce_state(&tx_nonce) != 0) {
        fprintf(stderr, "❌ Nonce init failed\n"); goto cleanup;
    }

    // 7. Routing
    printf("7️⃣  Configuring routing...\n");
    if (save_default_route(saved_route, sizeof(saved_route)) == 0) {
        printf("   ✅ Default route: %s\n", saved_route);
        if (extract_gateway(saved_route, saved_gateway,
                            sizeof(saved_gateway)) == 0) {
            if (route_add_vpn(server_ip, saved_gateway,
                              server_tun, tun_name) == 0)
                route_applied = 1;
        } else {
            fprintf(stderr, "   ⚠️  Could not parse gateway from route\n");
        }
    } else {
        fprintf(stderr, "   ⚠️  No default route found\n");
    }
    if (!route_applied)
        fprintf(stderr, "   ⚠️  Routing skipped — tunnel works, "
                        "internet won't route\n");
    printf("\n");

    // 8. DNS
    printf("8️⃣  Configuring DNS...\n");
    if (dns_apply() == 0) dns_applied = 1;
    printf("\n");

    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("✅ VPN connected — all traffic routing through server\n\n");
    printf("   Client : %s (%s)\n", client_ip, tun_name);
    printf("   Server : %s:%d\n",   server_ip, VPN_PORT);
    printf("   Auth   : ML-DSA-65 certificates\n");
    printf("   DNS    : %s\n",      VPN_DNS_SERVER);
    printf("   KA     : every %ds, idle timeout %ds\n\n",
           KEEPALIVE_INTERVAL_SEC, KEEPALIVE_IDLE_SEC);
    printf("   Test:  curl ifconfig.me   → should show server IP\n");
    printf("          ping google.com    → should work\n");
    printf("\n   Ctrl+C to disconnect\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    uint8_t tun_buf[MAX_TUN_PAYLOAD];
    uint8_t udp_buf[UDP_RECV_BUFSIZE];
    uint8_t enc_buf[VPN_HEADER_SIZE + MAX_TUN_PAYLOAD];

    struct pollfd fds[2];
    fds[0].fd = tun.fd;   fds[0].events = POLLIN;
    fds[1].fd = udp_sock; fds[1].events = POLLIN;

    time_t last_tx_time = time(NULL);

    while (running) {
        int ret = poll(fds, 2, 1000);
        if (ret < 0) { if (errno == EINTR) continue; perror("poll"); break; }

        // Send keepalive if idle
        if (time(NULL) - last_tx_time >= KEEPALIVE_INTERVAL_SEC) {
            if (send_keepalive(udp_sock, &server_addr, session_key,
                               &tx_nonce, &tx_sequence) == 0) {
                keepalives_sent++;
                printf("💓 Keepalive sent (#%lu)\n",
                       (unsigned long)keepalives_sent);
            }
            last_tx_time = time(NULL);
        }

        if (ret == 0) continue;

        // OUTGOING: TUN → encrypt → UDP
        if (fds[0].revents & POLLIN) {
            ssize_t nread = tun_read(&tun, tun_buf, sizeof(tun_buf));
            if (nread <= 0) continue;

            uint8_t nonce[IV_LEN];
            if (generate_nonce(&tx_nonce, nonce) != 0) {
                fprintf(stderr, "❌ Nonce failed\n"); running = 0; break;
            }

            vpn_packet_header_t *hdr = (vpn_packet_header_t *)enc_buf;
            hdr->magic    = htonl(VPN_MAGIC);
            hdr->type     = PKT_TYPE_DATA;
            hdr->sequence = htobe64(tx_sequence);
            memcpy(hdr->iv, nonce, IV_LEN);

            uint8_t tag[TAG_LEN];
            int ct_len = aes_gcm_encrypt(session_key, tun_buf, (int)nread,
                                         nonce, enc_buf + VPN_HEADER_SIZE, tag);
            if (ct_len < 0) { fprintf(stderr, "❌ Encrypt\n"); continue; }
            memcpy(hdr->tag, tag, TAG_LEN);

            size_t total = VPN_HEADER_SIZE + (size_t)ct_len;
            if (send_udp(udp_sock, enc_buf, total, &server_addr) < 0) continue;

            bytes_sent += total;
            pkts_sent++;
            tx_sequence++;
            last_tx_time = time(NULL);

            printf("📤 #%lu %zd→%zu | ", pkts_sent, nread, total);
            print_ip_packet(tun_buf, (size_t)nread);
        }

        // INCOMING: UDP → verify → decrypt → TUN
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            ssize_t nrecv = recv_udp(udp_sock, udp_buf, sizeof(udp_buf),
                                     &from, 0);
            if (nrecv < (ssize_t)VPN_HEADER_SIZE) continue;

            if (from.sin_addr.s_addr != server_addr.sin_addr.s_addr ||
                from.sin_port        != server_addr.sin_port) continue;

            vpn_packet_header_t *hdr = (vpn_packet_header_t *)udp_buf;
            if (ntohl(hdr->magic) != VPN_MAGIC) {
                fprintf(stderr, "⚠️  Bad magic — discarded\n"); continue;
            }

            if (hdr->type == PKT_TYPE_KEEPALIVE) {
                printf("💓 Server keepalive received\n"); continue;
            }

            uint64_t recv_seq = be64toh(hdr->sequence);
            if (!check_sequence(recv_seq, &rx_expected, &rx_bitmap)) {
                replays_blocked++; continue;
            }

            uint8_t plaintext[MAX_TUN_PAYLOAD];
            int pt_len = aes_gcm_decrypt(session_key,
                                         udp_buf + VPN_HEADER_SIZE,
                                         (int)(nrecv - VPN_HEADER_SIZE),
                                         hdr->iv, hdr->tag, plaintext);
            if (pt_len < 0) {
                fprintf(stderr, "❌ Decrypt\n"); continue;
            }

            if (tun_write(&tun, plaintext, (size_t)pt_len) < 0) continue;

            bytes_recv += (size_t)nrecv;
            pkts_recv++;
            printf("📥 #%lu %d bytes | ", pkts_recv, pt_len);
            print_ip_packet(plaintext, (size_t)pt_len);
        }
    }

cleanup:
    printf("\n🧹 Restoring network...\n");
    if (route_applied) route_remove_vpn(server_ip, server_tun, tun_name);
    if (dns_applied)   dns_restore();

    printf("\n📊 sent=%lu recv=%lu keepalives=%lu replays=%lu\n",
           (unsigned long)pkts_sent,       (unsigned long)pkts_recv,
           (unsigned long)keepalives_sent, (unsigned long)replays_blocked);

    memset(session_key, 0, sizeof(session_key));
    memset(&tx_nonce,   0, sizeof(tx_nonce));

    if (tun.fd >= 0) { tun_down(&tun); tun_close(&tun); }
    if (udp_sock >= 0) close(udp_sock);
    printf("✅ Stopped\n");
    return 0;
}