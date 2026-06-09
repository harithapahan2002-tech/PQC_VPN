// vpn_server.c
// Post-Quantum VPN Server — multi-client edition
//
// Uses session.h/c to handle multiple simultaneous clients.
// Each client gets its own thread with isolated crypto state.
//
// Architecture:
//   main thread: load certs → create TUN/UDP → accept loop
//   per-client:  cert auth (main) → KEM + tunnel (worker thread)

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>

#include "../common/pqc_common.h"
#include "../common/pqc_cert.h"
#include "tun.h"
#include "udp_support.h"
#include "session.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define SERVER_TUN_IP   "10.8.0.1"
#define CLIENT_TUN_IP   "10.8.0.2"
#define NETMASK         "255.255.255.0"
#define TUN_NAME        "tun0"

// ============================================================================
// GLOBAL STATE
// ============================================================================

static volatile sig_atomic_t running = 1;
static session_table_t       g_table;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
    g_table.server_running = 0;
    printf("\n🛑 Shutting down server...\n");
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║     Post-Quantum VPN Server — Multi-Client Edition       ║\n");
    printf("║     ML-DSA-65 + ML-KEM-768 + AES-256-GCM                ║\n");
    printf("║     Max clients: %-3d                                     ║\n",
           SESSION_MAX_CLIENTS);
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    tun_device_t  tun;
    int           udp_sock = -1;
    uint8_t       ca_pubkey[CERT_PUBKEY_LEN];
    pqc_cert_t    server_cert;

    memset(&tun, 0, sizeof(tun));
    tun.fd = -1;

    // -----------------------------------------------------------------------
    // 1. Load CA public key
    // -----------------------------------------------------------------------
    printf("1️⃣  Loading CA public key from '%s'...\n", CA_CERT_PATH);
    if (cert_load_ca_pubkey(ca_pubkey) != 0) {
        fprintf(stderr, "❌ Failed — run ./bin/gen_ca first\n");
        return 1;
    }
    printf("   ✅ CA public key loaded\n\n");

    // -----------------------------------------------------------------------
    // 2. Load server certificate
    // -----------------------------------------------------------------------
    printf("2️⃣  Loading server certificate from '%s'...\n", SERVER_CERT_PATH);
    if (cert_load(SERVER_CERT_PATH, &server_cert) != 0) {
        fprintf(stderr, "❌ Failed — run ./bin/gen_cert server first\n");
        return 1;
    }
    if (cert_verify(&server_cert, ca_pubkey) != 0) {
        fprintf(stderr, "❌ Server certificate invalid or expired\n");
        return 1;
    }
    printf("   ✅ Server certificate valid\n");
    cert_print(&server_cert);
    printf("\n");

    // -----------------------------------------------------------------------
    // 3. Create TUN interface
    // -----------------------------------------------------------------------
    printf("3️⃣  Creating TUN '%s'...\n", TUN_NAME);
    if (tun_create(&tun, TUN_NAME) != 0) {
        fprintf(stderr, "❌ TUN failed (run as root)\n");
        goto shutdown;
    }
    if (tun_set_ip(&tun, SERVER_TUN_IP, CLIENT_TUN_IP, NETMASK) != 0)
        goto shutdown;
    if (tun_up(&tun) != 0) goto shutdown;
    printf("\n");

    // -----------------------------------------------------------------------
    // 4. Create UDP socket
    // -----------------------------------------------------------------------
    printf("4️⃣  Binding UDP on port %d...\n", VPN_PORT);
    udp_sock = create_udp_socket(VPN_PORT);
    if (udp_sock < 0) {
        fprintf(stderr, "❌ UDP socket failed\n");
        goto shutdown;
    }
    printf("   ✅ Listening on 0.0.0.0:%d\n\n", VPN_PORT);

    // -----------------------------------------------------------------------
    // 5. Initialise session table
    // -----------------------------------------------------------------------
    if (session_table_init(&g_table, &tun, udp_sock,
                           ca_pubkey, &server_cert) != 0) {
        fprintf(stderr, "❌ Session table init failed\n");
        goto shutdown;
    }
    printf("5️⃣  Session table ready (max %d clients)\n\n",
           SESSION_MAX_CLIENTS);

    // -----------------------------------------------------------------------
    // 6. Accept loop — main thread handles auth, spawns threads per client
    // -----------------------------------------------------------------------
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("✅ Server ready — waiting for clients\n");
    printf("   TUN    : %s (%s)\n", SERVER_TUN_IP, TUN_NAME);
    printf("   Port   : %d UDP\n",  VPN_PORT);
    printf("   Auth   : ML-DSA-65 certificates\n");
    printf("   KEM    : ML-KEM-768\n");
    printf("   Cipher : AES-256-GCM\n");
    printf("   Ctrl+C to stop\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    int total_connections = 0;

    while (running) {
        printf("🔵 Waiting for client (active: %d/%d)...\n",
               session_count(&g_table), SESSION_MAX_CLIENTS);

        pqc_cert_t         client_cert;
        struct sockaddr_in client_addr;

        int slot = session_accept(&g_table, &client_cert, &client_addr);

        if (!running) break;

        if (slot < 0) {
            // Either server full or auth failed — wait briefly then retry
            sleep(1);
            continue;
        }

        total_connections++;
        printf("✅ Client accepted on slot %d "
               "(total connections: %d)\n\n",
               slot, total_connections);
    }

    // -----------------------------------------------------------------------
    // Shutdown — wait for all client threads to finish
    // -----------------------------------------------------------------------
shutdown:
    printf("\n🧹 Shutting down...\n");
    session_table_destroy(&g_table);

    if (tun.fd >= 0) { tun_down(&tun); tun_close(&tun); }
    if (udp_sock >= 0) close(udp_sock);

    printf("✅ Server stopped (handled %d total connection(s))\n",
           total_connections);
    return 0;
}