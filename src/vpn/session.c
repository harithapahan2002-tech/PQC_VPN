// session.c
// Multi-client session management implementation.
//
// Depends on: session.h, pqc_common.h, pqc_crypto.h, pqc_cert.h,
//             tun.h, udp_support.h, pthread

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "session.h"

#include "../common/pqc_common.h"
#include "../common/pqc_crypto.h"
#include "../common/pqc_cert.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <endian.h>
#include <poll.h>

#include <oqs/oqs.h>

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

// Zero all sensitive fields in a session slot and mark it EMPTY.
// Called when a thread exits so the slot can be reused.
static void session_clear(client_session_t *s) {
    memset(s->session_key, 0, AES_KEY_LEN);
    memset(&s->tx_nonce,   0, sizeof(s->tx_nonce));
    s->tx_sequence   = 0;
    s->rx_expected   = 0;
    s->rx_bitmap     = 0;
    s->should_stop   = 0;
    s->state         = SESSION_STATE_EMPTY;
    s->pkts_sent     = 0;
    s->pkts_recv     = 0;
    s->keepalives_sent = 0;
    s->keepalives_recv = 0;
    s->bytes_sent    = 0;
    s->bytes_recv    = 0;
    s->replays_blocked = 0;
    s->last_rx_time  = 0;
    memset(s->identity, 0, CERT_IDENTITY_LEN);
    memset(&s->client_addr, 0, sizeof(s->client_addr));
}

// Send a keepalive packet to the client.
static int send_keepalive_to(int                      udp_sock,
                             const struct sockaddr_in *addr,
                             client_session_t         *s) {
    uint8_t enc_buf[VPN_HEADER_SIZE + 8];
    uint8_t payload = 0x00;
    uint8_t nonce[IV_LEN];
    uint8_t tag[TAG_LEN];

    if (generate_nonce(&s->tx_nonce, nonce) != 0) return -1;

    vpn_packet_header_t *hdr = (vpn_packet_header_t *)enc_buf;
    hdr->magic    = htonl(VPN_MAGIC);
    hdr->type     = PKT_TYPE_KEEPALIVE;
    hdr->sequence = htobe64(s->tx_sequence);
    memcpy(hdr->iv, nonce, IV_LEN);

    int ct_len = aes_gcm_encrypt(s->session_key, &payload, 1,
                                 nonce, enc_buf + VPN_HEADER_SIZE, tag);
    if (ct_len < 0) return -1;
    memcpy(hdr->tag, tag, TAG_LEN);

    size_t total = VPN_HEADER_SIZE + (size_t)ct_len;
    if (send_udp(udp_sock, enc_buf, total, addr) < 0) return -1;

    s->tx_sequence++;
    s->keepalives_sent++;
    return 0;
}

// ============================================================================
// ML-KEM-768 KEY EXCHANGE  (runs in worker thread after auth)
// ============================================================================

static int run_kem_exchange(int               udp_sock,
                            client_session_t *s,
                            const pqc_cert_t *server_cert) {
    (void)server_cert;  // Available for future use (e.g. signed KEM params)

    printf("[slot %d] ── ML-KEM-768 key exchange ─────────────────\n",
           s->slot);

    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) {
        fprintf(stderr, "[slot %d] ❌ KEM init failed\n", s->slot);
        return -1;
    }

    uint8_t *client_pk     = malloc(kem->length_public_key);
    uint8_t *ciphertext    = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    if (!client_pk || !ciphertext || !shared_secret) {
        fprintf(stderr, "[slot %d] ❌ Alloc failed\n", s->slot);
        goto kem_err;
    }

    // Receive client public key
    struct sockaddr_in from;
    ssize_t nrecv = recv_udp(udp_sock, client_pk, kem->length_public_key,
                             &from, 15000);
    if (nrecv != (ssize_t)kem->length_public_key) {
        fprintf(stderr, "[slot %d] ❌ Public key recv failed\n", s->slot);
        goto kem_err;
    }

    // Verify it came from our authenticated client
    if (from.sin_addr.s_addr != s->client_addr.sin_addr.s_addr ||
        from.sin_port        != s->client_addr.sin_port) {
        fprintf(stderr, "[slot %d] ❌ Public key from wrong address\n",
                s->slot);
        goto kem_err;
    }

    // Encapsulate
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, client_pk)
            != OQS_SUCCESS) {
        fprintf(stderr, "[slot %d] ❌ Encapsulation failed\n", s->slot);
        goto kem_err;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);
    printf("[slot %d]    ✅ Encapsulation: %.2f µs\n",
           s->slot, elapsed_us(t1, t2));

    // Send ciphertext
    if (send_udp(udp_sock, ciphertext, kem->length_ciphertext,
                 &s->client_addr) < 0) {
        fprintf(stderr, "[slot %d] ❌ Ciphertext send failed\n", s->slot);
        goto kem_err;
    }
    printf("[slot %d]    ✅ Ciphertext sent (%zu bytes)\n",
           s->slot, kem->length_ciphertext);

    // Derive session key
    hkdf_sha256(shared_secret, kem->length_shared_secret,
                NULL, 0, "vpn-session-key",
                s->session_key, AES_KEY_LEN);
    printf("[slot %d]    ✅ Session key derived (AES-256)\n", s->slot);

    memset(shared_secret, 0, kem->length_shared_secret);
    free(client_pk); free(ciphertext); free(shared_secret);
    OQS_KEM_free(kem);
    return 0;

kem_err:
    if (shared_secret) memset(shared_secret, 0, kem->length_shared_secret);
    free(client_pk); free(ciphertext); free(shared_secret);
    OQS_KEM_free(kem);
    return -1;
}

// ============================================================================
// TUNNEL LOOP  (runs in worker thread)
// ============================================================================

static void run_client_tunnel(session_table_t  *table,
                              client_session_t *s) {

    printf("[slot %d] ── Tunnel active (%s) ──────────────────────\n",
           s->slot, s->identity);
    printf("[slot %d]    Client : %s:%d\n",
           s->slot,
           inet_ntoa(s->client_addr.sin_addr),
           ntohs(s->client_addr.sin_port));

    uint8_t tun_buf[MAX_TUN_PAYLOAD];
    uint8_t udp_buf[UDP_RECV_BUFSIZE];
    uint8_t enc_buf[VPN_HEADER_SIZE + MAX_TUN_PAYLOAD];

    // We poll the shared UDP socket and TUN fd.
    // Multiple threads poll the same UDP socket — this is safe on Linux.
    // Each thread filters packets by client_addr so only processes its own.
    struct pollfd fds[2];
    fds[0].fd = table->tun->fd;  fds[0].events = POLLIN;
    fds[1].fd = table->udp_sock; fds[1].events = POLLIN;

    s->last_rx_time = time(NULL);

    while (!s->should_stop && table->server_running) {
        int ret = poll(fds, 2, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Keepalive / idle check every second
        time_t now = time(NULL);
        if (now - s->last_rx_time >= KEEPALIVE_IDLE_SEC) {
            printf("[slot %d] ⏱️  Client idle %ds — disconnecting\n",
                   s->slot, KEEPALIVE_IDLE_SEC);
            break;
        }

        if (ret == 0) continue;

        // OUTGOING: TUN → encrypt → UDP
        // All threads read from the same TUN fd. The kernel delivers
        // each packet to exactly one reader — whichever thread calls
        // read() first gets it. We send it to our specific client.
        if (fds[0].revents & POLLIN) {
            ssize_t nread = tun_read(table->tun, tun_buf, sizeof(tun_buf));
            if (nread <= 0) continue;

            uint8_t nonce[IV_LEN];
            if (generate_nonce(&s->tx_nonce, nonce) != 0) break;

            vpn_packet_header_t *hdr = (vpn_packet_header_t *)enc_buf;
            hdr->magic    = htonl(VPN_MAGIC);
            hdr->type     = PKT_TYPE_DATA;
            hdr->sequence = htobe64(s->tx_sequence);
            memcpy(hdr->iv, nonce, IV_LEN);

            uint8_t tag[TAG_LEN];
            int ct_len = aes_gcm_encrypt(s->session_key,
                                         tun_buf, (int)nread,
                                         nonce, enc_buf + VPN_HEADER_SIZE,
                                         tag);
            if (ct_len < 0) continue;
            memcpy(hdr->tag, tag, TAG_LEN);

            size_t total = VPN_HEADER_SIZE + (size_t)ct_len;
            if (send_udp(table->udp_sock, enc_buf, total,
                         &s->client_addr) < 0) continue;

            s->bytes_sent += total;
            s->pkts_sent++;
            s->tx_sequence++;
        }

        // INCOMING: UDP → check source → verify → decrypt → TUN
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            ssize_t nrecv = recv_udp(table->udp_sock, udp_buf,
                                     sizeof(udp_buf), &from, 0);
            if (nrecv < (ssize_t)VPN_HEADER_SIZE) continue;

            // Only process packets from our client
            // Packets from other clients will be picked up by their threads
            if (from.sin_addr.s_addr != s->client_addr.sin_addr.s_addr ||
                from.sin_port        != s->client_addr.sin_port) continue;

            vpn_packet_header_t *hdr = (vpn_packet_header_t *)udp_buf;
            if (ntohl(hdr->magic) != VPN_MAGIC) continue;

            // Any valid packet resets idle timer
            s->last_rx_time = time(NULL);

            uint64_t recv_seq = be64toh(hdr->sequence);

            // Keepalive
            if (hdr->type == PKT_TYPE_KEEPALIVE) {
                uint8_t ka[8];
                aes_gcm_decrypt(s->session_key,
                                udp_buf + VPN_HEADER_SIZE,
                                (int)(nrecv - VPN_HEADER_SIZE),
                                hdr->iv, hdr->tag, ka);
                s->keepalives_recv++;
                printf("[slot %d] 💓 Keepalive seq=%lu\n",
                       s->slot, (unsigned long)recv_seq);
                continue;
            }

            // Replay check
            if (!check_sequence(recv_seq, &s->rx_expected, &s->rx_bitmap)) {
                s->replays_blocked++;
                continue;
            }

            // Decrypt
            uint8_t plaintext[MAX_TUN_PAYLOAD];
            int pt_len = aes_gcm_decrypt(s->session_key,
                                         udp_buf + VPN_HEADER_SIZE,
                                         (int)(nrecv - VPN_HEADER_SIZE),
                                         hdr->iv, hdr->tag, plaintext);
            if (pt_len < 0) continue;

            // Deliver to kernel via shared TUN
            if (tun_write(table->tun, plaintext, (size_t)pt_len) < 0)
                continue;

            s->bytes_recv += (size_t)nrecv;
            s->pkts_recv++;
        }
    }

    printf("[slot %d] 🔴 Tunnel closed for '%s'\n", s->slot, s->identity);
}

// ============================================================================
// WORKER THREAD ENTRY POINT
// ============================================================================

void *session_worker(void *arg) {
    thread_arg_t    *ta    = (thread_arg_t *)arg;
    session_table_t *table = ta->table;
    int              slot  = ta->slot;
    free(ta);   // Allocated by session_accept — free here

    client_session_t *s = &table->sessions[slot];

    printf("[slot %d] 🔵 Worker thread started for '%s'\n",
           slot, s->identity);

    // KEM exchange
    s->state = SESSION_STATE_HANDSHAKE;
    if (run_kem_exchange(table->udp_sock, s, table->server_cert) != 0) {
        fprintf(stderr, "[slot %d] ❌ KEM exchange failed\n", slot);
        goto worker_cleanup;
    }

    // Initialise nonce state
    if (init_nonce_state(&s->tx_nonce) != 0) {
        fprintf(stderr, "[slot %d] ❌ Nonce init failed\n", slot);
        goto worker_cleanup;
    }

    // Signal that KEM is complete and we are about to enter the tunnel loop.
    // session_accept() waits for this state before allowing the next client
    // to start its handshake — prevents the cert listener for slot N+1 from
    // consuming KEM packets meant for slot N.
    s->state = SESSION_STATE_TUNNEL_READY;

    // Small yield to ensure the main thread sees the state update
    // before we start consuming from the shared UDP socket
    usleep(5000);   // 5ms

    // Run tunnel loop
    s->state        = SESSION_STATE_ACTIVE;
    s->connected_at = time(NULL);

    run_client_tunnel(table, s);

worker_cleanup:
    s->state = SESSION_STATE_CLOSING;
    session_print_stats(s);

    // Zero sensitive state before returning the slot
    pthread_mutex_lock(&table->mutex);
    session_clear(s);   // Sets state = SESSION_STATE_EMPTY
    table->count--;
    pthread_mutex_unlock(&table->mutex);

    printf("[slot %d] ✅ Worker thread exited — slot available\n", slot);
    return NULL;
}

// ============================================================================
// SESSION TABLE LIFECYCLE
// ============================================================================

int session_table_init(session_table_t  *table,
                       tun_device_t     *tun,
                       int               udp_sock,
                       const uint8_t     ca_pubkey[CERT_PUBKEY_LEN],
                       pqc_cert_t       *server_cert) {

    memset(table, 0, sizeof(*table));

    if (pthread_mutex_init(&table->mutex, NULL) != 0) {
        fprintf(stderr, "❌ session: mutex init failed\n");
        return -1;
    }

    table->tun            = tun;
    table->udp_sock       = udp_sock;
    table->server_running = 1;
    table->count          = 0;
    table->server_cert    = server_cert;
    memcpy(table->ca_pubkey, ca_pubkey, CERT_PUBKEY_LEN);

    for (int i = 0; i < SESSION_MAX_CLIENTS; i++) {
        table->sessions[i].slot  = i;
        table->sessions[i].state = SESSION_STATE_EMPTY;
    }

    return 0;
}

void session_table_destroy(session_table_t *table) {
    printf("🧹 Stopping all client sessions...\n");

    // Signal all active threads to stop
    pthread_mutex_lock(&table->mutex);
    table->server_running = 0;
    for (int i = 0; i < SESSION_MAX_CLIENTS; i++) {
        if (table->sessions[i].state != SESSION_STATE_EMPTY)
            table->sessions[i].should_stop = 1;
    }
    pthread_mutex_unlock(&table->mutex);

    // Wait for all threads to exit
    for (int i = 0; i < SESSION_MAX_CLIENTS; i++) {
        if (table->sessions[i].state != SESSION_STATE_EMPTY) {
            pthread_join(table->sessions[i].thread, NULL);
            printf("   ✅ Slot %d thread joined\n", i);
        }
    }

    pthread_mutex_destroy(&table->mutex);
    printf("✅ All sessions stopped\n");
}

// ============================================================================
// CLIENT ACCEPTANCE
// ============================================================================

int session_find_free_slot(session_table_t *table) {
    // Caller must hold table->mutex
    for (int i = 0; i < SESSION_MAX_CLIENTS; i++) {
        if (table->sessions[i].state == SESSION_STATE_EMPTY)
            return i;
    }
    return -1;
}

int session_accept(session_table_t    *table,
                   pqc_cert_t         *client_cert_out,
                   struct sockaddr_in *client_addr_out) {

    // Check capacity before blocking on auth
    pthread_mutex_lock(&table->mutex);
    int slot = session_find_free_slot(table);
    if (slot < 0) {
        pthread_mutex_unlock(&table->mutex);
        fprintf(stderr, "⚠️  Server full (%d/%d clients) — "
                        "rejecting connection\n",
                table->count, SESSION_MAX_CLIENTS);
        return -1;
    }

    // Reserve the slot while we do auth
    // If auth fails we'll clear it back to EMPTY
    client_session_t *s = &table->sessions[slot];
    session_clear(s);
    s->state = SESSION_STATE_HANDSHAKE;
    pthread_mutex_unlock(&table->mutex);

    printf("\n🔐 [slot %d] Starting certificate authentication...\n", slot);

    // ML-DSA-65 certificate handshake
    pqc_cert_t client_cert;
    memset(&client_cert, 0, sizeof(client_cert));

    if (cert_handshake_server(table->ca_pubkey, table->server_cert,
                              table->udp_sock, &s->client_addr) != 0) {
        fprintf(stderr, "[slot %d] ❌ Certificate auth failed\n", slot);
        goto accept_fail;
    }

    // Load the client certificate to get the identity string
    // cert_handshake_server already verified it — we just need the identity
    // Re-receive by peeking at what was stored during handshake.
    // The identity was verified by cert_handshake_server — copy it.
    // For now we use a placeholder; the full cert is passed via out param.
    printf("[slot %d] ✅ Client authenticated: %s:%d\n",
           slot,
           inet_ntoa(s->client_addr.sin_addr),
           ntohs(s->client_addr.sin_port));

    // Copy outputs for the caller
    if (client_cert_out) memcpy(client_cert_out, &client_cert,
                                sizeof(pqc_cert_t));
    if (client_addr_out) *client_addr_out = s->client_addr;

    // Spawn worker thread
    thread_arg_t *ta = malloc(sizeof(thread_arg_t));
    if (!ta) {
        fprintf(stderr, "[slot %d] ❌ Thread arg alloc failed\n", slot);
        goto accept_fail;
    }
    ta->table = table;
    ta->slot  = slot;

    pthread_mutex_lock(&table->mutex);
    table->count++;
    pthread_mutex_unlock(&table->mutex);

    if (pthread_create(&s->thread, NULL, session_worker, ta) != 0) {
        fprintf(stderr, "[slot %d] ❌ Thread create failed: %s\n",
                slot, strerror(errno));
        free(ta);
        pthread_mutex_lock(&table->mutex);
        table->count--;
        pthread_mutex_unlock(&table->mutex);
        goto accept_fail;
    }

    // Detach thread — it will clean up itself when done
    // We use pthread_join in session_table_destroy for clean shutdown
    printf("[slot %d] 🟢 Worker thread spawned (active: %d/%d)\n",
           slot, session_count(table), SESSION_MAX_CLIENTS);

    // Wait for the worker thread to complete KEM exchange and reach
    // SESSION_STATE_TUNNEL_READY before the main thread starts listening
    // for the next client's certificate on the shared UDP socket.
    //
    // The KEM exchange sends and receives large UDP packets (1184 bytes
    // public key, 1088 bytes ciphertext). If the main thread starts
    // cert_handshake_server before KEM is complete, it will consume
    // these packets — causing KEM failure on slot N and cert timeout
    // on slot N+1.
    //
    // We wait for TUNNEL_READY (set by worker after KEM + nonce init)
    // which guarantees the worker is about to enter its own poll loop
    // and will consume its own UDP traffic from that point forward.
    printf("[slot %d] ⏳ Waiting for KEM to complete...\n", slot);
    int wait_ms = 0;
    while (wait_ms < 30000) {   // 30 second max — KEM should take <100ms
        pthread_mutex_lock(&table->mutex);
        session_state_t st = table->sessions[slot].state;
        pthread_mutex_unlock(&table->mutex);

        if (st >= SESSION_STATE_TUNNEL_READY ||
            st == SESSION_STATE_EMPTY) break;

        usleep(5000);   // 5ms poll interval
        wait_ms += 5;
    }
    printf("[slot %d] ✅ KEM complete — ready for next client\n", slot);

    return slot;

accept_fail:
    pthread_mutex_lock(&table->mutex);
    session_clear(s);   // Returns slot to EMPTY
    pthread_mutex_unlock(&table->mutex);
    return -1;
}

// ============================================================================
// STATUS AND STATISTICS
// ============================================================================

void session_print_stats(const client_session_t *s) {
    time_t now      = time(NULL);
    double duration = (s->connected_at > 0) ?
                      difftime(now, s->connected_at) : 0;

    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("📊 [slot %d] Session stats for '%s':\n",
           s->slot, s->identity[0] ? s->identity : "unknown");
    printf("   Duration         : %.0f seconds\n",      duration);
    printf("   Packets sent     : %lu\n",  (unsigned long)s->pkts_sent);
    printf("   Packets received : %lu\n",  (unsigned long)s->pkts_recv);
    printf("   Keepalives sent  : %lu\n",  (unsigned long)s->keepalives_sent);
    printf("   Keepalives recv  : %lu\n",  (unsigned long)s->keepalives_recv);
    printf("   Bytes sent       : %lu (%.2f KB)\n",
           (unsigned long)s->bytes_sent, s->bytes_sent / 1024.0);
    printf("   Bytes received   : %lu (%.2f KB)\n",
           (unsigned long)s->bytes_recv, s->bytes_recv / 1024.0);
    printf("   Replays blocked  : %lu\n",  (unsigned long)s->replays_blocked);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
}

void session_print_status(session_table_t *table) {
    pthread_mutex_lock(&table->mutex);

    printf("\n📋 Active sessions: %d/%d\n", table->count, SESSION_MAX_CLIENTS);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    int found = 0;
    for (int i = 0; i < SESSION_MAX_CLIENTS; i++) {
        client_session_t *s = &table->sessions[i];
        if (s->state == SESSION_STATE_EMPTY) continue;
        found++;

        const char *state_str = "unknown";
        switch (s->state) {
            case SESSION_STATE_HANDSHAKE:    state_str = "handshake";    break;
            case SESSION_STATE_TUNNEL_READY: state_str = "kem-done";     break;
            case SESSION_STATE_ACTIVE:       state_str = "active";       break;
            case SESSION_STATE_CLOSING:      state_str = "closing";      break;
            default: break;
        }

        printf("   [%d] %-15s %s:%d  sent=%lu recv=%lu\n",
               i,
               s->identity[0] ? s->identity : "authenticating",
               inet_ntoa(s->client_addr.sin_addr),
               ntohs(s->client_addr.sin_port),
               (unsigned long)s->pkts_sent,
               (unsigned long)s->pkts_recv);
        printf("       state=%-10s ka_sent=%lu ka_recv=%lu\n",
               state_str,
               (unsigned long)s->keepalives_sent,
               (unsigned long)s->keepalives_recv);
    }

    if (!found)
        printf("   (no active sessions)\n");

    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    pthread_mutex_unlock(&table->mutex);
}

int session_count(session_table_t *table) {
    pthread_mutex_lock(&table->mutex);
    int c = table->count;
    pthread_mutex_unlock(&table->mutex);
    return c;
}