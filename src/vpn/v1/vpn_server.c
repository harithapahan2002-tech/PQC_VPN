// vpn_server.c
// Post-Quantum VPN Server - ML-KEM-768 + AES-256-GCM
// WITH SECURITY HARDENING: Replay protection, counter-based nonces

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>
#include <endian.h>
#include <oqs/oqs.h>

#include "../common/pqc_common.h"
#include "../common/pqc_crypto.h"
#include "tun.h"
#include "udp_support.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define VPN_PORT 5555
#define SERVER_TUN_IP "10.8.0.1"
#define CLIENT_TUN_IP "10.8.0.2"
#define NETMASK "255.255.255.0"

// ============================================================================
// GLOBAL STATE
// ============================================================================

static volatile int running = 1;

// Security state
static nonce_state_t tx_nonce;      // Nonce generator for sending
static uint64_t tx_sequence = 0;     // Sequence number for packets we send
static uint64_t rx_expected_seq = 0; // Expected sequence from client
static uint64_t rx_seq_bitmap = 0;   // Bitmap for replay detection

void sigint_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\n🛑 Shutting down VPN server...\n");
}

// ============================================================================
// HANDSHAKE: ML-KEM KEY EXCHANGE
// ============================================================================

int perform_handshake(int udp_sock, struct sockaddr_in *client_addr, 
                     uint8_t session_key[AES_KEY_LEN]) {
    
    printf("\n🔐 Starting PQC Handshake...\n");
    
    // Initialize ML-KEM
    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) {
        fprintf(stderr, "❌ Failed to initialize %s\n", KEM_ALG);
        return -1;
    }

    printf("   Algorithm: %s\n", KEM_ALG);
    printf("   Public key: %zu bytes\n", kem->length_public_key);
    printf("   Ciphertext: %zu bytes\n", kem->length_ciphertext);
    printf("   Shared secret: %zu bytes\n\n", kem->length_shared_secret);

    // Allocate buffers
    uint8_t *server_pk = malloc(kem->length_public_key);
    uint8_t *server_sk = malloc(kem->length_secret_key);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *client_pk = malloc(kem->length_public_key);

    if (!server_pk || !server_sk || !shared_secret || !ciphertext || !client_pk) {
        fprintf(stderr, "❌ Memory allocation failed\n");
        OQS_KEM_free(kem);
        return -1;
    }

    // Generate server keypair
    printf("1️⃣  Generating server keypair...\n");
    struct timespec ts1, ts2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    
    if (OQS_KEM_keypair(kem, server_pk, server_sk) != OQS_SUCCESS) {
        fprintf(stderr, "❌ Keypair generation failed\n");
        goto cleanup_error;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    printf("   ⏱  Keypair generation: %.2f µs\n", elapsed_time_us(ts1, ts2));

    // Receive client public key
    printf("\n2️⃣  Waiting for client public key...\n");
    ssize_t nrecv = recv_udp(udp_sock, client_pk, kem->length_public_key, 
                             client_addr, 30000);  // 30 second timeout
    
    if (nrecv != (ssize_t)kem->length_public_key) {
        fprintf(stderr, "❌ Failed to receive client public key (timeout?)\n");
        goto cleanup_error;
    }

    printf("   ✅ Received client PK from %s:%d\n", 
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));

    // Encapsulate to derive shared secret
    printf("\n3️⃣  Encapsulating shared secret...\n");
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, client_pk) != OQS_SUCCESS) {
        fprintf(stderr, "❌ Encapsulation failed\n");
        goto cleanup_error;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    printf("   ⏱  Encapsulation: %.2f µs\n", elapsed_time_us(ts1, ts2));

    // Send ciphertext to client
    printf("\n4️⃣  Sending ciphertext to client...\n");
    if (send_udp(udp_sock, ciphertext, kem->length_ciphertext, client_addr) < 0) {
        fprintf(stderr, "❌ Failed to send ciphertext\n");
        goto cleanup_error;
    }
    printf("   ✅ Sent %zu bytes\n", kem->length_ciphertext);

    // Derive AES session key from shared secret
    printf("\n5️⃣  Deriving session key...\n");
    derive_key(shared_secret, kem->length_shared_secret, 
               "VPN-SESSION-KEY", session_key, AES_KEY_LEN);
    printf("   ✅ Session key derived (256 bits)\n");

    // Cleanup
    free(server_pk);
    free(server_sk);
    free(shared_secret);
    free(ciphertext);
    free(client_pk);
    OQS_KEM_free(kem);

    printf("\n✅ PQC Handshake Complete!\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    
    // Initialize security features
    printf("🔒 Initializing security features...\n");
    init_nonce_state(&tx_nonce);
    tx_sequence = 0;
    rx_expected_seq = 0;
    rx_seq_bitmap = 0;
    printf("   ✅ Counter-based nonces initialized\n");
    printf("   ✅ Replay protection enabled (window: %d)\n", SEQUENCE_WINDOW);
    printf("   ✅ Sequence tracking active\n\n");
    
    return 0;

cleanup_error:
    free(server_pk);
    free(server_sk);
    free(shared_secret);
    free(ciphertext);
    free(client_pk);
    OQS_KEM_free(kem);
    return -1;
}

// ============================================================================
// MAIN VPN LOOP
// ============================================================================

int main() {
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║   Post-Quantum VPN Server (ML-KEM-768)        ║\n");
    printf("║   WITH SECURITY: Replay Protection Enabled    ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    // Setup signal handler
    signal(SIGINT, sigint_handler);

    tun_device_t tun;
    memset(&tun, 0, sizeof(tun));
    tun.fd = -1;
    
    int udp_sock = -1;
    uint8_t session_key[AES_KEY_LEN];
    struct sockaddr_in client_addr;
    int handshake_complete = 0;

    // Statistics
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t replay_attempts = 0;

    // ========================================================================
    // 1. CREATE TUN INTERFACE
    // ========================================================================
    
    printf("1️⃣  Creating TUN interface...\n");
    if (tun_create(&tun, "tun0") < 0) {
        fprintf(stderr, "❌ Failed to create TUN (run as root: sudo %s)\n", 
                "bin/vpn_server");
        goto cleanup;
    }

    if (tun_set_ip(&tun, SERVER_TUN_IP, CLIENT_TUN_IP, NETMASK) < 0) {
        goto cleanup;
    }

    if (tun_up(&tun) < 0) {
        goto cleanup;
    }
    printf("\n");

    // ========================================================================
    // 2. CREATE UDP SOCKET
    // ========================================================================
    
    printf("2️⃣  Creating UDP socket...\n");
    udp_sock = create_udp_socket(VPN_PORT);
    if (udp_sock < 0) {
        fprintf(stderr, "❌ Failed to create UDP socket on port %d\n", VPN_PORT);
        goto cleanup;
    }
    printf("   ✅ Listening on 0.0.0.0:%d\n\n", VPN_PORT);

    // ========================================================================
    // 3. WAIT FOR CLIENT AND PERFORM HANDSHAKE
    // ========================================================================
    
    printf("3️⃣  Waiting for client connection...\n");
    printf("   (Client should connect to this server's IP on port %d)\n\n", VPN_PORT);

    if (perform_handshake(udp_sock, &client_addr, session_key) < 0) {
        fprintf(stderr, "❌ Handshake failed\n");
        goto cleanup;
    }
    handshake_complete = 1;

    // ========================================================================
    // 4. MAIN VPN TUNNEL LOOP
    // ========================================================================
    
    printf("4️⃣  VPN Tunnel Active!\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("✅ Secure tunnel established with client\n");
    printf("   Server: %s (tun0)\n", SERVER_TUN_IP);
    printf("   Client: %s (virtual)\n", CLIENT_TUN_IP);
    printf("   Security: ML-KEM-768 + AES-256-GCM + Replay Protection\n");
    printf("\n");
    printf("Try from client:\n");
    printf("   ping %s\n", SERVER_TUN_IP);
    printf("\n");
    printf("Press Ctrl+C to stop\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    // Setup poll for both TUN and UDP
    struct pollfd fds[2];
    fds[0].fd = tun.fd;
    fds[0].events = POLLIN;
    fds[1].fd = udp_sock;
    fds[1].events = POLLIN;

    uint8_t tun_buffer[2048];
    uint8_t udp_buffer[2048];
    uint8_t encrypted_packet[2048];

    while (running) {
        int ret = poll(fds, 2, 1000);  // 1 second timeout
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        
        if (ret == 0) continue;  // Timeout, check running flag

        // ====================================================================
        // OUTGOING: TUN → Encrypt → UDP
        // ====================================================================
        
        if (fds[0].revents & POLLIN) {
            ssize_t nread = tun_read(&tun, tun_buffer, sizeof(tun_buffer));
            if (nread < 0) {
                if (errno != EINTR) perror("tun_read");
                continue;
            }

            if (nread == 0) continue;

            packets_sent++;
            printf("\n📤 Outgoing packet #%lu (%zd bytes):\n", packets_sent, nread);
            print_ip_packet(tun_buffer, nread);

            // SECURITY: Generate unique nonce using counter (not random!)
            uint8_t nonce[IV_LEN];
            uint8_t tag[TAG_LEN];
            generate_nonce(&tx_nonce, nonce);

            // Prepare packet header with sequence number
            vpn_packet_header_t *header = (vpn_packet_header_t *)encrypted_packet;
            header->sequence = htobe64(tx_sequence);
            memcpy(header->iv, nonce, IV_LEN);

            // Encrypt the IP packet
            uint8_t *ct_ptr = encrypted_packet + VPN_HEADER_SIZE;
            int ct_len = aes_gcm_encrypt(session_key, tun_buffer, (int)nread,
                                         nonce, ct_ptr, tag);
            if (ct_len <= 0) {
                fprintf(stderr, "   ❌ Encryption failed\n");
                continue;
            }

            // Add authentication tag to header
            memcpy(header->tag, tag, TAG_LEN);

            // Build packet: [SEQ(8)][IV(12)][TAG(16)][Ciphertext]
            size_t total_len = VPN_HEADER_SIZE + ct_len;

            // Send to client
            if (send_udp(udp_sock, encrypted_packet, total_len, &client_addr) < 0) {
                fprintf(stderr, "   ❌ UDP send failed\n");
                continue;
            }

            bytes_sent += total_len;
            printf("   🔒 Encrypted: seq=%lu, size=%zu bytes\n", tx_sequence, total_len);
            
            // Increment sequence number
            tx_sequence++;
        }

        // ====================================================================
        // INCOMING: UDP → Decrypt → TUN
        // ====================================================================
        
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from_addr;
            ssize_t nrecv = recv_udp(udp_sock, udp_buffer, sizeof(udp_buffer),
                                     &from_addr, 0);
            
            // Check minimum packet size
            if (nrecv < (ssize_t)VPN_HEADER_SIZE) {
                if (nrecv > 0) {
                    fprintf(stderr, "   ⚠️  Packet too short (%zd bytes)\n", nrecv);
                }
                continue;
            }

            // SECURITY: Verify packet is from our client
            if (handshake_complete && 
                (from_addr.sin_addr.s_addr != client_addr.sin_addr.s_addr ||
                 from_addr.sin_port != client_addr.sin_port)) {
                fprintf(stderr, "   ⚠️  Packet from unknown source, ignoring\n");
                continue;
            }

            // Parse packet header
            vpn_packet_header_t *header = (vpn_packet_header_t *)udp_buffer;
            uint64_t recv_seq = be64toh(header->sequence);

            // SECURITY: Check sequence number (replay protection)
            if (!check_sequence(recv_seq, &rx_expected_seq, &rx_seq_bitmap)) {
                // Packet rejected - replay or duplicate
                replay_attempts++;
                continue;
            }

            // Extract IV, TAG, and ciphertext
            uint8_t *nonce = header->iv;
            uint8_t *tag = header->tag;
            uint8_t *ct = udp_buffer + VPN_HEADER_SIZE;
            int ct_len = nrecv - VPN_HEADER_SIZE;

            // Decrypt and authenticate
            uint8_t plaintext[2048];
            int pt_len = aes_gcm_decrypt(session_key, ct, ct_len, nonce, tag, plaintext);
            
            if (pt_len <= 0) {
                fprintf(stderr, "   ❌ Decryption/authentication failed\n");
                continue;
            }

            packets_received++;
            bytes_received += nrecv;
            
            printf("\n📥 Incoming packet #%lu (%d bytes plaintext):\n", 
                   packets_received, pt_len);
            print_ip_packet(plaintext, pt_len);
            printf("   ✅ Sequence: %lu (valid), decrypted successfully\n", recv_seq);

            // Write to TUN (deliver to kernel)
            if (tun_write(&tun, plaintext, pt_len) < 0) {
                perror("   ❌ tun_write");
                continue;
            }
        }
    }

    // ========================================================================
    // CLEANUP
    // ========================================================================
    
cleanup:
    printf("\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("📊 Session Statistics:\n");
    printf("   Packets sent:       %lu\n", packets_sent);
    printf("   Packets received:   %lu\n", packets_received);
    printf("   Bytes sent:         %lu (%.2f KB)\n", bytes_sent, bytes_sent/1024.0);
    printf("   Bytes received:     %lu (%.2f KB)\n", bytes_received, bytes_received/1024.0);
    if (replay_attempts > 0) {
        printf("   🛡️  Replay attempts blocked: %lu\n", replay_attempts);
    }
    printf("   Security overhead:  36 bytes per packet\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    printf("🧹 Cleaning up...\n");
    if (tun.fd >= 0) {
        tun_down(&tun);
        tun_close(&tun);
    }
    if (udp_sock >= 0) close(udp_sock);

    printf("✅ VPN server stopped\n");
    return 0;
}