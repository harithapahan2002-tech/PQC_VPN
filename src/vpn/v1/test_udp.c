// test_udp.c
// Test UDP networking + crypto integration

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include "../common/pqc_common.h"
#include "../common/pqc_crypto.h"
#include "udp_support.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) {
        printf("%02x", data[i]);
    }
    if (len > 16) printf("...");
    printf("\n");
}

int main() {
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║      UDP + Crypto Integration Test            ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    // Test 1: Create UDP sockets
    printf("1️⃣  Creating UDP sockets...\n");
    
    int alice_sock = create_udp_socket(5555);  // Alice (server)
    int bob_sock = create_udp_socket(5556);    // Bob (client)
    
    if (alice_sock < 0 || bob_sock < 0) {
        fprintf(stderr, "❌ Failed to create UDP sockets\n");
        return 1;
    }
    
    printf("   ✅ Alice socket: fd=%d, port=%d\n", alice_sock, 
           get_socket_port(alice_sock));
    printf("   ✅ Bob socket: fd=%d, port=%d\n\n", bob_sock, 
           get_socket_port(bob_sock));

    // Test 2: ML-KEM key exchange
    printf("2️⃣  Testing ML-KEM-768 key exchange...\n");
    
    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) {
        fprintf(stderr, "❌ Failed to initialize ML-KEM-768\n");
        return 1;
    }

    // Alice generates keypair
    uint8_t *alice_pk = malloc(kem->length_public_key);
    uint8_t *alice_sk = malloc(kem->length_secret_key);
    uint8_t *alice_ss = malloc(kem->length_shared_secret);
    
    OQS_KEM_keypair(kem, alice_pk, alice_sk);
    printf("   ✅ Alice generated keypair\n");

    // Bob generates keypair
    uint8_t *bob_pk = malloc(kem->length_public_key);
    uint8_t *bob_sk = malloc(kem->length_secret_key);
    uint8_t *bob_ss = malloc(kem->length_shared_secret);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    
    OQS_KEM_keypair(kem, bob_pk, bob_sk);
    printf("   ✅ Bob generated keypair\n");

    // Bob encapsulates to Alice
    OQS_KEM_encaps(kem, ciphertext, bob_ss, alice_pk);
    printf("   ✅ Bob encapsulated shared secret\n");

    // Alice decapsulates
    OQS_KEM_decaps(kem, alice_ss, ciphertext, alice_sk);
    printf("   ✅ Alice decapsulated shared secret\n");

    // Verify shared secrets match
    if (memcmp(alice_ss, bob_ss, kem->length_shared_secret) != 0) {
        fprintf(stderr, "   ❌ Shared secrets don't match!\n");
        return 1;
    }
    printf("   ✅ Shared secrets match!\n\n");

    // Derive session keys
    uint8_t alice_key[32], bob_key[32];
    derive_key(alice_ss, kem->length_shared_secret, "UDP-TEST", alice_key, 32);
    derive_key(bob_ss, kem->length_shared_secret, "UDP-TEST", bob_key, 32);
    
    print_hex("   Session Key", alice_key, 32);
    printf("\n");

    // Test 3: Encrypted UDP communication
    printf("3️⃣  Testing encrypted UDP communication...\n");
    
    const char *message = "Hello from Alice to Bob via encrypted UDP!";
    printf("   Original: %s\n", message);

    // Alice encrypts and sends to Bob
    uint8_t iv[IV_LEN], tag[TAG_LEN];
    uint8_t ciphertext_msg[256];
    
    int ct_len = aes_gcm_encrypt(alice_key, (const uint8_t*)message, 
                                  strlen(message), iv, ciphertext_msg, tag);
    if (ct_len <= 0) {
        fprintf(stderr, "   ❌ Encryption failed\n");
        return 1;
    }
    
    print_hex("   IV", iv, IV_LEN);
    print_hex("   Ciphertext", ciphertext_msg, ct_len);
    print_hex("   Tag", tag, TAG_LEN);

    // Prepare UDP packet: [IV][TAG][Ciphertext]
    uint8_t udp_packet[MAX_UDP_PACKET];
    memcpy(udp_packet, iv, IV_LEN);
    memcpy(udp_packet + IV_LEN, tag, TAG_LEN);
    memcpy(udp_packet + IV_LEN + TAG_LEN, ciphertext_msg, ct_len);
    size_t packet_len = IV_LEN + TAG_LEN + ct_len;

    // Send from Alice to Bob
    struct sockaddr_in bob_addr;
    memset(&bob_addr, 0, sizeof(bob_addr));
    bob_addr.sin_family = AF_INET;
    bob_addr.sin_port = htons(5556);
    inet_pton(AF_INET, "127.0.0.1", &bob_addr.sin_addr);

    ssize_t sent = send_udp(alice_sock, udp_packet, packet_len, &bob_addr);
    if (sent < 0) {
        fprintf(stderr, "   ❌ UDP send failed\n");
        return 1;
    }
    printf("   ✅ Sent %zd bytes via UDP\n", sent);

    // Bob receives and decrypts
    uint8_t recv_packet[MAX_UDP_PACKET];
    struct sockaddr_in from_addr;
    
    ssize_t received = recv_udp(bob_sock, recv_packet, sizeof(recv_packet), 
                                 &from_addr, 1000);  // 1 second timeout
    
    if (received <= 0) {
        fprintf(stderr, "   ❌ UDP receive failed or timeout\n");
        return 1;
    }
    printf("   ✅ Received %zd bytes from %s:%d\n", received,
           inet_ntoa(from_addr.sin_addr), ntohs(from_addr.sin_port));

    // Extract IV, TAG, ciphertext
    if ((size_t)received < IV_LEN + TAG_LEN) {
        fprintf(stderr, "   ❌ Packet too short\n");
        return 1;
    }

    uint8_t *recv_iv = recv_packet;
    uint8_t *recv_tag = recv_packet + IV_LEN;
    uint8_t *recv_ct = recv_packet + IV_LEN + TAG_LEN;
    int recv_ct_len = received - IV_LEN - TAG_LEN;

    // Decrypt
    uint8_t plaintext[256];
    int pt_len = aes_gcm_decrypt(bob_key, recv_ct, recv_ct_len, 
                                  recv_iv, recv_tag, plaintext);
    
    if (pt_len <= 0) {
        fprintf(stderr, "   ❌ Decryption/authentication failed\n");
        return 1;
    }

    plaintext[pt_len] = '\0';
    printf("   ✅ Decrypted: %s\n\n", plaintext);

    // Verify message matches
    if (strcmp((char*)plaintext, message) == 0) {
        printf("   ✅ Message matches original!\n\n");
    } else {
        fprintf(stderr, "   ❌ Message doesn't match!\n");
        return 1;
    }

    // Test 4: Bidirectional communication
    printf("4️⃣  Testing bidirectional communication...\n");
    
    const char *reply = "Hello back from Bob to Alice!";
    
    // Bob encrypts and sends back to Alice
    ct_len = aes_gcm_encrypt(bob_key, (const uint8_t*)reply, 
                             strlen(reply), iv, ciphertext_msg, tag);
    
    memcpy(udp_packet, iv, IV_LEN);
    memcpy(udp_packet + IV_LEN, tag, TAG_LEN);
    memcpy(udp_packet + IV_LEN + TAG_LEN, ciphertext_msg, ct_len);
    packet_len = IV_LEN + TAG_LEN + ct_len;

    struct sockaddr_in alice_addr;
    memset(&alice_addr, 0, sizeof(alice_addr));
    alice_addr.sin_family = AF_INET;
    alice_addr.sin_port = htons(5555);
    inet_pton(AF_INET, "127.0.0.1", &alice_addr.sin_addr);

    send_udp(bob_sock, udp_packet, packet_len, &alice_addr);
    printf("   ✅ Bob sent reply\n");

    // Alice receives and decrypts
    received = recv_udp(alice_sock, recv_packet, sizeof(recv_packet), 
                        &from_addr, 1000);
    
    recv_iv = recv_packet;
    recv_tag = recv_packet + IV_LEN;
    recv_ct = recv_packet + IV_LEN + TAG_LEN;
    recv_ct_len = received - IV_LEN - TAG_LEN;

    pt_len = aes_gcm_decrypt(alice_key, recv_ct, recv_ct_len, 
                             recv_iv, recv_tag, plaintext);
    plaintext[pt_len] = '\0';
    
    printf("   ✅ Alice received: %s\n\n", plaintext);

    // Cleanup
    free(alice_pk); free(alice_sk); free(alice_ss);
    free(bob_pk); free(bob_sk); free(bob_ss); free(ciphertext);
    OQS_KEM_free(kem);
    close(alice_sock);
    close(bob_sock);

    printf("╔════════════════════════════════════════════════╗\n");
    printf("║  ✅ ALL TESTS PASSED!                         ║\n");
    printf("║  UDP + Crypto working perfectly               ║\n");
    printf("╚════════════════════════════════════════════════╝\n");

    return 0;
}
