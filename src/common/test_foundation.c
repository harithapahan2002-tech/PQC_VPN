// test_foundation.c
// Test the foundation crypto layer

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include "pqc_common.h"
#include "pqc_crypto.h"

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
    printf("║   Foundation Layer Test Suite                 ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    // Test 1: Key Derivation
    printf("1️⃣  Testing Key Derivation...\n");
    uint8_t shared_secret[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    
    uint8_t aes_key[32];
    derive_key(shared_secret, 32, "AES-SESSION-KEY", aes_key, 32);
    
    print_hex("   Shared Secret", shared_secret, 32);
    print_hex("   Derived AES Key", aes_key, 32);
    printf("   ✅ Key derivation successful\n\n");

    // Test 2: AES-GCM Encryption
    printf("2️⃣  Testing AES-256-GCM Encryption...\n");
    const char *plaintext = "Hello, Post-Quantum VPN!";
    size_t pt_len = strlen(plaintext);
    
    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t ciphertext[256];
    
    int ct_len = aes_gcm_encrypt(aes_key, (const uint8_t*)plaintext, pt_len,
                                  iv, ciphertext, tag);
    
    if (ct_len <= 0) {
        fprintf(stderr, "   ❌ Encryption failed\n");
        return 1;
    }
    
    printf("   Plaintext: %s\n", plaintext);
    print_hex("   IV", iv, IV_LEN);
    print_hex("   Ciphertext", ciphertext, ct_len);
    print_hex("   Tag", tag, TAG_LEN);
    printf("   ✅ Encryption successful (%d bytes)\n\n", ct_len);

    // Test 3: AES-GCM Decryption
    printf("3️⃣  Testing AES-256-GCM Decryption...\n");
    uint8_t decrypted[256];
    
    int dec_len = aes_gcm_decrypt(aes_key, ciphertext, ct_len, iv, tag, decrypted);
    
    if (dec_len <= 0) {
        fprintf(stderr, "   ❌ Decryption failed\n");
        return 1;
    }
    
    decrypted[dec_len] = '\0';
    printf("   Decrypted: %s\n", decrypted);
    
    if (strcmp((char*)decrypted, plaintext) == 0) {
        printf("   ✅ Decryption successful - matches original!\n\n");
    } else {
        fprintf(stderr, "   ❌ Decrypted text doesn't match original\n");
        return 1;
    }

    // Test 4: Authentication (tampered data should fail)
    printf("4️⃣  Testing Authentication (tamper detection)...\n");
    uint8_t tampered_ct[256];
    memcpy(tampered_ct, ciphertext, ct_len);
    tampered_ct[0] ^= 0xFF;  // Flip bits in first byte
    
    int tamper_dec = aes_gcm_decrypt(aes_key, tampered_ct, ct_len, iv, tag, decrypted);
    
    if (tamper_dec <= 0) {
        printf("   ✅ Tampered ciphertext correctly rejected!\n\n");
    } else {
        fprintf(stderr, "   ❌ Tampered ciphertext was accepted (BAD!)\n");
        return 1;
    }

    // Test 5: ML-KEM Integration
    printf("5️⃣  Testing ML-KEM-768 + AES Integration...\n");
    
    OQS_KEM *kem = OQS_KEM_new(KEM_ALG);
    if (!kem) {
        fprintf(stderr, "   ❌ Failed to initialize ML-KEM-768\n");
        return 1;
    }
    
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ss_alice = malloc(kem->length_shared_secret);
    uint8_t *ss_bob = malloc(kem->length_shared_secret);
    uint8_t *ct = malloc(kem->length_ciphertext);
    
    // Alice and Bob generate keys
    OQS_KEM_keypair(kem, pk, sk);
    
    // Alice encapsulates
    OQS_KEM_encaps(kem, ct, ss_alice, pk);
    
    // Bob decapsulates
    OQS_KEM_decaps(kem, ss_bob, ct, sk);
    
    // Verify shared secrets match
    if (memcmp(ss_alice, ss_bob, kem->length_shared_secret) != 0) {
        fprintf(stderr, "   ❌ Shared secrets don't match!\n");
        return 1;
    }
    
    // Derive session keys
    uint8_t alice_key[32], bob_key[32];
    derive_key(ss_alice, kem->length_shared_secret, "VPN-SESSION", alice_key, 32);
    derive_key(ss_bob, kem->length_shared_secret, "VPN-SESSION", bob_key, 32);
    
    if (memcmp(alice_key, bob_key, 32) != 0) {
        fprintf(stderr, "   ❌ Derived keys don't match!\n");
        return 1;
    }
    
    print_hex("   ML-KEM Shared Secret", ss_alice, 32);
    print_hex("   Derived Session Key", alice_key, 32);
    printf("   ✅ ML-KEM + Key Derivation working perfectly!\n\n");

    // Cleanup
    free(pk); free(sk); free(ss_alice); free(ss_bob); free(ct);
    OQS_KEM_free(kem);

    printf("╔════════════════════════════════════════════════╗\n");
    printf("║  ✅ ALL TESTS PASSED!                         ║\n");
    printf("║  Foundation layer is ready for VPN            ║\n");
    printf("╚════════════════════════════════════════════════╝\n");

    return 0;
}
