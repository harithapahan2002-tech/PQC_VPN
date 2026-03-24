// pqc_crypto.c
// Implementation of AES-256-GCM encryption/decryption

#include "pqc_crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================================================
// AES-256-GCM ENCRYPTION
// ============================================================================

int aes_gcm_encrypt(const uint8_t key[AES_KEY_LEN], 
                    const uint8_t *plaintext, int pt_len,
                    uint8_t iv[IV_LEN], 
                    uint8_t *ciphertext, 
                    uint8_t tag[TAG_LEN]) {
    
    // Generate random IV (CRITICAL: must be unique for each message)
    if (RAND_bytes(iv, IV_LEN) != 1) {
        return 0;  // Random generation failed
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    int len = 0;
    int ciphertext_len = 0;
    int ret = 0;

    do {
        // Initialize encryption with AES-256-GCM
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            break;
        }

        // Set IV length (12 bytes is standard for GCM)
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
            break;
        }

        // Initialize key and IV
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
            break;
        }

        // Encrypt plaintext
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1) {
            break;
        }
        ciphertext_len = len;

        // Finalize encryption (GCM doesn't usually output more, but must be called)
        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
            break;
        }
        ciphertext_len += len;

        // Get authentication tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
            break;
        }

        ret = ciphertext_len;  // Success
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// ============================================================================
// AES-256-GCM DECRYPTION
// ============================================================================

int aes_gcm_decrypt(const uint8_t key[AES_KEY_LEN], 
                    const uint8_t *ciphertext, int ct_len,
                    const uint8_t iv[IV_LEN], 
                    const uint8_t tag[TAG_LEN],
                    uint8_t *plaintext) {
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    int len = 0;
    int plaintext_len = 0;
    int ret = 0;

    do {
        // Initialize decryption with AES-256-GCM
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            break;
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
            break;
        }

        // Initialize key and IV
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
            break;
        }

        // Decrypt ciphertext
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1) {
            break;
        }
        plaintext_len = len;

        // Set expected tag for verification
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, 
                                (void*)tag) != 1) {
            break;
        }

        // Finalize and verify authentication tag
        // This is where authentication happens - if tag doesn't match, this fails
        if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
            ret = 0;  // Authentication failed or decryption error
            break;
        }
        plaintext_len += len;

        ret = plaintext_len;  // Success
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// ============================================================================
// HIGH-LEVEL MESSAGE ENCRYPTION
// ============================================================================

int send_encrypted_message(int fd, const uint8_t key[AES_KEY_LEN], 
                           const uint8_t *msg, uint32_t msg_len,
                           double *enc_time_us) {
    
    // Sanity check
    if (msg_len > MAX_MESSAGE_SIZE) {
        return 0;
    }

    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t *ciphertext = malloc(msg_len);
    if (!ciphertext) {
        return 0;
    }

    // Time the encryption operation
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    int ct_len = aes_gcm_encrypt(key, msg, (int)msg_len, iv, ciphertext, tag);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    if (enc_time_us) {
        *enc_time_us = elapsed_time_us(start, end);
    }

    if (ct_len <= 0) {
        free(ciphertext);
        return 0;
    }

    // Frame format: [length(4)][IV(12)][TAG(16)][ciphertext]
    uint32_t payload_len = IV_LEN + TAG_LEN + (uint32_t)ct_len;
    uint32_t net_len = htonl(payload_len);  // Convert to network byte order

    // Send all parts in order
    int success = (write_all(fd, &net_len, sizeof(net_len)) > 0 &&
                   write_all(fd, iv, IV_LEN) > 0 &&
                   write_all(fd, tag, TAG_LEN) > 0 &&
                   write_all(fd, ciphertext, ct_len) > 0);

    free(ciphertext);
    return success;
}

int recv_encrypted_message(int fd, const uint8_t key[AES_KEY_LEN], 
                           uint8_t **msg_out, uint32_t *msg_len_out,
                           double *dec_time_us) {
    
    // Read length prefix
    uint32_t net_len = 0;
    if (read_exact(fd, &net_len, sizeof(net_len)) <= 0) {
        return 0;
    }
    
    uint32_t payload_len = ntohl(net_len);  // Convert from network byte order
    
    // Sanity check
    if (payload_len < IV_LEN + TAG_LEN || payload_len > MAX_MESSAGE_SIZE) {
        return 0;
    }

    // Read IV, TAG, and ciphertext
    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    uint32_t ct_len = payload_len - IV_LEN - TAG_LEN;
    
    uint8_t *ciphertext = malloc(ct_len);
    if (!ciphertext) {
        return 0;
    }

    if (read_exact(fd, iv, IV_LEN) <= 0 || 
        read_exact(fd, tag, TAG_LEN) <= 0 || 
        read_exact(fd, ciphertext, ct_len) <= 0) {
        free(ciphertext);
        return 0;
    }

    // Allocate plaintext buffer (+1 for null terminator for string safety)
    uint8_t *plaintext = malloc(ct_len + 1);
    if (!plaintext) {
        free(ciphertext);
        return 0;
    }

    // Time the decryption operation
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    int pt_len = aes_gcm_decrypt(key, ciphertext, (int)ct_len, iv, tag, plaintext);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    if (dec_time_us) {
        *dec_time_us = elapsed_time_us(start, end);
    }

    free(ciphertext);

    if (pt_len <= 0) {
        free(plaintext);
        return 0;  // Decryption or authentication failed
    }

    // Null-terminate for string safety
    plaintext[pt_len] = '\0';
    
    *msg_out = plaintext;
    *msg_len_out = (uint32_t)pt_len;
    return 1;
}
