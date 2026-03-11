// pqc_crypto.h
// AES-256-GCM encryption and decryption functions

#ifndef PQC_CRYPTO_H
#define PQC_CRYPTO_H

#include "pqc_common.h"
#include <stdint.h>

// ============================================================================
// AES-256-GCM ENCRYPTION/DECRYPTION
// ============================================================================

// Encrypt plaintext using AES-256-GCM
//
// Parameters:
//   key: 32-byte AES-256 key
//   plaintext: Data to encrypt
//   pt_len: Length of plaintext
//   iv: Output buffer for 12-byte IV (generated randomly)
//   ciphertext: Output buffer for encrypted data (same size as plaintext)
//   tag: Output buffer for 16-byte authentication tag
//
// Returns: Length of ciphertext on success, 0 on failure
int aes_gcm_encrypt(const uint8_t key[AES_KEY_LEN], 
                    const uint8_t *plaintext, int pt_len,
                    uint8_t iv[IV_LEN], 
                    uint8_t *ciphertext, 
                    uint8_t tag[TAG_LEN]);

// Decrypt ciphertext using AES-256-GCM with authentication
//
// Parameters:
//   key: 32-byte AES-256 key
//   ciphertext: Encrypted data
//   ct_len: Length of ciphertext
//   iv: 12-byte IV (from encryption)
//   tag: 16-byte authentication tag (from encryption)
//   plaintext: Output buffer for decrypted data
//
// Returns: Length of plaintext on success, 0 on failure (including auth failure)
int aes_gcm_decrypt(const uint8_t key[AES_KEY_LEN], 
                    const uint8_t *ciphertext, int ct_len,
                    const uint8_t iv[IV_LEN], 
                    const uint8_t tag[TAG_LEN],
                    uint8_t *plaintext);

// ============================================================================
// HIGH-LEVEL MESSAGE ENCRYPTION
// ============================================================================

// Send encrypted message over network
// Frame format: [uint32_t length][IV 12B][TAG 16B][ciphertext]
//
// Parameters:
//   fd: File descriptor (socket)
//   key: AES-256 key
//   msg: Message to send
//   msg_len: Length of message
//   enc_time_us: Optional output - encryption time in microseconds
//
// Returns: 1 on success, 0 on failure
int send_encrypted_message(int fd, const uint8_t key[AES_KEY_LEN], 
                           const uint8_t *msg, uint32_t msg_len,
                           double *enc_time_us);

// Receive encrypted message from network
// Allocates memory for msg_out (caller must free)
//
// Parameters:
//   fd: File descriptor (socket)
//   key: AES-256 key
//   msg_out: Output pointer (will be allocated)
//   msg_len_out: Output length of message
//   dec_time_us: Optional output - decryption time in microseconds
//
// Returns: 1 on success, 0 on failure
int recv_encrypted_message(int fd, const uint8_t key[AES_KEY_LEN], 
                           uint8_t **msg_out, uint32_t *msg_len_out,
                           double *dec_time_us);

#endif // PQC_CRYPTO_H
