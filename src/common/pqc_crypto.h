// pqc_crypto.h
// AES-256-GCM encryption and decryption interface.
//
// Key design change from the previous version:
//   aes_gcm_encrypt no longer generates the IV internally.
//   The caller is responsible for generating the nonce (via generate_nonce)
//   and passing it in. This ensures the counter-based nonce from
//   pqc_common.c is the one actually used — the old version silently
//   overwrote the caller's nonce with a fresh RAND_bytes value, making
//   the entire counter-nonce system a no-op.
//
// Depends on: pqc_common.h

#ifndef PQC_CRYPTO_H
#define PQC_CRYPTO_H

#include "pqc_common.h"
#include <stdint.h>

// ============================================================================
// AES-256-GCM  (low-level — used by the VPN tunnel loop)
// ============================================================================

// Encrypt plaintext with AES-256-GCM.
//
//   key        : 32-byte AES-256 key
//   plaintext  : data to encrypt
//   pt_len     : length of plaintext in bytes (must be > 0)
//   iv         : 12-byte nonce — CALLER MUST PROVIDE THIS.
//                Generate with generate_nonce(). Do not pass a zero buffer.
//   ciphertext : output buffer — must be at least pt_len bytes
//   tag        : output buffer for 16-byte authentication tag
//
// Returns: ciphertext length (== pt_len) on success, -1 on failure.
//
// Note: GCM ciphertext is always the same length as the plaintext.
int aes_gcm_encrypt(const uint8_t  key[AES_KEY_LEN],
                    const uint8_t *plaintext, int pt_len,
                    const uint8_t  iv[IV_LEN],
                    uint8_t       *ciphertext,
                    uint8_t        tag[TAG_LEN]);

// Decrypt and authenticate ciphertext with AES-256-GCM.
//
//   key        : 32-byte AES-256 key
//   ciphertext : encrypted data
//   ct_len     : length of ciphertext in bytes
//   iv         : 12-byte nonce used during encryption
//   tag        : 16-byte authentication tag from encryption
//   plaintext  : output buffer — must be at least ct_len bytes
//
// Returns: plaintext length (== ct_len) on success.
//          -1 on authentication failure OR decryption error.
//
// IMPORTANT: Returns -1 (not 0) on failure. This distinguishes a
// decryption error from successfully decrypting a zero-length message,
// which the old version could not. Callers must check (ret < 0).
int aes_gcm_decrypt(const uint8_t  key[AES_KEY_LEN],
                    const uint8_t *ciphertext, int ct_len,
                    const uint8_t  iv[IV_LEN],
                    const uint8_t  tag[TAG_LEN],
                    uint8_t       *plaintext);

// ============================================================================
// FRAMED MESSAGE ENCRYPTION  (used by the auth handshake over TCP-style I/O)
// ============================================================================
//
// These functions are NOT used by the VPN data tunnel (which uses raw
// aes_gcm_encrypt/decrypt with counter nonces). They are used during the
// handshake phase where messages are framed with a 4-byte length prefix
// and sent over the same UDP socket in a request/response pattern.
//
// Wire format:  [uint32_t total_len (BE)][IV 12B][TAG 16B][ciphertext]

// Encrypt msg and write the framed packet to fd.
//   enc_time_us : if non-NULL, receives encryption time in microseconds
// Returns 1 on success, 0 on failure.
int send_encrypted_message(int fd,
                           const uint8_t  key[AES_KEY_LEN],
                           const uint8_t *msg, uint32_t msg_len,
                           double        *enc_time_us);

// Read a framed packet from fd, decrypt, and return the plaintext.
//   msg_out     : set to a malloc'd buffer containing the plaintext
//                 (caller must free)
//   msg_len_out : set to plaintext length
//   dec_time_us : if non-NULL, receives decryption time in microseconds
// Returns 1 on success, 0 on failure.
int recv_encrypted_message(int fd,
                           const uint8_t  key[AES_KEY_LEN],
                           uint8_t      **msg_out, uint32_t *msg_len_out,
                           double        *dec_time_us);

#endif // PQC_CRYPTO_H