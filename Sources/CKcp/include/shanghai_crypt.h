//
// shanghai_crypt.h — portable crypt primitives for the kcptun wire format.
//
// Why this exists: the packet codec needs PBKDF2-HMAC-SHA1 (key derivation,
// salt "kcp-go", 4096 rounds) and AES-CFB128 (packet obfuscation) to stay
// byte-compatible with kcptun. CommonCrypto provides both but is Apple-only,
// and libsodium provides NEITHER (no CFB mode, no PBKDF2). A dependency-free
// C implementation is the portable common denominator for Linux/FreeBSD hubs
// and, later, Android via JNI.
//
// This layer is obfuscation against DPI, not confidentiality — WireGuard
// inside already encrypts. Software AES throughput (no AES-NI) is plenty for
// cross-border link bandwidths.
//
#ifndef SHANGHAI_CRYPT_H
#define SHANGHAI_CRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// AES-CFB128 one-shot over a whole packet (matches Go cipher.NewCFBEncrypter
// and CommonCrypto kCCModeCFB semantics, including a trailing partial block).
// key_len must be 16, 24 or 32. encrypt: nonzero = encrypt, 0 = decrypt.
// input/output may be the same buffer. Returns 0 on success, -1 on bad args.
int shanghai_aes_cfb(const uint8_t *key, size_t key_len,
                     const uint8_t iv[16],
                     int encrypt,
                     const uint8_t *input, size_t length,
                     uint8_t *output);

// PBKDF2-HMAC-SHA1 (RFC 2898). Returns 0 on success, -1 on bad args.
int shanghai_pbkdf2_sha1(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations,
                         uint8_t *derived, size_t derived_len);

#ifdef __cplusplus
}
#endif

#endif /* SHANGHAI_CRYPT_H */
