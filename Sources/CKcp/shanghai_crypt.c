// shanghai_crypt.c — see shanghai_crypt.h for why this is hand-rolled.
//
// AES (encrypt direction only — CFB never needs the inverse cipher),
// SHA1, HMAC-SHA1, PBKDF2. All constant-table, no platform intrinsics,
// so the same bytes come out on macOS/iOS/Linux/FreeBSD/Android.

#include "shanghai_crypt.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* AES block cipher (FIPS-197), encrypt direction                      */
/* ------------------------------------------------------------------ */

static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

typedef struct {
    /* round keys as bytes: 16 * (rounds + 1) */
    uint8_t rk[16 * 15];
    int rounds;
} aes_ctx;

static int aes_key_expand(aes_ctx *ctx, const uint8_t *key, size_t key_len) {
    int nk, nr;
    switch (key_len) {
    case 16: nk = 4; nr = 10; break;
    case 24: nk = 6; nr = 12; break;
    case 32: nk = 8; nr = 14; break;
    default: return -1;
    }
    ctx->rounds = nr;

    uint8_t *w = ctx->rk;
    memcpy(w, key, key_len);

    int total_words = 4 * (nr + 1);
    for (int i = nk; i < total_words; i++) {
        uint8_t t[4];
        memcpy(t, w + 4 * (i - 1), 4);
        if (i % nk == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(aes_sbox[t[1]] ^ aes_rcon[i / nk]);
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[tmp];
        } else if (nk > 6 && i % nk == 4) {
            /* AES-256 extra SubWord */
            t[0] = aes_sbox[t[0]];
            t[1] = aes_sbox[t[1]];
            t[2] = aes_sbox[t[2]];
            t[3] = aes_sbox[t[3]];
        }
        for (int b = 0; b < 4; b++) {
            w[4 * i + b] = (uint8_t)(w[4 * (i - nk) + b] ^ t[b]);
        }
    }
    return 0;
}

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

static void aes_encrypt_block(const aes_ctx *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    const uint8_t *rk = ctx->rk;

    for (int i = 0; i < 16; i++) s[i] = (uint8_t)(in[i] ^ rk[i]);

    for (int round = 1; round <= ctx->rounds; round++) {
        rk += 16;

        /* SubBytes */
        for (int i = 0; i < 16; i++) s[i] = aes_sbox[s[i]];

        /* ShiftRows (state is column-major: s[col*4 + row]) */
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

        /* MixColumns (skipped on the final round) */
        if (round != ctx->rounds) {
            for (int c = 0; c < 16; c += 4) {
                uint8_t a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
                uint8_t all = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                s[c]     ^= (uint8_t)(xtime((uint8_t)(a0 ^ a1)) ^ all);
                s[c + 1] ^= (uint8_t)(xtime((uint8_t)(a1 ^ a2)) ^ all);
                s[c + 2] ^= (uint8_t)(xtime((uint8_t)(a2 ^ a3)) ^ all);
                s[c + 3] ^= (uint8_t)(xtime((uint8_t)(a3 ^ a0)) ^ all);
            }
        }

        /* AddRoundKey */
        for (int i = 0; i < 16; i++) s[i] ^= rk[i];
    }

    memcpy(out, s, 16);
}

/* ------------------------------------------------------------------ */
/* AES-CFB128                                                          */
/* ------------------------------------------------------------------ */

int shanghai_aes_cfb(const uint8_t *key, size_t key_len,
                     const uint8_t iv[16],
                     int encrypt,
                     const uint8_t *input, size_t length,
                     uint8_t *output) {
    if (!key || !iv || (!input && length > 0) || (!output && length > 0)) return -1;

    aes_ctx ctx;
    if (aes_key_expand(&ctx, key, key_len) != 0) return -1;

    uint8_t feedback[16];
    uint8_t keystream[16];
    memcpy(feedback, iv, 16);

    size_t offset = 0;
    while (offset < length) {
        size_t chunk = length - offset;
        if (chunk > 16) chunk = 16;

        aes_encrypt_block(&ctx, feedback, keystream);

        /* Save ciphertext into the feedback register. On decrypt the
           ciphertext is the INPUT, and input/output may alias, so grab
           it before XORing over it. */
        if (!encrypt) memcpy(feedback, input + offset, chunk);
        for (size_t i = 0; i < chunk; i++) {
            output[offset + i] = (uint8_t)(input[offset + i] ^ keystream[i]);
        }
        if (encrypt) memcpy(feedback, output + offset, chunk);
        /* A trailing partial block leaves the register stale past
           `chunk`, but the loop ends here anyway. */

        offset += chunk;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* SHA-1 (FIPS 180-4)                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[5];
    uint64_t total_len;
    uint8_t buffer[64];
    size_t buffer_len;
} sha1_ctx;

static void sha1_init(sha1_ctx *ctx) {
    ctx->h[0] = 0x67452301u;
    ctx->h[1] = 0xefcdab89u;
    ctx->h[2] = 0x98badcfeu;
    ctx->h[3] = 0x10325476u;
    ctx->h[4] = 0xc3d2e1f0u;
    ctx->total_len = 0;
    ctx->buffer_len = 0;
}

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_block(sha1_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999u; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
        else { f = b ^ c ^ d; k = 0xca62c1d6u; }

        uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32(b, 30); b = a; a = tmp;
    }

    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d; ctx->h[4] += e;
}

static void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;
    while (len > 0) {
        size_t take = 64 - ctx->buffer_len;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;
        if (ctx->buffer_len == 64) {
            sha1_block(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

static void sha1_final(sha1_ctx *ctx, uint8_t digest[20]) {
    uint64_t bit_len = ctx->total_len * 8;
    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);
    uint8_t zero = 0x00;
    while (ctx->buffer_len != 56) sha1_update(ctx, &zero, 1);

    uint8_t len_be[8];
    for (int i = 0; i < 8; i++) len_be[i] = (uint8_t)(bit_len >> (56 - 8 * i));
    /* bypass total_len accounting for the length field itself */
    memcpy(ctx->buffer + 56, len_be, 8);
    sha1_block(ctx, ctx->buffer);

    for (int i = 0; i < 5; i++) {
        digest[4 * i] = (uint8_t)(ctx->h[i] >> 24);
        digest[4 * i + 1] = (uint8_t)(ctx->h[i] >> 16);
        digest[4 * i + 2] = (uint8_t)(ctx->h[i] >> 8);
        digest[4 * i + 3] = (uint8_t)(ctx->h[i]);
    }
}

/* ------------------------------------------------------------------ */
/* HMAC-SHA1 + PBKDF2 (RFC 2104 / RFC 2898)                            */
/* ------------------------------------------------------------------ */

typedef struct {
    sha1_ctx inner;
    uint8_t opad_key[64];
} hmac_sha1_ctx;

static void hmac_sha1_init(hmac_sha1_ctx *ctx, const uint8_t *key, size_t key_len) {
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        sha1_ctx h;
        sha1_init(&h);
        sha1_update(&h, key, key_len);
        sha1_final(&h, k); /* 20 bytes, rest stays zero */
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        ctx->opad_key[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    sha1_init(&ctx->inner);
    sha1_update(&ctx->inner, ipad, 64);
}

static void hmac_sha1_final(hmac_sha1_ctx *ctx, uint8_t mac[20]) {
    uint8_t inner_digest[20];
    sha1_final(&ctx->inner, inner_digest);

    sha1_ctx outer;
    sha1_init(&outer);
    sha1_update(&outer, ctx->opad_key, 64);
    sha1_update(&outer, inner_digest, 20);
    sha1_final(&outer, mac);
}

int shanghai_pbkdf2_sha1(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations,
                         uint8_t *derived, size_t derived_len) {
    if ((!password && password_len > 0) || (!salt && salt_len > 0) ||
        !derived || derived_len == 0 || iterations == 0) {
        return -1;
    }

    uint32_t block_index = 1;
    size_t produced = 0;

    while (produced < derived_len) {
        /* U1 = HMAC(password, salt || INT_BE(block_index)) */
        hmac_sha1_ctx hmac;
        hmac_sha1_init(&hmac, password, password_len);
        sha1_update(&hmac.inner, salt, salt_len);
        uint8_t index_be[4] = {
            (uint8_t)(block_index >> 24), (uint8_t)(block_index >> 16),
            (uint8_t)(block_index >> 8), (uint8_t)block_index,
        };
        sha1_update(&hmac.inner, index_be, 4);

        uint8_t u[20];
        hmac_sha1_final(&hmac, u);

        uint8_t t[20];
        memcpy(t, u, 20);

        for (uint32_t iter = 1; iter < iterations; iter++) {
            hmac_sha1_init(&hmac, password, password_len);
            sha1_update(&hmac.inner, u, 20);
            hmac_sha1_final(&hmac, u);
            for (int i = 0; i < 20; i++) t[i] ^= u[i];
        }

        size_t take = derived_len - produced;
        if (take > 20) take = 20;
        memcpy(derived + produced, t, take);
        produced += take;
        block_index++;
    }

    return 0;
}
