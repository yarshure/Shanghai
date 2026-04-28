// kcp_rs.h — extern "C" wrapper around libkcp's ReedSolomon class so Swift
// can call it through the SPM C target without dragging C++ headers into
// Shanghai's Swift module.
//
// Wire-format compatible with klauspost/reedsolomon (kcptun-go's RS layer):
// systematic Reed-Solomon over GF(256), Vandermonde matrix, generator
// polynomial 0x11d. Encoder produces parity bytes that kcptun-go's decoder
// will accept and vice versa.
//
// MIT-licensed source ported from libkcp by Daniel Fu (xtaci).

#ifndef CKCP_RS_H
#define CKCP_RS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kcp_rs kcp_rs_t;

// Create an RS codec for `data_shards` + `parity_shards`. Returns NULL on
// invalid input (e.g. data_shards <= 0, or data + parity > 256).
kcp_rs_t* kcp_rs_new(int data_shards, int parity_shards);

void kcp_rs_free(kcp_rs_t* rs);

// Compute parity into the trailing `parity_shards` entries of `shards`.
// `shards` is an array of (data_shards + parity_shards) pointers; each
// shard is a buffer of `shard_size` bytes. Data shards are read; parity
// shards are written. Returns 0 on success, non-zero on error.
int kcp_rs_encode(kcp_rs_t* rs,
                  uint8_t* const* shards,
                  int shard_count,
                  size_t shard_size);

// Reconstruct missing shards in place. `present[i] != 0` means
// `shards[i]` already has valid bytes; `present[i] == 0` means
// `shards[i]` is missing and the function should fill it in (the
// pointer must still point at a buffer of `shard_size` bytes).
//
// Returns 0 on success, non-zero on too-few-shards / size mismatch.
int kcp_rs_reconstruct(kcp_rs_t* rs,
                       uint8_t* const* shards,
                       int shard_count,
                       size_t shard_size,
                       const uint8_t* present);

#ifdef __cplusplus
}
#endif

#endif // CKCP_RS_H
