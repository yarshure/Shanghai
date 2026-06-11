// kcp_rs.cpp — extern "C" bridge between Swift and libkcp's ReedSolomon
// C++ class. Construct a heap object, do the standard row_type
// (shared_ptr<vector<byte>>) marshalling at the boundary, copy bytes in
// and out so Swift sees a plain `uint8_t**` shape.
//
// The marshalling does ~2 copies per shard per call (in + out for parity
// or reconstructed slots). At a typical 10+3 group with 1350-byte shards
// that's ~35 KB of memcpy per group — negligible vs. the network cost.
// Optimise later only if profiling shows up here.

#include "kcp_rs.h"
#include "reedsolomon.h"

#include <vector>
#include <memory>
#include <cstring>
#include <stdexcept>

struct kcp_rs {
    ReedSolomon codec;
    int data_shards;
    int parity_shards;
};

extern "C" kcp_rs_t* kcp_rs_new(int data_shards, int parity_shards) {
    if (data_shards <= 0 || parity_shards < 0) return nullptr;
    if (data_shards + parity_shards > 256) return nullptr;
    try {
        auto* rs = new kcp_rs{
            ReedSolomon::New(data_shards, parity_shards),
            data_shards,
            parity_shards,
        };
        return rs;
    } catch (...) {
        return nullptr;
    }
}

extern "C" void kcp_rs_free(kcp_rs_t* rs) {
    delete rs;
}

// Build the shared_ptr<vector<byte>> shape libkcp expects from a
// uint8_t** + size pair. Always copies in (so the C++ side can treat
// vectors as owned).
static std::vector<row_type>
make_shards(uint8_t* const* shards, int n, size_t sz) {
    std::vector<row_type> out;
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto v = std::make_shared<std::vector<byte>>(sz);
        if (shards[i]) {
            std::memcpy(v->data(), shards[i], sz);
        }
        out.push_back(std::move(v));
    }
    return out;
}

extern "C" int kcp_rs_encode(kcp_rs_t* rs,
                             uint8_t* const* shards,
                             int shard_count,
                             size_t shard_size) {
    if (!rs || !shards || shard_size == 0) return -1;
    if (shard_count != rs->data_shards + rs->parity_shards) return -2;
    try {
        auto vecs = make_shards(shards, shard_count, shard_size);
        rs->codec.Encode(vecs);
        // Parity slots (the last parity_shards entries) were written
        // into the C++ vectors; copy them back to caller buffers.
        for (int i = rs->data_shards; i < shard_count; ++i) {
            std::memcpy(shards[i], vecs[i]->data(), shard_size);
        }
        return 0;
    } catch (const std::exception&) {
        return -3;
    } catch (...) {
        return -4;
    }
}

extern "C" int kcp_rs_reconstruct(kcp_rs_t* rs,
                                  uint8_t* const* shards,
                                  int shard_count,
                                  size_t shard_size,
                                  const uint8_t* present) {
    if (!rs || !shards || !present || shard_size == 0) return -1;
    if (shard_count != rs->data_shards + rs->parity_shards) return -2;

    try {
        // libkcp's Reconstruct() detects missing shards by
        // `shards[i] != nullptr` — i.e., a default-constructed
        // (null) shared_ptr means "missing". An empty vector
        // would still be non-null and would be treated as
        // "present but zero-length" → checkShards trips.
        std::vector<row_type> vecs;
        vecs.reserve(shard_count);
        for (int i = 0; i < shard_count; ++i) {
            if (present[i] && shards[i]) {
                auto v = std::make_shared<std::vector<byte>>(shard_size);
                std::memcpy(v->data(), shards[i], shard_size);
                vecs.push_back(std::move(v));
            } else {
                // Null shared_ptr — Reconstruct() will allocate
                // and fill it with the recovered bytes.
                vecs.push_back(row_type{});
            }
        }

        rs->codec.Reconstruct(vecs);

        // Copy reconstructed shards back to caller buffers (only the
        // ones that were missing).
        for (int i = 0; i < shard_count; ++i) {
            if (!present[i] && shards[i]) {
                if (vecs[i] && vecs[i]->size() == shard_size) {
                    std::memcpy(shards[i], vecs[i]->data(), shard_size);
                } else {
                    return -5; // Reconstruct didn't produce expected size
                }
            }
        }
        return 0;
    } catch (const std::exception&) {
        return -3;
    } catch (...) {
        return -4;
    }
}
