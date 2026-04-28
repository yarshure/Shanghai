import CKcp
import Foundation

/// Wire-format-compatible Reed-Solomon (Vandermonde GF(256)) for the
/// kcptun-go FEC layer. Encoder produces parity bytes that
/// klauspost/reedsolomon's decoder accepts; decoder reconstructs from
/// any `dataShards`-of-(data + parity) survivors.
///
/// Backed by the libkcp C++ port (Daniel Fu, MIT). The bridge into
/// CKcp does one memcpy per shard in/out per call — for typical kcptun
/// groups (10 + 3 shards × 1350 bytes each) that's ~35 KB of copy per
/// call, well below the network throughput floor.
public final class KcpReedSolomon: @unchecked Sendable {

    public enum Error: Swift.Error {
        case invalidShape          // data + parity > 256, or non-positive
        case invalidShardCount     // caller passed wrong number of shards
        case shardSizeZero
        case tooFewShards          // reconstruct can't proceed
        case sizeMismatch          // reconstructed shard differs from expected size
        case unknown(code: Int32)
    }

    public let dataShards: Int
    public let parityShards: Int
    private let handle: OpaquePointer

    public init(dataShards: Int, parityShards: Int) throws {
        guard dataShards > 0, parityShards >= 0 else { throw Error.invalidShape }
        guard dataShards + parityShards <= 256 else { throw Error.invalidShape }
        guard let handle = kcp_rs_new(Int32(dataShards), Int32(parityShards)) else {
            throw Error.invalidShape
        }
        self.dataShards = dataShards
        self.parityShards = parityShards
        self.handle = handle
    }

    deinit {
        kcp_rs_free(handle)
    }

    public var totalShards: Int { dataShards + parityShards }

    /// Encode parity in place. `shards` must contain `dataShards`
    /// data buffers followed by `parityShards` empty buffers, all of
    /// `shardSize` bytes. Parity buffers are overwritten with the
    /// computed parity.
    public func encode(_ shards: inout [Data]) throws {
        guard shards.count == totalShards else { throw Error.invalidShardCount }
        guard let shardSize = shards.first?.count, shardSize > 0 else {
            throw Error.shardSizeZero
        }
        // Validate every shard is the same size (the C++ side returns
        // -3 on mismatch but we want a cleaner error path).
        for s in shards {
            guard s.count == shardSize else { throw Error.sizeMismatch }
        }
        try shards.withUnsafeMutablePointers(shardSize: shardSize) { ptrs in
            let rc = kcp_rs_encode(self.handle, ptrs, Int32(self.totalShards), shardSize)
            guard rc == 0 else { throw self.mapError(rc) }
        }
    }

    /// Reconstruct missing data shards in place. `shards.count` must
    /// equal `totalShards`. `present[i] == false` marks shard `i` as
    /// missing — its buffer must still exist (size == shardSize) and
    /// will be overwritten with the reconstructed bytes. The number
    /// of `true` entries must be at least `dataShards`.
    public func reconstruct(_ shards: inout [Data], present: [Bool]) throws {
        guard shards.count == totalShards, present.count == totalShards else {
            throw Error.invalidShardCount
        }
        guard let shardSize = shards.first?.count, shardSize > 0 else {
            throw Error.shardSizeZero
        }
        for s in shards {
            guard s.count == shardSize else { throw Error.sizeMismatch }
        }
        let presentBytes: [UInt8] = present.map { $0 ? 1 : 0 }
        try shards.withUnsafeMutablePointers(shardSize: shardSize) { ptrs in
            try presentBytes.withUnsafeBufferPointer { presentBuf in
                let rc = kcp_rs_reconstruct(self.handle, ptrs, Int32(self.totalShards), shardSize, presentBuf.baseAddress)
                guard rc == 0 else { throw self.mapError(rc) }
            }
        }
    }

    private func mapError(_ rc: Int32) -> Error {
        switch rc {
        case -1: return .invalidShape
        case -2: return .invalidShardCount
        case -3, -4: return .tooFewShards
        case -5: return .sizeMismatch
        default: return .unknown(code: rc)
        }
    }
}

private extension Array where Element == Data {
    /// Spread the array into a contiguous `uint8_t* const *` view that
    /// the C bridge expects. We materialise all shards into a single
    /// flat buffer of `n * shardSize` bytes, hand the C side an array
    /// of pointers into that buffer, then copy each shard's stride
    /// back into the original `Data` slots after the call. One alloc,
    /// 2N memcpy.
    mutating func withUnsafeMutablePointers<R>(
        shardSize: Int,
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>) throws -> R
    ) rethrows -> R {
        let n = count
        var flat = ContiguousArray<UInt8>(repeating: 0, count: n * shardSize)
        for i in 0..<n {
            self[i].withUnsafeBytes { src in
                if let base = src.baseAddress {
                    let count = Swift.min(self[i].count, shardSize)
                    flat.withUnsafeMutableBufferPointer { dst in
                        memcpy(dst.baseAddress!.advanced(by: i * shardSize),
                               base, count)
                    }
                }
            }
        }

        return try flat.withUnsafeMutableBufferPointer { flatBuf -> R in
            let base = flatBuf.baseAddress!
            var ptrs: [UnsafeMutablePointer<UInt8>?] = (0..<n).map {
                base.advanced(by: $0 * shardSize)
            }
            let result = try ptrs.withUnsafeMutableBufferPointer { ptrBuf in
                try body(ptrBuf.baseAddress!)
            }
            // Copy back so caller sees parity / reconstructed bytes.
            for i in 0..<n {
                self[i] = Data(bytes: base.advanced(by: i * shardSize),
                               count: shardSize)
            }
            return result
        }
    }
}
