import Testing
import Foundation
@testable import Shanghai

@Test func reedSolomonEncodeReconstructRoundTrip() async throws {
    // 10 + 3 — kcptun-go's default group size.
    let rs = try KcpReedSolomon(dataShards: 10, parityShards: 3)
    let shardSize = 1350

    // Build 10 deterministic data shards + 3 zero parity slots.
    var shards: [Data] = (0..<10).map { i in
        Data((0..<shardSize).map { j in UInt8((i * 7 + j) & 0xff) })
    } + Array(repeating: Data(count: shardSize), count: 3)

    // Encode parity in place.
    try rs.encode(&shards)

    // Snapshot the original data shards so we can compare after reconstruct.
    let original = shards.prefix(10).map { Data($0) }

    // Drop 2 data shards and 1 parity shard. RS(10,3) recovers any
    // 10 of 13, so this is the boundary case.
    var present = Array(repeating: true, count: 13)
    present[2] = false
    present[7] = false
    present[12] = false
    for (i, p) in present.enumerated() where !p {
        shards[i] = Data(count: shardSize)
    }

    try rs.reconstruct(&shards, present: present)

    for i in 0..<10 {
        #expect(shards[i] == original[i], "data shard \(i) mismatch after reconstruct")
    }
}

@Test func reedSolomonRejectsInvalidShape() {
    #expect(throws: KcpReedSolomon.Error.self) {
        _ = try KcpReedSolomon(dataShards: 0, parityShards: 3)
    }
    #expect(throws: KcpReedSolomon.Error.self) {
        _ = try KcpReedSolomon(dataShards: 200, parityShards: 100)  // > 256
    }
}
