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

/// Loopback test: encoder produces FEC-framed packets that the
/// decoder un-frames back to the original KCP packets — both the
/// no-loss path (data shards arrive intact, decoder skips RS) and
/// the recovery path (drop one data shard, decoder reconstructs).
@Test func fecEncoderDecoderLoopback() async throws {
    let encoder = try KcpFECEncoder(dataShards: 3, parityShards: 1)
    let decoder = try KcpFECDecoder(dataShards: 3, parityShards: 1)

    // Three deterministic KCP packets of varying length. Real KCP
    // packets are usually equal-mtu; varying length here exercises
    // the size-field padding/trim path harder.
    let kcpPackets: [Data] = [
        Data("alpha-1234".utf8),
        Data("bravo-charlie".utf8),
        Data("delta-the-longest-of-three".utf8),
    ]

    // Encode all three; the third call closes the group and returns
    // 1 data + 1 parity = 2 frames.
    var allFrames: [Data] = []
    for k in kcpPackets {
        allFrames.append(contentsOf: encoder.encode(kcpPacket: k))
    }
    #expect(allFrames.count == 4) // 3 data + 1 parity

    // Path A: feed all 4 frames in order — decoder should surface
    // 3 immediate KCP packets (no reconstruct needed).
    var recoveredA: [Data] = []
    for f in allFrames {
        for r in decoder.decode(framedPacket: f) {
            switch r {
            case .immediate(let kcp): recoveredA.append(kcp)
            case .recovered: #expect(Bool(false), "no recovery expected on lossless path")
            }
        }
    }
    #expect(recoveredA == kcpPackets)

    // Path B: a fresh decoder, drop the second data frame entirely,
    // and feed the rest — RS should recover the missing data shard.
    let decoderB = try KcpFECDecoder(dataShards: 3, parityShards: 1)
    var recoveredB: [Data] = []
    for (i, f) in allFrames.enumerated() {
        if i == 1 { continue } // simulate loss of seqid=1
        for r in decoderB.decode(framedPacket: f) {
            switch r {
            case .immediate(let kcp): recoveredB.append(kcp)
            case .recovered(let kcps): recoveredB.append(contentsOf: kcps)
            }
        }
    }
    // Order of arrival on decoder side: pkt0 (immediate),
    // pkt2 (immediate), then parity arrival completes the group →
    // pkt1 reconstructed. recoveredB has 3 entries but ordered by
    // arrival, so pkt1 is last.
    #expect(Set(recoveredB) == Set(kcpPackets))
    #expect(recoveredB.count == 3)
}
