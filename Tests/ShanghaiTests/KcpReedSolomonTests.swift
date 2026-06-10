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

/// Reproduces the field bug: on a real (jittery) link a parity frame can
/// arrive BEFORE the last data frame of its group — no actual loss, pure
/// reordering. The decoder must never surface a CORRUPT packet (one that
/// isn't byte-identical to an original). Uses 10/3 + WG-like variable
/// sizes, which is what exposed the 75%-loss-on-clean-link behaviour.
@Test func fecReorderNoLossNeverCorrupts() throws {
    let dataShards = 10, parityShards = 3
    let encoder = try KcpFECEncoder(dataShards: dataShards, parityShards: parityShards)

    // WG-shaped sizes: handshake init 148, response 92, data ~128,
    // keepalive 32 — cycled so every group has mixed lengths.
    let sizes = [148, 92, 128, 32, 148, 116, 64, 92, 128, 32]
    var kcpPackets: [Data] = []
    for (i, n) in sizes.enumerated() {
        kcpPackets.append(Data((0..<n).map { UInt8(($0 &+ i &* 13) & 0xff) }))
    }
    let originals = Set(kcpPackets)

    // Encode one full group (10 data → returns 10 data + 3 parity total
    // across the calls; the 10th call appends the 3 parity frames).
    var frames: [Data] = []
    for k in kcpPackets { frames.append(contentsOf: encoder.encode(kcpPacket: k)) }
    #expect(frames.count == dataShards + parityShards)

    // Reorder: deliver the 3 parity frames (indices 10,11,12) right
    // after the first 8 data frames, i.e. BEFORE data shards 8 and 9.
    // This drives tryReconstruct to fire while shards 8,9 are still
    // "missing" — the exact early-reconstruct-on-reorder situation.
    let reordered = Array(frames[0..<8]) + Array(frames[10..<13]) + Array(frames[8..<10])

    let decoder = try KcpFECDecoder(dataShards: dataShards, parityShards: parityShards)
    var delivered: [Data] = []
    for f in reordered {
        for r in decoder.decode(framedPacket: f) {
            switch r {
            case .immediate(let kcp): delivered.append(kcp)
            case .recovered(let kcps): delivered.append(contentsOf: kcps)
            }
        }
    }

    // The decisive assertion: EVERY delivered packet must be a real
    // original. A reconstructed-garbage packet shows up here.
    for d in delivered {
        #expect(originals.contains(d), "decoder surfaced a CORRUPT packet len=\(d.count) not among originals")
    }
    // And every original must have been delivered at least once (no loss).
    #expect(Set(delivered) == originals, "some original packets were lost")
}

/// Sustained multi-group stress: many WG-shaped variable-size packets,
/// pseudo-random reorder within a window, and ~1-shard-per-group loss
/// (recoverable). Mimics a jittery lossy cross-border link over many
/// groups. Asserts the decoder NEVER surfaces a corrupt packet and loses
/// nothing recoverable. This is the harness for diagnosing the field bug.
@Test func fecSustainedReorderLossIntegrity() throws {
    let dataShards = 10, parityShards = 3, total = dataShards + parityShards
    let encoder = try KcpFECEncoder(dataShards: dataShards, parityShards: parityShards)
    let groups = 20

    // Deterministic LCG (no Math.random in workflow/test sandbox).
    var seed: UInt64 = 0x9E3779B97F4A7C15
    func rnd(_ mod: Int) -> Int {
        seed = seed &* 6364136223846793005 &+ 1442695040888963407
        return Int((seed >> 33) % UInt64(mod))
    }

    var kcpPackets: [Data] = []
    let sizeMenu = [148, 92, 128, 32, 116, 64, 256, 40]
    for i in 0..<(groups * dataShards) {
        let n = sizeMenu[rnd(sizeMenu.count)]
        kcpPackets.append(Data((0..<n).map { UInt8(($0 &+ i &* 7) & 0xff) }))
    }
    let originals = Set(kcpPackets)

    // Build per-group frame lists so we can drop/reorder within a group.
    let decoder = try KcpFECDecoder(dataShards: dataShards, parityShards: parityShards)
    var delivered: [Data] = []
    var idx = 0
    for _ in 0..<groups {
        var groupFrames: [Data] = []
        for _ in 0..<dataShards {
            groupFrames.append(contentsOf: encoder.encode(kcpPacket: kcpPackets[idx]))
            idx += 1
        }
        #expect(groupFrames.count == total)
        // Drop at most parityShards data frames (still recoverable).
        let dropCount = rnd(parityShards + 1) // 0..parityShards
        var dropSet = Set<Int>()
        while dropSet.count < dropCount { dropSet.insert(rnd(dataShards)) }
        var surviving = groupFrames.enumerated().filter { !dropSet.contains($0.offset) }.map { $0.element }
        // Reorder: swap random adjacent pairs a few times.
        for _ in 0..<surviving.count {
            let a = rnd(surviving.count), b = rnd(surviving.count)
            surviving.swapAt(a, b)
        }
        for f in surviving {
            for r in decoder.decode(framedPacket: f) {
                switch r {
                case .immediate(let kcp): delivered.append(kcp)
                case .recovered(let kcps): delivered.append(contentsOf: kcps)
                }
            }
        }
    }

    for d in delivered {
        #expect(originals.contains(d), "CORRUPT packet surfaced len=\(d.count)")
    }
    #expect(Set(delivered) == originals, "lost recoverable packets: \(originals.count - Set(delivered).count) missing")
}
