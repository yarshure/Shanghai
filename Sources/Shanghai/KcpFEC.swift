import Foundation

/// kcptun-go FEC framing layer (typeData=0xf1, typeFEC=0xf2).
///
/// Wire shape (after AES encryption is layered ON TOP of these bytes):
///
///     Data packet:    [seqid:4 | flag=0xf1:2 | size+2:2 | <kcp_packet:N>]
///                     ↑ 8-byte FEC header                ↑ original kcp UDP datagram
///     Parity packet:  [seqid:4 | flag=0xf2:2 | <parity:M>]
///                     ↑ 6-byte FEC header
///
/// `size+2` in data packets is the kcp_packet length plus 2 (the size
/// field counts itself), present so a Reed-Solomon-recovered shard
/// — which has been zero-padded to the group's max length — can be
/// trimmed back to the original kcp packet boundary.
///
/// The RS-protected region per shard is `[size:2 | payload:N]`,
/// **NOT** including the 6-byte FEC header. Receiver derives seqid
/// and flag from the header on each arrived packet; reconstructed
/// data shards re-acquire their seqid by `seqid = group_base + i`.

enum KcpFEC {
    static let headerSize = 6           // seqid(4) + flag(2)
    static let headerSizePlus2 = 8      // headerSize + size(2) for data packets
    static let typeData: UInt16 = 0xf1
    static let typeFEC: UInt16 = 0xf2
    static let defaultRxLimit = 2048    // hold up to N out-of-order packets before evicting
    static let groupExpireMs: UInt64 = 30_000
}

private extension Data {
    mutating func appendUInt32LE(_ value: UInt32) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }
    mutating func appendUInt16LE(_ value: UInt16) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }
    func uint32LE(at offset: Int) -> UInt32 {
        withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self).littleEndian }
    }
    func uint16LE(at offset: Int) -> UInt16 {
        withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt16.self).littleEndian }
    }
}

/// Outbound side of the FEC framing layer. Wrap each KCP UDP packet
/// in a typeData FEC frame; every `dataShards` packets, compute and
/// emit `parityShards` typeFEC frames over the same group.
///
/// The encoder is single-threaded by contract — owners must serialise
/// calls (KcpSession does this via `stateQueue`).
final class KcpFECEncoder {
    private let codec: KcpReedSolomon
    private let dataShards: Int
    private let parityShards: Int
    private var nextSeqid: UInt32 = 0
    /// Per-shard `[size:2 | payload]` body for the running group.
    /// Index `i` corresponds to position `i` within the group.
    private var groupBuffer: [Data] = []
    /// PAWS-safe rollover so seqid never collides on a group boundary.
    /// Mirrors libkcp's `paws = (0xffffffff/totalShards - 1) * totalShards`.
    private let pawsLimit: UInt32

    init(dataShards: Int, parityShards: Int) throws {
        self.codec = try KcpReedSolomon(dataShards: dataShards, parityShards: parityShards)
        self.dataShards = dataShards
        self.parityShards = parityShards
        self.groupBuffer.reserveCapacity(dataShards)
        let total = UInt32(dataShards + parityShards)
        self.pawsLimit = (UInt32.max / total - 1) * total
    }

    var totalShards: Int { dataShards + parityShards }

    /// Wrap one KCP UDP packet into a typeData FEC frame and (if the
    /// group just filled) generate the parity frames. Returns 1
    /// data frame, optionally followed by `parityShards` parity
    /// frames. Caller is responsible for handing each Data to the
    /// packet codec / UDP write path in order.
    func encode(kcpPacket: Data) -> [Data] {
        var output: [Data] = []

        // Build the data frame on the wire.
        let dataFrame = makeDataFrame(seqid: nextSeqid, payload: kcpPacket)
        output.append(dataFrame)

        // Track the shard's RS-protected body — `[size:2 | payload]`.
        var shardBody = Data(capacity: 2 + kcpPacket.count)
        shardBody.appendUInt16LE(UInt16(kcpPacket.count + 2))
        shardBody.append(kcpPacket)
        groupBuffer.append(shardBody)

        nextSeqid &+= 1

        // Group is full — compute parity and emit M frames.
        if groupBuffer.count == dataShards {
            output.append(contentsOf: emitGroupParity())
            groupBuffer.removeAll(keepingCapacity: true)
        }

        // PAWS rollover guard. Only safe to reset between groups
        // (we just emitted the last data shard for this group; the
        // upcoming parity shards take seqids `next..next+parity-1`,
        // and only AFTER those should we wrap).
        if nextSeqid >= pawsLimit {
            nextSeqid = 0
        }

        return output
    }

    private func emitGroupParity() -> [Data] {
        // Pad all data shards to the max length so RS can operate on
        // equal-size byte arrays.
        let maxLen = groupBuffer.lazy.map { $0.count }.max() ?? 0
        var shards = groupBuffer.map { body -> Data in
            if body.count == maxLen { return body }
            var padded = body
            padded.append(Data(count: maxLen - body.count))
            return padded
        }
        // Append zero-filled parity slots — RS.Encode overwrites them.
        for _ in 0..<parityShards {
            shards.append(Data(count: maxLen))
        }

        do {
            try codec.encode(&shards)
        } catch {
            KcpLog.error("FEC parity encode failed: \(error)")
            return []
        }

        // Build wire frames for the M parity shards.
        var parityFrames: [Data] = []
        parityFrames.reserveCapacity(parityShards)
        for i in 0..<parityShards {
            let parityBytes = shards[dataShards + i]
            let frame = makeParityFrame(seqid: nextSeqid, payload: parityBytes)
            parityFrames.append(frame)
            nextSeqid &+= 1
        }
        return parityFrames
    }

    private func makeDataFrame(seqid: UInt32, payload: Data) -> Data {
        var frame = Data(capacity: KcpFEC.headerSizePlus2 + payload.count)
        frame.appendUInt32LE(seqid)
        frame.appendUInt16LE(KcpFEC.typeData)
        frame.appendUInt16LE(UInt16(payload.count + 2))
        frame.append(payload)
        return frame
    }

    private func makeParityFrame(seqid: UInt32, payload: Data) -> Data {
        var frame = Data(capacity: KcpFEC.headerSize + payload.count)
        frame.appendUInt32LE(seqid)
        frame.appendUInt16LE(KcpFEC.typeFEC)
        frame.append(payload)
        return frame
    }
}

/// Inbound side of the FEC framing layer. For arrived data shards
/// the receiver can immediately surface the inner KCP packet to the
/// caller. For groups with missing data shards, the decoder runs
/// Reed-Solomon reconstruction once enough siblings (≥ dataShards)
/// have arrived, then surfaces the recovered KCP packets.
///
/// Single-threaded by contract; KcpSession serialises through
/// `stateQueue`.
final class KcpFECDecoder {

    enum Result {
        case immediate(kcpPacket: Data)
        /// Reconstructed KCP packets, in seqid order within their group.
        case recovered(kcpPackets: [Data])
    }

    private let codec: KcpReedSolomon
    private let dataShards: Int
    private let parityShards: Int
    private let totalShards: Int
    private let rxLimit: Int

    /// One entry per arrived packet, ordered by `seqid` ascending.
    /// Body is the RS-protected region: `[size:2 | payload]` for
    /// data shards (already without FEC header) or raw parity bytes
    /// for parity shards.
    private struct Entry {
        let seqid: UInt32
        let isData: Bool
        var body: Data
        let arrivedMs: UInt64
    }
    private var rx: [Entry] = []
    private var lastEvictMs: UInt64 = 0

    init(dataShards: Int, parityShards: Int, rxLimit: Int = KcpFEC.defaultRxLimit) throws {
        self.codec = try KcpReedSolomon(dataShards: dataShards, parityShards: parityShards)
        self.dataShards = dataShards
        self.parityShards = parityShards
        self.totalShards = dataShards + parityShards
        self.rxLimit = rxLimit
    }

    /// Parse a plaintext FEC frame and produce results.
    /// Returns `nil` if the frame can't be parsed; otherwise a
    /// list of zero or more results. A typeData frame always
    /// produces an `.immediate(kcpPacket:)` result; a group-completion
    /// event additionally produces a `.recovered(...)`.
    func decode(framedPacket data: Data) -> [Result] {
        guard data.count >= KcpFEC.headerSize else { return [] }
        let seqid = data.uint32LE(at: 0)
        let flag = data.uint16LE(at: 4)
        let now = Self.nowMs()

        var output: [Result] = []
        let body: Data
        switch flag {
        case KcpFEC.typeData:
            // [size:2 | kcp_packet:N], where size = N + 2.
            // Wire offset 6..8 is the size; payload starts at offset 8.
            guard data.count >= KcpFEC.headerSizePlus2 else { return [] }
            let size = data.uint16LE(at: KcpFEC.headerSize)
            // Hand the inner KCP packet to the caller right away.
            // Most arrived data shards take this path — we only need
            // to also queue them for reconstruct in case a sibling
            // data shard is missing.
            let payloadStart = KcpFEC.headerSizePlus2
            let payloadEnd = data.count
            // Sanity: the embedded size should match the on-wire
            // length within our slice. If wildly off, drop the
            // packet — better than feeding garbage to ikcp_input.
            let expectedLen = Int(size) - 2
            guard expectedLen >= 0, expectedLen <= (payloadEnd - payloadStart) else { return [] }
            let kcpPacket = data.subdata(in: payloadStart..<(payloadStart + expectedLen))
            output.append(.immediate(kcpPacket: kcpPacket))
            // Body for RS purposes is `[size:2 | payload]`, padded
            // later to group max.
            body = data.subdata(in: KcpFEC.headerSize..<data.count)
        case KcpFEC.typeFEC:
            body = data.subdata(in: KcpFEC.headerSize..<data.count)
        default:
            return []
        }

        // Insertion-sort by seqid (typical kcptun groups are tiny;
        // O(N) per insert is fine vs. the cost of a real heap).
        evictExpired(nowMs: now)
        let isData = (flag == KcpFEC.typeData)
        let entry = Entry(seqid: seqid, isData: isData, body: body, arrivedMs: now)
        var insertAt = rx.count
        for i in stride(from: rx.count - 1, through: 0, by: -1) {
            if rx[i].seqid == seqid { return output } // duplicate
            if rx[i].seqid < seqid {
                insertAt = i + 1
                break
            }
            insertAt = i
        }
        rx.insert(entry, at: insertAt)

        // Try a reconstruct pass on the group containing this packet.
        if let recovered = tryReconstruct(seqid: seqid) {
            output.append(.recovered(kcpPackets: recovered))
        }

        // Bound the rx queue.
        while rx.count > rxLimit {
            rx.removeFirst()
        }

        return output
    }

    // MARK: - Internals

    private func tryReconstruct(seqid pivot: UInt32) -> [Data]? {
        let groupBase = pivot - (pivot % UInt32(totalShards))
        let groupEnd = groupBase + UInt32(totalShards) - 1

        // Pull out all rx entries that belong to this group.
        var slots: [Data?] = Array(repeating: nil, count: totalShards)
        var slotIsData: [Bool] = Array(repeating: false, count: totalShards)
        var presentCount = 0
        var dataPresentCount = 0
        var maxLen = 0
        var groupIndices: [Int] = []
        for (i, e) in rx.enumerated() {
            if e.seqid > groupEnd { break }
            if e.seqid >= groupBase {
                let idx = Int(e.seqid - groupBase)
                slots[idx] = e.body
                slotIsData[idx] = e.isData
                presentCount += 1
                if e.isData { dataPresentCount += 1 }
                if e.body.count > maxLen { maxLen = e.body.count }
                groupIndices.append(i)
            }
        }

        // Nothing to do unless we can produce a recovery.
        if dataPresentCount == dataShards {
            // All data shards present — just clean up the group.
            removeIndices(groupIndices)
            return nil
        }
        if presentCount < dataShards {
            return nil  // not enough siblings yet
        }

        // Pad to equal length and run RS reconstruct.
        var shards: [Data] = []
        shards.reserveCapacity(totalShards)
        var present: [Bool] = []
        present.reserveCapacity(totalShards)
        for i in 0..<totalShards {
            if let body = slots[i] {
                if body.count == maxLen {
                    shards.append(body)
                } else {
                    var padded = body
                    padded.append(Data(count: maxLen - body.count))
                    shards.append(padded)
                }
                present.append(true)
            } else {
                shards.append(Data(count: maxLen))
                present.append(false)
            }
        }

        do {
            try codec.reconstruct(&shards, present: present)
        } catch {
            KcpLog.error("FEC reconstruct failed seqid=\(pivot) group=\(groupBase): \(error)")
            removeIndices(groupIndices)
            return nil
        }

        // Walk the data slots and emit only the ones that were
        // missing on arrival — caller already received the rest via
        // .immediate(). Trim each by the embedded size field.
        var recovered: [Data] = []
        for i in 0..<dataShards {
            if !slotIsData[i] && shards[i].count >= 2 {
                let size = shards[i].uint16LE(at: 0)
                let payloadLen = Int(size) - 2
                if payloadLen >= 0, payloadLen <= shards[i].count - 2 {
                    recovered.append(shards[i].subdata(in: 2..<(2 + payloadLen)))
                }
            }
        }
        removeIndices(groupIndices)
        return recovered.isEmpty ? nil : recovered
    }

    private func removeIndices(_ indices: [Int]) {
        // indices are ascending; iterate backwards so removeAt
        // doesn't shift later indices.
        for i in indices.reversed() {
            rx.remove(at: i)
        }
    }

    private func evictExpired(nowMs: UInt64) {
        if nowMs &- lastEvictMs < KcpFEC.groupExpireMs { return }
        lastEvictMs = nowMs
        rx.removeAll { entry in
            (nowMs &- entry.arrivedMs) > KcpFEC.groupExpireMs
        }
    }

    private static func nowMs() -> UInt64 {
        var ts = timespec()
        clock_gettime(CLOCK_MONOTONIC, &ts)
        return UInt64(ts.tv_sec) * 1000 + UInt64(ts.tv_nsec) / 1_000_000
    }
}
