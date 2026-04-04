import Foundation
import snappy

enum KcpSnappyFramedCodecError: Error, Sendable {
    case invalidStreamIdentifier
    case invalidChunkLength
    case checksumMismatch
    case unsupportedChunkType(UInt8)
}

struct KcpSnappyFramedEncoder: Sendable {
    private static let streamIdentifierChunk = Data([
        0xff, 0x06, 0x00, 0x00,
        0x73, 0x4e, 0x61, 0x50, 0x70, 0x59,
    ])
    private static let maxUncompressedChunkSize = 32_768

    private var wroteStreamIdentifier = false

    mutating func encode(_ data: Data) throws -> Data {
        var output = Data()
        if !wroteStreamIdentifier {
            output.append(Self.streamIdentifierChunk)
            wroteStreamIdentifier = true
        }

        guard !data.isEmpty else {
            return output
        }

        var offset = 0
        while offset < data.count {
            let upperBound = min(offset + Self.maxUncompressedChunkSize, data.count)
            let chunk = data.subdata(in: offset..<upperBound)
            output.append(try makeCompressedChunk(for: chunk))
            offset = upperBound
        }

        return output
    }

    private func makeCompressedChunk(for payload: Data) throws -> Data {
        let compressed = try snappy.compress(payload)

        var body = Data()
        var checksum = Self.maskedCRC32C(payload).littleEndian
        withUnsafeBytes(of: &checksum) { body.append(contentsOf: $0) }
        body.append(compressed)

        var chunk = Data()
        chunk.append(0x00)
        chunk.append(UInt8(body.count & 0xff))
        chunk.append(UInt8((body.count >> 8) & 0xff))
        chunk.append(UInt8((body.count >> 16) & 0xff))
        chunk.append(body)
        return chunk
    }

    private static func maskedCRC32C(_ data: Data) -> UInt32 {
        let crc = crc32c(data)
        return ((crc >> 15) | (crc << 17)) &+ 0xa282_ead8
    }
}

struct KcpSnappyFramedDecoder: Sendable {
    private static let streamIdentifier = Data("sNaPpY".utf8)

    private var buffer = Data()
    private var sawStreamIdentifier = false

    mutating func append(_ data: Data) {
        buffer.append(data)
    }

    mutating func readAvailable() throws -> [Data] {
        var decoded: [Data] = []

        while buffer.count >= 4 {
            let chunkType = buffer[0]
            let length = Int(buffer[1]) | (Int(buffer[2]) << 8) | (Int(buffer[3]) << 16)
            guard length >= 0 else {
                throw KcpSnappyFramedCodecError.invalidChunkLength
            }

            let totalLength = 4 + length
            guard buffer.count >= totalLength else {
                break
            }

            let body = buffer.subdata(in: 4..<totalLength)
            buffer.removeSubrange(0..<totalLength)

            switch chunkType {
            case 0xff:
                guard body == Self.streamIdentifier else {
                    throw KcpSnappyFramedCodecError.invalidStreamIdentifier
                }
                sawStreamIdentifier = true

            case 0x00:
                guard sawStreamIdentifier else {
                    throw KcpSnappyFramedCodecError.invalidStreamIdentifier
                }
                guard body.count >= 4 else {
                    throw KcpSnappyFramedCodecError.invalidChunkLength
                }
                let expectedChecksum = body.withUnsafeBytes { rawBuffer in
                    rawBuffer.loadUnaligned(as: UInt32.self)
                }
                let compressed = body.dropFirst(4)
                let payload = try snappy.decompress(Data(compressed))
                guard Self.maskedCRC32C(payload) == UInt32(littleEndian: expectedChecksum) else {
                    throw KcpSnappyFramedCodecError.checksumMismatch
                }
                decoded.append(payload)

            case 0x01:
                guard sawStreamIdentifier else {
                    throw KcpSnappyFramedCodecError.invalidStreamIdentifier
                }
                guard body.count >= 4 else {
                    throw KcpSnappyFramedCodecError.invalidChunkLength
                }
                let expectedChecksum = body.withUnsafeBytes { rawBuffer in
                    rawBuffer.loadUnaligned(as: UInt32.self)
                }
                let payload = Data(body.dropFirst(4))
                guard Self.maskedCRC32C(payload) == UInt32(littleEndian: expectedChecksum) else {
                    throw KcpSnappyFramedCodecError.checksumMismatch
                }
                decoded.append(payload)

            case 0x80...0xfd:
                continue

            default:
                throw KcpSnappyFramedCodecError.unsupportedChunkType(chunkType)
            }
        }

        return decoded
    }

    private static func maskedCRC32C(_ data: Data) -> UInt32 {
        let crc = crc32c(data)
        return ((crc >> 15) | (crc << 17)) &+ 0xa282_ead8
    }
}

private let crc32cTable: [UInt32] = {
    (0..<256).map { index in
        var crc = UInt32(index)
        for _ in 0..<8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >>= 1
            }
        }
        return crc
    }
}()

private func crc32c(_ data: Data) -> UInt32 {
    var crc: UInt32 = 0xffff_ffff
    for byte in data {
        let tableIndex = Int((crc ^ UInt32(byte)) & 0xff)
        crc = (crc >> 8) ^ crc32cTable[tableIndex]
    }
    return crc ^ 0xffff_ffff
}
