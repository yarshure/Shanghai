import Foundation
import Sodium

#if canImport(CommonCrypto)
import CommonCrypto
#endif

public enum KcpPacketCryptoMethod: String, Sendable {
    case none = "none"
    case aes = "aes"
    case aes128 = "aes-128"
    case aes192 = "aes-192"

    var derivedKeyLength: Int {
        switch self {
        case .none:
            0
        case .aes:
            32
        case .aes128:
            16
        case .aes192:
            24
        }
    }
}

enum KcpPacketCodecError: Error, Sendable {
    case invalidHeader
    case crcMismatch
    case cryptoUnavailable
    case cryptoFailed(status: Int32)
    case keyDerivationFailed
    case randomFailed
}

struct KcpPacketCodec: Sendable {
    private static let salt = Data("kcp-go".utf8)
    private static let headerNonceSize = 16
    private static let headerCRCSize = 4
    private static let headerSize = headerNonceSize + headerCRCSize
    private static let iv: [UInt8] = [167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107]

    let crypt: KcpPacketCryptoMethod
    let key: Data?

    init(crypt: KcpPacketCryptoMethod, password: String) throws {
        self.crypt = crypt
        if crypt == .none {
            self.key = nil
        } else {
            self.key = try Self.deriveKey(password: password, length: crypt.derivedKeyLength)
        }
    }

    func encode(_ payload: Data) throws -> Data {
        var packet = Data()
        packet.append(try Self.randomBytes(count: Self.headerNonceSize))

        var checksum = Self.crc32(payload).littleEndian
        withUnsafeBytes(of: &checksum) { packet.append(contentsOf: $0) }
        packet.append(payload)

        guard crypt != .none else {
            return packet
        }

        return try cryptPacket(packet, operation: CCOperation(kCCEncrypt))
    }

    func decode(_ packet: Data) throws -> Data {
        let plaintext: Data
        if crypt == .none {
            plaintext = packet
        } else {
            plaintext = try cryptPacket(packet, operation: CCOperation(kCCDecrypt))
        }

        guard plaintext.count >= Self.headerSize else {
            throw KcpPacketCodecError.invalidHeader
        }

        let body = plaintext.dropFirst(Self.headerSize)
        let storedCRC = plaintext.withUnsafeBytes { rawBuffer -> UInt32 in
            let crcOffset = Self.headerNonceSize
            return rawBuffer.loadUnaligned(fromByteOffset: crcOffset, as: UInt32.self)
        }

        guard Self.crc32(body) == UInt32(littleEndian: storedCRC) else {
            throw KcpPacketCodecError.crcMismatch
        }

        return Data(body)
    }

    private func cryptPacket(_ packet: Data, operation: CCOperation) throws -> Data {
#if canImport(CommonCrypto)
        guard let key else {
            throw KcpPacketCodecError.keyDerivationFailed
        }

        var cryptor: CCCryptorRef?
        let createStatus = key.withUnsafeBytes { keyBytes in
            Self.iv.withUnsafeBytes { ivBytes in
                CCCryptorCreateWithMode(
                    operation,
                    CCMode(kCCModeCFB),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBytes.baseAddress,
                    keyBytes.baseAddress,
                    key.count,
                    nil,
                    0,
                    0,
                    CCModeOptions(),
                    &cryptor
                )
            }
        }
        guard createStatus == kCCSuccess, let cryptor else {
            throw KcpPacketCodecError.cryptoFailed(status: createStatus)
        }
        defer { CCCryptorRelease(cryptor) }

        let outputLength = CCCryptorGetOutputLength(cryptor, packet.count, true)
        var output = Data(count: outputLength)
        var moved = 0
        let updateStatus = output.withUnsafeMutableBytes { outputBytes in
            packet.withUnsafeBytes { inputBytes in
                CCCryptorUpdate(
                    cryptor,
                    inputBytes.baseAddress,
                    packet.count,
                    outputBytes.baseAddress,
                    outputLength,
                    &moved
                )
            }
        }
        guard updateStatus == kCCSuccess else {
            throw KcpPacketCodecError.cryptoFailed(status: updateStatus)
        }

        var finalMoved = 0
        let finalStatus = output.withUnsafeMutableBytes { outputBytes in
            CCCryptorFinal(
                cryptor,
                outputBytes.baseAddress?.advanced(by: moved),
                outputLength - moved,
                &finalMoved
            )
        }
        guard finalStatus == kCCSuccess else {
            throw KcpPacketCodecError.cryptoFailed(status: finalStatus)
        }

        output.removeSubrange((moved + finalMoved)..<output.count)
        return output
#else
        throw KcpPacketCodecError.cryptoUnavailable
#endif
    }

    private static func randomBytes(count: Int) throws -> Data {
        let sodium = Sodium()
        guard let bytes = sodium.randomBytes.buf(length: count) else {
            throw KcpPacketCodecError.randomFailed
        }
        return Data(bytes)
    }

    private static func deriveKey(password: String, length: Int) throws -> Data {
#if canImport(CommonCrypto)
        var derivedKey = Data(repeating: 0, count: length)
        let status = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password,
                    password.utf8.count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress,
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                    4096,
                    derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                    length
                )
            }
        }
        guard status == kCCSuccess else {
            throw KcpPacketCodecError.keyDerivationFailed
        }
        return derivedKey
#else
        throw KcpPacketCodecError.cryptoUnavailable
#endif
    }

    private static func crc32<T: DataProtocol>(_ data: T) -> UInt32 {
        var crc: UInt32 = 0xffff_ffff
        for byte in data {
            var x = (crc ^ UInt32(byte)) & 0xff
            for _ in 0..<8 {
                if (x & 1) != 0 {
                    x = (x >> 1) ^ 0xedb8_8320
                } else {
                    x >>= 1
                }
            }
            crc = (crc >> 8) ^ x
        }
        return crc ^ 0xffff_ffff
    }
}
