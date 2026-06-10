import Foundation
import Testing
@testable import Shanghai

/// Cross-validates the portable C crypt (CKcp/shanghai_crypt.c, the path
/// Linux/FreeBSD hubs run) against CommonCrypto (the Apple path originally
/// verified wire-compatible with go kcptun). Byte equality here is what
/// guarantees a Linux kcpfwd and an Apple client speak the same wire format.
struct KcpPacketCodecPortableTests {

    @Test func portableKeyDerivationMatchesCommonCrypto() throws {
#if canImport(CommonCrypto)
        for (password, length) in [("it's a secrect", 32), ("polar-hub", 16), ("跨境", 24), ("x", 32)] {
            let portable = try KcpPacketCodec.portableDeriveKey(password: password, length: length)
            let reference = try KcpPacketCodec.deriveKey(password: password, length: length)
            #expect(portable == reference, "PBKDF2 mismatch for password=\(password) length=\(length)")
        }
#endif
    }

    @Test func portableCFBMatchesCommonCrypto() throws {
#if canImport(CommonCrypto)
        for keyLength in [16, 24, 32] {
            let key = try KcpPacketCodec.portableDeriveKey(password: "cross-check", length: keyLength)
            // Cover partial blocks, exact blocks, multi-block, and a
            // realistic WG-handshake-sized payload.
            for payloadSize in [0, 1, 15, 16, 17, 64, 148, 1_400] {
                let payload = Data((0..<payloadSize).map { _ in UInt8.random(in: 0...255) })

                let portableCipher = try KcpPacketCodec.portableCrypt(payload, key: key, encrypt: true)
                let referenceCipher = try KcpPacketCodec.commonCryptoCrypt(payload, key: key, encrypt: true)
                #expect(portableCipher == referenceCipher, "CFB encrypt mismatch keyLen=\(keyLength) size=\(payloadSize)")

                // Decrypt across implementations both ways.
                #expect(try KcpPacketCodec.portableCrypt(referenceCipher, key: key, encrypt: false) == payload)
                #expect(try KcpPacketCodec.commonCryptoCrypt(portableCipher, key: key, encrypt: false) == payload)
            }
        }
#endif
    }

    @Test func portableCryptRoundTrip() throws {
        // Pure C-path round trip — the only self-check available on Linux.
        let key = try KcpPacketCodec.portableDeriveKey(password: "roundtrip", length: 32)
        for payloadSize in [0, 1, 16, 31, 1_280] {
            let payload = Data((0..<payloadSize).map { _ in UInt8.random(in: 0...255) })
            let cipher = try KcpPacketCodec.portableCrypt(payload, key: key, encrypt: true)
            if payloadSize > 0 {
                #expect(cipher != payload)
            }
            #expect(try KcpPacketCodec.portableCrypt(cipher, key: key, encrypt: false) == payload)
        }
    }

    @Test func codecEncodeDecodeStillRoundTrips() throws {
        // End-to-end packet codec (nonce + CRC + crypt) sanity after the
        // Sodium removal and crypt refactor.
        for method in [KcpPacketCryptoMethod.none, .aes, .aes128, .aes192] {
            let codec = try KcpPacketCodec(crypt: method, password: "it's a secrect")
            let payload = Data((0..<333).map { _ in UInt8.random(in: 0...255) })
            let wire = try codec.encode(payload)
            #expect(try codec.decode(wire) == payload, "codec round trip failed crypt=\(method.rawValue)")
            if method != .none {
                #expect(!wire.dropFirst(20).elementsEqual(payload), "crypt=\(method.rawValue) left payload in clear")
            }
        }
    }
}
