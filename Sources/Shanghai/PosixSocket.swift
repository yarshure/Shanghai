#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif

// Module-qualified references resolved once, so the methods below (whose
// names shadow the libc ones) stay free of per-call #if ladders.
#if canImport(Darwin)
private let libcRecv = Darwin.recv
private let libcSend = Darwin.send
private let libcRecvfrom = Darwin.recvfrom
private let libcSendto = Darwin.sendto
#elseif canImport(Glibc)
private let libcRecv = Glibc.recv
private let libcSend = Glibc.send
private let libcRecvfrom = Glibc.recvfrom
private let libcSendto = Glibc.sendto
#elseif canImport(Musl)
private let libcRecv = Musl.recv
private let libcSend = Musl.send
private let libcRecvfrom = Musl.recvfrom
private let libcSendto = Musl.sendto
#elseif canImport(Android)
private let libcRecv = Android.recv
private let libcSend = Android.send
private let libcRecvfrom = Android.recvfrom
private let libcSendto = Android.sendto
#endif

/// Thin libc socket shim so the rest of the package never spells out
/// `Darwin.` / `Glibc.` / `Musl.`. Two reasons it exists:
///
/// 1. Inside `KcpSession`/`KcpUdpForwarder` the libc names `send`/`recv`
///    are shadowed by methods, so call sites need SOME qualifier — this
///    one works on both platforms.
/// 2. A few constants don't line up across libcs: on Glibc `SOCK_DGRAM`
///    is a `__socket_type` enum (needs `.rawValue`), and the
///    `addrinfo`/`sockaddr_in6` layouts differ in ways that break
///    memberwise inits and union field access.
enum Posix {
    @inline(__always)
    static func recv(_ fd: Int32, _ buffer: UnsafeMutableRawPointer?, _ length: Int, _ flags: Int32) -> Int {
        libcRecv(fd, buffer, length, flags)
    }

    @inline(__always)
    static func send(_ fd: Int32, _ buffer: UnsafeRawPointer?, _ length: Int, _ flags: Int32) -> Int {
#if canImport(Android)
        // bionic types the buffer as `_Nonnull`; nothing useful to send if nil.
        guard let buffer else { return 0 }
        return libcSend(fd, buffer, length, flags)
#else
        return libcSend(fd, buffer, length, flags)
#endif
    }

    @inline(__always)
    static func recvfrom(
        _ fd: Int32,
        _ buffer: UnsafeMutableRawPointer?,
        _ length: Int,
        _ flags: Int32,
        _ address: UnsafeMutablePointer<sockaddr>?,
        _ addressLength: UnsafeMutablePointer<socklen_t>?
    ) -> Int {
        libcRecvfrom(fd, buffer, length, flags, address, addressLength)
    }

    @inline(__always)
    static func sendto(
        _ fd: Int32,
        _ buffer: UnsafeRawPointer?,
        _ length: Int,
        _ flags: Int32,
        _ address: UnsafePointer<sockaddr>?,
        _ addressLength: socklen_t
    ) -> Int {
#if canImport(Android)
        guard let buffer else { return 0 }
        return libcSendto(fd, buffer, length, flags, address, addressLength)
#else
        return libcSendto(fd, buffer, length, flags, address, addressLength)
#endif
    }

    static var socketTypeDatagram: Int32 {
#if canImport(Glibc)
        Int32(SOCK_DGRAM.rawValue) // Glibc imports it as a __socket_type enum
#else
        Int32(SOCK_DGRAM) // Darwin & Musl: plain integer constant
#endif
    }

    static var protocolUDP: Int32 {
        Int32(IPPROTO_UDP)
    }

    /// Zeroed `addrinfo` hints for a numeric-service UDP lookup. Built
    /// field-by-field because Darwin and Glibc declare the struct members
    /// in different orders, which breaks the labeled memberwise init.
    static func udpAddrInfoHints(passive: Bool) -> addrinfo {
        var hints = addrinfo()
        hints.ai_flags = passive ? (AI_NUMERICSERV | AI_PASSIVE) : AI_NUMERICSERV
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = socketTypeDatagram
        hints.ai_protocol = protocolUDP
        return hints
    }

    /// Resolve host:port (numeric service) into the first matching UDP
    /// sockaddr, returned as storage + length.
    static func resolveUDP(host: String, port: UInt16) -> (sockaddr_storage, socklen_t)? {
        var hints = udpAddrInfoHints(passive: false)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else {
            return nil
        }
        defer { freeaddrinfo(first) }
        guard let addr = first.pointee.ai_addr else { return nil }
        var storage = sockaddr_storage()
        let length = first.pointee.ai_addrlen
        withUnsafeMutableBytes(of: &storage) { dest in
            dest.copyMemory(from: UnsafeRawBufferPointer(start: addr, count: Int(length)))
        }
        return (storage, socklen_t(length))
    }
}
