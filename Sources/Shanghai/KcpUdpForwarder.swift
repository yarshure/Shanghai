import Dispatch
import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// KcpUdpForwarder — carry a UDP datagram protocol (e.g. WireGuard) over KCP,
/// bypassing the smux/stream layer entirely.
///
/// Why this exists (vs. KcpTunConnector): kcptun's smux is a *reliable, ordered
/// stream* multiplexer built for TCP. WireGuard is datagram-oriented and does its
/// own crypto + loss tolerance, so pushing it through a reliable stream adds
/// head-of-line blocking. Instead we run KCP in **message mode** (`stream = 0`)
/// so each inbound UDP datagram maps 1:1 to one KCP message and back, preserving
/// packet boundaries with no smux framing.
///
/// Topology (client side):
///
///     WireGuard  --UDP-->  127.0.0.1:localPort  (this forwarder)
///                              | each datagram -> KcpSession.send
///                              v
///                          KcpSession  (AES crypt + RS-FEC + KCP over UDP)
///                              v  to the remote KCP server :remotePort
///
/// The remote end needs a SYMMETRIC forwarder (NOT stock kcptun-go, which is
/// TCP→TCP): it accepts these KCP messages and `sendto`s each as a UDP datagram
/// to the real WireGuard server, and relays replies back. Both ends MUST share
/// the same KcpConfiguration crypt/key/datashard/parityshard/nodelay so the wire
/// bytes match. See WORK.md / shanghai-kcp-project notes.
///
/// Threading: a single serial queue owns the local socket + WG-peer address.
/// KcpSession owns its own state queue; we only touch it through send()/onReceive.
public final class KcpUdpForwarder: @unchecked Sendable {
    public enum ForwarderError: Error, Sendable {
        case alreadyStarted
        case localSocketFailed(code: Int32)
        case localBindFailed(code: Int32)
        case sessionFailed(Error)
    }

    public var onStop: (@Sendable (Error?) -> Void)?

    private let localHost: String
    private let localPort: UInt16
    private let configuration: KcpConfiguration

    private let queue = DispatchQueue(label: "shanghai.kcp.udpfwd")
    private let session: KcpSession

    private var localFD: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var started = false
    private var stopped = false

    /// Fixed address of the local WireGuard listener, if known up front.
    private let wgEndpoint: (host: String, port: UInt16)?

    /// Last source address a WG datagram arrived from on the local socket.
    /// Replies coming back out of KCP are `sendto`'d here. WireGuard talks from
    /// one socket per interface, so a single tracked peer is enough; if you ever
    /// fan in multiple local clients, key a table by source addr instead.
    private var wgPeer: sockaddr_storage?
    private var wgPeerLen: socklen_t = 0

    private var recvBuffer = [UInt8](repeating: 0, count: 65_535)

    /// - Parameters:
    ///   - localHost/localPort: where WireGuard's `Endpoint` should point
    ///     (typically 127.0.0.1:<port>).
    ///   - remoteHost/remotePort: the remote KCP server forwarder.
    ///   - kcpLocalPort: fixed local UDP port for the KCP socket itself.
    ///     Required for symmetric hub-to-hub peering, where the two
    ///     forwarders connect() to each other's well-known ports and
    ///     neither side runs accept/demux logic.
    ///   - wgEndpoint: where the local WireGuard actually listens (e.g.
    ///     127.0.0.1:1632). When set, decoded KCP messages always go there.
    ///     Without it the forwarder replies to the last learned source
    ///     address — fine for the initiator side, but a pure responder
    ///     would have to DROP inbound packets until its own WG speaks
    ///     first. Hub deployments should always set this.
    ///   - configuration: forced to message mode (`streamMode = false`). Crypt /
    ///     FEC / nodelay params MUST match the remote forwarder.
    public init(
        localHost: String = "127.0.0.1",
        localPort: UInt16,
        remoteHost: String,
        remotePort: UInt16,
        kcpLocalPort: UInt16? = nil,
        wgEndpoint: (host: String, port: UInt16)? = nil,
        configuration: KcpConfiguration = .init()
    ) {
        self.localHost = localHost
        self.localPort = localPort
        self.wgEndpoint = wgEndpoint

        // Datagram forwarding REQUIRES message mode — override regardless of
        // what the caller passed, so packet boundaries survive end to end.
        var cfg = configuration
        cfg.streamMode = false
        self.configuration = cfg

        self.session = KcpSession(
            remoteHost: remoteHost,
            remotePort: remotePort,
            localPort: kcpLocalPort,
            configuration: cfg,
            callbackQueue: queue
        )
    }

    public func start() throws {
        try queue.sync {
            guard !started else { throw ForwarderError.alreadyStarted }

            // 1. KCP message <- remote: forward straight back to the WG peer.
            session.onReceive = { [weak self] data in
                self?.forwardToWireGuard(data)
            }
            // onReceive/onStop fire on `queue` (we passed it as callbackQueue),
            // so they can touch our state directly — no extra hop needed.
            session.onStop = { [weak self] error in
                self?.shutdown(error, notify: true)
            }

            // 2. Local UDP socket WG points its Endpoint at.
            localFD = try Self.makeBoundUDPSocket(host: localHost, port: localPort)

            // Preset the reply target when the WG listener is known, so a
            // responder-side forwarder can deliver the very first inbound
            // packet before local WG has sent anything.
            if let wgEndpoint {
                if let (storage, length) = Posix.resolveUDP(host: wgEndpoint.host, port: wgEndpoint.port) {
                    wgPeer = storage
                    wgPeerLen = length
                } else {
                    KcpLog.warning("udpfwd cannot resolve wg endpoint \(wgEndpoint.host):\(wgEndpoint.port)")
                }
            }

            // 3. Drain WG datagrams -> KCP.
            let source = DispatchSource.makeReadSource(fileDescriptor: localFD, queue: queue)
            source.setEventHandler { [weak self] in self?.handleLocalReadable() }
            readSource = source
            source.resume()

            // 4. Bring up the KCP transport.
            do {
                try session.start()
            } catch {
                shutdown(error, notify: false)
                throw ForwarderError.sessionFailed(error)
            }

            started = true
            stopped = false
            KcpLog.info("udpfwd up local=\(localHost):\(localPort) -> kcp remote (msg mode)")
        }
    }

    public func stop() {
        queue.async { [weak self] in self?.shutdown(nil, notify: true) }
    }

    // MARK: - WG -> KCP

    private func handleLocalReadable() {
        guard localFD >= 0, !stopped else { return }
        while true {
            var from = sockaddr_storage()
            var fromLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n: Int = recvBuffer.withUnsafeMutableBytes { buf in
                withUnsafeMutablePointer(to: &from) { sa in
                    sa.withMemoryRebound(to: sockaddr.self, capacity: 1) { sap in
                        Posix.recvfrom(localFD, buf.baseAddress, buf.count, 0, sap, &fromLen)
                    }
                }
            }
            if n > 0 {
                // Remember who to reply to (WG's ephemeral source).
                wgPeer = from
                wgPeerLen = fromLen
                let packet = Data(recvBuffer.prefix(n))
                // TODO backpressure: if ikcp_waitsnd(session) > threshold, drop or
                // pause reading rather than letting KCP's send queue balloon under
                // a WG flood (see TODO.md ikcp_waitsnd note). Needs a hook on
                // KcpSession to expose waitsnd.
                session.send(packet)
                continue
            }
            if n == 0 { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK { break }
            KcpLog.error("udpfwd local recv errno=\(errno)")
            shutdown(ForwarderError.localSocketFailed(code: errno), notify: true)
            return
        }
    }

    // MARK: - KCP -> WG

    /// Runs on `queue` (called from session.onReceive). Sends one decoded KCP
    /// message back out the local socket to whoever WG last spoke from.
    private func forwardToWireGuard(_ data: Data) {
        guard localFD >= 0, !stopped else { return }
        guard var peer = wgPeer else {
            // No WG datagram seen yet → nowhere to send the reply. (WG is
            // client-initiated, so the server shouldn't speak first.)
            KcpLog.warning("udpfwd drop reply: no WG peer addr yet bytes=\(data.count)")
            return
        }
        let len = wgPeerLen
        let sent = data.withUnsafeBytes { buf in
            withUnsafeMutablePointer(to: &peer) { sa in
                sa.withMemoryRebound(to: sockaddr.self, capacity: 1) { sap in
                    Posix.sendto(localFD, buf.baseAddress, data.count, 0, sap, len)
                }
            }
        }
        if sent < 0 { KcpLog.error("udpfwd local sendto errno=\(errno)") }
    }

    // MARK: - lifecycle

    private func shutdown(_ error: Error?, notify: Bool) {
        if stopped { return }
        stopped = true
        started = false
        readSource?.setEventHandler {}
        readSource?.cancel()
        readSource = nil
        session.stop()
        if localFD >= 0 { _ = close(localFD); localFD = -1 }
        KcpLog.info("udpfwd down error=\(String(describing: error))")
        if notify { onStop?(error) }
    }

    // MARK: - socket helper

    /// Bind a non-blocking UDP socket on host:port (the address WG dials). Unlike
    /// KcpSession's `connect()`ed client socket, this one stays unconnected and
    /// uses recvfrom/sendto so it can learn WG's source address.
    private static func makeBoundUDPSocket(host: String, port: UInt16) throws -> Int32 {
        var hints = Posix.udpAddrInfoHints(passive: true)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else {
            throw ForwarderError.localBindFailed(code: errno)
        }
        defer { freeaddrinfo(first) }

        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let cur = cursor {
            let fd = socket(cur.pointee.ai_family, cur.pointee.ai_socktype, cur.pointee.ai_protocol)
            if fd >= 0, let addr = cur.pointee.ai_addr {
                var one: Int32 = 1
                setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
                if bind(fd, addr, cur.pointee.ai_addrlen) == 0 {
                    let flags = fcntl(fd, F_GETFL, 0)
                    _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
                    return fd
                }
                _ = close(fd)
            }
            cursor = cur.pointee.ai_next
        }
        throw ForwarderError.localBindFailed(code: errno)
    }
}
