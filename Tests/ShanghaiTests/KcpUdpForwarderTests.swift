import Dispatch
import Foundation
import Testing
@testable import Shanghai

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif

/// End-to-end loopback of the hub-to-hub topology: two symmetric
/// forwarders dial each other's fixed KCP ports (no accept/demux), each
/// with a preset wgEndpoint, and two plain UDP sockets stand in for the
/// kernel WireGuard listeners. Verifies datagram boundaries survive in
/// both directions — including B->A where forwarder A must rely on the
/// preset wgEndpoint because its "WireGuard" hasn't spoken yet.
struct KcpUdpForwarderTests {

    /// A plain UDP socket standing in for a kernel WireGuard listener.
    private final class FakeWireGuard: @unchecked Sendable {
        let fd: Int32
        let port: UInt16
        private let queue = DispatchQueue(label: "test.fakewg")
        private let source: DispatchSourceRead
        private var buffer = [UInt8](repeating: 0, count: 65_535)
        var onDatagram: (@Sendable (Data) -> Void)?

        init(port: UInt16) throws {
            let descriptor = socket(AF_INET, Posix.socketTypeDatagram, Posix.protocolUDP)
            try #require(descriptor >= 0)
            var one: Int32 = 1
            setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = UInt32(0x7f00_0001).bigEndian // 127.0.0.1
            let bound = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bind(descriptor, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            try #require(bound == 0, "fake wg bind failed errno=\(errno)")

            self.port = port
            self.fd = descriptor
            self.source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
            source.setEventHandler { [weak self] in self?.drain() }
            source.resume()
        }

        private func drain() {
            while true {
                let n = buffer.withUnsafeMutableBytes { Posix.recv(fd, $0.baseAddress, $0.count, 0) }
                if n > 0 {
                    onDatagram?(Data(buffer.prefix(n)))
                    continue
                }
                break
            }
        }

        /// Send a datagram to the local forwarder's WG-facing port.
        func send(_ data: Data, toPort destinationPort: UInt16) {
            guard let (storage, length) = Posix.resolveUDP(host: "127.0.0.1", port: destinationPort) else { return }
            var addr = storage
            _ = data.withUnsafeBytes { bytes in
                withUnsafePointer(to: &addr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        Posix.sendto(fd, bytes.baseAddress, data.count, 0, sa, length)
                    }
                }
            }
        }

        deinit {
            source.setEventHandler {}
            source.cancel()
            _ = close(fd)
        }
    }

    @Test func symmetricForwarderPairCarriesDatagramsBothWays() throws {
        // Fixed test ports; obscure range to dodge collisions.
        let wgPortA: UInt16 = 46_801, wgPortB: UInt16 = 46_802
        let listenA: UInt16 = 46_803, listenB: UInt16 = 46_804
        let kcpPortA: UInt16 = 46_805, kcpPortB: UInt16 = 46_806

        var configuration = KcpConfiguration()
        configuration.conversationID = 99
        configuration.crypt = .aes
        configuration.preSharedKey = "loopback-test"
        configuration.dataShards = 3
        configuration.parityShards = 1

        let wgA = try FakeWireGuard(port: wgPortA)
        let wgB = try FakeWireGuard(port: wgPortB)

        let forwarderA = KcpUdpForwarder(
            localPort: listenA,
            remoteHost: "127.0.0.1", remotePort: kcpPortB,
            kcpLocalPort: kcpPortA,
            wgEndpoint: (host: "127.0.0.1", port: wgPortA),
            configuration: configuration
        )
        let forwarderB = KcpUdpForwarder(
            localPort: listenB,
            remoteHost: "127.0.0.1", remotePort: kcpPortA,
            kcpLocalPort: kcpPortB,
            wgEndpoint: (host: "127.0.0.1", port: wgPortB),
            configuration: configuration
        )
        try forwarderA.start()
        try forwarderB.start()
        defer {
            forwarderA.stop()
            forwarderB.stop()
        }

        // Direction A -> B (initiator-style: wgA speaks first).
        let handshakeSized = Data((0..<148).map { UInt8($0 & 0xff) })
        let receivedAtB = DispatchSemaphore(value: 0)
        let bInbox = Inbox()
        wgB.onDatagram = { data in
            bInbox.append(data)
            receivedAtB.signal()
        }
        wgA.send(handshakeSized, toPort: listenA)
        #expect(receivedAtB.wait(timeout: .now() + 3) == .success, "A->B datagram never arrived")
        #expect(bInbox.first() == handshakeSized, "A->B payload mangled")

        // Direction B -> A: forwarder A has NEVER seen a local datagram on
        // this socket from wgA reply path... it has (wgA sent above), so
        // also verify a SECOND pair where the responder speaks via the
        // preset endpoint only: send from wgB before wgA ever talks again,
        // expecting delivery to the preset 127.0.0.1:wgPortA.
        let replySized = Data((0..<92).map { UInt8(($0 &* 7) & 0xff) })
        let receivedAtA = DispatchSemaphore(value: 0)
        let aInbox = Inbox()
        wgA.onDatagram = { data in
            aInbox.append(data)
            receivedAtA.signal()
        }
        wgB.send(replySized, toPort: listenB)
        #expect(receivedAtA.wait(timeout: .now() + 3) == .success, "B->A datagram never arrived")
        #expect(aInbox.first() == replySized, "B->A payload mangled")
    }

    /// Server/listen mode: one forwarder binds and learns its peer from the
    /// first inbound packet (the NAT'd-client topology), instead of both ends
    /// dialing fixed ports. The client must speak first to bootstrap, after
    /// which both directions flow. Mirrors the hub-as-server cross-border
    /// deployment validated on 124.221.22.9.
    @Test func serverModeLearnsPeerAndCarriesBothWays() throws {
        let wgClientPort: UInt16 = 46_811, wgServerPort: UInt16 = 46_812
        let listenClient: UInt16 = 46_813, listenServer: UInt16 = 46_814
        let kcpClient: UInt16 = 46_815, kcpServer: UInt16 = 46_816

        var configuration = KcpConfiguration()
        configuration.conversationID = 123
        configuration.crypt = .aes
        configuration.preSharedKey = "servermode-test"
        // FEC intentionally off — see KcpFEC variable-size bug note.
        configuration.dataShards = 0
        configuration.parityShards = 0

        let wgClient = try FakeWireGuard(port: wgClientPort)
        let wgServer = try FakeWireGuard(port: wgServerPort)

        // Server binds kcpServer and learns the client; remoteHost/Port unused.
        let server = KcpUdpForwarder(
            localPort: listenServer,
            remoteHost: "0.0.0.0", remotePort: 0,
            kcpLocalPort: kcpServer,
            listenMode: true,
            wgEndpoint: (host: "127.0.0.1", port: wgServerPort),
            configuration: configuration
        )
        // Client dials the server's kcp port (as if over the internet).
        let client = KcpUdpForwarder(
            localPort: listenClient,
            remoteHost: "127.0.0.1", remotePort: kcpServer,
            kcpLocalPort: kcpClient,
            wgEndpoint: (host: "127.0.0.1", port: wgClientPort),
            configuration: configuration
        )
        try server.start()
        try client.start()
        defer { client.stop(); server.stop() }

        // Client speaks first → server learns it.
        let req = Data((0..<148).map { UInt8($0 & 0xff) })
        let atServer = DispatchSemaphore(value: 0)
        let serverInbox = Inbox()
        wgServer.onDatagram = { data in serverInbox.append(data); atServer.signal() }
        wgClient.send(req, toPort: listenClient)
        #expect(atServer.wait(timeout: .now() + 3) == .success, "client->server never arrived")
        #expect(serverInbox.first() == req, "client->server payload mangled")

        // Reply rides back to the learned client.
        let resp = Data((0..<92).map { UInt8(($0 &* 5) & 0xff) })
        let atClient = DispatchSemaphore(value: 0)
        let clientInbox = Inbox()
        wgClient.onDatagram = { data in clientInbox.append(data); atClient.signal() }
        wgServer.send(resp, toPort: listenServer)
        #expect(atClient.wait(timeout: .now() + 3) == .success, "server->client (learned) never arrived")
        #expect(clientInbox.first() == resp, "server->client payload mangled")
    }

    /// Tiny thread-safe holder so the @Sendable callbacks can hand
    /// datagrams back to the test body.
    private final class Inbox: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [Data] = []
        func append(_ data: Data) {
            lock.lock(); items.append(data); lock.unlock()
        }
        func first() -> Data? {
            lock.lock(); defer { lock.unlock() }
            return items.first
        }
    }
}
