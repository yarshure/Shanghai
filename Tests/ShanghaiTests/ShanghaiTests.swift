import Testing
@testable import Shanghai
import Foundation

private struct TestServer {
    static let endpoint = KcpRemoteEndpoint(host: "45.76.141.59", port: 63_201)
}

private final class TestStreamHandler: KcpTunStreamHandler, @unchecked Sendable {
    let sessionID: UInt32

    private let lock = NSLock()
    private var chunks: [Data] = []
    private var connectEvents = 0
    private var disconnectError: Error?

    init(sessionID: UInt32) {
        self.sessionID = sessionID
    }

    func connectorDidConnect(_ connector: KcpTunConnector) {
        lock.lock()
        connectEvents += 1
        lock.unlock()
    }

    func connector(_ connector: KcpTunConnector, didReceive data: Data, for sessionID: UInt32) {
        lock.lock()
        chunks.append(data)
        lock.unlock()
    }

    func connector(_ connector: KcpTunConnector, didDisconnect sessionID: UInt32, error: Error?) {
        lock.lock()
        disconnectError = error
        lock.unlock()
    }

    var receivedData: Data {
        lock.lock()
        defer { lock.unlock() }
        return chunks.reduce(into: Data()) { $0.append($1) }
    }

    var connectionCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return connectEvents
    }

    var lastDisconnectError: Error? {
        lock.lock()
        defer { lock.unlock() }
        return disconnectError
    }
}

private func waitUntil(
    timeout: TimeInterval,
    pollInterval: UInt64 = 100_000_000,
    condition: @escaping @Sendable () -> Bool
) async -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() {
            return true
        }
        try? await Task.sleep(nanoseconds: pollInterval)
    }
    return condition()
}

private func printHTTPPreview(_ data: Data) {
    let text = String(decoding: data, as: UTF8.self)
    let parts = text.components(separatedBy: "\r\n\r\n")
    let headers = parts.first ?? text
    let body = parts.count > 1 ? parts.dropFirst().joined(separator: "\r\n\r\n") : ""
    let bodyPreview = String(body.prefix(1_024))
    print("========== HTTP RESPONSE HEADERS ==========")
    print(headers)
    print("========== HTTP RESPONSE BODY (first 1KB) ==========")
    print(bodyPreview)
    print("========== HTTP RESPONSE HEXDUMP ==========")
    KcpLog.hexDump("test http response", data: data, limit: 1024)
}

@Test func configurationDefaults() async throws {
    let config = KcpConfiguration()
    #expect(config.mtu == 1_400)
    #expect(config.sendWindow == 128)
    #expect(config.receiveWindow == 128)
    #expect(config.streamMode)
}

@Test func sessionCanBeCreated() async throws {
    let session = KcpSession(remoteHost: "127.0.0.1", remotePort: 29_999)
    #expect(session.localEndpoint() == nil)
}

@Test func frameRoundTrip() async throws {
    let original = KcpFrame(version: KcpSmuxVersion.v1.rawValue, command: .psh, sessionID: 7, payload: Data("hello".utf8))
    var decoder = KcpFrameDecoder(expectedVersion: KcpSmuxVersion.v1.rawValue)
    decoder.append(original.encoded())

    let decoded = decoder.nextFrame()
    #expect(decoded.error == nil)
    #expect(decoded.frame?.command == .psh)
    #expect(decoded.frame?.sessionID == 7)
    #expect(decoded.frame?.payload == Data("hello".utf8))
}

@Test func frameRoundTripSupportsSmuxV2() async throws {
    let original = KcpFrame(version: KcpSmuxVersion.v2.rawValue, command: .upd, sessionID: 9, payload: Data([1, 2, 3, 4, 5, 6, 7, 8]))
    var decoder = KcpFrameDecoder(expectedVersion: KcpSmuxVersion.v2.rawValue)
    decoder.append(original.encoded())

    let decoded = decoder.nextFrame()
    #expect(decoded.error == nil)
    #expect(decoded.frame?.version == KcpSmuxVersion.v2.rawValue)
    #expect(decoded.frame?.command == .upd)
    #expect(decoded.frame?.sessionID == 9)
    #expect(decoded.frame?.payload == Data([1, 2, 3, 4, 5, 6, 7, 8]))
}

@Test func managerUsesEndpointAsIdentity() async throws {
    let manager = KcpTunConnectorManager()
    let endpoint = KcpRemoteEndpoint(host: "1.2.3.4", port: 29900)
    let connectorA = manager.connector(for: endpoint) { endpoint in
        KcpTunConnectorConfiguration(endpoint: endpoint)
    }
    let connectorB = manager.connector(for: endpoint) { endpoint in
        KcpTunConnectorConfiguration(endpoint: endpoint, kcp: .init(conversationID: 2))
    }

    #expect(connectorA === connectorB)
}

@Test("Manager + connector can send plain HTTP GET through test KCPTUN", .timeLimit(.minutes(1)))
func integrationHTTPOverKcpTunnel() async throws {
    let manager = KcpTunConnectorManager()
    let endpoint = TestServer.endpoint
    let connector = manager.connector(for: endpoint) { endpoint in
        KcpTunConnectorConfiguration(
            endpoint: endpoint,
            kcp: KcpConfiguration(
                conversationID: 1,
                mtu: 1_350,
                sendWindow: 128,
                receiveWindow: 512,
                noDelay: 0,
                interval: 30,
                resend: 2,
                disableCongestionControl: 1,
                streamMode: true
            ),
            smuxVersion: .v2,
            keepAliveInterval: 3,
            maxFrameSize: 4_096,
            maxStreamBuffer: 65_536,
            bootstrapSessionID: 0
        )
    }

    let stream = TestStreamHandler(sessionID: 1)

    try connector.start()
    connector.openStream(stream)

    let didConnect = await waitUntil(timeout: 5) {
        stream.connectionCount > 0
    }
    #expect(didConnect)

    let request = Data("""
    GET http://example.com/ HTTP/1.1\r
    Host: example.com\r
    User-Agent: ShanghaiTests/1.0\r
    Accept: */*\r
    Proxy-Connection: close\r
    Connection: close\r
    \r
    """.utf8)

    connector.send(request, for: stream.sessionID)

    let didReceiveResponse = await waitUntil(timeout: 20) {
        !stream.receivedData.isEmpty
    }
    #expect(didReceiveResponse)

    KcpLog.hexDump("test http request", data: request, limit: 1024)
    let responseText = String(decoding: stream.receivedData, as: UTF8.self)
    printHTTPPreview(stream.receivedData)
    #expect(responseText.contains("HTTP/"))

    let managerStillOwnsConnector = await waitUntil(timeout: 4) {
        manager.connector(for: endpoint) === connector
    }
    #expect(managerStillOwnsConnector)

    connector.closeStream(sessionID: stream.sessionID)
    manager.removeConnector(for: endpoint)
}
