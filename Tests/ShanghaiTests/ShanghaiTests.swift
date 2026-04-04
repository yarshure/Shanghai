import Testing
@testable import Shanghai
import Foundation

private struct LocalKcptunCase: Sendable {
    let name: String
    let endpoint: KcpRemoteEndpoint
    let smuxVersion: KcpSmuxVersion
    let crypt: KcpPacketCryptoMethod
    let compressed: Bool
    let password: String
    let targetHost: String
    let targetPort: UInt16
    let requestMethod: String
    let requestURL: String
    let requestHostHeader: String
    let expectedResponseMarker: String
}

private enum LocalKcptunTestConfig {
    static func current() -> LocalKcptunCase? {
        let env = ProcessInfo.processInfo.environment
        guard env["SHANGHAI_RUN_LOCAL_KCPTUN_CASE"] == "1" else {
            return nil
        }

        let host = env["SHANGHAI_KCPTUN_HOST"] ?? "127.0.0.1"
        guard let portString = env["SHANGHAI_KCPTUN_PORT"], let port = UInt16(portString) else {
            return nil
        }

        let smuxRaw = env["SHANGHAI_KCPTUN_SMUXVER"] ?? "2"
        let smuxVersion: KcpSmuxVersion = smuxRaw == "1" ? .v1 : .v2
        let crypt = (env["SHANGHAI_KCPTUN_CRYPT"] ?? "none").lowercased()
        let compressed = env["SHANGHAI_KCPTUN_NOCOMP"] != "1"
        let name = env["SHANGHAI_KCPTUN_CASE_NAME"] ?? "local-kcptun-case"
        let password = env["SHANGHAI_KCPTUN_PASSWORD"] ?? "Xifeng2026"
        let targetHost = env["SHANGHAI_TARGET_HOST"] ?? "127.0.0.1"
        let targetPort = UInt16(env["SHANGHAI_TARGET_PORT"] ?? "6152") ?? 6152
        let requestMethod = (env["SHANGHAI_PROXY_REQUEST_METHOD"] ?? "GET").uppercased()
        let requestURL = env["SHANGHAI_PROXY_REQUEST_URL"] ?? "http://example.com/"
        let requestHostHeader = env["SHANGHAI_PROXY_REQUEST_HOST"] ?? "example.com"
        let expectedResponseMarker = env["SHANGHAI_EXPECT_RESPONSE_MARKER"] ?? "HTTP/"
        let cryptMethod: KcpPacketCryptoMethod
        switch crypt {
        case "aes":
            cryptMethod = .aes
        case "aes-128":
            cryptMethod = .aes128
        case "aes-192":
            cryptMethod = .aes192
        default:
            cryptMethod = .none
        }

        return LocalKcptunCase(
            name: name,
            endpoint: KcpRemoteEndpoint(host: host, port: port),
            smuxVersion: smuxVersion,
            crypt: cryptMethod,
            compressed: compressed,
            password: password,
            targetHost: targetHost,
            targetPort: targetPort,
            requestMethod: requestMethod,
            requestURL: requestURL,
            requestHostHeader: requestHostHeader,
            expectedResponseMarker: expectedResponseMarker
        )
    }

    static func shouldRunCurrentCase() -> Bool {
        current() != nil
    }
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

private func buildProxyRequest(for profile: LocalKcptunCase) -> Data {
    let requestLineTarget: String
    switch profile.requestMethod {
    case "CONNECT":
        requestLineTarget = profile.requestHostHeader
    default:
        requestLineTarget = profile.requestURL
    }

    return Data("""
    \(profile.requestMethod) \(requestLineTarget) HTTP/1.1\r
    Host: \(profile.requestHostHeader)\r
    User-Agent: ShanghaiTests/1.0 (\(profile.name))\r
    Proxy-Connection: Keep-Alive\r
    \r
    """.utf8)
}

private func makeConnector(
    manager: KcpTunConnectorManager,
    profile: LocalKcptunCase
) -> KcpTunConnector {
    manager.connector(for: profile.endpoint) { endpoint in
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
                streamMode: true,
                preSharedKey: profile.password,
                crypt: profile.crypt
            ),
            smuxVersion: profile.smuxVersion,
            keepAliveInterval: 10,
            maxFrameSize: 8_192,
            maxStreamBuffer: 2_097_152,
            compressionEnabled: profile.compressed,
            bootstrapSessionID: 0
        )
    }
}

private func runHTTPProbe(profile: LocalKcptunCase) async throws {
    let manager = KcpTunConnectorManager()
    let connector = makeConnector(manager: manager, profile: profile)
    // Match xtaci/smux client-side stream numbering.
    let stream = TestStreamHandler(sessionID: 3)

    try connector.start()
    connector.openStream(stream)

    let didConnect = await waitUntil(timeout: 5) {
        stream.connectionCount > 0
    }
    #expect(didConnect)

    let request = buildProxyRequest(for: profile)

    connector.send(request, for: stream.sessionID)

    let didReceiveResponse = await waitUntil(timeout: 20) {
        !stream.receivedData.isEmpty
    }
    #expect(didReceiveResponse)

    KcpLog.info("local kcptun case=\(profile.name) endpoint=\(profile.endpoint) smux=\(profile.smuxVersion.rawValue) crypt=\(profile.crypt.rawValue) compressed=\(profile.compressed) password=\(profile.password)")
    KcpLog.hexDump("test http request", data: request, limit: 1024)
    let responseText = String(decoding: stream.receivedData, as: UTF8.self)
    printHTTPPreview(stream.receivedData)
    #expect(responseText.contains(profile.expectedResponseMarker))

    let managerStillOwnsConnector = await waitUntil(timeout: 4) {
        manager.connector(for: profile.endpoint) === connector
    }
    #expect(managerStillOwnsConnector)

    connector.closeStream(sessionID: stream.sessionID)
    manager.removeConnector(for: profile.endpoint)
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

@Test func snappyFramedRoundTripSupportsPartialReads() async throws {
    var encoder = KcpSnappyFramedEncoder()
    let source = Data("hello smux over framed snappy".utf8)
    let encoded = try encoder.encode(source)

    var decoder = KcpSnappyFramedDecoder()
    decoder.append(encoded.prefix(7))
    #expect(try decoder.readAvailable().isEmpty)

    decoder.append(encoded.dropFirst(7))
    let decoded = try decoder.readAvailable()
    #expect(decoded == [source])
}

@Test func packetCodecAddsPerPacketHeader() async throws {
    let codec = try KcpPacketCodec(crypt: .none, password: "Xifeng2026")
    let payload = Data("plain-kcp-payload".utf8)
    let packetA = try codec.encode(payload)
    let packetB = try codec.encode(payload)

    #expect(packetA.count == payload.count + 20)
    #expect(packetB.count == payload.count + 20)
    #expect(packetA != packetB)
    #expect(try codec.decode(packetA) == payload)
    #expect(try codec.decode(packetB) == payload)
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

@Test func proxyRouteTableMatchesHTTPAndHTTPSHosts() async throws {
    let upstream = KcpProxyUpstreamConfiguration(
        endpoint: KcpRemoteEndpoint(host: "192.168.11.35", port: 63201),
        smuxVersion: .v2,
        crypt: .none,
        compressionEnabled: false,
        password: "Xifeng2026"
    )
    let table = KcpProxyRouteTable(
        routes: [
            KcpProxyRoute(name: "proxy1", hostPatterns: ["www.x.com"], upstream: upstream),
            KcpProxyRoute(name: "proxy2", hostPatterns: ["ifconfig.co"], upstream: upstream),
            KcpProxyRoute(name: "proxy3", hostPatterns: ["www.google.com"], upstream: upstream),
        ],
        defaultUpstream: upstream
    )

    let httpX = Data("GET http://www.x.com/ HTTP/1.1\r\nHost: www.x.com\r\n\r\n".utf8)
    let httpsIfconfig = Data("CONNECT ifconfig.co:443 HTTP/1.1\r\nHost: ifconfig.co:443\r\n\r\n".utf8)
    let httpGoogle = Data("GET http://www.google.com/ HTTP/1.1\r\nHost: www.google.com\r\n\r\n".utf8)

    #expect(table.selectTarget(for: httpX)?.route?.name == "proxy1")
    #expect(table.selectTarget(for: httpsIfconfig)?.route?.name == "proxy2")
    #expect(table.selectTarget(for: httpGoogle)?.route?.name == "proxy3")
}

@Test func proxyRuntimeRegistryReleasesSessions() async throws {
    let registry = KcpProxyRuntimeRegistry()
    registry.insert(3)
    registry.insert(5)
    #expect(registry.count == 2)
    registry.remove(3)
    #expect(registry.count == 1)
    registry.remove(5)
    #expect(registry.count == 0)
}

@Test(
    "Local KCPTUN case",
    .enabled(if: LocalKcptunTestConfig.shouldRunCurrentCase(), "Set SHANGHAI_RUN_LOCAL_KCPTUN_CASE=1 and SHANGHAI_KCPTUN_PORT to run a local kcptun integration case."),
    .timeLimit(.minutes(1))
)
func integrationHTTPOverLocalKcptunCase() async throws {
    guard let profile = LocalKcptunTestConfig.current() else {
        Issue.record("Missing local kcptun test configuration.")
        return
    }
    try await runHTTPProbe(profile: profile)
}
