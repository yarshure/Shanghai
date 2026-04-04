import Foundation
import Network
import Shanghai

private enum ProxyError: Error {
    case invalidRequest
}

private final class SessionIDAllocator: @unchecked Sendable {
    private let queue = DispatchQueue(label: "shanghai.proxy.sid")
    private var nextID: UInt32 = 3

    func next() -> UInt32 {
        queue.sync {
            defer { nextID += 2 }
            return nextID
        }
    }
}

private final class ProxyContext: @unchecked Sendable {
    let connection: NWConnection
    let sessionID: UInt32

    private let lock = NSLock()
    private var established = false
    private var bufferedClientData = [Data]()

    init(connection: NWConnection, sessionID: UInt32) {
        self.connection = connection
        self.sessionID = sessionID
    }

    func queueClientData(_ data: Data) {
        lock.lock()
        bufferedClientData.append(data)
        lock.unlock()
    }

    func markEstablished() -> [Data] {
        lock.lock()
        established = true
        let buffered = bufferedClientData
        bufferedClientData.removeAll(keepingCapacity: false)
        lock.unlock()
        return buffered
    }

    var isEstablished: Bool {
        lock.lock()
        defer { lock.unlock() }
        return established
    }
}

private final class ProxyRuntime: NSObject, KcpTunStreamHandler, @unchecked Sendable {
    let sessionID: UInt32

    private let connector: KcpTunConnector
    private let context: ProxyContext
    private let owner: LocalConnectProxy
    private let queue = DispatchQueue(label: "shanghai.proxy.runtime")
    private var handshakeBuffer = Data()
    private var responseForwardingStarted = false

    init(sessionID: UInt32, connector: KcpTunConnector, context: ProxyContext, owner: LocalConnectProxy) {
        self.sessionID = sessionID
        self.connector = connector
        self.context = context
        self.owner = owner
    }

    func start(with connectRequest: Data) {
        connector.openStream(self)
        connector.send(connectRequest, for: sessionID)
        readClientTunnelBytes()
    }

    func connectorDidConnect(_ connector: KcpTunConnector) {}

    func connector(_ connector: KcpTunConnector, didReceive data: Data, for sessionID: UInt32) {
        queue.async {
            if self.responseForwardingStarted {
                self.sendToClient(data)
                return
            }

            self.handshakeBuffer.append(data)
            let marker = Data("\r\n\r\n".utf8)
            guard let range = self.handshakeBuffer.range(of: marker) else { return }

            let headerData = self.handshakeBuffer[..<range.upperBound]
            let headerText = String(decoding: headerData, as: UTF8.self)
            self.sendToClient(Data(headerData))

            let remainder = Data(self.handshakeBuffer[range.upperBound...])
            self.handshakeBuffer.removeAll(keepingCapacity: false)
            self.responseForwardingStarted = true

            if headerText.contains("200 Connection established") || headerText.contains("200 Connection Established") {
                let buffered = self.context.markEstablished()
                for chunk in buffered {
                    self.connector.send(chunk, for: self.sessionID)
                }
            }

            if !remainder.isEmpty {
                self.sendToClient(remainder)
            }
        }
    }

    func connector(_ connector: KcpTunConnector, didDisconnect sessionID: UInt32, error: Error?) {
        queue.async {
            self.context.connection.cancel()
            self.owner.removeRuntime(sessionID: sessionID)
        }
    }

    private func readClientTunnelBytes() {
        context.connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }

            if let data, !data.isEmpty {
                if self.context.isEstablished {
                    self.connector.send(data, for: self.sessionID)
                } else {
                    self.context.queueClientData(data)
                }
            }

            if isComplete || error != nil {
                self.connector.closeStream(sessionID: self.sessionID)
                self.owner.removeRuntime(sessionID: self.sessionID)
                return
            }

            self.readClientTunnelBytes()
        }
    }

    private func sendToClient(_ data: Data) {
        context.connection.send(content: data, completion: .contentProcessed { _ in })
    }
}

private final class LocalConnectProxy: @unchecked Sendable {
    private let listener: NWListener
    private let connector: KcpTunConnector
    private let sidAllocator = SessionIDAllocator()
    private let queue = DispatchQueue(label: "shanghai.proxy.listener")
    private let runtimeQueue = DispatchQueue(label: "shanghai.proxy.runtime.map")
    private var runtimes: [UInt32: ProxyRuntime] = [:]

    init(listenPort: UInt16, connector: KcpTunConnector) throws {
        self.connector = connector
        self.listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: listenPort)!)
    }

    func start() throws {
        try connector.start()
        listener.newConnectionHandler = { [weak self] connection in
            self?.handle(connection: connection)
        }
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                print("ShanghaiProxy listening on \(self.listener.port?.rawValue ?? 0)")
            case .failed(let error):
                fputs("ShanghaiProxy listener failed: \(error)\n", stderr)
                exit(1)
            default:
                break
            }
        }
        listener.start(queue: queue)
    }

    func removeRuntime(sessionID: UInt32) {
        runtimeQueue.async {
            self.runtimes.removeValue(forKey: sessionID)
        }
    }

    private func handle(connection: NWConnection) {
        connection.start(queue: queue)
        readConnectRequest(from: connection, buffer: Data())
    }

    private func readConnectRequest(from connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8_192) { [weak self] data, _, isComplete, error in
            guard let self else { return }

            var buffer = buffer
            if let data, !data.isEmpty {
                buffer.append(data)
            }

            let marker = Data("\r\n\r\n".utf8)
            if let range = buffer.range(of: marker) {
                let requestData = Data(buffer[..<range.upperBound])
                do {
                    try self.validateConnectRequest(requestData)
                    let sessionID = self.sidAllocator.next()
                    let context = ProxyContext(connection: connection, sessionID: sessionID)
                    let runtime = ProxyRuntime(sessionID: sessionID, connector: self.connector, context: context, owner: self)
                    self.runtimeQueue.async {
                        self.runtimes[sessionID] = runtime
                    }
                    runtime.start(with: requestData)
                } catch {
                    connection.send(content: Data("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".utf8), completion: .contentProcessed { _ in
                        connection.cancel()
                    })
                }
                return
            }

            if isComplete || error != nil {
                connection.cancel()
                return
            }

            self.readConnectRequest(from: connection, buffer: buffer)
        }
    }

    private func validateConnectRequest(_ data: Data) throws {
        let text = String(decoding: data, as: UTF8.self)
        guard text.hasPrefix("CONNECT ") else {
            throw ProxyError.invalidRequest
        }
    }
}

private func env(_ key: String, default value: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? value
}

private func envUInt16(_ key: String, default value: UInt16) -> UInt16 {
    UInt16(env(key, default: String(value))) ?? value
}

let remoteHost = env("SHANGHAI_KCPTUN_HOST", default: "127.0.0.1")
let remotePort = envUInt16("SHANGHAI_KCPTUN_PORT", default: 63201)
let listenPort = envUInt16("SHANGHAI_LOCAL_PROXY_PORT", default: 13059)
let password = env("SHANGHAI_KCPTUN_PASSWORD", default: "Xifeng2026")
let smuxVersion = env("SHANGHAI_KCPTUN_SMUXVER", default: "2") == "1" ? KcpSmuxVersion.v1 : .v2
let cryptString = env("SHANGHAI_KCPTUN_CRYPT", default: "none")
let crypt: KcpPacketCryptoMethod
switch cryptString {
case "aes":
    crypt = .aes
case "aes-128":
    crypt = .aes128
case "aes-192":
    crypt = .aes192
default:
    crypt = .none
}
let compressed = env("SHANGHAI_KCPTUN_NOCOMP", default: "1") != "1"

let manager = KcpTunConnectorManager()
let connector = manager.connector(for: KcpRemoteEndpoint(host: remoteHost, port: remotePort)) { endpoint in
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
            preSharedKey: password,
            crypt: crypt
        ),
        smuxVersion: smuxVersion,
        keepAliveInterval: 10,
        maxFrameSize: 8_192,
        maxStreamBuffer: 2_097_152,
        compressionEnabled: compressed,
        bootstrapSessionID: 0
    )
}

do {
    let proxy = try LocalConnectProxy(listenPort: listenPort, connector: connector)
    try proxy.start()
    dispatchMain()
} catch {
    fputs("ShanghaiProxy failed: \(error)\n", stderr)
    exit(1)
}
