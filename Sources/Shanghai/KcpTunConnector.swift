import Dispatch
import Foundation

public protocol KcpTunStreamHandler: Sendable, AnyObject {
    var sessionID: UInt32 { get }
    func connectorDidConnect(_ connector: KcpTunConnector)
    func connector(_ connector: KcpTunConnector, didReceive data: Data, for sessionID: UInt32)
    func connector(_ connector: KcpTunConnector, didDisconnect sessionID: UInt32, error: Error?)
}

public struct KcpTunConnectorConfiguration: Sendable {
    public var endpoint: KcpRemoteEndpoint
    public var kcp: KcpConfiguration
    public var smuxVersion: KcpSmuxVersion
    public var keepAliveInterval: TimeInterval
    public var maxFrameSize: Int
    public var maxStreamBuffer: Int
    public var compressionEnabled: Bool
    public var bootstrapSessionID: UInt32

    public init(
        endpoint: KcpRemoteEndpoint,
        kcp: KcpConfiguration = .init(),
        smuxVersion: KcpSmuxVersion = .v2,
        keepAliveInterval: TimeInterval = 10,
        maxFrameSize: Int = 4_096,
        maxStreamBuffer: Int = 65_536,
        compressionEnabled: Bool = false,
        bootstrapSessionID: UInt32 = 0
    ) {
        self.endpoint = endpoint
        self.kcp = kcp
        self.smuxVersion = smuxVersion
        self.keepAliveInterval = keepAliveInterval
        self.maxFrameSize = maxFrameSize
        self.maxStreamBuffer = maxStreamBuffer
        self.compressionEnabled = compressionEnabled
        self.bootstrapSessionID = bootstrapSessionID
    }
}

public final class KcpTunConnector: @unchecked Sendable {
    public let configuration: KcpTunConnectorConfiguration

    public var onStateChange: (@Sendable (KcpTunConnector, Bool) -> Void)?

    private let queue: DispatchQueue
    private let session: KcpSession
    private var decoder: KcpFrameDecoder
    private var compressionEncoder: KcpSnappyFramedEncoder?
    private var compressionDecoder: KcpSnappyFramedDecoder?
    private var keepAliveTimer: DispatchSourceTimer?
    private var streams: [UInt32: KcpTunStreamHandler] = [:]
    private var pendingStreams = Set<UInt32>()
    private var establishedStreams = Set<UInt32>()
    private var waitingOpenStreams: [UInt32] = []
    private var streamBytesConsumed: [UInt32: UInt32] = [:]
    private var started = false
    private var controlChannelReady = false
    private var lastRemoteActivity = Date()

    public init(
        configuration: KcpTunConnectorConfiguration,
        callbackQueue: DispatchQueue = .main
    ) {
        self.configuration = configuration
        self.queue = DispatchQueue(label: "shanghai.kcptun.connector.\(configuration.endpoint.host).\(configuration.endpoint.port)")
        self.decoder = KcpFrameDecoder(expectedVersion: configuration.smuxVersion.rawValue)
        self.compressionEncoder = configuration.compressionEnabled ? KcpSnappyFramedEncoder() : nil
        self.compressionDecoder = configuration.compressionEnabled ? KcpSnappyFramedDecoder() : nil
        self.session = KcpSession(
            remoteHost: configuration.endpoint.host,
            remotePort: configuration.endpoint.port,
            configuration: configuration.kcp,
            callbackQueue: callbackQueue
        )
        wireSessionCallbacks()
    }

    public func start() throws {
        try queue.sync {
            guard !started else { return }
            KcpLog.info("connector start endpoint=\(configuration.endpoint)")
            try session.start()
            started = true
            lastRemoteActivity = Date()
            controlChannelReady = true
            installKeepAliveTimer()
            sendFrame(KcpFrame(command: .nop, sessionID: configuration.bootstrapSessionID))
            drainWaitingStreams()
            onStateChange?(self, true)
        }
    }

    public func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            KcpLog.info("connector stop endpoint=\(self.configuration.endpoint)")
            self.keepAliveTimer?.cancel()
            self.keepAliveTimer = nil
            self.session.stop()
            self.resetState()
        }
    }

    public func openStream(_ stream: KcpTunStreamHandler) {
        queue.async { [weak self] in
            guard let self else { return }
            KcpLog.info("open stream sid=\(stream.sessionID) endpoint=\(self.configuration.endpoint)")
            self.streams[stream.sessionID] = stream
            if self.controlChannelReady {
                self.openStreamWhenReady(stream.sessionID)
            } else if !self.waitingOpenStreams.contains(stream.sessionID) {
                self.waitingOpenStreams.append(stream.sessionID)
            }
        }
    }

    public func closeStream(sessionID: UInt32) {
        queue.async { [weak self] in
            KcpLog.info("close stream sid=\(sessionID) endpoint=\(self?.configuration.endpoint.description ?? "?")")
            self?.sendFin(sessionID)
        }
    }

    public func send(_ data: Data, for sessionID: UInt32) {
        queue.async { [weak self] in
            KcpLog.trace("connector send sid=\(sessionID) bytes=\(data.count) endpoint=\(self?.configuration.endpoint.description ?? "?")")
            KcpLog.hexDump("connector plain send sid=\(sessionID)", data: data)
            self?.sendRawData(data, command: .psh, sessionID: sessionID)
        }
    }

    public func localEndpoint() -> String? {
        session.localEndpoint()
    }

    private func wireSessionCallbacks() {
        // 预先捕获队列，减少 self?. 访问
        let q = self.queue
        
        session.onReceive = { [weak self] data in
            guard let self = self else { return }
            // 只有在大吞吐量导致 UI 卡顿时才切换，否则保持在 IO 线程
            q.async {
                self.handleInboundPayload(data)
            }
        }
        
        // onStop 频率极低，维持原有逻辑即可
        session.onStop = { [weak self] error in
            // 1. 立即检查 self 是否存在，避免不必要的派发任务到队列
            guard let self = self else { return }
            
            // 2. 捕获需要用到的引用，减少在 async 块中的 self 查找开销
            let queue = self.queue
            
            queue.async { [weak self] in
                // 3. 在执行具体逻辑前再次确认 self 没被析构
                guard let self = self else { return }
                self.handleSessionStop(error: error)
            }
        }
    }

    private func handleInboundPayload(_ data: Data) {
        lastRemoteActivity = Date()
        KcpLog.trace("connector inbound bytes=\(data.count) endpoint=\(configuration.endpoint)")
        if configuration.compressionEnabled {
            do {
                compressionDecoder?.append(data)
                let chunks = try compressionDecoder?.readAvailable() ?? []
                for chunk in chunks {
                    processInboundSmuxBytes(chunk)
                }
            } catch {
                KcpLog.warning("drop compressed payload endpoint=\(configuration.endpoint) error=\(error)")
            }
            return
        }

        processInboundSmuxBytes(data)
    }

    private func processInboundSmuxBytes(_ data: Data) {
        decoder.append(data)
        while true {
            let result = decoder.nextFrame()
            guard let frame = result.frame else {
                if result.error == .invalidVersion {
                    decoder = KcpFrameDecoder(expectedVersion: configuration.smuxVersion.rawValue)
                }
                break
            }

            process(frame: frame, error: result.error)

            if result.error == .bodyNotFull || result.error == .noHeader {
                break
            }
        }
    }

    private func process(frame: KcpFrame, error: KcpMuxError?) {
        if frame.sessionID == configuration.bootstrapSessionID {
            KcpLog.trace("bootstrap frame cmd=\(frame.command.rawValue) endpoint=\(configuration.endpoint)")
            controlChannelReady = true
            drainWaitingStreams()
            return
        }

        guard let stream = streams[frame.sessionID] else {
            KcpLog.warning("drop frame for unknown sid=\(frame.sessionID) cmd=\(frame.command.rawValue) endpoint=\(configuration.endpoint)")
            if frame.command != .fin && frame.command != .upd {
                sendFin(frame.sessionID)
            }
            return
        }

        switch frame.command {
        case .syn:
            markStreamEstablished(frame.sessionID)
            KcpLog.info("stream established by SYN sid=\(frame.sessionID) endpoint=\(configuration.endpoint)")
            stream.connectorDidConnect(self)

        case .fin:
            clearStreamState(frame.sessionID, removeStream: true)
            KcpLog.info("stream FIN sid=\(frame.sessionID) endpoint=\(configuration.endpoint)")
            stream.connector(self, didDisconnect: frame.sessionID, error: nil)

        case .nop:
            if frame.sessionID == configuration.bootstrapSessionID {
                controlChannelReady = true
                drainWaitingStreams()
            } else {
                markStreamEstablished(frame.sessionID)
            }

        case .psh:
            markStreamEstablished(frame.sessionID)
            if error == .bodyNotFull {
                KcpLog.trace("partial payload sid=\(frame.sessionID) endpoint=\(configuration.endpoint)")
                return
            }
            if let payload = frame.payload, !payload.isEmpty {
                KcpLog.trace("deliver payload sid=\(frame.sessionID) bytes=\(payload.count) endpoint=\(configuration.endpoint)")
                KcpLog.hexDump("connector plain recv sid=\(frame.sessionID)", data: payload)
                stream.connector(self, didReceive: payload, for: frame.sessionID)
                if configuration.smuxVersion == .v2 {
                    sendWindowUpdate(for: frame.sessionID, bytesConsumed: payload.count)
                }
            }

        case .upd:
            KcpLog.trace("receive UPD sid=\(frame.sessionID) endpoint=\(configuration.endpoint)")
        }
    }

    private func openStreamWhenReady(_ sessionID: UInt32) {
        pendingStreams.insert(sessionID)
        establishedStreams.remove(sessionID)
        KcpLog.info("send SYN sid=\(sessionID) endpoint=\(configuration.endpoint)")
        sendFrame(KcpFrame(command: .syn, sessionID: sessionID))
        streams[sessionID]?.connectorDidConnect(self)
    }

    private func drainWaitingStreams() {
        guard controlChannelReady else { return }
        while !waitingOpenStreams.isEmpty {
            openStreamWhenReady(waitingOpenStreams.removeFirst())
        }
    }

    private func sendRawData(_ data: Data, command: KcpFrameCommand, sessionID: UInt32) {
        var encoded = Data()
        splitKcpFrames(data, command: command, sessionID: sessionID, maxFrameSize: configuration.maxFrameSize)
            .forEach { frame in
                var frame = frame
                frame.version = configuration.smuxVersion.rawValue
                encoded.append(frame.encoded())
            }

        do {
            session.send(try encodeTransportBytes(encoded))
        } catch {
            KcpLog.error("compress send failed sid=\(sessionID) endpoint=\(configuration.endpoint) error=\(error)")
        }
    }

    private func sendFrame(_ frame: KcpFrame) {
        var frame = frame
        frame.version = configuration.smuxVersion.rawValue
        let encoded = frame.encoded()
        KcpLog.trace("send frame sid=\(frame.sessionID) cmd=\(frame.command.rawValue) bytes=\(frame.payload?.count ?? 0) endpoint=\(configuration.endpoint)")
        KcpLog.hexDump("smux frame send sid=\(frame.sessionID) cmd=\(frame.command.rawValue)", data: encoded)
        do {
            session.send(try encodeTransportBytes(encoded))
        } catch {
            KcpLog.error("compress control frame failed sid=\(frame.sessionID) endpoint=\(configuration.endpoint) error=\(error)")
        }
    }

    private func sendFin(_ sessionID: UInt32) {
        clearStreamState(sessionID, removeStream: true)
        KcpLog.info("send FIN sid=\(sessionID) endpoint=\(configuration.endpoint)")
        sendFrame(KcpFrame(command: .fin, sessionID: sessionID))
    }

    private func sendWindowUpdate(for sessionID: UInt32, bytesConsumed: Int) {
        guard bytesConsumed > 0 else { return }
        let totalConsumed = streamBytesConsumed[sessionID, default: 0] &+ UInt32(bytesConsumed)
        streamBytesConsumed[sessionID] = totalConsumed

        var payload = Data(count: KcpTunnelConstants.updatePayloadSize)
        payload.withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            let buffer = baseAddress.assumingMemoryBound(to: UInt8.self)
            let consumed = totalConsumed.littleEndian
            let window = UInt32(configuration.maxStreamBuffer).littleEndian
            withUnsafeBytes(of: consumed) { bytes in
                buffer.advanced(by: 0).update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 4)
            }
            withUnsafeBytes(of: window) { bytes in
                buffer.advanced(by: 4).update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 4)
            }
        }

        KcpLog.trace("send UPD sid=\(sessionID) consumed=\(totalConsumed) window=\(configuration.maxStreamBuffer) endpoint=\(configuration.endpoint)")
        sendFrame(KcpFrame(command: .upd, sessionID: sessionID, payload: payload))
    }

    private func installKeepAliveTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + configuration.keepAliveInterval, repeating: configuration.keepAliveInterval)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let idle = Date().timeIntervalSince(self.lastRemoteActivity)
            if idle > self.configuration.keepAliveInterval * 1.3 {
                KcpLog.warning("connector keepalive timeout idle=\(idle) endpoint=\(self.configuration.endpoint)")
                self.session.stop()
            } else {
                KcpLog.trace("connector send keepalive endpoint=\(self.configuration.endpoint)")
                self.sendFrame(KcpFrame(command: .nop, sessionID: self.configuration.bootstrapSessionID))
            }
        }
        keepAliveTimer = timer
        timer.resume()
    }

    private func handleSessionStop(error: Error?) {
        keepAliveTimer?.cancel()
        keepAliveTimer = nil
        let disconnectedStreams = streams
        KcpLog.warning("connector stopped endpoint=\(configuration.endpoint) streams=\(disconnectedStreams.count) error=\(String(describing: error))")
        resetState()
        onStateChange?(self, false)
        disconnectedStreams.values.forEach { handler in
            handler.connector(self, didDisconnect: handler.sessionID, error: error)
        }
    }

    private func resetState() {
        started = false
        controlChannelReady = false
        decoder = KcpFrameDecoder(expectedVersion: configuration.smuxVersion.rawValue)
        compressionEncoder = configuration.compressionEnabled ? KcpSnappyFramedEncoder() : nil
        compressionDecoder = configuration.compressionEnabled ? KcpSnappyFramedDecoder() : nil
        streams.removeAll(keepingCapacity: false)
        pendingStreams.removeAll(keepingCapacity: false)
        establishedStreams.removeAll(keepingCapacity: false)
        waitingOpenStreams.removeAll(keepingCapacity: false)
        streamBytesConsumed.removeAll(keepingCapacity: false)
    }

    private func markStreamEstablished(_ sessionID: UInt32) {
        guard pendingStreams.contains(sessionID) else { return }
        pendingStreams.remove(sessionID)
        establishedStreams.insert(sessionID)
    }

    private func clearStreamState(_ sessionID: UInt32, removeStream: Bool) {
        pendingStreams.remove(sessionID)
        establishedStreams.remove(sessionID)
        waitingOpenStreams.removeAll { $0 == sessionID }
        streamBytesConsumed.removeValue(forKey: sessionID)
        if removeStream {
            streams.removeValue(forKey: sessionID)
        }
    }

    private func encodeTransportBytes(_ data: Data) throws -> Data {
        guard configuration.compressionEnabled else { return data }
        guard var compressionEncoder else { return data }
        let encoded = try compressionEncoder.encode(data)
        self.compressionEncoder = compressionEncoder
        return encoded
    }
}
