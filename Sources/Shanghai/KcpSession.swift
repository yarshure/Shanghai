import CKcp
import Dispatch
import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public struct KcpConfiguration: Sendable {
    public var conversationID: UInt32
    public var mtu: Int32
    public var sendWindow: Int32
    public var receiveWindow: Int32
    public var noDelay: Int32
    public var interval: Int32
    public var resend: Int32
    public var disableCongestionControl: Int32
    public var streamMode: Bool

    public init(
        conversationID: UInt32 = UInt32.random(in: 1...UInt32.max),
        mtu: Int32 = 1_400,
        sendWindow: Int32 = 128,
        receiveWindow: Int32 = 128,
        noDelay: Int32 = 1,
        interval: Int32 = 20,
        resend: Int32 = 2,
        disableCongestionControl: Int32 = 1,
        streamMode: Bool = true
    ) {
        self.conversationID = conversationID
        self.mtu = mtu
        self.sendWindow = sendWindow
        self.receiveWindow = receiveWindow
        self.noDelay = noDelay
        self.interval = interval
        self.resend = resend
        self.disableCongestionControl = disableCongestionControl
        self.streamMode = streamMode
    }
}

public enum KcpSessionError: Error, Sendable {
    case alreadyStarted
    case notStarted
    case socketCreationFailed(code: Int32)
    case socketConfigurationFailed(code: Int32)
    case addressResolutionFailed(code: Int32)
    case connectFailed(code: Int32)
    case kcpCreationFailed
}

public final class KcpSession: @unchecked Sendable {
    public var onReceive: (@Sendable (Data) -> Void)?
    public var onStop: (@Sendable (Error?) -> Void)?

    private let remoteHost: String
    private let remotePort: UInt16
    private let configuration: KcpConfiguration
    private let callbackQueue: DispatchQueue
    private let stateQueue = DispatchQueue(label: "shanghai.kcp.session")

    private var socketDescriptor: Int32 = -1
    private var kcp: UnsafeMutablePointer<ikcpcb>?
    private var readSource: DispatchSourceRead?
    private var updateTimer: DispatchSourceTimer?
    private var started = false
    private var stopped = false
    private var receiveBuffer = [UInt8](repeating: 0, count: 65_535)

    public init(
        remoteHost: String,
        remotePort: UInt16,
        configuration: KcpConfiguration = .init(),
        callbackQueue: DispatchQueue = .main
    ) {
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.configuration = configuration
        self.callbackQueue = callbackQueue
    }

    deinit {
        stateQueue.sync {
            shutdown(nil, notify: false)
        }
    }

    public func start() throws {
        try stateQueue.sync {
            if started {
                throw KcpSessionError.alreadyStarted
            }

            KcpLog.info("starting session to \(remoteHost):\(remotePort) conv=\(configuration.conversationID)")
            socketDescriptor = try Self.makeConnectedSocket(host: remoteHost, port: remotePort)
            try Self.makeSocketNonBlocking(socketDescriptor)

            guard let rawKcp = ikcp_create(configuration.conversationID, Unmanaged.passUnretained(self).toOpaque()) else {
                let fd = socketDescriptor
                socketDescriptor = -1
                _ = close(fd)
                throw KcpSessionError.kcpCreationFailed
            }

            kcp = rawKcp
            rawKcp.pointee.output = shanghai_kcp_output
            ikcp_setmtu(rawKcp, configuration.mtu)
            ikcp_wndsize(rawKcp, configuration.sendWindow, configuration.receiveWindow)
            ikcp_nodelay(
                rawKcp,
                configuration.noDelay,
                configuration.interval,
                configuration.resend,
                configuration.disableCongestionControl
            )
            rawKcp.pointee.stream = configuration.streamMode ? 1 : 0

            installReadSource()
            installUpdateTimer()
            started = true
            stopped = false
            scheduleNextUpdate()
            KcpLog.info("session started local=\(Self.describeLocalEndpoint(socketDescriptor) ?? "unknown") remote=\(remoteHost):\(remotePort)")
        }
    }

    public func send(_ data: Data) {
        stateQueue.async { [weak self] in
            guard let self, let rawKcp = self.rawKcp, self.started, !self.stopped else { return }
            KcpLog.trace("queue kcp send bytes=\(data.count) remote=\(self.remoteHost):\(self.remotePort)")
            KcpLog.hexDump("kcp input", data: data)
            let result = data.withUnsafeBytes { buffer -> Int32 in
                guard let baseAddress = buffer.bindMemory(to: Int8.self).baseAddress else {
                    return 0
                }
                return ikcp_send(rawKcp, baseAddress, Int32(buffer.count))
            }

            guard result >= 0 else {
                KcpLog.error("ikcp_send failed result=\(result) remote=\(self.remoteHost):\(self.remotePort)")
                return
            }
            ikcp_flush(rawKcp)
            self.scheduleNextUpdate()
        }
    }

    public func stop() {
        stateQueue.async { [weak self] in
            KcpLog.info("stopping session remote=\(self?.remoteHost ?? "?"):\(self?.remotePort ?? 0)")
            self?.shutdown(nil, notify: true)
        }
    }

    public func localEndpoint() -> String? {
        stateQueue.sync {
            guard socketDescriptor >= 0 else { return nil }
            return Self.describeLocalEndpoint(socketDescriptor)
        }
    }

    private var rawKcp: UnsafeMutablePointer<ikcpcb>? { kcp }

    private func installReadSource() {
        let source = DispatchSource.makeReadSource(fileDescriptor: socketDescriptor, queue: stateQueue)
        source.setEventHandler { [weak self] in
            self?.handleReadableSocket()
        }
        source.setCancelHandler {}
        readSource = source
        source.resume()
    }

    private func installUpdateTimer() {
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.setEventHandler { [weak self] in
            self?.handleUpdateTimer()
        }
        updateTimer = timer
        timer.resume()
    }

    private func handleReadableSocket() {
        guard let rawKcp = rawKcp, socketDescriptor >= 0, !stopped else { return }

        while true {
            let count = receiveBuffer.withUnsafeMutableBytes { bytes -> Int in
                guard let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress else {
                    return -1
                }
                return Darwin.recv(socketDescriptor, baseAddress, bytes.count, 0)
            }

            if count > 0 {
                KcpLog.trace("socket recv bytes=\(count) remote=\(remoteHost):\(remotePort)")
                KcpLog.hexDump("udp recv", data: Data(receiveBuffer.prefix(count)))
                receiveBuffer.withUnsafeBytes { bytes in
                    guard let baseAddress = bytes.bindMemory(to: Int8.self).baseAddress else {
                        return
                    }
                    _ = ikcp_input(rawKcp, baseAddress, count)
                }
                drainKcpReceiveQueue()
                scheduleNextUpdate()
                continue
            }

            if count == 0 {
                drainKcpReceiveQueue()
                continue
            }

            if errno == EAGAIN || errno == EWOULDBLOCK {
                break
            }

            KcpLog.error("socket recv error errno=\(errno) remote=\(remoteHost):\(remotePort)")
            shutdown(KcpSessionError.socketConfigurationFailed(code: errno), notify: true)
            return
        }
    }

    private func handleUpdateTimer() {
        guard let rawKcp = rawKcp, started, !stopped else { return }
        ikcp_update(rawKcp, Self.currentMilliseconds())
        drainKcpReceiveQueue()
        scheduleNextUpdate()
    }

    private func drainKcpReceiveQueue() {
        guard let rawKcp = rawKcp else { return }

        while true {
            let received = receiveBuffer.withUnsafeMutableBytes { bytes -> Int32 in
                guard let baseAddress = bytes.bindMemory(to: Int8.self).baseAddress else {
                    return -1
                }
                return ikcp_recv(rawKcp, baseAddress, Int32(bytes.count))
            }

            guard received > 0 else { break }
            let data = Data(receiveBuffer.prefix(Int(received)))
            KcpLog.trace("kcp recv bytes=\(received) remote=\(remoteHost):\(remotePort)")
            KcpLog.hexDump("kcp output", data: data)
            callbackQueue.async { [onReceive] in
                onReceive?(data)
            }
        }
    }

    private func scheduleNextUpdate() {
        guard let rawKcp = rawKcp, let updateTimer else { return }
        let now = Self.currentMilliseconds()
        let next = ikcp_check(rawKcp, now)
        let delta = next <= now ? 0 : Int(next - now)
        updateTimer.schedule(deadline: .now() + .milliseconds(delta))
    }

    fileprivate func writeKcpPacket(_ buffer: UnsafePointer<Int8>, length: Int32) -> Int32 {
        guard socketDescriptor >= 0 else { return -1 }
        let data = Data(bytes: buffer, count: Int(length))
        KcpLog.hexDump("udp send", data: data)
        let sent = Darwin.send(socketDescriptor, buffer, Int(length), 0)
        if sent < 0 {
            KcpLog.error("udp send failed errno=\(errno) remote=\(remoteHost):\(remotePort)")
            return -1
        }
        KcpLog.trace("udp send bytes=\(sent) remote=\(remoteHost):\(remotePort)")
        return Int32(sent)
    }

    private func shutdown(_ error: Error?, notify: Bool) {
        if stopped {
            return
        }
        stopped = true
        started = false
        KcpLog.info("session shutdown remote=\(remoteHost):\(remotePort) error=\(String(describing: error))")

        updateTimer?.setEventHandler {}
        updateTimer?.cancel()
        updateTimer = nil

        readSource?.setEventHandler {}
        readSource?.cancel()
        readSource = nil

        if let rawKcp {
            ikcp_release(rawKcp)
            kcp = nil
        }

        if socketDescriptor >= 0 {
            _ = close(socketDescriptor)
            socketDescriptor = -1
        }

        if notify {
            callbackQueue.async { [onStop] in
                onStop?(error)
            }
        }
    }

    private static func makeConnectedSocket(host: String, port: UInt16) throws -> Int32 {
        var hints = addrinfo(
            ai_flags: AI_NUMERICSERV,
            ai_family: AF_UNSPEC,
            ai_socktype: Self.socketTypeDatagram,
            ai_protocol: IPPROTO_UDP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )

        let service = String(port)
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, service, &hints, &result)
        guard status == 0, let first = result else {
            throw KcpSessionError.addressResolutionFailed(code: Int32(status))
        }
        defer { freeaddrinfo(first) }

        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let current = cursor {
            let fd = socket(current.pointee.ai_family, current.pointee.ai_socktype, current.pointee.ai_protocol)
            if fd >= 0 {
                guard let address = current.pointee.ai_addr else {
                    _ = close(fd)
                    cursor = current.pointee.ai_next
                    continue
                }
                let connected = connect(fd, address, current.pointee.ai_addrlen)
                if connected == 0 {
                    return fd
                }
                _ = close(fd)
            }
            cursor = current.pointee.ai_next
        }

        throw KcpSessionError.connectFailed(code: errno)
    }

    private static func makeSocketNonBlocking(_ fd: Int32) throws {
        let currentFlags = fcntl(fd, F_GETFL, 0)
        guard currentFlags >= 0 else {
            throw KcpSessionError.socketConfigurationFailed(code: errno)
        }
        if fcntl(fd, F_SETFL, currentFlags | O_NONBLOCK) != 0 {
            throw KcpSessionError.socketConfigurationFailed(code: errno)
        }
    }

    private static func currentMilliseconds() -> UInt32 {
        UInt32((DispatchTime.now().uptimeNanoseconds / 1_000_000) & 0xffff_ffff)
    }

    private static var socketTypeDatagram: Int32 {
#if canImport(Darwin)
        Int32(SOCK_DGRAM)
#else
        SOCK_DGRAM.rawValue
#endif
    }

    private static func describeLocalEndpoint(_ fd: Int32) -> String? {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getsockname(fd, sockaddrPointer, &length)
            }
        }
        guard result == 0 else { return nil }

        var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var serviceBuffer = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let nameInfo = withUnsafePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getnameinfo(
                    sockaddrPointer,
                    length,
                    &hostBuffer,
                    socklen_t(hostBuffer.count),
                    &serviceBuffer,
                    socklen_t(serviceBuffer.count),
                    NI_NUMERICHOST | NI_NUMERICSERV
                )
            }
        }
        guard nameInfo == 0 else { return nil }
        return "\(String(cString: hostBuffer)):\(String(cString: serviceBuffer))"
    }
}

@_cdecl("shanghai_kcp_output")
private func shanghai_kcp_output(
    _ buffer: UnsafePointer<Int8>?,
    _ length: Int32,
    _ kcp: UnsafeMutablePointer<ikcpcb>?,
    _ user: UnsafeMutableRawPointer?
) -> Int32 {
    guard
        let buffer,
        length > 0,
        let user
    else {
        return -1
    }

    let session = Unmanaged<KcpSession>.fromOpaque(user).takeUnretainedValue()
    return session.writeKcpPacket(buffer, length: length)
}
