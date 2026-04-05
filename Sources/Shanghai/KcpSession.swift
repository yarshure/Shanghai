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
    public var preSharedKey: String
    public var crypt: KcpPacketCryptoMethod

    public init(
        conversationID: UInt32 = UInt32.random(in: 1...UInt32.max),
        mtu: Int32 = 1_400,
        sendWindow: Int32 = 128,
        receiveWindow: Int32 = 128,
        noDelay: Int32 = 1,
        interval: Int32 = 20,
        resend: Int32 = 2,
        disableCongestionControl: Int32 = 1,
        streamMode: Bool = true,
        preSharedKey: String = "it's a secrect",
        crypt: KcpPacketCryptoMethod = .none
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
        self.preSharedKey = preSharedKey
        self.crypt = crypt
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
    private var packetCodec: KcpPacketCodec?

    private static let kcpOverhead = 24

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
            packetCodec = try? KcpPacketCodec(crypt: configuration.crypt, password: configuration.preSharedKey)

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
            self.logKcpState("after send queued bytes=\(data.count)")
            ikcp_flush(rawKcp)
            self.logKcpState("after flush")
            self.updateKcpNow()
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
                let packet = Data(receiveBuffer.prefix(count))
                KcpLog.trace("socket recv bytes=\(count) remote=\(remoteHost):\(remotePort)")
                KcpLog.hexDump("udp recv", data: packet)
                do {
                    let payload = try decodePacket(packet)
                    logKcpSegments("udp recv payload", data: payload)
                    payload.withUnsafeBytes { bytes in
                        guard let baseAddress = bytes.bindMemory(to: Int8.self).baseAddress else {
                            return
                        }
                        let inputResult = ikcp_input(rawKcp, baseAddress, Int(bytes.count))
                        KcpLog.trace("ikcp_input result=\(inputResult) payloadBytes=\(bytes.count) remote=\(remoteHost):\(remotePort)")
                    }
                    logKcpState("after input")
                    updateKcpNow()
                } catch {
                    KcpLog.warning("drop invalid udp packet remote=\(remoteHost):\(remotePort) error=\(error)")
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
        logKcpState("after timer update")
        drainKcpReceiveQueue()
        scheduleNextUpdate()
    }

    private func drainKcpReceiveQueue() {
        guard let rawKcp = rawKcp else { return }
        updateKcpNow()
        logKcpState("before recv drain")

        while true {
            let peekSize = ikcp_peeksize(rawKcp)
            KcpLog.trace("ikcp_peeksize=\(peekSize) remote=\(remoteHost):\(remotePort)")
            let received = receiveBuffer.withUnsafeMutableBytes { bytes -> Int32 in
                guard let baseAddress = bytes.bindMemory(to: Int8.self).baseAddress else {
                    return -1
                }
                return ikcp_recv(rawKcp, baseAddress, Int32(bytes.count))
            }
            KcpLog.trace("ikcp_recv result=\(received) remote=\(remoteHost):\(remotePort)")

            guard received > 0 else { break }
            let data = Data(receiveBuffer.prefix(Int(received)))
            KcpLog.trace("kcp recv bytes=\(received) remote=\(remoteHost):\(remotePort)")
            KcpLog.hexDump("kcp output", data: data)
            callbackQueue.async { [onReceive] in
                onReceive?(data)
            }
            updateKcpNow()
            logKcpState("after recv bytes=\(received)")
        }
    }

    private func updateKcpNow() {
        guard let rawKcp = rawKcp, started, !stopped else { return }
        ikcp_update(rawKcp, Self.currentMilliseconds())
        logKcpState("after immediate update")
    }

    private func logKcpState(_ context: String) {
        guard let rawKcp = rawKcp, started, !stopped else { return }
        let peekSize = ikcp_peeksize(rawKcp)
        let waitSend = ikcp_waitsnd(rawKcp)
        let sndNxt = rawKcp.pointee.snd_nxt
        let sndUna = rawKcp.pointee.snd_una
        let rcvNxt = rawKcp.pointee.rcv_nxt
        let cwnd = rawKcp.pointee.cwnd
        let remoteWnd = rawKcp.pointee.rmt_wnd
        let rxRto = rawKcp.pointee.rx_rto
        KcpLog.trace(
            "kcp state \(context) peek=\(peekSize) waitsnd=\(waitSend) snd_nxt=\(sndNxt) snd_una=\(sndUna) rcv_nxt=\(rcvNxt) cwnd=\(cwnd) rmt_wnd=\(remoteWnd) rx_rto=\(rxRto) remote=\(remoteHost):\(remotePort)"
        )
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
        let payload = Data(bytes: buffer, count: Int(length))
        let data: Data
        do {
            data = try encodePacket(payload)
        } catch {
            KcpLog.error("udp packet encode failed remote=\(remoteHost):\(remotePort) error=\(error)")
            return -1
        }
        KcpLog.hexDump("udp send", data: data)
        if let plaintext = try? decodePacket(data) {
            logKcpSegments("udp send payload", data: plaintext)
        }
        let sent = data.withUnsafeBytes { bytes in
            Darwin.send(socketDescriptor, bytes.baseAddress, data.count, 0)
        }
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
        packetCodec = nil

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

    private func encodePacket(_ payload: Data) throws -> Data {
        guard let packetCodec else { return payload }
        return try packetCodec.encode(payload)
    }

    private func decodePacket(_ packet: Data) throws -> Data {
        guard let packetCodec else { return packet }
        return try packetCodec.decode(packet)
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
//        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
//        let result = withUnsafeMutablePointer(to: &storage) { pointer in
//            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
//                getsockname(fd, sockaddrPointer, &length)
//            }
//        }
//        guard result == 0 else { return nil }
//        // 假设 storage 是 sockaddr_storage，length 是该地址的实际长度
//        var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
//        var serviceBuffer = [CChar](repeating: 0, count: Int(NI_MAXSERV))
//        let nameInfo = withUnsafePointer(to: &storage) { pointer in
//            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
//                getnameinfo(
//                    sockaddrPointer,
//                    socklen_t(length), // 确保转为 socklen_t,
//                    &hostBuffer,
//                    socklen_t(hostBuffer.count),
//                    &serviceBuffer,
//                    socklen_t(serviceBuffer.count),
//                    NI_NUMERICHOST | NI_NUMERICSERV
//                )
//            }
//        }
//
//        guard nameInfo == 0 else { return nil }
//
//        // 转换为 Swift String
//        let host =   String(cString: hostBuffer)
//        let service = String(cString: serviceBuffer)
//        return "\(host):\(service)"
        
        // 针对 IPv4 的极致快速路径 (无需 getnameinfo)
        if storage.ss_family == sa_family_t(AF_INET) {
            // IPv4 保持不变
            return withUnsafePointer(to: &storage) { ptr in
                ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    let addr = sin.pointee.sin_addr.s_addr
                    let p = sin.pointee.sin_port.byteSwapped
                    return "\(Int(addr & 0xFF)).\(Int((addr >> 8) & 0xFF)).\(Int((addr >> 16) & 0xFF)).\(Int((addr >> 24) & 0xFF)):\(p)"
                }
            }
        } else if storage.ss_family == sa_family_t(AF_INET6) {
            // IPv6 高性能手动解析
            return withUnsafePointer(to: &storage) { ptr in
                ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    let addr = sin6.pointee.sin6_addr.__u6_addr.__u6_addr16
                    let p = sin6.pointee.sin6_port.byteSwapped
                    
                    // 提取 8 个 16 位片段（注意字节序转换）
                    let segments = [
                        addr.0.byteSwapped, addr.1.byteSwapped, addr.2.byteSwapped, addr.3.byteSwapped,
                        addr.4.byteSwapped, addr.5.byteSwapped, addr.6.byteSwapped, addr.7.byteSwapped
                    ]
                    
                    // 格式化为标准 IPv6 字符串 [addr]:port
                    let ipStr = segments.map { String(format: "%x", $0) }.joined(separator: ":")
                    return "[\(ipStr)]:\(p)"
                }
            }
        }
        return ""
        
    }

    private func logKcpSegments(_ label: String, data: Data) {
        let segments = Self.parseKcpSegments(data)
        guard !segments.isEmpty else {
            KcpLog.trace("\(label) segments=0 bytes=\(data.count) remote=\(remoteHost):\(remotePort)")
            return
        }

        for (index, segment) in segments.enumerated() {
            let command = Self.kcpCommandName(segment.cmd)
            let smuxSummary = Self.parseSmuxSummary(segment.payload)
            KcpLog.trace(
                "\(label) segment[\(index)] conv=\(segment.conv) cmd=\(command)(\(segment.cmd)) frg=\(segment.frg) wnd=\(segment.wnd) ts=\(segment.ts) sn=\(segment.sn) una=\(segment.una) len=\(segment.length)\(smuxSummary.map { " \($0)" } ?? "") remote=\(remoteHost):\(remotePort)"
            )
        }
    }

    private static func parseKcpSegments(_ data: Data) -> [ParsedKcpSegment] {
        var segments: [ParsedKcpSegment] = []
        var offset = 0
        while offset + kcpOverhead <= data.count {
            let conv = data.loadUInt32LE(at: offset)
            let cmd = data[offset + 4]
            let frg = data[offset + 5]
            let wnd = data.loadUInt16LE(at: offset + 6)
            let ts = data.loadUInt32LE(at: offset + 8)
            let sn = data.loadUInt32LE(at: offset + 12)
            let una = data.loadUInt32LE(at: offset + 16)
            let length = data.loadUInt32LE(at: offset + 20)
            let payloadStart = offset + kcpOverhead
            let payloadEnd = payloadStart + Int(length)
            guard payloadEnd <= data.count else { break }
            let payload = Data(data[payloadStart..<payloadEnd])
            segments.append(
                ParsedKcpSegment(
                    conv: conv,
                    cmd: cmd,
                    frg: frg,
                    wnd: wnd,
                    ts: ts,
                    sn: sn,
                    una: una,
                    length: length,
                    payload: payload
                )
            )
            offset = payloadEnd
        }
        return segments
    }

    private static func kcpCommandName(_ cmd: UInt8) -> String {
        switch cmd {
        case 81: return "PUSH"
        case 82: return "ACK"
        case 83: return "WASK"
        case 84: return "WINS"
        default: return "UNKNOWN"
        }
    }

    private static func parseSmuxSummary(_ data: Data) -> String? {
        guard data.count >= 8 else { return nil }
        let version = data[0]
        let command = data[1]
        let length = data.loadUInt16LE(at: 2)
        let streamID = data.loadUInt32LE(at: 4)
        let commandName: String
        switch command {
        case 0: commandName = "SYN"
        case 1: commandName = "FIN"
        case 2: commandName = "PSH"
        case 3: commandName = "NOP"
        case 4: commandName = "UPD"
        default: commandName = "UNKNOWN"
        }
        return "smux[v=\(version) cmd=\(commandName)(\(command)) sid=\(streamID) len=\(length)]"
    }
}

private struct ParsedKcpSegment {
    let conv: UInt32
    let cmd: UInt8
    let frg: UInt8
    let wnd: UInt16
    let ts: UInt32
    let sn: UInt32
    let una: UInt32
    let length: UInt32
    let payload: Data
}

private extension Data {
    func loadUInt16LE(at offset: Int) -> UInt16 {
        withUnsafeBytes { rawBuffer in
            rawBuffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self)
        }.littleEndian
    }

    func loadUInt32LE(at offset: Int) -> UInt32 {
        withUnsafeBytes { rawBuffer in
            rawBuffer.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
        }.littleEndian
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
