import CKcp
import Dispatch
import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
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
    /// Number of data shards per FEC group. 0 disables FEC framing
    /// entirely (kcp UDP packets go directly to the packet codec).
    /// Must match the kcptun-server's `--datashard` flag.
    public var dataShards: Int
    /// Number of parity shards per FEC group. 0 disables FEC.
    /// Must match the kcptun-server's `--parityshard` flag.
    public var parityShards: Int

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
        crypt: KcpPacketCryptoMethod = .none,
        dataShards: Int = 0,
        parityShards: Int = 0
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
        self.dataShards = dataShards
        self.parityShards = parityShards
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
    private let localPort: UInt16?
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
    /// Outbound FEC encoder; nil when configuration.dataShards == 0
    /// (kcptun-server started with `--datashard 0 --parityshard 0`).
    private var fecEncoder: KcpFECEncoder?
    /// Inbound FEC decoder. Lifecycle mirrors fecEncoder.
    private var fecDecoder: KcpFECDecoder?

    private static let kcpOverhead = 24

    /// - Parameter localPort: optionally bind the UDP socket to a fixed
    ///   local port before connecting. Symmetric peering (two forwarders
    ///   dialing each other, hub-to-hub) needs BOTH ends on well-known
    ///   ports — an ephemeral source port would be unknowable to the
    ///   remote side's connect().
    public init(
        remoteHost: String,
        remotePort: UInt16,
        localPort: UInt16? = nil,
        configuration: KcpConfiguration = .init(),
        callbackQueue: DispatchQueue = .main
    ) {
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.localPort = localPort
        self.configuration = configuration
        self.callbackQueue = callbackQueue
    }

    deinit {
        // Cannot dispatch_sync to stateQueue from deinit — deinit
        // can fire from a closure already executing ON stateQueue
        // (e.g. send()'s `stateQueue.async { [weak self] in guard
        // let self … }` upgrades to a strong ref for the body, and
        // when the last external strong ref has been dropped, the
        // closure's tail-release IS the final release → deinit
        // runs inline on stateQueue → sync from same queue
        // deadlocks in __DISPATCH_WAIT_FOR_QUEUE__).
        //
        // Direct call is safe by ARC contract: at deinit-time no
        // other thread holds a reference. All dispatch sources
        // (readSource, updateTimer) captured `[weak self]` and
        // would no-op via `self?`; any pending dispatched blocks
        // that captured `[weak self]` will hit `guard let self`
        // and fall through cleanly.
        shutdown(nil, notify: false)
    }

    public func start() throws {
        try stateQueue.sync {
            if started {
                throw KcpSessionError.alreadyStarted
            }

            KcpLog.info("starting session to \(remoteHost):\(remotePort) conv=\(configuration.conversationID)")
            socketDescriptor = try Self.makeConnectedSocket(host: remoteHost, port: remotePort, localPort: localPort)
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

            // Initialise FEC if the caller asked for it. Both
            // shards must be > 0 to enable; either being 0 means
            // FEC framing is disabled and KCP UDP datagrams flow
            // straight through the packet codec.
            if configuration.dataShards > 0 && configuration.parityShards > 0 {
                do {
                    fecEncoder = try KcpFECEncoder(
                        dataShards: configuration.dataShards,
                        parityShards: configuration.parityShards)
                    fecDecoder = try KcpFECDecoder(
                        dataShards: configuration.dataShards,
                        parityShards: configuration.parityShards)
                    KcpLog.info("FEC enabled datashard=\(configuration.dataShards) parityshard=\(configuration.parityShards) remote=\(remoteHost):\(remotePort)")
                } catch {
                    KcpLog.error("FEC init failed datashard=\(configuration.dataShards) parityshard=\(configuration.parityShards) error=\(error) — proceeding without FEC")
                    fecEncoder = nil
                    fecDecoder = nil
                }
            }

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
                return Posix.recv(socketDescriptor, baseAddress, bytes.count, 0)
            }

            if count > 0 {
                let packet = Data(receiveBuffer.prefix(count))
                KcpLog.trace("socket recv bytes=\(count) remote=\(remoteHost):\(remotePort)")
                KcpLog.hexDump("udp recv", data: packet)
                do {
                    let payload = try decodePacket(packet)
                    // FEC framing layer (when enabled). Each plaintext
                    // packet is `[seqid|flag|...]` per kcptun-go's
                    // wire format; the decoder surfaces immediate
                    // KCP packets and any reconstructed ones.
                    let kcpPackets = unframeFEC(payload)
                    for kcp in kcpPackets {
                        logKcpSegments("udp recv payload", data: kcp)
                        kcp.withUnsafeBytes { bytes in
                            guard let baseAddress = bytes.bindMemory(to: Int8.self).baseAddress else { return }
                            let inputResult = ikcp_input(rawKcp, baseAddress, Int(bytes.count))
                            KcpLog.trace("ikcp_input result=\(inputResult) payloadBytes=\(bytes.count) remote=\(remoteHost):\(remotePort)")
                        }
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
        let kcpPacket = Data(bytes: buffer, count: Int(length))

        // FEC framing layer (when enabled). One KCP packet expands
        // into 1 data frame plus optionally `parityShards` parity
        // frames at every group boundary. Each frame is then routed
        // through the packet codec (AES) before going on the wire.
        let frames: [Data]
        if let fecEncoder {
            frames = fecEncoder.encode(kcpPacket: kcpPacket)
        } else {
            frames = [kcpPacket]
        }

        var totalSent: Int32 = 0
        for frame in frames {
            let data: Data
            do {
                data = try encodePacket(frame)
            } catch {
                KcpLog.error("udp packet encode failed remote=\(remoteHost):\(remotePort) error=\(error)")
                return -1
            }
            KcpLog.hexDump("udp send", data: data)
            let sent = data.withUnsafeBytes { bytes in
                Posix.send(socketDescriptor, bytes.baseAddress, data.count, 0)
            }
            if sent < 0 {
                KcpLog.error("udp send failed errno=\(errno) remote=\(remoteHost):\(remotePort)")
                return -1
            }
            KcpLog.trace("udp send bytes=\(sent) frame=\(frames.firstIndex(of: frame).map(String.init) ?? "?")/\(frames.count) remote=\(remoteHost):\(remotePort)")
            // Only the data frame counts toward what KCP thinks it sent;
            // parity frames are parallel UDP work, not KCP layer.
            if totalSent == 0 { totalSent = Int32(sent) }
        }
        return totalSent
    }

    /// Unwrap a plaintext UDP payload through the FEC framing layer
    /// (when enabled). Without FEC the input passes through as a
    /// single KCP packet. With FEC, each arriving frame is
    /// `[seqid|flag|...]`; the decoder surfaces the inner KCP packet
    /// from data frames and any reconstructed packets when a group
    /// completes with missing data shards.
    private func unframeFEC(_ payload: Data) -> [Data] {
        guard let fecDecoder else { return [payload] }
        var out: [Data] = []
        for result in fecDecoder.decode(framedPacket: payload) {
            switch result {
            case .immediate(let kcp):
                out.append(kcp)
            case .recovered(let kcps):
                out.append(contentsOf: kcps)
            }
        }
        return out
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

    private static func makeConnectedSocket(host: String, port: UInt16, localPort: UInt16?) throws -> Int32 {
        var hints = Posix.udpAddrInfoHints(passive: false)

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
                if let localPort, !bindLocalPort(fd, family: current.pointee.ai_family, port: localPort) {
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

    /// Bind the not-yet-connected UDP socket to a fixed local port on the
    /// wildcard address of the matching family.
    private static func bindLocalPort(_ fd: Int32, family: Int32, port: UInt16) -> Bool {
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))

        if family == AF_INET {
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            return withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
                }
            }
        }
        if family == AF_INET6 {
            var addr = sockaddr_in6()
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = port.bigEndian
            return withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in6>.size)) == 0
                }
            }
        }
        return false
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

    private static func describeLocalEndpoint(_ fd: Int32) -> String? {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                getsockname(fd, sockaddrPointer, &length)
            }
        }
        guard result == 0 else { return nil }

        if storage.ss_family == sa_family_t(AF_INET) {
            return withUnsafePointer(to: &storage) { ptr in
                ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    let addr = sin.pointee.sin_addr.s_addr
                    let p = UInt16(bigEndian: sin.pointee.sin_port)
                    return "\(Int(addr & 0xFF)).\(Int((addr >> 8) & 0xFF)).\(Int((addr >> 16) & 0xFF)).\(Int((addr >> 24) & 0xFF)):\(p)"
                }
            }
        }
        if storage.ss_family == sa_family_t(AF_INET6) {
            return withUnsafePointer(to: &storage) { ptr in
                ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    let p = UInt16(bigEndian: sin6.pointee.sin6_port)
                    // in6_addr's union member names differ between Darwin
                    // (__u6_addr) and Glibc (__in6_u) — read raw bytes instead.
                    let segments = withUnsafeBytes(of: sin6.pointee.sin6_addr) { raw -> [UInt16] in
                        (0..<8).map { UInt16(bigEndian: raw.loadUnaligned(fromByteOffset: $0 * 2, as: UInt16.self)) }
                    }
                    let ipStr = segments.map { String(format: "%x", $0) }.joined(separator: ":")
                    return "[\(ipStr)]:\(p)"
                }
            }
        }
        return nil
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
