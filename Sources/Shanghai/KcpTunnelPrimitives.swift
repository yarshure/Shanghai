import Foundation

public struct KcpRemoteEndpoint: Hashable, Sendable, CustomStringConvertible {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public var description: String {
        "\(host):\(port)"
    }
}

public enum KcpFrameCommand: UInt8, Sendable {
    case syn = 0
    case fin = 1
    case psh = 2
    case nop = 3
    case upd = 4
}

public enum KcpSmuxVersion: UInt8, Sendable {
    case v1 = 1
    case v2 = 2
}

enum KcpTunnelConstants {
    static let headerSize = 8
    static let maxFramePayload = 4_096
    static let defaultSmuxVersion: KcpSmuxVersion = .v2
    static let defaultMaxStreamBuffer = 65_536
    static let updatePayloadSize = 8
}

public struct KcpFrame: Sendable, CustomStringConvertible {
    public var version: UInt8
    public var command: KcpFrameCommand
    public var sessionID: UInt32
    public var payload: Data?
    var left: Int = 0

    public init(
        version: UInt8 = KcpSmuxVersion.v2.rawValue,
        command: KcpFrameCommand,
        sessionID: UInt32,
        payload: Data? = nil
    ) {
        self.version = version
        self.command = command
        self.sessionID = sessionID
        self.payload = payload
    }

    public func encoded() -> Data {
        var data = Data()
        data.append(version)
        data.append(command.rawValue)

        let length = UInt16(payload?.count ?? 0).littleEndian
        withUnsafeBytes(of: length) { data.append(contentsOf: $0) }

        let session = sessionID.littleEndian
        withUnsafeBytes(of: session) { data.append(contentsOf: $0) }

        if let payload {
            data.append(payload)
        }
        return data
    }

    public var description: String {
        "ver:\(version) cmd:\(command.rawValue) sid:\(sessionID) bytes:\(payload?.count ?? 0)"
    }
}

enum KcpMuxError: Error, Sendable {
    case noHeader
    case invalidVersion
    case bodyNotFull
}

struct KcpFrameDecoder {
    let expectedVersion: UInt8
    private(set) var readBuffer = Data()
    private(set) var pendingFrame: KcpFrame?

    init(expectedVersion: UInt8 = KcpTunnelConstants.defaultSmuxVersion.rawValue) {
        self.expectedVersion = expectedVersion
    }

    mutating func append(_ data: Data) {
        readBuffer.append(data)
    }

    mutating func nextFrame() -> (frame: KcpFrame?, error: KcpMuxError?) {
        if var pendingFrame {
            let required = min(pendingFrame.left, readBuffer.count)
            if required > 0 {
                let chunk = readBuffer.subdata(in: 0..<required)
                if pendingFrame.payload == nil {
                    pendingFrame.payload = chunk
                } else {
                    pendingFrame.payload?.append(chunk)
                }
                readBuffer.removeSubrange(0..<required)
                pendingFrame.left -= required
            }

            self.pendingFrame = pendingFrame.left == 0 ? nil : pendingFrame
            return (pendingFrame, pendingFrame.left == 0 ? nil : .bodyNotFull)
        }

        guard readBuffer.count >= KcpTunnelConstants.headerSize else {
            return (nil, .noHeader)
        }

        let header = readBuffer.prefix(KcpTunnelConstants.headerSize)
        let version = header[header.startIndex]
        guard version == expectedVersion else {
            return (nil, .invalidVersion)
        }

        guard let command = KcpFrameCommand(rawValue: header[header.startIndex + 1]) else {
            return (nil, .invalidVersion)
        }

        let length = Int(UInt16(header[2]) | (UInt16(header[3]) << 8))
        let sessionID = UInt32(header[4]) | (UInt32(header[5]) << 8) | (UInt32(header[6]) << 16) | (UInt32(header[7]) << 24)
        var frame = KcpFrame(version: version, command: command, sessionID: sessionID)

        if length == 0 {
            readBuffer.removeSubrange(0..<KcpTunnelConstants.headerSize)
            return (frame, nil)
        }

        let totalLength = KcpTunnelConstants.headerSize + length
        if readBuffer.count >= totalLength {
            frame.payload = readBuffer.subdata(in: KcpTunnelConstants.headerSize..<totalLength)
            readBuffer.removeSubrange(0..<totalLength)
            return (frame, nil)
        }

        frame.payload = readBuffer.count > KcpTunnelConstants.headerSize
            ? readBuffer.subdata(in: KcpTunnelConstants.headerSize..<readBuffer.count)
            : nil
        frame.left = totalLength - readBuffer.count
        readBuffer.removeAll(keepingCapacity: true)
        pendingFrame = frame
        return (frame, .bodyNotFull)
    }
}

func splitKcpFrames(_ data: Data, command: KcpFrameCommand, sessionID: UInt32, maxFrameSize: Int = KcpTunnelConstants.maxFramePayload) -> [KcpFrame] {
    guard !data.isEmpty else {
        return [KcpFrame(command: command, sessionID: sessionID)]
    }

    var frames: [KcpFrame] = []
    var offset = 0
    while offset < data.count {
        let upperBound = min(offset + maxFrameSize, data.count)
        frames.append(
            KcpFrame(
                command: command,
                sessionID: sessionID,
                payload: data.subdata(in: offset..<upperBound)
            )
        )
        offset = upperBound
    }
    return frames
}
