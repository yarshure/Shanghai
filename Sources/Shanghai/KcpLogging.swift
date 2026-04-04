import Foundation
import Lisao

enum KcpLogLevel: String {
    case trace = "TRACE"
    case info = "INFO"
    case warning = "WARN"
    case error = "ERROR"
}

enum KcpLog {
    static func trace(_ message: @autoclosure () -> String) {
        write(.trace, message())
    }

    static func info(_ message: @autoclosure () -> String) {
        write(.info, message())
    }

    static func warning(_ message: @autoclosure () -> String) {
        write(.warning, message())
    }

    static func error(_ message: @autoclosure () -> String) {
        write(.error, message())
    }

    static func hexDump(_ label: String, data: Data, limit: Int = 512) {
        let clipped = data.prefix(limit)
        let hex = clipped.enumerated().map { index, byte in
            let prefix = index.isMultiple(of: 16) ? String(format: "\n%04x: ", index) : ""
            return prefix + String(format: "%02x ", byte)
        }.joined()
        let suffix = data.count > limit ? "\n... truncated \(data.count - limit) bytes" : ""
        write(.trace, "\(label) bytes=\(data.count)\(hex)\(suffix)")
    }

    private static func write(_ level: KcpLogLevel, _ message: String) {
        let formatter = ISO8601DateFormatter()
        let timestamp = formatter.string(from: Date())
        print("[\(timestamp)] [\(level.rawValue)] [Shanghai.KCP] \(message)")
    }
}
