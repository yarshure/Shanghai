import Foundation
import Lisao

enum KcpLogLevel: String {
    case trace = "TRACE"
    case info = "INFO"
    case warning = "WARN"
    case error = "ERROR"
}
struct NativeLog {
    static func timestamp() -> Int64 {
        var tv = timeval()
        gettimeofday(&tv, nil)
        // 转换为毫秒 (1秒 = 1000毫秒, 1微秒 = 1/1000毫秒)
        return Int64(tv.tv_sec) * 1000 + Int64(tv.tv_usec) / 1000
    }
}
enum KcpLog {
    
    // 线程安全，因为 ContinuousClock 是 Sendable 的
    @available(iOS 16.0, *)
    private static let clock = NativeLog()
    
    static func getTimestamp() -> String {
        // 返回从系统启动开始的秒数，纳秒级精度
        let now = NativeLog.timestamp()
        return "\(now)"
    }
    private static let minimumLevel = configuredMinimumLevel()

    static func trace(_ message: @autoclosure () -> String) {
        guard shouldLog(.trace) else { return }
        write(.trace, message())
    }

    static func info(_ message: @autoclosure () -> String) {
        guard shouldLog(.info) else { return }
        write(.info, message())
    }

    static func warning(_ message: @autoclosure () -> String) {
        guard shouldLog(.warning) else { return }
        write(.warning, message())
    }

    static func error(_ message: @autoclosure () -> String) {
        guard shouldLog(.error) else { return }
        write(.error, message())
    }

    static func hexDump(_ label: String, data: Data, limit: Int = 512) {
        guard shouldLog(.trace) else { return }
        let clipped = data.prefix(limit)
        let hex = clipped.enumerated().map { index, byte in
            let prefix = index.isMultiple(of: 16) ? String(format: "\n%04x: ", index) : ""
            return prefix + String(format: "%02x ", byte)
        }.joined()
        let suffix = data.count > limit ? "\n... truncated \(data.count - limit) bytes" : ""
        write(.trace, "\(label) bytes=\(data.count)\(hex)\(suffix)")
    }

    private static func write(_ level: KcpLogLevel, _ message: String) {
        //let timestamp = String(format: "%.3f", Date().timeIntervalSince1970)
        print("[\(getTimestamp())] [\(level.rawValue)] [Shanghai.KCP] \(message)")
    }

    private static func configuredMinimumLevel() -> KcpLogLevel {
        let raw = ProcessInfo.processInfo.environment["SHANGHAI_LOG_LEVEL"]?.lowercased()
        switch raw {
        case "trace":
            return .trace
        case "warning", "warn":
            return .warning
        case "error":
            return .error
        case "info", nil:
            return .info
        default:
            return .info
        }
    }

    private static func shouldLog(_ level: KcpLogLevel) -> Bool {
        priority(of: level) >= priority(of: minimumLevel)
    }

    private static func priority(of level: KcpLogLevel) -> Int {
        switch level {
        case .trace:
            return 0
        case .info:
            return 1
        case .warning:
            return 2
        case .error:
            return 3
        }
    }
}
