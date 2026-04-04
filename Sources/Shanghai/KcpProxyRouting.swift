import Foundation

public struct KcpProxyUpstreamConfiguration: Sendable, Equatable {
    public let endpoint: KcpRemoteEndpoint
    public let smuxVersion: KcpSmuxVersion
    public let crypt: KcpPacketCryptoMethod
    public let compressionEnabled: Bool
    public let password: String

    public init(
        endpoint: KcpRemoteEndpoint,
        smuxVersion: KcpSmuxVersion = .v2,
        crypt: KcpPacketCryptoMethod = .none,
        compressionEnabled: Bool = false,
        password: String = "Xifeng2026"
    ) {
        self.endpoint = endpoint
        self.smuxVersion = smuxVersion
        self.crypt = crypt
        self.compressionEnabled = compressionEnabled
        self.password = password
    }
}

public struct KcpProxyRoute: Sendable, Equatable {
    public let name: String
    public let hostPatterns: [String]
    public let upstream: KcpProxyUpstreamConfiguration

    public init(name: String, hostPatterns: [String], upstream: KcpProxyUpstreamConfiguration) {
        self.name = name
        self.hostPatterns = hostPatterns
        self.upstream = upstream
    }

    func matches(host: String) -> Bool {
        let normalizedHost = host.lowercased()
        return hostPatterns.contains { pattern in
            let normalizedPattern = pattern.lowercased()
            if normalizedPattern.hasPrefix("*.") {
                let suffix = String(normalizedPattern.dropFirst(1))
                return normalizedHost.hasSuffix(suffix)
            }
            return normalizedHost == normalizedPattern
        }
    }
}

public struct KcpProxyRequestTarget: Sendable, Equatable {
    public let host: String
    public let port: UInt16?

    public init(host: String, port: UInt16? = nil) {
        self.host = host
        self.port = port
    }
}

public struct KcpProxyRouteSelection: Sendable, Equatable {
    public let route: KcpProxyRoute?
    public let upstream: KcpProxyUpstreamConfiguration
}

public struct KcpProxyRouteTable: Sendable, Equatable {
    public let routes: [KcpProxyRoute]
    public let defaultUpstream: KcpProxyUpstreamConfiguration

    public init(routes: [KcpProxyRoute], defaultUpstream: KcpProxyUpstreamConfiguration) {
        self.routes = routes
        self.defaultUpstream = defaultUpstream
    }

    public func selectTarget(for requestData: Data) -> KcpProxyRouteSelection? {
        guard let target = parseTarget(from: requestData) else { return nil }
        if let route = routes.first(where: { $0.matches(host: target.host) }) {
            return KcpProxyRouteSelection(route: route, upstream: route.upstream)
        }
        return KcpProxyRouteSelection(route: nil, upstream: defaultUpstream)
    }

    public func parseTarget(from requestData: Data) -> KcpProxyRequestTarget? {
        let request = String(decoding: requestData, as: UTF8.self)
        guard let requestLine = request.split(separator: "\n", omittingEmptySubsequences: false).first?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !requestLine.isEmpty
        else {
            return nil
        }

        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2 else { return nil }
        let method = parts[0].uppercased()
        let target = String(parts[1])

        if method == "CONNECT" {
            let hostPort = target.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: true)
            guard let host = hostPort.first else { return nil }
            let port = hostPort.count == 2 ? UInt16(hostPort[1]) : 443
            return KcpProxyRequestTarget(host: String(host), port: port)
        }

        if let url = URL(string: target), let host = url.host {
            let port = url.port.map(UInt16.init(_:))
            return KcpProxyRequestTarget(host: host, port: port)
        }

        return nil
    }
}

public final class KcpProxyRuntimeRegistry: @unchecked Sendable {
    private let queue = DispatchQueue(label: "shanghai.proxy.runtime.registry")
    private var sessionIDs = Set<UInt32>()

    public init() {}

    public func insert(_ sessionID: UInt32) {
        _ = queue.sync {
            sessionIDs.insert(sessionID)
        }
    }

    public func remove(_ sessionID: UInt32) {
        _ = queue.sync {
            sessionIDs.remove(sessionID)
        }
    }

    public var count: Int {
        queue.sync { sessionIDs.count }
    }
}
