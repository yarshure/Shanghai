import Dispatch
import Foundation

public final class KcpTunConnectorManager: @unchecked Sendable {
    public static let shared = KcpTunConnectorManager()

    private let queue = DispatchQueue(label: "shanghai.kcptun.manager")
    private var connectors: [KcpRemoteEndpoint: KcpTunConnector] = [:]

    public init() {}

    public func connector(
        for endpoint: KcpRemoteEndpoint,
        makeConfiguration: @escaping @Sendable (KcpRemoteEndpoint) -> KcpTunConnectorConfiguration
    ) -> KcpTunConnector {
        queue.sync {
            if let connector = connectors[endpoint] {
                KcpLog.trace("reuse connector endpoint=\(endpoint)")
                return connector
            }

            KcpLog.info("create connector endpoint=\(endpoint)")
            let connector = KcpTunConnector(configuration: makeConfiguration(endpoint))
            connector.onStateChange = { [weak self] connector, connected in
                guard !connected else { return }
                self?.queue.async { [weak self] in
                    guard let self else { return }
                    if self.connectors[endpoint] === connector {
                        KcpLog.info("remove stopped connector endpoint=\(endpoint)")
                        self.connectors.removeValue(forKey: endpoint)
                    }
                }
            }
            connectors[endpoint] = connector
            return connector
        }
    }

    public func connector(for endpoint: KcpRemoteEndpoint) -> KcpTunConnector? {
        queue.sync { connectors[endpoint] }
    }

    public func removeConnector(for endpoint: KcpRemoteEndpoint) {
        queue.async { [weak self] in
            guard let connector = self?.connectors.removeValue(forKey: endpoint) else { return }
            KcpLog.info("remove connector endpoint=\(endpoint)")
            connector.stop()
        }
    }

    public func removeAllConnectors() {
        queue.async { [weak self] in
            guard let self else { return }
            let all = Array(self.connectors.values)
            self.connectors.removeAll(keepingCapacity: false)
            KcpLog.info("remove all connectors count=\(all.count)")
            all.forEach { $0.stop() }
        }
    }
}
