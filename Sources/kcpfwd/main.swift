// kcpfwd — symmetric UDP<->KCP forwarder for carrying WireGuard over KCP.
//
// Run the SAME binary on both hubs, each pointing --peer at the other and
// using identical --conv/--key/--crypt/--datashard/--parityshard. Each side
// binds a fixed KCP port (--kcp-port) and connect()s to the other's, so
// neither end needs accept/demux logic. Kernel WireGuard stays untouched:
// point the hub-to-hub peer's Endpoint at this forwarder's --listen port.
//
//   hub A                                            hub B
//   wg peer Endpoint=127.0.0.1:4001                  wg peer Endpoint=127.0.0.1:4001
//   kcpfwd --listen 4001 --wg 127.0.0.1:1632 \       kcpfwd --listen 4001 --wg 127.0.0.1:1632 \
//          --peer <B-ip>:4000 --kcp-port 4000 \             --peer <A-ip>:4000 --kcp-port 4000 \
//          --conv 77 --crypt aes --key <psk>                --conv 77 --crypt aes --key <psk>
//
// Remember: open UDP --kcp-port in both security groups, and drop the WG
// interface MTU (~1280) so WG+KCP+FEC+crypt never IP-fragments.

import Dispatch
import Foundation
import Shanghai

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif

struct CLIError: Error, CustomStringConvertible {
    let description: String
}

func parseHostPort(_ raw: String, flag: String) throws -> (host: String, port: UInt16) {
    // Accept host:port and [v6addr]:port.
    let host: Substring
    let portText: Substring
    if raw.hasPrefix("[") {
        guard let closing = raw.firstIndex(of: "]"),
              raw.index(after: closing) < raw.endIndex,
              raw[raw.index(after: closing)] == ":" else {
            throw CLIError(description: "\(flag): expected [host]:port, got '\(raw)'")
        }
        host = raw[raw.index(after: raw.startIndex)..<closing]
        portText = raw[raw.index(closing, offsetBy: 2)...]
    } else {
        guard let colon = raw.lastIndex(of: ":") else {
            throw CLIError(description: "\(flag): expected host:port, got '\(raw)'")
        }
        host = raw[raw.startIndex..<colon]
        portText = raw[raw.index(after: colon)...]
    }
    guard let port = UInt16(portText), port > 0, !host.isEmpty else {
        throw CLIError(description: "\(flag): bad port in '\(raw)'")
    }
    return (String(host), port)
}

struct ForwarderOptions {
    var listenHost = "127.0.0.1"
    var listenPort: UInt16 = 0
    var wg: (host: String, port: UInt16)?
    var peer: (host: String, port: UInt16)?
    var kcpPort: UInt16?
    var server = false
    var conv: UInt32?
    var key = "it's a secrect"
    var crypt = KcpPacketCryptoMethod.aes
    var dataShards = 10
    var parityShards = 3
    var mtu: Int32 = 1_350
    var sendWindow: Int32 = 1_024
    var receiveWindow: Int32 = 1_024
}

let usage = """
usage: kcpfwd --listen <port> --wg <host:port> --peer <host:port> \
--kcp-port <port> --conv <id> [options]

required:
  --listen <port>        local UDP port WireGuard's Endpoint points at
  --wg <host:port>       where the local WireGuard listens (e.g. 127.0.0.1:1632)
  --peer <host:port>     the remote kcpfwd's --kcp-port endpoint
                         (omit with --server: the client's addr is learned)
  --kcp-port <port>      fixed local UDP port for the KCP transport
                         (with --server this is the PUBLIC port clients dial)
  --conv <id>            KCP conversation id, identical on both ends

  --server               act as the KCP server for a NAT'd client: bind
                         --kcp-port and learn the peer from its first packet
                         instead of connecting to --peer. The client side
                         runs WITHOUT --server and dials this --kcp-port.

options (must match the remote end):
  --key <psk>            pre-shared key            (default: kcptun default)
  --crypt <mode>         none|aes|aes-128|aes-192  (default: aes)
  --datashard <n>        FEC data shards           (default: 10)
  --parityshard <n>      FEC parity shards         (default: 3)
  --mtu <n>              KCP mtu                   (default: 1350)
  --sndwnd <n>           send window               (default: 1024)
  --rcvwnd <n>           receive window            (default: 1024)
  --listen-host <host>   bind address for --listen (default: 127.0.0.1)
"""

func parseOptions(_ arguments: [String]) throws -> ForwarderOptions {
    var options = ForwarderOptions()
    var index = 0

    func value(_ flag: String) throws -> String {
        index += 1
        guard index < arguments.count else {
            throw CLIError(description: "\(flag) needs a value")
        }
        return arguments[index]
    }

    while index < arguments.count {
        let flag = arguments[index]
        switch flag {
        case "--listen":
            guard let port = UInt16(try value(flag)) else { throw CLIError(description: "--listen: bad port") }
            options.listenPort = port
        case "--listen-host":
            options.listenHost = try value(flag)
        case "--wg":
            options.wg = try parseHostPort(try value(flag), flag: flag)
        case "--peer":
            options.peer = try parseHostPort(try value(flag), flag: flag)
        case "--kcp-port":
            guard let port = UInt16(try value(flag)) else { throw CLIError(description: "--kcp-port: bad port") }
            options.kcpPort = port
        case "--server":
            options.server = true
        case "--conv":
            guard let conv = UInt32(try value(flag)) else { throw CLIError(description: "--conv: bad id") }
            options.conv = conv
        case "--key":
            options.key = try value(flag)
        case "--crypt":
            let raw = try value(flag)
            guard let crypt = KcpPacketCryptoMethod(rawValue: raw) else {
                throw CLIError(description: "--crypt: unknown mode '\(raw)'")
            }
            options.crypt = crypt
        case "--datashard":
            guard let n = Int(try value(flag)), n >= 0 else { throw CLIError(description: "--datashard: bad count") }
            options.dataShards = n
        case "--parityshard":
            guard let n = Int(try value(flag)), n >= 0 else { throw CLIError(description: "--parityshard: bad count") }
            options.parityShards = n
        case "--mtu":
            guard let n = Int32(try value(flag)), n > 0 else { throw CLIError(description: "--mtu: bad value") }
            options.mtu = n
        case "--sndwnd":
            guard let n = Int32(try value(flag)), n > 0 else { throw CLIError(description: "--sndwnd: bad value") }
            options.sendWindow = n
        case "--rcvwnd":
            guard let n = Int32(try value(flag)), n > 0 else { throw CLIError(description: "--rcvwnd: bad value") }
            options.receiveWindow = n
        case "-h", "--help":
            print(usage)
            exit(0)
        default:
            throw CLIError(description: "unknown flag '\(flag)'")
        }
        index += 1
    }

    guard options.listenPort > 0 else { throw CLIError(description: "--listen is required") }
    guard options.wg != nil else { throw CLIError(description: "--wg is required") }
    guard options.kcpPort != nil else { throw CLIError(description: "--kcp-port is required") }
    guard options.conv != nil else { throw CLIError(description: "--conv is required (same value on both ends)") }
    if options.server {
        // Server learns the peer; --peer is meaningless and a NAT'd client's
        // address is unknowable up front.
        if options.peer != nil {
            throw CLIError(description: "--peer must be omitted with --server (peer is learned)")
        }
    } else {
        guard options.peer != nil else { throw CLIError(description: "--peer is required (or use --server)") }
    }
    return options
}

let options: ForwarderOptions
do {
    options = try parseOptions(Array(CommandLine.arguments.dropFirst()))
} catch {
    FileHandle.standardError.write(Data("kcpfwd: \(error)\n\n\(usage)\n".utf8))
    exit(2)
}

var configuration = KcpConfiguration()
configuration.conversationID = options.conv!
configuration.mtu = options.mtu
configuration.sendWindow = options.sendWindow
configuration.receiveWindow = options.receiveWindow
configuration.preSharedKey = options.key
configuration.crypt = options.crypt
configuration.dataShards = options.dataShards
configuration.parityShards = options.parityShards
// Datagram mode: each forwarded WG UDP packet must map 1:1 to one KCP
// message so boundaries survive the hop. KcpConfiguration defaults to
// streamMode=true (byte-stream) — wrong for carrying discrete WG packets,
// and it mismatches the iOS PacketTunnelProvider (which sets false), so only
// KCP control frames cross and the WG handshake never reaches the far wg.
// Both ends of a kcpfwd pair must agree; keep this false everywhere.
configuration.streamMode = false
// nodelay=1 interval=20 resend=2 nc=1 defaults already suit hub-to-hub.

let forwarder = KcpUdpForwarder(
    localHost: options.listenHost,
    localPort: options.listenPort,
    remoteHost: options.peer?.host ?? "0.0.0.0",
    remotePort: options.peer?.port ?? 0,
    kcpLocalPort: options.kcpPort,
    listenMode: options.server,
    wgEndpoint: options.wg,
    configuration: configuration
)

forwarder.onStop = { error in
    if let error {
        FileHandle.standardError.write(Data("kcpfwd: stopped: \(error)\n".utf8))
        exit(1)
    }
    exit(0)
}

do {
    try forwarder.start()
} catch {
    FileHandle.standardError.write(Data("kcpfwd: start failed: \(error)\n".utf8))
    exit(1)
}

let kcpTarget = options.server ? "LISTEN :\(options.kcpPort!) (learn client)" : "\(options.peer!.host):\(options.peer!.port) (local kcp port \(options.kcpPort!))"
print("kcpfwd: wg-facing \(options.listenHost):\(options.listenPort) -> kcp \(kcpTarget), conv \(options.conv!), crypt \(options.crypt.rawValue), fec \(options.dataShards)/\(options.parityShards), wg listener \(options.wg!.host):\(options.wg!.port)")

// Clean shutdown on SIGINT/SIGTERM. signal() ignores so the dispatch
// sources are the only consumers.
signal(SIGINT, SIG_IGN)
signal(SIGTERM, SIG_IGN)
let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
for source in [sigint, sigterm] {
    source.setEventHandler { forwarder.stop() }
    source.resume()
}

dispatchMain()
