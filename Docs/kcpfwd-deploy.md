# kcpfwd — hub-to-hub WireGuard-over-KCP 部署

目标拓扑：只有跨境 hub↔hub 这一条 WG 链路从 KCP 隧道里走（混淆 + FEC 抗 QoS），
其余所有 spoke 流量保持普通 WireGuard 不变。内核 WG 完全不动，只改这条 peer 的
`Endpoint` 指向本机 kcpfwd。

```
hub A (境内)                                    hub B (境外)
kernel wg, listen 1632                          kernel wg, listen 1632
  peer B: Endpoint = 127.0.0.1:4001               peer A: Endpoint = 127.0.0.1:4001
        │ UDP                                           │ UDP
  kcpfwd ──── 跨境 UDP :4000 ←→ :4000 (KCP+FEC+AES) ──── kcpfwd
```

两端跑**同一个二进制、对称参数**：各自固定 KCP 端口 (`--kcp-port`) 并 connect 对端
的同一端口，没有任何 accept/demux 逻辑。`--conv`、`--key`、`--crypt`、
`--datashard/--parityshard` 两端必须一致。

## NAT 后面的客户端（server 模式）

对称 connect 只适用于两端都有固定公网端点（hub-to-hub）。当一端在 NAT 后面
（移动端、家宽 spoke）时，公网侧用 `--server`：它 bind `--kcp-port` 并从客户端
第一个包里**学习**对端地址，而不是 connect 一个未知端点。客户端不带 `--server`，
正常 dial 公网侧的 `--kcp-port`。**客户端必须先发包**来 bootstrap（hub=server 时，
从客户端侧先 ping 一下）。已在 124.221.22.9 实测：真·WG（macOS wireguard-go
客户端 ↔ 内核 WG hub）跨真实网络跑通，~12ms，0 丢包。

## FEC 状态：逻辑正确（之前"FEC bug"系误判）

> 更正：早期记录里说 FEC 在真实链路上损坏 WG 流量 —— **那是误判**，是被混淆变量
> 污染的实验（切 FEC 时同时重启了两端 + 重置 WG 握手 + 撞上下面两个真实问题）。

深入排查结论：
- **FEC 编解码逻辑正确**。三个严格单元测试覆盖：变长包重排（无丢包）、单组丢包恢复、
  多组变长+丢包+重排压力测试 —— 全部 0 损坏、0 丢可恢复包。见 KcpReedSolomonTests。
- 受控实验（真实 ikcp + 注入丢包/重排的本地中继）里 **FEC 在重排下反而显著降低丢包**
  （11% vs 关 FEC 的表象 75%），符合预期。

真正找到并修掉的是下面这个 bug ↓

## ⚠️ 已修：client 会话在 ICMP 错误上永久自杀

连接型 UDP 的 client 在收到一次 `ECONNREFUSED`（server 端口短暂不在/重启的瞬间会回
ICMP port-unreachable）就**永久 shutdown 不重连**。生产里 server 一抖动/重启，所有
client 全死。已修：KcpSession 把 `ECONNREFUSED/ECONNRESET/EHOSTUNREACH/ENETUNREACH/
EHOSTDOWN` 当作瞬态吞掉（KCP 自会重传，连通恢复即自愈）。**这极可能就是当初"FEC 失败"
的真凶之一**（反复重启 server，client 们都 ECONNREFUSED 死了）。

## 限制：KCP 有状态，单侧重启需两端重建

KCP 像 TCP 是有状态连接：server 重启后是全新 KCP 状态（seq 从 0），client 仍在高
seq，两边永久 desync，**ICMP 修复只保证进程不死、瞬态抖动自愈，但 server 真正重启后
这条 KCP 会话仍需两端重建**（由 supervisor 重拉 client，或后续做 KCP 会话重协商）。
部署时 server 端用 systemd 常驻、避免无谓重启；client 端也挂 supervisor。

## 构建（macOS 上交叉编译出 Linux 静态二进制）

```sh
# 一次性：装 swift.org 工具链 + Static Linux SDK（版本必须配套）
swift sdk install <static-linux-sdk-url> --checksum <官方 checksum>

# 出静态 musl 二进制，scp 即部署，hub 上不需要任何运行时
swift build -c release --swift-sdk x86_64-swift-linux-musl --product kcpfwd
scp .build/x86_64-swift-linux-musl/release/kcpfwd ubuntu@<hub>:/usr/local/sbin/kcpfwd
```

## 运行

hub A（假设 B 的公网 IP 是 203.0.113.7）：

```sh
kcpfwd --listen 4001 --wg 127.0.0.1:1632 \
       --peer 203.0.113.7:4000 --kcp-port 4000 \
       --conv 77 --crypt aes --key '<psk>' \
       --datashard 10 --parityshard 3
```

hub B 同一条命令，`--peer` 换成 A 的 IP。然后改 WG 配置里**对端 hub 这一个 peer**：

```ini
[Peer]   # 对端 hub
PublicKey = ...
Endpoint = 127.0.0.1:4001     # 原来是 <对端公网IP>:1632
AllowedIPs = ...
PersistentKeepalive = 25
```

`wg syncconf` 热加载即可，不影响其他 spoke peer。

## 必查清单

- **安全组/防火墙放行 UDP `--kcp-port`**（两端都要；之前 1632 就栽在腾讯安全组上）。
- **WG 接口 MTU 降到 ~1280**：WG(~60B)+KCP(24B)+FEC(8B)+crypt(20B) 叠在一个 UDP
  包里，决不能让跨境链路上发生 IP 分片。
- crypt 是混淆不是保密（WG 本身有加密），但 key 仍别用默认值——它决定 DPI 看到的字节。
- conv 是 KCP 会话标识，两端不一致时静默丢包，排障先查它。

## systemd

`/etc/systemd/system/kcpfwd.service`：

```ini
[Unit]
Description=WireGuard-over-KCP forwarder (hub-to-hub)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/kcpfwd --listen 4001 --wg 127.0.0.1:1632 \
  --peer <REMOTE_HUB_IP>:4000 --kcp-port 4000 \
  --conv 77 --crypt aes --key <PSK> --datashard 10 --parityshard 3
Restart=always
RestartSec=2
# 转发器不需要任何特权
DynamicUser=yes
AmbientCapabilities=
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now kcpfwd
journalctl -u kcpfwd -f      # SHANGHAI_LOG_LEVEL=trace 可加到 Environment= 排障
```

## 验证

1. 两端 `kcpfwd` 起来后：`wg show <iface> latest-handshakes` 看对端 hub 是否重新握手。
2. `tcpdump -ni any udp port 4000`：跨境线上应该只看到高熵 KCP 包，没有 WG 特征
   （0x01/0x02/0x03/0x04 开头的明文 type 字节消失）。
3. 跨 hub ping 内网地址（如 100.64.0.1 ↔ 对端 mesh IP），再跑 iperf3 对比裸 WG。

## 回滚

把那个 peer 的 `Endpoint` 改回对端公网 IP:1632，`wg syncconf`，停掉 kcpfwd。完全无损。
