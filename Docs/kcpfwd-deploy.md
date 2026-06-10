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
