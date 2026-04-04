# Shanghai KCP Tunnel Design Notes

## Goal

这个目录现在承担两件事：

1. 提供一个可被 Swift Package 直接依赖的 `CKcp` 静态 target，内部只保留最小 KCP C 内核。
2. 在 Swift 层重写原来 `sess` / `KcpStocket` 那一层，把 socket 读写、KCP 驱动、SMux 拆帧、多 stream 分发放到可组合的新架构里。

这次实现刻意没有把旧工程里的 `Adapter`、`Xcon`、`ProxyConnector`、`SFProxy`、`NetworkExtension` 等上层强依赖直接搬进来，而是先把 tunnel 核心抽出来，方便后续接入新的代理 Swift Package。

## Why Not Reuse Old sess

旧实现的问题不是功能不对，而是边界太大：

- C++ `sess` 同时管 socket、KCP、FEC、加密、Network.framework 分支。
- `KcpTunConnector` 和 `KcpStocket` 强耦合旧代理栈。
- 单例 `shared` 模式天然不适合多个远端 endpoint 并存。

所以这次的原则是：

- 保留上游 `ikcp.c/.h`，不要重写 KCP 算法。
- 放弃旧 `sess.cpp`，Swift 重写 session 驱动层。
- 单个远端 `ip:port` 对应一个 connector。
- manager 只做路由和复用，不承载具体 tunnel 状态机。

## Current Structure

### 1. `CKcp`

文件：

- `Sources/CKcp/ikcp.c`
- `Sources/CKcp/include/ikcp.h`

职责：

- 只暴露最小 KCP C 实现。
- 作为独立 static library 产品 `CKcp` 输出。

这样做的好处：

- 构建边界清晰。
- Swift 只桥接稳定的 C API。
- 后续如果加 FEC/crypt，可以按需要继续扩 target，而不是先把旧大包整体搬进来。

### 2. `KcpSession`

文件：

- `Sources/Shanghai/KcpSession.swift`

职责：

- 创建并连接 UDP socket。
- 设置 non-blocking。
- 创建 `ikcpcb*`。
- 接管 KCP output callback，把 KCP 输出写回 UDP socket。
- 用 `DispatchSourceRead` 驱动 socket 可读事件。
- 用 `DispatchSourceTimer` + `ikcp_check`/`ikcp_update` 驱动 KCP 时钟。
- 把 KCP 解出来的 payload 通过 callback 抛给上层。

这是新的最底层“传输适配层”。

它只关心：

- “怎么把 bytes 写进 KCP”
- “怎么把 bytes 从 KCP 读出来”
- “怎么和 UDP socket 对接”

它不关心：

- SMux frame
- stream id
- HTTP/SOCKS/SS 代理协议
- 上层连接对象生命周期

### 3. `KcpTunnelPrimitives`

文件：

- `Sources/Shanghai/KcpTunnelPrimitives.swift`

职责：

- 定义远端 endpoint：`KcpRemoteEndpoint`
- 定义 SMux frame：`KcpFrame`
- 定义 SMux 版本：`v1/v2`
- 定义 command：`syn/fin/psh/nop/upd`
- 定义 frame 编解码
- 定义旧 `readFrame` 迁移后的增量解包器：`KcpFrameDecoder`
- 定义按最大帧长拆包：`splitKcpFrames`

这里迁移的是旧 `Frame.swift` 和 `KcpStocket.readFrame()` 的核心逻辑。

拆出这一层的目的是让 frame 协议和 transport 解耦：

- `KcpSession` 不需要知道 frame 结构
- `KcpTunConnector` 不需要关心 UDP 和 KCP 的事件驱动细节

### 4. `KcpTunConnector`

文件：

- `Sources/Shanghai/KcpTunConnector.swift`

职责：

- 一个 connector 只服务一个远端 `ip:port`
- 内部持有一个 `KcpSession`
- 维护 stream 状态：
  - `streams`
  - `pendingStreams`
  - `establishedStreams`
  - `waitingOpenStreams`
- 维护 `smux v2` 的 stream consumed bytes，用于回发窗口更新
- 把上层 payload 封成 SMux frame
- 把下层 payload 解成 SMux frame
- 响应 `SYN/FIN/PSH/NOP/UPD`
- 管理 keepalive
- 支持按 connector 配置切换 `smux v1/v2`

这里相当于重写后的 `KcpStocket + KcpTunConnector` 融合版，但不再绑定旧代理对象。

上层只需要实现：

- `KcpTunStreamHandler`

当前提供的入口：

- `start()`
- `openStream(_:)`
- `send(_:for:)`
- `closeStream(sessionID:)`
- `stop()`

### 5. `KcpTunConnectorManager`

文件：

- `Sources/Shanghai/KcpTunConnectorManager.swift`

职责：

- 维护 `KcpRemoteEndpoint -> KcpTunConnector` 的 1:1 映射。
- 相同远端复用同一个 connector。
- connector 停止时自动回收。
- 对上层隐藏 connector 创建细节。

这是这次架构调整最核心的一步。

旧模型是：

- 一个全局 `shared` tunnel connector

新模型是：

- 一个远端 endpoint 一个 connector
- 一个 manager 管所有 connector

这样后续可以自然支持：

- 多个 tun
- 多个代理上游
- 多个不同的远端 KCPTUN server

## Data Flow

### Upstream -> Remote

1. 上层通过 manager 根据 `ip:port` 取到 `KcpTunConnector`
2. 上层为某个 `sessionID` 调用 `openStream`
3. connector 发送 `SYN`
4. 上层调用 `send(_:for:)`
5. payload 被拆成一个或多个 `KcpFrame(.psh)`
6. `KcpFrame` 编码成 bytes
7. bytes 交给 `KcpSession.send`
8. `ikcp_send` -> `ikcp_flush`
9. KCP output callback 写入 UDP socket

当 `smuxVersion == v2` 时：

- connector 发出的 frame version 为 `2`
- 远端通过 `UPD` 控制发送窗口
- 本地收到 `PSH` 后会累计 consumed bytes，并回发 `UPD(consumed, window)`

### Remote -> Upstream

1. UDP socket 收到数据
2. `KcpSession` 调用 `ikcp_input`
3. `ikcp_recv` 取出 payload
4. payload 交给 `KcpTunConnector`
5. `KcpFrameDecoder` 增量解出 frame
6. connector 根据 `sid/cmd` 分发：
   - `SYN` -> 建立 stream
   - `FIN` -> 关闭 stream
   - `PSH` -> 把 payload 转发给上层 handler
   - `NOP` -> keepalive/control
   - `UPD` -> `smux v2` 窗口更新控制帧

## Logging Strategy

文件：

- `Sources/Shanghai/KcpLogging.swift`

日志分三层：

1. transport 层
   - UDP send/recv
   - KCP input/output

2. tunnel/frame 层
   - SMux frame send
   - plain payload send/recv
   - stream open/close
   - keepalive timeout

3. test 层
   - HTTP request hexdump
   - HTTP response headers
   - HTTP response body preview
   - HTTP response hexdump

另外加了 hexdump，是为了定位：

- KCP 是否真的发出包
- SMux frame 是否正确封包
- 上层 HTTP 明文是否被原样传递

## Testing

文件：

- `Tests/ShanghaiTests/ShanghaiTests.swift`

当前测试包含两类：

1. 纯逻辑测试
   - 默认配置
   - `smux v1` frame round-trip
   - `smux v2` frame round-trip
   - manager endpoint identity

2. 集成测试
   - 通过 manager 创建 connector
   - 连接测试 server `45.76.141.59:63201`
   - 打开一个 stream
   - 发 `GET http://example.com/ HTTP/1.1`
   - 等待响应并观察日志
   - 当前集成测试配置已切到 `smux v2`

## Design Tradeoffs

### 这次先没做的部分

- FEC
- crypt
- snappy 压缩
- Network.framework 分支
- 旧代理对象直接接线

原因是先把最小可工作的链路稳定下来：

- UDP socket
- KCP
- frame
- multi-stream
- manager route

这条链先通了，后面的能力都可以作为可插拔层再叠上去。

### 为什么 bootstrap/session0 现在简化了

旧实现里有更重的 `session0Ready` 语义。

现在保留了 `bootstrapSessionID` 概念，但默认启动时直接认为控制通道 ready，然后用 `NOP` 做 keepalive。这样能先让 manager/connector 的多实例结构稳定下来，后面如果远端协议要求严格 session0 握手，再把 bootstrap 状态机补细即可。

## How To Integrate With Future Proxy Package

后续新的代理 Swift Package 接入时，推荐做法：

1. 让上层连接对象实现 `KcpTunStreamHandler`
2. 为每个远端 `ip:port` 从 manager 取 connector
3. 为每条代理流分配一个 `sessionID`
4. 调用：
   - `connector.openStream(handler)`
   - `connector.send(data, for: sessionID)`
   - `connector.closeStream(sessionID:)`

如果后续还需要 adapter 层：

- 把 HTTP/SOCKS/SS 的协议转换放在 connector 上层
- connector 只继续负责 tunnel/frame

这样职责边界会比较稳。

## Next Suggested Steps

1. 跑通真实测试 server 的集成测试，确认实际 KCPTUN 协议兼容情况。
2. 如果远端要求严格控制流握手，补全 `session0` bootstrap 状态机。
3. 明确新的代理 Swift Package 上层接口后，把 `KcpTunStreamHandler` 接到真实 stream object。
4. 按需要恢复：
   - crypt
   - compression
   - FEC
5. 如果一个 connector 内 stream 数量很多，再补更细的 backpressure / timeout / metrics。
