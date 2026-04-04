//
//  KcpStocket.swift
//  Xcon
//
//  Created by yarshure on 2018/1/12.
//  Copyright © 2018年 yarshure. All rights reserved.
//

import Foundation
import KCP
import libkcp
import snappy
import NetworkExtension
import AxLogger

/// SMux 解析过程中的异常类型
///
/// - noHead: 读取数据不足一个头部
/// - VerError: 版本字段不匹配
/// - bodyNotFull: 包体未接收完整，需要等待后续数据
/// - internalError: 内部错误（当前未具体区分）
/// - recvFin: 收到 FIN 结束信号
enum SmuxError:Error {
    case noHead
    case VerError
    case bodyNotFull
    case internalError
    case recvFin
}

/// KcpStocket 是 KCP 隧道与多路复用 (SMux) 的核心实现：
///
/// - 负责与实际 KCPTUN 上游打通 KCP 传输通道（`tun: KCP`）
/// - 负责分流会话状态、流控制、心跳保活、拆帧/组帧
/// - 负责基于 `Frame` 协议从 BLOB 中提取会话 ID 并派发给对应 `Xcon` 实例
class KcpStocket {
    /// KCP 传输通道
    var tun:KCP? //重构没搞好啊
   // var tun:SFKcpTun

    /// 超时阈值（秒）：超时则视为远端失活，触发 shutdown
    static let SMuxTimeOut = 13.0

    /// 可选压缩层（Snappy）
    var snappy:SnappyHelper?

    /// KCP 配置
    var config:KcpConfig?

    /// SMux 配置（当前默认构造用）
    var smuxConfig:Config = Config()

    /// tun 是否准备好（KCP 连接成功且可写）
    var ready:Bool = false

    /// KeepAlive 定时器
    var dispatchTimer:DispatchSourceTimer?

    /// 用于 KCP 和控制逻辑的串行队列
    var dispatchQueue :DispatchQueue

    /// 解压后待解析的字节流缓存
    var readBuffer:Data = Data()

    /// 未完成的部分帧，可能尚未收到全部 body
    var lastFrame:Frame? // not full frame ,需要快速把已经收到的data 给应用

    /// 本地活跃时间
    var lastActive:Date = Date()

    /// 远端活跃时间（用于 KeepAlive 超时判断）
    var lastRemoteActive:Date = Date()

    /// 代理配置
    var proxy:SFProxy

    /// 发送缓存（KCP 未就绪时先缓存数据）
    var sendbuffer:Data = Data()

    /// 通过隧道关联的上层连接映射：sid -> Xcon
    var streams:[UInt32:Xcon] = [:]

    /// 本地已发 SYN 但未确认的会话ID集合
    var pendingStreams:Set<UInt32> = []

    /// 已建立会话集合
    var establishedStreams:Set<UInt32> = []

    /// 0 号会话是否准备完成（控制通道是否可用）
    var session0Ready:Bool = false

    /// 等待 session0 建立后再打开的会话队列
    var waitingOpenStreams:[UInt32] = []

    /// HTTP KCPTUN 模式可直接跳过 session0 引导，使用 stream 即可直连
    private var useDirectStreamOpenMode: Bool {
        return proxy.kcptun && proxy.type == .HTTP
    }

    private var hasPendingFrame: Bool {
        return lastFrame != nil
    }

    /// 格式化数据为十六进制字符串，用于调试日志输出
    private func hexPreview(_ data: Data, limit: Int = 96) -> String {
        let prefix = data.prefix(limit)
        let body = prefix.map { String(format: "%02x", $0) }.joined(separator: " ")
        if data.count > limit {
            return "\(body) ..."
        }
        return body
    }

    /// 停止当前 KCP 隧道并释放资源
    func shutdown(){
        if let t = dispatchTimer {
            t.cancel()
        }
        self.destoryTun()
    }

    /// 是否走蜂窝网络（由 tun 实现判断）
    var useCell:Bool{
        get {
            if let t = tun {
              return t.useCell()
            }
            return false
        }
    }

    /// 初始化 KCP隧道并启动 receive 回调
    init(proxy:SFProxy,config:KcpConfig,queue:DispatchQueue) {
        self.proxy = proxy
        self.dispatchQueue = queue
        Xcon.log("KcpStocket init start proxy=\(proxy.proxyName) server=\(proxy.serverAddress):\(proxy.serverPort) kcptun=\(proxy.kcptun)", level: .Info)
     
        
        let type:SOCKS5HostType = proxy.serverAddress.validateIpAddr()
        if type != .DOMAIN {
            
            self.tun = KCP.init(config: config, ipaddr: proxy.serverAddress, port: (proxy.serverPort), queue: self.dispatchQueue)
        }else {
            let ips = query(proxy.serverAddress)
            //解析
            
            if !ips.isEmpty {
                if proxy.serverIP.isEmpty {
                    self.proxy.updateIPAddr(ip: ips.first!)
                   
                }
                self.tun = KCP.init(config: config, ipaddr: ips.first!, port:(proxy.serverPort), queue: self.dispatchQueue)
            }else {
                Xcon.log("dns resolv failure:\(proxy.serverAddress)", level: .Info)
                self.tun = KCP.init(config: config, ipaddr: proxy.serverAddress, port: (proxy.serverPort), queue: self.dispatchQueue)
            }
        }
        if !config.NoComp {
            snappy = SnappyHelper()
            Xcon.log("KcpStocket initialized with Snappy compression enabled", level: .Info)
        } else {
            Xcon.log("KcpStocket initialized without compression (NoComp=true)", level: .Info)
        }
        self.tun!.start({[unowned self] (tun) in
            self.ready = true
            self.session0Ready = false
            
            Xcon.log("tun connected", level: .Info)
            if !self.sendbuffer.isEmpty {
                let buffer = self.sendbuffer
                self.sendbuffer.removeAll(keepingCapacity: false)
                Xcon.log("kcptun startup flush buffered bytes=\(buffer.count)", level: .Info)
                tun.input(data: buffer)
            }
            if self.useDirectStreamOpenMode {
                self.session0Ready = true
                Xcon.log("direct stream open mode active, skip session 0 bootstrap", level: .Warning)
            } else {
                self.sendNop(sid: 0)
                self.session0Ready = true
                Xcon.log("session 0 ready after local control channel bootstrap", level: .Info)
            }
            self.drainWaitingStreams()
            self.sendNop(sid: 0)
            
        }, recv: { [unowned self] (tun, date) in
            Xcon.log("tun recv len=\(date.count)", level: .Info)
            self.didRecevied(date);
        }) {[unowned self]  (tun) in
            Xcon.log("Session Closed",level: .Info)
            self.ready = false
        }
        self.keepAlive(timeOut: Int(KcpStocket.SMuxTimeOut));
        
      
        
    }
    
  
   
    
    /// 处理 KCP 收到的数据包，并进行 SMux 帧解析、会话分发
    /// - 参数 data: 从 KCP 解包后的原始数据（可能已经过 Snappy 解压）
    func didRecevied(_ data: Data!) {
        let now = Date()
        self.lastActive = now
        self.lastRemoteActive = now
        Xcon.log("kcptun received raw bytes=\(data.count) snappy=\(snappy != nil)", level: .Info)
        Xcon.log("kcptun recv raw preview=\(hexPreview(data))", level: .Info)
       
        if let  s = snappy {
            if let newData = s.decompress(data) {
                Xcon.log("kcptun decompressed bytes=\(newData.count)", level: .Info)
                Xcon.log("kcptun decompressed preview=\(hexPreview(newData))", level: .Info)
                self.readBuffer.append(newData)
            } else {
                Xcon.log("kcptun decompression returned nil for bytes=\(data.count)", level: .Error)
            }
            
        }else {
            self.readBuffer.append(data)
        }
        
        
        
       // Xcon.log("mux recv data: \(data.count) \(data as NSData)",level: .Debug)
        let _ = streams.compactMap{ k,v in
            return k
        }
        //cpu high
        //SKit.log("\(ss.sorted()) all active stream", level: .Debug)
        while hasPendingFrame || self.readBuffer.count >= headerSize {
            let r = readFrame()
            if let f = r.frame {
                Xcon.log("kcptun frame recv sid=\(f.sid) cmd=\(f.cmd) hasData=\(f.data != nil) error=\(String(describing: r.error))", level: .Info)
                if let d = f.data {
                    Xcon.log("kcptun frame payload preview sid=\(f.sid) bytes=\(d.count) preview=\(hexPreview(d))", level: .Info)
                }
                if f.sid == 0 {
                    Xcon.log("main connection keep alive ok", level: .Debug)
                }else {
                    guard let stream = streams[f.sid] else {
                        processFrame(f: f,error: r.error)
                        Xcon.log("mux not found stream cleand\(f.sid)", level: .Error)
                        continue
                        
                    }
                    if let d = f.data {
                        markStreamEstablished(f.sid, reason: "first remote payload bytes=\(d.count)")
                        Xcon.log("kcptun deliver payload sid=\(f.sid) bytes=\(d.count)", level: .Info)
                         //Xcon.log("frame data:\(d as NSData)", level: .Debug)
                        if r.error == nil {
                            //full packet
                            
                            KcpTunConnector.shared.didReadData(d, withTag: 0, stream: stream)
                            
                            self.lastFrame = nil
                        }else {
                            //no full
                            if !d.isEmpty {
                                
                                KcpTunConnector.shared.didReadData(d, withTag: 0, stream: stream)
                            }
                            
                            
                            
                            self.lastFrame = f
                            //reset data
                            self.lastFrame?.data = nil
                        }
                        
                    }else {
                        if f.cmd == cmdFIN {
                            clearStreamState(f.sid, removeStream: true)
                            KcpTunConnector.shared.didDisconnect(stream, error: nil)
                        }else  {
                            markStreamEstablished(f.sid, reason: "remote control frame cmd=\(f.cmd)")
                            if r.1 == SmuxError.bodyNotFull {
                                Xcon.log("frame \(f.desc) packet not full",level: .Error)
                                
                                break
                            }
                        }
                        
                    }
                    
   
                }
                
            }else {
                if r.error == .VerError {
                    Xcon.log("invalid smux version, drop unread buffer", level: .Error)
                    self.readBuffer.removeAll(keepingCapacity: false)
                }
                break
            }
        }
        Xcon.log("Process KCP Frame Data Done", level: AxLoggerLevel.Info)
        
    }
    /// 处理未能找到对应流的控制帧或失败帧，发送 FIN 并清理状态
    func processFrame(f:Frame,error:SmuxError?) {
        
        if let _ = f.data {
            if error == nil {
                //full packet
                //stream.didReadData(d, withTag: 0, from: self)
                Xcon.log("\(f.sid) full drop", level: .Notify)
                self.lastFrame = nil
            }else {
                //no full
                //stream.didReadData(d, withTag: 0, from: self)
                
                Xcon.log("\(f.sid) not full \(f.left) ", level: .Notify)
                self.lastFrame = f
                //reset data
                self.lastFrame?.data = nil
            }
            
        }else {
            if f.left > 0  {
                Xcon.log("\(f.sid) not full \(f.cmd) frame left \(f.left)", level: .Notify)
            }
            
            
            
        }
        sendFin(f.sid)
        //关闭链接
        //Need ....
        Xcon.log("Close Session ID \(f.sid)", level: AxLoggerLevel.Info)
    }
    /// 从 readBuffer 解析一个完整 Frame
    /// - 返回: 可能的 Frame 以及对应的解析错误（若无足够数据会返回 .noHead 或 .bodyNotFull）
    func readFrame() -> (frame:Frame?,error:SmuxError?) {
        Xcon.log("readFrame \(Frame.testframe()) ",level: AxLoggerLevel.Trace)
        //Xcon.log("readbuffer \(readBuffer as NSData)", level: .Debug)
        if let _ = lastFrame {
            let l = lastFrame!.left
            var tocopy:Int = 0
            if l <= readBuffer.count {
                tocopy = l
            }else {
                tocopy = readBuffer.count
            }
            
            let newChunk = readBuffer.subdata(in: 0 ..< tocopy)
            if let existing = lastFrame!.data, !existing.isEmpty {
                var merged = existing
                merged.append(newChunk)
                lastFrame!.data = merged
            } else {
                lastFrame!.data = newChunk
            }
            readBuffer.replaceSubrange(0 ..< tocopy, with: Data())
            //self.leastFrame!.left -= tocopy
            lastFrame!.left -= tocopy
            if lastFrame!.left == 0 {
                Xcon.log("kcptun assembled pending frame sid=\(lastFrame!.sid) bytes=\(lastFrame!.data?.count ?? 0)", level: .Info)
                return (lastFrame,nil)
            }else {
                Xcon.log("kcptun pending frame sid=\(lastFrame!.sid) waitingLeft=\(lastFrame!.left) currentBytes=\(lastFrame!.data?.count ?? 0)", level: .Info)
                return (lastFrame,SmuxError.bodyNotFull)
            }
            
        }
        guard  readBuffer.count >= headerSize else {
            return (nil , SmuxError.noHead)
        }
        let h = readBuffer.subdata(in: 0 ..< headerSize) as rawHeader
        Xcon.log("kcptun header raw=\(hexPreview(h)) desc=\(h.desc())", level: .Info)
        
        if h.Version() != kcp.version {
            return (nil , SmuxError.VerError)
        }
        Xcon.log("readFrame \(h.Version()) \(h.length) ",level: AxLoggerLevel.Trace)
        var frame:Frame = Frame.init(h.cmd(), sid: h.StreamID())
        let length = h.Length()
        if length > 0 {
            if readBuffer.count >= headerSize + length {
                frame.data = readBuffer.subdata(in: headerSize ..< headerSize + length)
                
                //readBuffer.resetBytes(in: 0 ..< headerSize + length)
                readBuffer.replaceSubrange(0 ..< headerSize + length, with: Data())
                return (frame,nil)
            }else {
                //等待
                let left = headerSize + length - readBuffer.count
                Xcon.log("Session :\(frame.sid) left:\(left)", level: .Debug)
                frame.data = readBuffer.subdata(in: headerSize ..< readBuffer.count)
                Xcon.log("kcptun partial frame sid=\(frame.sid) have=\(frame.data?.count ?? 0) left=\(left)", level: .Info)
                readBuffer.replaceSubrange(0  ..< readBuffer.count, with: Data())
                frame.left = left
                return (frame, SmuxError.bodyNotFull)
            }
        }else {
            readBuffer.replaceSubrange(0 ..< headerSize,with:Data())
            return (frame, nil)
        }
        
    }
    
}

extension KcpStocket{
    //tun delegate
    /// 获取底层 KCP 本地地址（NWHostEndpoint），用于外部查询
    func localAddress() ->NWHostEndpoint? {
        if let tun = tun {
            
            //BSD Socket
            //return NWHostEndpoint.init(hostname: tun.localAddress() , port: "\(tun.localPort())")
            
        }
        return nil
    }
    /// 获取当前远端地址（仅打印用）
    func remoteAddress() ->String {
        if let _ = tun {
            return proxy.serverAddress
        }
        return "remote"
    }
   
    /// 销毁 KCP 会话，并重置内部状态（网络变更时调用）
    func destoryTun() {
        if let tun = tun {
            tun.shutdownUDPSession()
            self.tun = nil
            ready = false
            session0Ready = false
            lastFrame = nil
            readBuffer.removeAll(keepingCapacity: false)
            sendbuffer.removeAll(keepingCapacity: false)
            pendingStreams.removeAll(keepingCapacity: false)
            establishedStreams.removeAll(keepingCapacity: false)
            streams.removeAll(keepingCapacity: false)
            waitingOpenStreams.removeAll(keepingCapacity: false)
        }
    }
    /// 向指定会话发送 FIN 控制帧，通知对端关闭连接
    func sendFin(_ sessionID:UInt32){
        clearStreamState(sessionID, removeStream: true)
        let frame = Frame(cmdFIN,sid:sessionID)
        let data = frame.frameData()
        writeData(data, withTag: 0)
    }

    /// 发送数据到 KCP 隧道，必要时缓存（KCP 未 ready 前）
    public  func writeData(_ data: Data, withTag: Int) {

        // api
        self.lastActive = Date()
        Xcon.log("KCP write bytes=\(data.count) payload=\(data as NSData)",level: .Info)
        let outData = snappy != nil ? snappy!.compress(data) : data
        Xcon.log("KCP encode bytes raw=\(data.count) out=\(outData.count) snappy=\(snappy != nil)", level: .Info)
        if let tun = tun ,ready == true{
            tun.input(data: outData)
            Xcon.log("kcptun input accepted bytes=\(outData.count) buffered=\(sendbuffer.count)", level: .Info)

            if !sendbuffer.isEmpty {
                let buffer = sendbuffer
                tun.input(data: buffer)
                //可能浪费内存
                Xcon.log("kcptun flushed buffered bytes=\(buffer.count)", level: .Info)
                sendbuffer.removeAll(keepingCapacity: false)
            }

        }else {
            sendbuffer.append(outData)
            Xcon.log("kcptun not ready, buffered bytes now=\(sendbuffer.count)", level: .Warning)
        }
    }
    /// 设置心跳定时器，在超时后触发断开、或发送控制 NOP
    func keepAlive(timeOut:Int)  {
        //  q = DispatchQueue(label:"com.yarshure.keepalive")
        let timer = DispatchSource.makeTimerSource(flags: DispatchSource.TimerFlags.init(rawValue: 0), queue:dispatchQueue )
        dispatchQueue.async{
            let interval: Double = Double(timeOut)
            
            let delay = DispatchTime.now() + interval
            
            //timer.schedule(deadline: delay, repeating: interval, leeway: .nanoseconds(0))
            timer.schedule(deadline: delay, repeating: interval, leeway: .nanoseconds(0))
            timer.setEventHandler {[unowned self] in
                
                let idleSinceRemote = Date().timeIntervalSince(self.lastRemoteActive)
                if idleSinceRemote > KcpStocket.SMuxTimeOut{
                    Xcon.log("kcptun timeout no remote activity for \(String(format: "%.2f", idleSinceRemote))s", level: .Warning)
                    self.shutdown()
                }else if !self.useDirectStreamOpenMode {
                    self.sendNop(sid: 0)
                }
                //self.call(self.dispatch_timer)
            }
            timer.setCancelHandler {
                print("dispatch_timer cancel")
            }
            timer.resume()
            
        }
        self.dispatchTimer = timer
    }
    /// 发送 NOP 控制帧，用于保持连接活跃
    func sendNop(sid:UInt32){
        Xcon.log("send Nop \(sid)", level: .Info)
        let frame = Frame(cmdNOP,sid:sid)
        let data = frame.frameData()
        self.writeData(data, withTag: 0)
    }
    //tcp send read data need update?
    public func readDataWithTag( _ tag:Int){
        if let _ = tun {
            //tun.upDate()
        }
    }
    /// 打开一个新流：发送 SYN 控制帧并设为 pending
    private func openStreamWhenReady(_ sid:UInt32, session:Xcon) {
        Xcon.log("send SYN \(sid)", level: .Info)
        pendingStreams.insert(sid)
        establishedStreams.remove(sid)
        let frame = Frame(cmdSYN,sid:UInt32(sid))
        let fdata = frame.frameData()
        writeData(fdata, withTag: 0)
        Xcon.log("stream \(sid) opened locally, awaiting first remote frame", level: .Info)
        KcpTunConnector.shared.didConnect(session)
    }
    /// 当 session0 就绪时，依次处理等待的流并发送 SYN
    private func drainWaitingStreams() {
        guard session0Ready else { return }
        while !waitingOpenStreams.isEmpty {
            let sid = waitingOpenStreams.removeFirst()
            guard let stream = streams[sid] else { continue }
            if useDirectStreamOpenMode {
                Xcon.log("direct stream open, opening deferred stream \(sid)", level: .Info)
            } else {
                Xcon.log("session 0 ready, opening deferred stream \(sid)", level: .Info)
            }
            openStreamWhenReady(sid, session: stream)
        }
    }
    /// 新 TCP 流请求进入，与 KCP 流绑定，必要时延迟启动
    func incomingStream(_ sid:UInt32,session:Xcon) {
        guard let _ = tun else { return}
        self.streams[sid] = session
        if session0Ready {
            openStreamWhenReady(sid, session: session)
        } else {
            if !waitingOpenStreams.contains(sid) {
                waitingOpenStreams.append(sid)
            }
            if useDirectStreamOpenMode {
                Xcon.log("defer stream \(sid) until KCP connected", level: .Info)
            } else {
                Xcon.log("defer stream \(sid) until session 0 ready", level: .Info)
            }
        }
      
//        dispatchQueue.asyncAfter(deadline: .now() + .milliseconds(100)) {
//            //.didConnect(self)
//            //Xcon.log("defer stream noti  \(sid) until session 0 ready", level: .Info)
//        }
    }
   
}

private extension KcpStocket {
    /// 标记流已建立状态（SYN 已确认/收到了首包）
    func markStreamEstablished(_ sid: UInt32, reason: String) {
        guard pendingStreams.contains(sid) && !establishedStreams.contains(sid) else { return }
        establishedStreams.insert(sid)
        pendingStreams.remove(sid)
        Xcon.log("stream \(sid) established by \(reason)", level: .Info)
    }

    /// 清理指定流的状态集合，并可选择移除 `streams` 映射
    func clearStreamState(_ sid: UInt32, removeStream: Bool) {
        pendingStreams.remove(sid)
        establishedStreams.remove(sid)
        waitingOpenStreams.removeAll { $0 == sid }
        if removeStream {
            streams.removeValue(forKey: sid)
        }
    }
}
