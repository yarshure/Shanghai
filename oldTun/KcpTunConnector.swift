//
//  KcpTunConnector.swift
//  Xcon
//
//  Created by yarshure on 2018/1/12.
//  Copyright © 2018年 yarshure. All rights reserved.

// provide KCP for other layer use
// iOS app can't fork process
// so use socket
//应该是shared
// 可以先不实行adapter，加密,用kun 加密
// 测试先是不加密，aes 加密， adapter 加密
// 重新链接 需要？

import NetworkExtension
import Foundation
import libkcp
import KCP
import AxLogger

/// KcpTunConnector 是一个在 KCP 隧道层上管理多路会话的连接器。
///
/// 主要职责：
/// - 管理每个会话 ID 对应的 Adapter
/// - 负责 KCP 数据帧的封包、拆包和发送
/// - 将上层 Xcon 连接与底层 KcpStocket 进行适配（forward/receive）
/// - 执行初次连接握手、断开与错误处理
class KcpTunConnector: ProxyConnector{
    static let shared:KcpTunConnector = {
        
        if let p = SFProxy.createProxyWithLine(line: "SS,0.0.0.0,6000,,", pname: "testdontuse"){
            return KcpTunConnector.init(p: p)
        }
        fatalError()
    }()
   
    // adapter 映射表：会话 ID -> Adapter 实例
    // 每个流对应一个 Adapter 用于协议转换、加密/解密、分包等逻辑
    var adapters:[UInt32:Adapter] = [:]

    // KCP 底层 socket 负责与远端 KCPTUN 服务器完成数据包收发
    var tunSocket:KcpStocket!

    // 最大单帧负载，超过该长度需要拆分
    let frameSize = 4096

    // 超时时间：在没有数据时可以认为会话结束或需要重试
    static let SMuxTimeOut = 13.0

    
    /// 新 TCP 流进入（上层 Xcon 建立一条新连接）
    /// - sid: 会话 ID
    /// - session: 上层 Xcon 连接实例
    /// - host/port: 目标地址，用于创建下层代理 Adapter
    func incomingStream(_ sid:UInt32,session:Xcon,host:String,port:UInt16) {
        
        guard let a = Adapter.createAdapter(self.proxy, host: host  , port: port) else  {
            fatalError()
        }
        adapters[sid] = a
        
    
        if tunSocket == nil {
            let config = createTunConfig(self.proxy)
            tunSocket = KcpStocket.init(proxy: self.proxy, config: config, queue: queue)
        }
        
        
        guard let socket = tunSocket else {return}
        
        socket.incomingStream(sid, session: session)
       
        
    }
    //开始发送
    //MARK: for socket use
    /// 上层 Xcon 连接断开时回调
    /// 清理对应 Adapter 并通知上层完成断开动作
    public func didDisconnect(_ stream:Xcon, error: Error?) {
        Xcon.log("\(stream.sessionID) socket disconnect,remove adapter", level: .Notify)
        adapters.removeValue(forKey: stream.sessionID)
        stream.didDisconnectWith(socket: self)
        
    }

    /// 上层 Xcon 连接已建立时回调（适配器可发送握手数据）
    public func didConnect(_ stream:Xcon) {
        
        guard let a = adapters[stream.sessionID] else {return}
        // adapter handshake data
        
        let result = a.send(Data())
        if !result.data.isEmpty {
            self.sendRawData(result.data, session: stream.sessionID)
            Xcon.log("send \(result.data)", level: .Trace)
        } else {
            Xcon.log("adapter \(type(of: a)) has no initial handshake bytes for session \(stream.sessionID)", level: .Info)
        }
        if let httpAdapter = a as? HTTPAdapter, httpAdapter.suppressUpstreamForwarding {
            Xcon.log("session \(stream.sessionID) running in HTTP proxy test mode, suppress upstream didConnect", level: .Info)
            return
        }
        if a.streaming || a.proxy.type == .SS || a.proxy.type == .SS3 {
            DispatchQueue.main.async {
                stream.didConnectWith(adapterSocket: self)
            }
        }else {
            Xcon.log("session \(stream.sessionID) \(stream.remoteAddress) \(stream.remotePort) don't known forward.. ", level: .Info)
        }

    }
    
    /// 从上层 Xcon 读取到数据后回调（已解密/协议转换后向上游发送）
    /// - data: 收到的原始数据（经过 KCP 解帧后的有效负载）
    func didReadData(_ data: Data,withTag:Int, stream: Xcon) {
        
        guard let a = adapters[stream.sessionID] else {return}
        Xcon.log("KcpTunConnector didReadData session=\(stream.sessionID) bytes=\(data.count) adapter=\(type(of: a)) streaming=\(a.streaming)", level: .Info)
        
        // 流模式直接交给 adapter 解析并透传
        if a.streaming || a.proxy.type == .SS || a.proxy.type == .SS3 {
            do {
                let result = try a.recv(data)
                if !result.value.isEmpty {
                    Xcon.log("KcpTunConnector forward upstream session=\(stream.sessionID) bytes=\(result.value.count)", level: .Info)
                    stream.didRead(data: result.value, from: self)
                } else {
                    Xcon.log("KcpTunConnector adapter returned empty bytes session=\(stream.sessionID)", level: .Info)
                }
            }catch let e {
                Xcon.log("\(e.localizedDescription)", level: .Error)
            }
            
        }else {
            //handshake
            
            do {
                let cnnctFlag = a.streaming
                
                let result = try a.recv(data)
                if result.result {
                    //http socks5
                    // socks 5 todo ,mutil time send shake and data
                    let newcflag = a.streaming
                    if cnnctFlag != newcflag {
                        Xcon.log(" shake hand finished \(stream) result.value \(result.value as NSData)", level: .Debug)
                        //变动第一次才发这个event
                        stream.didConnectWith(adapterSocket: self)
                        
                    }else {
                        Xcon.log(" shake hand finished \(stream) not finished , todo fixed", level: .Debug)
                        fatalError()
                    }
                }else {
                    Xcon.log("recv failure ", level: .Error)
                }
                
            }catch let e  {
                Xcon.log("recv error \(e.localizedDescription)", level: .Error)
            }
        }

        
    }
    
    //MARK: --------
    
    //MARK for Xcon use
    //需要协议转换和处理
    /// 向底层发送数据（上层数据经过 Adapter 加密/混包后写入 KCP）
    func writeData(_ data: Data, withTag: Int,session:UInt32) {
        Xcon.log("\(String(data:data, encoding:.utf8)) write \(session)", level: AxLoggerLevel.Info)
        guard let a = adapters[session] else {
            fatalError()
            return
            
        }
        // HTTP 代理测试模式直接丢弃上游写入数据，不继续透传
        if let httpAdapter = a as? HTTPAdapter, httpAdapter.suppressUpstreamForwarding {
            Xcon.log("drop upstream bytes in HTTP proxy test mode session=\(session) bytes=\(data.count)", level: .Info)
            return
        }
        // 未完成握手前不得直接写入
        if !a.streaming {
            fatalError()
        }
        // SS/SS3/HTTP 走 Adapter 封包
        if a.proxy.type == .SS || a.proxy.type == .SS3 || a is HTTPAdapter {
            let result = a.send(data)
            Xcon.log("KcpTunConnector adapter send session=\(session) inBytes=\(data.count) outBytes=\(result.data.count) adapter=\(type(of: a))", level: .Info)
            self.sendRawData(result.data, session: session)
        }else {
             self.sendRawData(data, session: session)
        }
    }

    /// 封装 KCP 帧并写入 tunSocket。
    /// 该方法依据帧大小拆分数据，调用 split 生成 Frame 列表
    func sendRawData(_ data:Data,session:UInt32){
        var databuffer:Data = Data()
        let frames = split(data, cmd: cmdPSH, sid: session)
        for f in frames {
            databuffer.append(f.frameData())
            
        }
        tunSocket.writeData(databuffer, withTag: 0)
    }
    public override func readDataWithTag(_ tag: Int) {
        guard let s = tunSocket else {
            return
        }
        s.readDataWithTag(tag)
    }
   
    public func didWriteData(_ data: Data?, withTag: Int, stream:Xcon) {
        
        stream.didWrite(data: data, by: self)
    }
    
    

    //Ctrol+C
    public override func forceDisconnect(_ sessionID: UInt32) {
        Xcon.log("send Fin Close \(sessionID)", level: .Notify)
        adapters.removeValue(forKey: sessionID)
        tunSocket.sendFin(sessionID)
    }
    public override var local:NWHostEndpoint?{
        get {
            return tunSocket.localAddress()
        }
    }
    public override var remote: NWHostEndpoint? {
        get {
            if !tunSocket.proxy.serverIP.isEmpty {
                 //return NWHostEndpoint.init(hostname:tunSocket.proxy.serverIP,port:tunSocket.proxy.serverPort)
                return nil
            }
            return NWHostEndpoint.init(hostname:tunSocket.proxy.serverAddress,port:tunSocket.proxy.serverPort)
            
        }
    }

}


extension KcpTunConnector{
    /// 根据 SFProxy 配置生成 KCP 连接参数
    /// - p: 代理配置对象
    /// - 返回: 生成的 KcpConfig，包含 nodelay、mtu、加密、FEC 等参数
    func createTunConfig(_ p:SFProxy) ->KcpConfig {
        var c = KcpConfig()
        let useHTTPProxyTestProfile = p.kcptun && p.type == .HTTP
        let requestedNoComp = p.config.noComp
        let effectiveNoComp = useHTTPProxyTestProfile ? true : requestedNoComp
        let requestedCrypt = p.config.crypt.lowercased()
//        let resolvedCrypt = KcpCryptoMethod.resolvedSwiftV1Method(from: requestedCrypt)
//        c.crypt = resolvedCrypt.method
        if c.crypt != .none {
            if  let d = p.pkbdf2Key() {
                c.key = d
            }
        }

        c.dataShards = p.config.datashard
        c.parityShards = p.config.parityshard
        c.NoComp = effectiveNoComp
        //c.nodelay = p.config.
        c.sndwnd = p.config.sndwnd
        c.rcvwnd = p.config.rcvwnd
        c.mtu = p.config.mtu
        c.iptos = p.config.dscp
        switch p.config.mode {
        case "normal":
            c.nodelay = 0
            c.interval = 40
            c.resend = 2
            c.nc = 1
        case "fast":
            c.nodelay = 0
            c.interval = 30
            c.resend = 2
            c.nc = 1
        case "fast2":
            c.nodelay = 1
            c.interval = 20
            c.resend = 2
            c.nc = 1
        case "fast3":
            c.nodelay = 1
            c.interval = 10
            c.resend = 2
            c.nc = 1
        default:
            c.nodelay = 0
            c.interval = 30
            c.resend = 2
            c.nc = 1
            break
        }
        
        Xcon.log("KCPTUN: #######################", level: .Info)
        if useHTTPProxyTestProfile {
            Xcon.log("KCPTUN: HTTP proxy test profile active -> keep default KCP params, force nocomp=true", level: .Warning)
        }
//        if resolvedCrypt.fallback {
//            Xcon.log("KCPTUN: unsupported crypt '\(p.config.crypt)' for Swift v1, fallback to \(c.crypt.displayName)", level: .Warning)
//        }
        Xcon.log("KCPTUN: Crypto requested = \(p.config.crypt)", level: .Info)
        Xcon.log("KCPTUN: Crypto effective = \(c.crypt.rawValue)", level: .Info)
        Xcon.log("KCPTUN: key = \(c.key as NSData?)", level: .Debug)

        Xcon.log("KCPTUN: noComp requested = \(requestedNoComp)", level: .Info)
        Xcon.log("KCPTUN: noComp effective = \(effectiveNoComp)", level: .Info)
        Xcon.log("KCPTUN: compress effective = \(!effectiveNoComp)", level: .Info)
        Xcon.log("KCPTUN: mode = \(p.config.mode)", level: .Info)
        Xcon.log("KCPTUN: datashard effective = \(c.dataShards)", level: .Info)
        Xcon.log("KCPTUN: parityshard effective = \(c.parityShards)", level: .Info)
        Xcon.log("KCPTUN: #######################", level: .Info)
        return c
    }
    /// 将待发送数据按照 frameSize 进行拆分，生成多个 KCP Frame
    /// - data: 原始待发数据
    /// - cmd: KCPTUN 命令类型（例如 cmdPSH）
    /// - sid: 会话 ID
    /// - 返回: 拆分后的 Frame 数组
    func split(_ data:Data, cmd:UInt8,sid:UInt32) ->[Frame]{
        //let fs = data.count/frameSize + 1
        var result:[Frame] = []
        var left:Int = data.count
        var index:Int = 0
        var chunkIndex = 0
        Xcon.log("KcpTunConnector.split start: session=\(sid) total=\(data.count) frameSize=\(frameSize)", level: .Info)
        while left > frameSize {
            if index >= data.count {
                break
            }
            let subData = data.subdata(in: index ..< index + frameSize)
            let f = Frame.init(cmd, sid: sid, data: subData)
            index += frameSize
            left -= frameSize
            result.append(f)
            chunkIndex += 1
            Xcon.log("KcpTunConnector.split chunk=\(chunkIndex) size=\(subData.count) left=\(left)", level: .Debug)
        }
        
        if left > 0 {
            let subData = data.subdata(in: index ..< data.count )
            let f = Frame.init(cmd, sid: sid, data: subData)
            result.append(f)
            chunkIndex += 1
            Xcon.log("KcpTunConnector.split final chunk=\(chunkIndex) size=\(subData.count)", level: .Debug)
        }
        
        Xcon.log("KcpTunConnector.split end: session=\(sid) chunks=\(chunkIndex)", level: .Info)
        return result
        
    }
    
}
