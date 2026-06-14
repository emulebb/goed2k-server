package ed2ksrv

import (
	"encoding/binary"
	"net"
	"time"
)

// eD2k 客户端向服务器 UDP 端口发送统计请求（通常为 TCP 端口 + 4）。
// aMule ServerUDPSocket.cpp OP_GLOBSERVSTATRES：challenge、用户数、文件数、maxusers、softfiles、hardfiles。
const (
	ed2kUDPHeader       byte = 0xe3
	opGlobServStatReq   byte = 0x96
	opGlobServStatRes   byte = 0x97
	globServStatResSize      = 24 // challenge + 6×uint32
)

func (s *Server) maybeStartServerUDP() {
	if !s.cfg.ServerUDP {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpConn != nil || s.listener == nil {
		return
	}
	tcpAddr, ok := s.listener.Addr().(*net.TCPAddr)
	if !ok {
		return
	}
	off := s.cfg.UDPPortOffset
	if off <= 0 {
		off = 4
	}
	port := tcpAddr.Port + off
	if port <= 0 || port > 65535 {
		s.logger.Warn("server UDP: invalid derived port", "tcp_port", tcpAddr.Port, "offset", off)
		return
	}
	udpAddr := &net.UDPAddr{IP: tcpAddr.IP, Port: port}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.logger.Warn("server UDP listener failed (soft/hard file limits stay unknown to clients)", "err", err, "addr", udpAddr.String())
		return
	}
	s.udpConn = pc
	s.startUDPWorkersLocked()
	s.logger.Info("eD2k server UDP listening", "addr", pc.LocalAddr().String())
	go s.serveUDP()
	if s.peers.len() > 0 {
		go s.pingPeers()
	}
}

// pingPeers periodically sends OP_GLOBSERVSTATREQ to each configured peer server
// to track liveness (active server-to-server peering). Runs only when peers are
// configured; stops when the server closes.
func (s *Server) pingPeers() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	s.sendPeerPings()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			s.sendPeerPings()
		}
	}
}

// buildUDPServerListReply encodes an OP_SERVER_LIST_RES: count + the IPv4 peers
// we know (count(1) + N×(IP(4)+port LE u16)).
func (s *Server) buildUDPServerListReply() []byte {
	entries := make([]byte, 0)
	count := 0
	for _, a := range s.peers.addrs() {
		v4 := a.IP.To4()
		if v4 == nil {
			continue
		}
		entries = append(entries, v4[0], v4[1], v4[2], v4[3], byte(a.Port), byte(a.Port>>8))
		count++
	}
	out := []byte{ed2kUDPHeader, udpOpServerListRes, byte(count)}
	return append(out, entries...)
}

func (s *Server) sendPeerPings() {
	req := make([]byte, 6)
	req[0] = ed2kUDPHeader
	req[1] = opGlobServStatReq
	binary.LittleEndian.PutUint32(req[2:6], uint32(time.Now().UnixNano()))
	for _, addr := range s.peers.addrs() {
		s.writeUDP(addr, opGlobServStatReq, req)
	}
}

func (s *Server) serveUDP() {
	s.mu.RLock()
	pc := s.udpConn
	s.mu.RUnlock()
	if pc == nil {
		return
	}
	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return
		}
		if n < 2 {
			continue
		}
		if buf[0] != ed2kUDPHeader {
			continue
		}
		// Copy the datagram out of the shared receive buffer before it is reused
		// (search jobs are processed asynchronously by worker goroutines).
		packet := make([]byte, n)
		copy(packet, buf[:n])
		s.dispatchUDP(addr, packet)
	}
}

// dispatchUDP routes one validated ED2K UDP datagram. packet[0] is the 0xE3
// protocol byte and packet[1] is the opcode; body is packet[2:].
func (s *Server) dispatchUDP(addr *net.UDPAddr, packet []byte) {
	opcode := packet[1]
	body := packet[2:]
	s.tracer.record(traceIn, "udp", addr.String(), packet[0], opcode, len(packet), body)
	s.bumpCounter(func(stats *serverCounters) {
		stats.InboundPackets++
		stats.InboundBytes += int64(len(packet))
	})

	if !s.udpLimiter.allow(addr.IP.String()) {
		s.bumpCounter(func(stats *serverCounters) { stats.UDPRateLimited++ })
		return
	}

	ok := true
	switch opcode {
	case opGlobServStatReq:
		if len(body) < 4 {
			ok = false
			break
		}
		challenge := binary.LittleEndian.Uint32(body[:4])
		s.writeUDP(addr, opGlobServStatRes, s.buildGlobServStatRes(challenge))
	case udpOpGlobSearchReq, udpOpGlobSearchReq2, udpOpGlobSearchReq3:
		ok = s.handleUDPSearchRequest(addr, opcode, body)
	case udpOpGlobGetSources:
		ok = s.handleUDPGetSources(addr, body, false)
	case udpOpGlobGetSources2:
		ok = s.handleUDPGetSources(addr, body, true)
	case udpOpServerDescReq:
		s.writeUDP(addr, udpOpServerDescRes, s.buildServerDescRes())
	case udpOpGlobCallbackReq:
		ok = s.handleUDPCallback(addr, body)
	case opGlobServStatRes:
		// A peer server answered our liveness ping.
		if s.peers.markSeen(addr) {
			s.bumpCounter(func(stats *serverCounters) { stats.PeerStatusReplies++ })
		}
	case udpOpServerListReq, udpOpServerListReq2:
		// A peer requests our server list; answer with the peers we know.
		s.writeUDP(addr, udpOpServerListRes, s.buildUDPServerListReply())
	case udpOpServerListRes:
		// Learn additional peers from a configured peer's server list (only from a
		// known peer source, to bound abuse).
		if s.peers.markSeen(addr) {
			learned := 0
			for _, p := range parseServerListBody(body) {
				if s.peers.add(p) {
					learned++
				}
			}
			if learned > 0 {
				s.bumpCounter(func(stats *serverCounters) { stats.PeersLearned += int64(learned) })
			}
		}
	default:
		// Unsupported opcode: count and ignore (no reply).
		s.bumpCounter(func(stats *serverCounters) { stats.UDPMalformed++ })
		return
	}
	if !ok {
		s.bumpCounter(func(stats *serverCounters) { stats.UDPMalformed++ })
	}
}

// buildServerDescRes encodes the legacy OP_SERVER_DESC_RES payload: the server
// name and description, each as a little-endian uint16 length followed by its
// bytes. Clients use this to display the server identity in their server list.
func (s *Server) buildServerDescRes() []byte {
	name := []byte(s.cfg.ServerName)
	desc := []byte(s.cfg.ServerDescription)
	out := make([]byte, 0, 2+2+len(name)+2+len(desc))
	out = append(out, ed2kUDPHeader, udpOpServerDescRes)
	out = append(out, byte(len(name)), byte(len(name)>>8))
	out = append(out, name...)
	out = append(out, byte(len(desc)), byte(len(desc)>>8))
	out = append(out, desc...)
	return out
}

func (s *Server) buildGlobServStatRes(challenge uint32) []byte {
	out := make([]byte, 2+globServStatResSize)
	out[0] = ed2kUDPHeader
	out[1] = opGlobServStatRes
	payload := out[2:]
	binary.LittleEndian.PutUint32(payload[0:4], challenge)
	binary.LittleEndian.PutUint32(payload[4:8], uint32(s.clientCount()))
	binary.LittleEndian.PutUint32(payload[8:12], uint32(s.currentFilesCount()))
	binary.LittleEndian.PutUint32(payload[12:16], s.cfg.MaxUsersAdvertised)
	binary.LittleEndian.PutUint32(payload[16:20], uint32(s.cfg.SoftFilesLimit))
	binary.LittleEndian.PutUint32(payload[20:24], uint32(s.cfg.HardFilesLimit))
	return out
}
