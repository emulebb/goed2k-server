package ed2ksrv

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/monkeyWie/goed2k/protocol"
	serverproto "github.com/monkeyWie/goed2k/protocol/server"
)

// ED2K UDP search and source-lookup opcodes (eMule/aMule names). All are framed
// after the 0xE3 (ed2kUDPHeader) protocol byte.
const (
	udpOpGlobSearchReq3   byte = 0x90 // search, leading uint32 tag count then tree
	udpOpGlobSearchReq2   byte = 0x92 // search, tree at offset 0
	udpOpGlobGetSources2  byte = 0x94 // sources, records of hash(16)+size(4[/8])
	udpOpGlobSearchReq    byte = 0x98 // search, tree at offset 0 (older clients)
	udpOpGlobSearchRes    byte = 0x99 // search result entry
	udpOpGlobGetSources   byte = 0x9a // sources, records of hash(16)
	udpOpGlobFoundSources byte = 0x9b // sources result
	udpOpServerDescReq    byte = 0xa2 // OP_SERVER_DESC_REQ
	udpOpServerDescRes    byte = 0xa3 // OP_SERVER_DESC_RES: u16 nameLen+name + u16 descLen+desc
	udpOpGlobCallbackReq  byte = 0x9c // OP_GLOBCALLBACKREQUEST: ip(4)+port(2)+targetLowID(4)
	udpOpServerListReq    byte = 0xa0 // OP_SERVER_LIST_REQ (server-to-server)
	udpOpServerListRes    byte = 0xa1 // OP_SERVER_LIST_RES: count(1) + N×(IP(4)+port(2))
	udpOpServerListReq2   byte = 0xa4 // OP_SERVER_LIST_REQ variant (ServerGiveUDPList)
)

// udpCallbackRequest is the decoded body of an OP_GLOBCALLBACKREQUEST: a UDP peer
// (requesterIP:requesterPort) asks the server to tell a connected LowID client
// (targetID) to call it back.
type udpCallbackRequest struct {
	requesterIP   int32
	requesterPort uint16
	targetID      int32
}

// parseUDPCallback decodes an OP_GLOBCALLBACKREQUEST body (the bytes after the
// 0xE3/opcode pair). Returns false if too short.
func parseUDPCallback(body []byte) (udpCallbackRequest, bool) {
	if len(body) < 10 {
		return udpCallbackRequest{}, false
	}
	return udpCallbackRequest{
		requesterIP:   int32(binary.LittleEndian.Uint32(body[0:4])),
		requesterPort: binary.LittleEndian.Uint16(body[4:6]),
		targetID:      int32(binary.LittleEndian.Uint32(body[6:10])),
	}, true
}

// handleUDPCallback relays a UDP callback request to the target LowID client.
// The requester IP in the packet must match the datagram source (anti-spoofing).
func (s *Server) handleUDPCallback(addr *net.UDPAddr, body []byte) bool {
	cb, ok := parseUDPCallback(body)
	if !ok {
		return false
	}
	v4 := addr.IP.To4()
	if v4 == nil || int32(binary.LittleEndian.Uint32(v4)) != cb.requesterIP {
		return false // spoofed or non-IPv4 source
	}
	if s.callbackLimiter != nil && !s.callbackLimiter.allow(addr.IP.String()) {
		s.bumpCounter(func(stats *serverCounters) { stats.CallbackRateLimited++ })
		return true
	}
	target := s.findClient(cb.targetID)
	if target == nil {
		return true // unknown LowID; nothing to relay (UDP gets no error reply)
	}
	origin := protocol.NewEndpoint(cb.requesterIP, int(cb.requesterPort))
	_ = target.send("server.CallbackRequestIncoming", &serverproto.CallbackRequestIncoming{Point: origin})
	s.bumpCounter(func(stats *serverCounters) { stats.CallbackRequests++ })
	return true
}

// udpSearchJob is queued from the UDP read loop and executed by a worker so an
// expensive catalog scan never blocks datagram reception.
type udpSearchJob struct {
	addr     *net.UDPAddr
	query    SearchQuery
	packMany bool // client can take many results per datagram (REQ2/REQ3)
}

// startUDPWorkersLocked starts the search worker pool. Caller holds s.mu and has
// already set s.udpConn. Safe to call once per UDP listener lifetime.
func (s *Server) startUDPWorkersLocked() {
	if s.udpSearchQueue != nil {
		return
	}
	s.udpLimiter = newUDPLimiter(s.cfg.UDP.PerIPPacketsPerSecond)
	s.udpSearchQueue = make(chan udpSearchJob, s.cfg.UDP.SearchQueueSize)
	for i := 0; i < s.cfg.UDP.SearchWorkers; i++ {
		go s.udpSearchWorker()
	}
}

func (s *Server) udpSearchWorker() {
	for {
		select {
		case <-s.closed:
			return
		case job, ok := <-s.udpSearchQueue:
			if !ok {
				return
			}
			s.runUDPSearch(job)
		}
	}
}

// handleUDPSearchRequest parses a search datagram body and enqueues it. body is
// the bytes after the 0xE3/opcode pair. Returns false if the request was
// malformed (caller counts it).
func (s *Server) handleUDPSearchRequest(addr *net.UDPAddr, opcode byte, body []byte) bool {
	if !s.cfg.UDP.SearchEnabled {
		return true
	}
	tree := body
	packMany := opcode != udpOpGlobSearchReq
	if opcode == udpOpGlobSearchReq3 {
		// REQ3 prefixes a uint32 tag count followed by that many ED2K tags; the
		// search tree begins after them.
		if len(body) < 4 {
			return false
		}
		count := binary.LittleEndian.Uint32(body[:4])
		reader := bytes.NewReader(body[4:])
		for i := uint32(0); i < count; i++ {
			if err := skipED2KTag(reader); err != nil {
				return false
			}
		}
		offset := len(body) - reader.Len()
		tree = body[offset:]
	}
	query, err := ParseSearchRequestLimited(tree, s.cfg.UDP.MaxASTDepth)
	if err != nil {
		return false
	}
	job := udpSearchJob{addr: addr, query: query, packMany: packMany}
	select {
	case s.udpSearchQueue <- job:
		s.bumpCounter(func(stats *serverCounters) { stats.UDPSearchRequests++ })
	default:
		// Queue full: drop rather than block the read loop.
		s.bumpCounter(func(stats *serverCounters) { stats.UDPDropped++ })
	}
	return true
}

func (s *Server) runUDPSearch(job udpSearchJob) {
	results := s.searchAll(job.query)
	limit := s.cfg.UDP.MaxResults
	if !job.packMany && limit > 8 {
		// Older REQ clients expect a far smaller result set per Lugdunum policy.
		limit = limit / 8
	}
	if limit < 1 {
		limit = 1
	}
	if len(results) > limit {
		results = results[:limit]
	}

	writer := newUDPDatagramWriter(s, job.addr, udpOpGlobSearchRes)
	for i := range results {
		block := &bytes.Buffer{}
		block.WriteByte(ed2kUDPHeader)
		block.WriteByte(udpOpGlobSearchRes)
		if err := results[i].Put(block); err != nil {
			continue
		}
		writer.add(block.Bytes())
	}
	writer.flush()
	s.bumpCounter(func(stats *serverCounters) {
		stats.SearchResultEntries += int64(len(results))
	})
}

// handleUDPGetSources parses a source-lookup datagram and replies. body is the
// bytes after the 0xE3/opcode pair. withSize selects the OP_GLOBGETSOURCES2
// layout (hash + size). Returns false if malformed.
func (s *Server) handleUDPGetSources(addr *net.UDPAddr, body []byte, withSize bool) bool {
	if !s.cfg.UDP.SourcesEnabled {
		return true
	}
	reader := bytes.NewReader(body)
	writer := newUDPDatagramWriter(s, addr, udpOpGlobFoundSources)
	requested := 0
	for reader.Len() >= 16 {
		hash, err := protocol.ReadHash(reader)
		if err != nil {
			return false
		}
		if withSize {
			// 4-byte size; if zero, an 8-byte size follows (large-file form).
			if reader.Len() < 4 {
				return false
			}
			var size32 uint32
			if err := binary.Read(reader, binary.LittleEndian, &size32); err != nil {
				return false
			}
			if size32 == 0 {
				if reader.Len() < 8 {
					return false
				}
				var size64 uint64
				if err := binary.Read(reader, binary.LittleEndian, &size64); err != nil {
					return false
				}
			}
		}
		requested++
		sources := orderAndCapSources(s.sourcesAll(hash, false), s.cfg.MaxSourcesPerReply)
		if len(sources) == 0 {
			continue
		}
		endpoints := make([]protocol.Endpoint, 0, len(sources))
		for _, src := range sources {
			endpoints = append(endpoints, protocol.NewEndpoint(src.ClientID, src.Port))
		}
		block := &bytes.Buffer{}
		block.WriteByte(ed2kUDPHeader)
		block.WriteByte(udpOpGlobFoundSources)
		found := serverproto.FoundFileSources{Hash: hash, Sources: endpoints}
		if err := found.Put(block); err != nil {
			continue
		}
		writer.add(block.Bytes())
	}
	writer.flush()
	if requested == 0 {
		return false
	}
	s.bumpCounter(func(stats *serverCounters) { stats.UDPSourceRequests++ })
	return true
}

// udpDatagramWriter accumulates back-to-back ED2K mini-packets into datagrams,
// flushing before exceeding the configured max payload. A single mini-packet is
// never split across datagrams (it is sent oversized if it alone exceeds max).
type udpDatagramWriter struct {
	s    *Server
	addr *net.UDPAddr
	op   byte
	max  int
	buf  []byte
}

func newUDPDatagramWriter(s *Server, addr *net.UDPAddr, op byte) *udpDatagramWriter {
	max := s.cfg.UDP.MaxPayloadBytes
	if max <= 0 {
		max = 1300
	}
	return &udpDatagramWriter{s: s, addr: addr, op: op, max: max}
}

func (w *udpDatagramWriter) add(block []byte) {
	if len(w.buf) > 0 && len(w.buf)+len(block) > w.max {
		w.flush()
	}
	w.buf = append(w.buf, block...)
}

func (w *udpDatagramWriter) flush() {
	if len(w.buf) == 0 {
		return
	}
	w.s.writeUDP(w.addr, w.op, w.buf)
	w.buf = w.buf[:0]
}

// writeUDP sends a prepared datagram and traces it. datagram already includes
// the leading 0xE3/opcode bytes of its first (and possibly only) mini-packet.
func (s *Server) writeUDP(addr *net.UDPAddr, op byte, datagram []byte) {
	s.mu.RLock()
	pc := s.udpConn
	s.mu.RUnlock()
	if pc == nil {
		return
	}
	if _, err := pc.WriteToUDP(datagram, addr); err != nil {
		s.logger.Debug("udp write", "err", err)
		return
	}
	s.bumpCounter(func(stats *serverCounters) {
		stats.OutboundPackets++
		stats.OutboundBytes += int64(len(datagram))
	})
	body := datagram
	if len(body) >= 2 {
		body = body[2:]
	}
	s.tracer.record(traceOut, "udp", addr.String(), ed2kUDPHeader, op, len(datagram), body)
}

// skipED2KTag advances reader past one ED2K tag (eMule encoding) without
// retaining its value, reusing the shared tag decoder so the REQ3 option block
// is parsed identically to the rest of the protocol code.
func skipED2KTag(reader *bytes.Reader) error {
	var tag protocol.SimpleTag
	return tag.Get(reader)
}
