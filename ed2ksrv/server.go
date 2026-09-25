package ed2ksrv

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/monkeyWie/goed2k/protocol"
	serverproto "github.com/monkeyWie/goed2k/protocol/server"
)

// maxDecodedFrameBytes caps the inflated size of a single packed (zlib) ED2K
// frame, bounding memory and guarding against decompression bombs.
const maxDecodedFrameBytes = 1 << 20

// minPackBodyBytes is the smallest frame payload worth attempting to compress on
// the way out; small control packets are never packed.
const minPackBodyBytes = 256

// maybePackFrame re-encodes a plain ED2K frame as a packed (zlib) frame when the
// body is large enough that compression saves bytes, matching how eMule servers
// compress big replies such as search results and source lists. Returns raw
// unchanged when packing is not applicable or not beneficial. eMule/aMule clients
// transparently inflate OP_PACKEDPROT server packets.
func maybePackFrame(raw []byte) []byte {
	if len(raw) <= protocol.PacketHeaderSize || raw[0] != protocol.EdonkeyHeader {
		return raw
	}
	body := raw[protocol.PacketHeaderSize:]
	if len(body) < minPackBodyBytes {
		return raw
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		return raw
	}
	if err := zw.Close(); err != nil {
		return raw
	}
	compressed := buf.Bytes()
	if len(compressed) >= len(body) {
		return raw
	}
	out := make([]byte, protocol.PacketHeaderSize+len(compressed))
	out[0] = protocol.PackedProt
	binary.LittleEndian.PutUint32(out[1:5], uint32(len(compressed)+1))
	out[5] = raw[5] // opcode is preserved across packing
	copy(out[protocol.PacketHeaderSize:], compressed)
	return out
}

const (
	ctServerFlags                 byte   = 0x20
	srvCapSupportCrypt            uint32 = 0x0200
	srvCapRequestCrypt            uint32 = 0x0400
	srvCapRequireCrypt            uint32 = 0x0800
	sourceObfuscationUserHashFlag uint8  = 0x80
)

// ServerStats is the admin-facing runtime metrics snapshot.
type ServerStats struct {
	StartedAt           time.Time `json:"started_at"`
	CurrentClients      int       `json:"current_clients"`
	CurrentFiles        int       `json:"current_files"`
	TotalConnections    int64     `json:"total_connections"`
	TotalDisconnects    int64     `json:"total_disconnects"`
	InboundPackets      int64     `json:"inbound_packets"`
	OutboundPackets     int64     `json:"outbound_packets"`
	InboundBytes        int64     `json:"inbound_bytes"`
	OutboundBytes       int64     `json:"outbound_bytes"`
	SearchRequests      int64     `json:"search_requests"`
	SearchResultPackets int64     `json:"search_result_packets"`
	SearchResultEntries int64     `json:"search_result_entries"`
	SourceRequests      int64     `json:"source_requests"`
	CallbackRequests    int64     `json:"callback_requests"`
	FilesRegistered     int64     `json:"files_registered"`
	FilesRemoved        int64     `json:"files_removed"`
	PersistWrites       int64     `json:"persist_writes"`
	UDPSearchRequests   int64     `json:"udp_search_requests"`
	UDPSourceRequests   int64     `json:"udp_source_requests"`
	UDPDropped          int64     `json:"udp_dropped"`
	UDPMalformed        int64     `json:"udp_malformed"`
	UDPRateLimited      int64     `json:"udp_rate_limited"`
	ConnRateLimited     int64     `json:"conn_rate_limited"`
	OfferFilesDropped   int64     `json:"offer_files_dropped"`
	CallbackRateLimited int64     `json:"callback_rate_limited"`
	PeerStatusReplies   int64     `json:"peer_status_replies"`
	PeersLearned        int64     `json:"peers_learned"`
	HTTPProbes          int64     `json:"http_probes"`
	Peers               int       `json:"peers"`
}

// ClientSnapshot is the admin-facing view of a connected client.
type ClientSnapshot struct {
	ClientID         int32         `json:"client_id"`
	ClientName       string        `json:"client_name"`
	ClientHash       protocol.Hash `json:"client_hash"`
	RemoteAddress    string        `json:"remote_address"`
	ListenEndpoint   string        `json:"listen_endpoint"`
	ConnectedAt      time.Time     `json:"connected_at"`
	LastSeenAt       time.Time     `json:"last_seen_at"`
	SearchRequests   int64         `json:"search_requests"`
	SourceRequests   int64         `json:"source_requests"`
	CallbackRequests int64         `json:"callback_requests"`
	InboundPackets   int64         `json:"inbound_packets"`
	OutboundPackets  int64         `json:"outbound_packets"`
	InboundBytes     int64         `json:"inbound_bytes"`
	OutboundBytes    int64         `json:"outbound_bytes"`
}

// Server exposes the subset of the ED2K/eMule server protocol used by goed2k.
type Server struct {
	cfg      Config
	catalog  *Catalog
	logger   *slog.Logger
	combiner protocol.PacketCombiner

	tracer          *packetTracer
	connLimiter     *udpLimiter // per-IP new-TCP-connection rate limiter; nil when disabled
	callbackLimiter *udpLimiter // per-IP callback rate limiter (TCP+UDP); nil when disabled
	peers           *peerRegistry

	mu             sync.RWMutex
	listener       net.Listener
	udpConn        *net.UDPConn
	udpSearchQueue chan udpSearchJob
	udpLimiter     *udpLimiter
	adminListener  net.Listener
	clients        map[int32]*clientSession
	dynamicFiles   map[string]*dynamicSharedFile
	auditLog       []AuditEntry
	closed         chan struct{}
	nextID         int32
	startedAt      time.Time
	stats          serverCounters
}

type dynamicSharedFile struct {
	record    FileRecord
	byClient  map[int32]SourceEntry
	completes map[int32]bool
}

type serverCounters struct {
	TotalConnections    int64
	TotalDisconnects    int64
	InboundPackets      int64
	OutboundPackets     int64
	InboundBytes        int64
	OutboundBytes       int64
	SearchRequests      int64
	SearchResultPackets int64
	SearchResultEntries int64
	SourceRequests      int64
	CallbackRequests    int64
	FilesRegistered     int64
	FilesRemoved        int64
	PersistWrites       int64
	UDPSearchRequests   int64
	UDPSourceRequests   int64
	UDPDropped          int64
	UDPMalformed        int64
	UDPRateLimited      int64
	ConnRateLimited     int64
	OfferFilesDropped   int64
	CallbackRateLimited int64
	PeerStatusReplies   int64
	PeersLearned        int64
	HTTPProbes          int64
}

type clientSession struct {
	server *Server
	conn   net.Conn
	remote *net.TCPAddr

	writeMu sync.Mutex
	mu      sync.Mutex

	clientHash       protocol.Hash
	connectOptions   byte
	loginPoint       protocol.Endpoint
	assignedID       int32
	clientName       string
	offeredFiles     map[string]FileRecord
	searchResult     []serverproto.SharedFileEntry
	searchOffset     int
	connectedAt      time.Time
	lastSeenAt       time.Time
	searchRequests   int64
	sourceRequests   int64
	callbackRequests int64
	inboundPackets   int64
	outboundPackets  int64
	inboundBytes     int64
	outboundBytes    int64
}

// NewServer constructs a ready-to-run server instance.
func NewServer(cfg Config, catalog *Catalog, logger *slog.Logger) (*Server, error) {
	normalized, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	if catalog == nil {
		catalog, err = LoadCatalogFromConfig(normalized)
		if err != nil {
			return nil, err
		}
	}
	if logger == nil {
		logger = slog.Default()
	}
	tracer, err := newPacketTracer(normalized, logger)
	if err != nil {
		return nil, err
	}
	var connLimiter *udpLimiter
	if normalized.MaxConnsPerIPPerSecond > 0 {
		connLimiter = newUDPLimiter(normalized.MaxConnsPerIPPerSecond)
	}
	var callbackLimiter *udpLimiter
	if normalized.MaxCallbacksPerIPPerSecond > 0 {
		callbackLimiter = newUDPLimiter(normalized.MaxCallbacksPerIPPerSecond)
	}
	return &Server{
		cfg:             normalized,
		catalog:         catalog,
		logger:          logger,
		tracer:          tracer,
		connLimiter:     connLimiter,
		callbackLimiter: callbackLimiter,
		peers:           newPeerRegistry(normalized.PeerServers),
		combiner:        serverproto.NewPacketCombiner(),
		clients:         make(map[int32]*clientSession),
		dynamicFiles:    make(map[string]*dynamicSharedFile),
		closed:          make(chan struct{}),
		nextID:          16777217,
		startedAt:       time.Now(),
	}, nil
}

// Config returns the normalized runtime configuration.
func (s *Server) Config() Config {
	return s.cfg
}

// ListenAndServe opens the configured TCP and HTTP admin listeners.
func (s *Server) ListenAndServe() error {
	if s.cfg.AdminListenAddress != "" {
		adminListener, err := net.Listen("tcp", s.cfg.AdminListenAddress)
		if err != nil {
			return err
		}
		go func() {
			if err := s.ServeAdmin(adminListener); err != nil && !errors.Is(err, net.ErrClosed) {
				s.logger.Error("admin server stopped", "err", err)
			}
		}()
	}
	listener, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return err
	}
	return s.Serve(listener)
}

// Serve accepts ED2K connections on an existing listener.
func (s *Server) Serve(listener net.Listener) error {
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	s.maybeStartServerUDP()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		go s.handleConn(conn)
	}
}

// Shutdown stops the listeners and closes all active client connections.
func (s *Server) Shutdown(ctx context.Context) error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}

	s.mu.Lock()
	listener := s.listener
	udpConn := s.udpConn
	s.udpConn = nil
	adminListener := s.adminListener
	clients := make([]*clientSession, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.mu.Unlock()

	if udpConn != nil {
		_ = udpConn.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	if adminListener != nil {
		_ = adminListener.Close()
	}
	if s.catalog != nil {
		_ = s.catalog.Close()
	}
	s.tracer.close()
	for _, client := range clients {
		_ = client.conn.Close()
	}
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// StatsSnapshot returns a point-in-time runtime metrics view.
func (s *Server) StatsSnapshot() ServerStats {
	s.mu.RLock()
	stats := ServerStats{
		StartedAt:           s.startedAt,
		CurrentClients:      len(s.clients),
		CurrentFiles:        s.catalog.Count() + len(s.dynamicFiles),
		TotalConnections:    s.stats.TotalConnections,
		TotalDisconnects:    s.stats.TotalDisconnects,
		InboundPackets:      s.stats.InboundPackets,
		OutboundPackets:     s.stats.OutboundPackets,
		InboundBytes:        s.stats.InboundBytes,
		OutboundBytes:       s.stats.OutboundBytes,
		SearchRequests:      s.stats.SearchRequests,
		SearchResultPackets: s.stats.SearchResultPackets,
		SearchResultEntries: s.stats.SearchResultEntries,
		SourceRequests:      s.stats.SourceRequests,
		CallbackRequests:    s.stats.CallbackRequests,
		FilesRegistered:     s.stats.FilesRegistered,
		FilesRemoved:        s.stats.FilesRemoved,
		PersistWrites:       s.stats.PersistWrites,
		UDPSearchRequests:   s.stats.UDPSearchRequests,
		UDPSourceRequests:   s.stats.UDPSourceRequests,
		UDPDropped:          s.stats.UDPDropped,
		UDPMalformed:        s.stats.UDPMalformed,
		UDPRateLimited:      s.stats.UDPRateLimited,
		ConnRateLimited:     s.stats.ConnRateLimited,
		OfferFilesDropped:   s.stats.OfferFilesDropped,
		CallbackRateLimited: s.stats.CallbackRateLimited,
		PeerStatusReplies:   s.stats.PeerStatusReplies,
		PeersLearned:        s.stats.PeersLearned,
		HTTPProbes:          s.stats.HTTPProbes,
		Peers:               s.peers.len(),
	}
	s.mu.RUnlock()
	return stats
}

// ClientsSnapshot returns the current dynamic user table.
func (s *Server) ClientsSnapshot() []ClientSnapshot {
	s.mu.RLock()
	clients := make([]*clientSession, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.mu.RUnlock()
	snapshots := make([]ClientSnapshot, 0, len(clients))
	for _, client := range clients {
		snapshots = append(snapshots, client.snapshot())
	}
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].ClientID < snapshots[j].ClientID
	})
	return snapshots
}

// FilesSnapshot returns a copy of all shared file entries.
func (s *Server) FilesSnapshot() []FileRecord {
	files := s.catalog.Snapshot()
	s.mu.RLock()
	for _, shared := range s.dynamicFiles {
		files = append(files, cloneFiles([]FileRecord{shared.materialize()})...)
	}
	s.mu.RUnlock()
	return files
}

// FileSnapshot returns one shared file record by hash.
func (s *Server) FileSnapshot(hash protocol.Hash) (FileRecord, bool) {
	if record, ok := s.catalog.Get(hash); ok {
		return record, true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	shared, ok := s.dynamicFiles[hash.String()]
	if !ok {
		return FileRecord{}, false
	}
	return shared.materialize(), true
}

// ClientSnapshotByID returns one connected client by assigned ID.
func (s *Server) ClientSnapshotByID(clientID int32) (ClientSnapshot, bool) {
	s.mu.RLock()
	client := s.clients[clientID]
	s.mu.RUnlock()
	if client == nil {
		return ClientSnapshot{}, false
	}
	return client.snapshot(), true
}

// UpsertFile registers or replaces a shared file and persists it to disk.
func (s *Server) UpsertFile(record FileRecord) error {
	if err := s.catalog.Upsert(record); err != nil {
		return err
	}
	s.mu.Lock()
	s.stats.FilesRegistered++
	s.mu.Unlock()
	return s.persistCatalog()
}

// DeleteFile removes a shared file and persists the new catalog.
func (s *Server) DeleteFile(hash protocol.Hash) (bool, error) {
	deleted := s.catalog.Delete(hash)
	if !deleted {
		return false, nil
	}
	s.mu.Lock()
	s.stats.FilesRemoved++
	s.mu.Unlock()
	if err := s.persistCatalog(); err != nil {
		return false, err
	}
	return true, nil
}

// PersistCatalog writes the current runtime catalog to disk.
func (s *Server) PersistCatalog() error {
	return s.persistCatalog()
}

func (s *Server) handleConn(conn net.Conn) {
	if s.connLimiter != nil {
		host := conn.RemoteAddr().String()
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			host = tcpAddr.IP.String()
		}
		if !s.connLimiter.allow(host) {
			s.bumpCounter(func(stats *serverCounters) { stats.ConnRateLimited++ })
			_ = conn.Close()
			return
		}
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(conn, first); err != nil {
		_ = conn.Close()
		return
	}
	if s.cfg.ProtocolObfuscation && !isPlainEd2kFirstByte(first[0]) {
		c2, err := serverObfuscatedHandshake(conn, first[0])
		if err != nil {
			s.logger.Warn("obfuscation handshake failed", "remote", conn.RemoteAddr().String(), "err", err)
			_ = conn.Close()
			return
		}
		conn = c2
	} else {
		if !isPlainEd2kFirstByte(first[0]) {
			if isHTTPMethodStart(first[0]) {
				// Answer browser/port-scanner HTTP probes with an HTTP error instead
				// of a confusing ED2K parse failure.
				s.bumpCounter(func(stats *serverCounters) { stats.HTTPProbes++ })
				_, _ = conn.Write([]byte("HTTP/1.0 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
			} else {
				s.logger.Warn("rejected non-ed2k first byte (protocol_obfuscation is false)", "remote", conn.RemoteAddr().String())
			}
			_ = conn.Close()
			return
		}
		conn = &prependConn{Conn: conn, prefix: []byte{first[0]}}
	}

	tcpAddr, _ := conn.RemoteAddr().(*net.TCPAddr)
	client := &clientSession{
		server:       s,
		conn:         conn,
		remote:       tcpAddr,
		offeredFiles: make(map[string]FileRecord),
		connectedAt:  time.Now(),
		lastSeenAt:   time.Now(),
	}
	s.bumpCounter(func(stats *serverCounters) {
		stats.TotalConnections++
	})
	defer func() {
		s.unregisterClient(client)
		_ = conn.Close()
	}()

	s.logger.Info("client connected", "remote", conn.RemoteAddr().String())
	for {
		header, body, frameBytes, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.logger.Warn("connection closed", "remote", conn.RemoteAddr().String(), "err", err)
			}
			return
		}
		client.noteInbound(frameBytes)
		s.bumpCounter(func(stats *serverCounters) {
			stats.InboundPackets++
			stats.InboundBytes += int64(frameBytes)
		})
		s.tracer.record(traceIn, "tcp", conn.RemoteAddr().String(), header.Protocol, header.Packet, frameBytes, body)
		if header.Protocol != protocol.EdonkeyHeader {
			s.logger.Warn("unsupported protocol", "protocol", header.Protocol, "remote", conn.RemoteAddr().String())
			return
		}
		if err := s.dispatch(client, header.Packet, body); err != nil {
			s.logger.Warn("request handling failed", "packet", fmt.Sprintf("0x%02x", header.Packet), "remote", conn.RemoteAddr().String(), "err", err)
			return
		}
	}
}

func (s *Server) dispatch(client *clientSession, packet byte, body []byte) error {
	switch packet {
	case opLoginRequest:
		var req serverproto.LoginRequest
		if err := req.Get(bytes.NewReader(body)); err != nil {
			return err
		}
		return s.handleLogin(client, req)
	case opGetServerList:
		return s.handleGetServerList(client)
	case opOfferFiles:
		var req OfferFiles
		if err := req.Get(bytes.NewReader(body)); err != nil {
			return err
		}
		return s.handleOfferFiles(client, req)
	case opSearchRequest:
		query, err := ParseSearchRequest(body)
		if err != nil {
			s.logger.Warn("invalid search request", "remote", client.conn.RemoteAddr().String(), "err", err)
			return s.handleSearch(client, SearchQuery{Root: searchMatchNoneExpr{}})
		}
		return s.handleSearch(client, query)
	case opSearchMore:
		return s.handleSearchMore(client)
	case opGetSources:
		var req serverproto.GetFileSources
		if err := req.Get(bytes.NewReader(body)); err != nil {
			return err
		}
		return s.handleGetSources(client, req, false)
	case opGetSourcesObfu:
		var req serverproto.GetFileSources
		if err := req.Get(bytes.NewReader(body)); err != nil {
			return err
		}
		return s.handleGetSources(client, req, true)
	case opCallbackReq:
		var req serverproto.CallbackRequest
		if err := req.Get(bytes.NewReader(body)); err != nil {
			return err
		}
		return s.handleCallback(client, req)
	case opDisconnect:
		return io.EOF
	default:
		s.logger.Warn("unsupported packet", "packet", fmt.Sprintf("0x%02x", packet), "remote", client.conn.RemoteAddr().String())
		return nil
	}
}

func (s *Server) handleLogin(client *clientSession, req serverproto.LoginRequest) error {
	client.mu.Lock()
	client.clientHash = req.Hash
	client.connectOptions = extractClientConnectOptions(req.Properties)
	client.loginPoint = req.Point
	client.clientName = extractClientName(req.Properties)
	client.assignedID = s.allocateClientID(client.remote)
	client.searchResult = nil
	client.searchOffset = 0
	assignedID := client.assignedID
	client.mu.Unlock()

	s.registerClient(client)

	if err := client.send("server.Status", &serverproto.Status{UsersCount: int32(s.clientCount()), FilesCount: int32(s.currentFilesCount())}); err != nil {
		return err
	}
	if s.cfg.Message != "" {
		if err := client.send("server.Message", &serverproto.Message{Value: protocol.ByteContainer16FromString(s.cfg.Message)}); err != nil {
			return err
		}
	}
	ic := idChangeExtended{
		ClientID:           assignedID,
		TCPFlags:           s.cfg.TCPFlags,
		AuxPort:            s.cfg.AuxPort,
		ReportedIP:         reportedIPForIdChange(assignedID),
		ObfuscationTCPPort: obfuscationTCPPortAdvertised(s.cfg, s.serverTCPPort()),
	}
	return client.send("server.IdChange", &ic)
}

func (s *Server) handleGetServerList(client *clientSession) error {
	if err := client.send("server.Status", &serverproto.Status{UsersCount: int32(s.clientCount()), FilesCount: int32(s.currentFilesCount())}); err != nil {
		return err
	}
	if s.cfg.ServerDescription != "" {
		if err := client.send("server.Message", &serverproto.Message{Value: protocol.ByteContainer16FromString(s.cfg.ServerDescription)}); err != nil {
			return err
		}
	}
	// Reply with an OP_SERVERLIST carrying this server's own endpoint, the
	// address the client reached us on, so clients (e.g. aMule) that request the
	// list on connect get a well-formed answer instead of nothing.
	if localTCP, ok := client.conn.LocalAddr().(*net.TCPAddr); ok {
		if body := buildServerListBody(localTCP.IP, s.serverTCPPort(), s.cfg.PeerServers); body != nil {
			return client.sendRawEd2k(opServerList, body)
		}
	}
	return nil
}

// buildServerListBody encodes an OP_SERVERLIST payload: a 1-byte server count
// followed by that many (4-byte IPv4 + little-endian uint16 port) entries. The
// first entry is this server (the address the client reached us on); peers are
// the configured "ip:port" peer servers. Returns nil if no valid entry exists.
func buildServerListBody(self net.IP, selfPort uint16, peers []string) []byte {
	body := make([]byte, 0, 1+(1+len(peers))*6)
	count := 0
	appendEntry := func(v4 net.IP, port uint16) {
		body = append(body, v4[0], v4[1], v4[2], v4[3])
		body = append(body, byte(port), byte(port>>8))
		count++
	}
	if v4 := self.To4(); v4 != nil {
		appendEntry(v4, selfPort)
	}
	for _, peer := range peers {
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(peer))
		if err != nil {
			continue
		}
		v4 := net.ParseIP(host).To4()
		port, perr := strconv.Atoi(portStr)
		if v4 == nil || perr != nil || port <= 0 || port > 65535 {
			continue
		}
		appendEntry(v4, uint16(port))
	}
	if count == 0 {
		return nil
	}
	return append([]byte{byte(count)}, body...)
}

func (s *Server) handleOfferFiles(client *clientSession, req OfferFiles) error {
	client.mu.Lock()
	clientID := client.assignedID
	listenPort := client.loginPoint.Port()
	remoteHost := ""
	if client.remote != nil && client.remote.IP != nil {
		remoteHost = client.remote.IP.String()
	}
	client.mu.Unlock()
	if clientID == 0 {
		return fmt.Errorf("client must login before offering files")
	}
	records := make([]FileRecord, 0, len(req.Entries))
	for _, entry := range req.Entries {
		record, err := fileRecordFromSharedEntry(entry)
		if err != nil {
			return err
		}
		source, ok := sourceFromSharedEntry(clientID, listenPort, remoteHost, entry)
		if ok {
			record.Endpoints = []SourceEntry{source}
		}
		records = append(records, record)
	}
	accepted, dropped := s.mergeClientOfferedFiles(clientID, records)
	s.bumpCounter(func(stats *serverCounters) {
		stats.FilesRegistered += int64(accepted)
		stats.OfferFilesDropped += int64(dropped)
	})
	return client.send("server.Status", &serverproto.Status{UsersCount: int32(s.clientCount()), FilesCount: int32(s.currentFilesCount())})
}

// capSearchResults limits a result set to max entries; max <= 0 means unlimited.
func capSearchResults(results []serverproto.SharedFileEntry, max int) []serverproto.SharedFileEntry {
	if max > 0 && len(results) > max {
		return results[:max]
	}
	return results
}

// loggedIn reports whether the client has completed OP_LOGINREQUEST (has an ID).
func (c *clientSession) loggedIn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.assignedID != 0
}

func (s *Server) handleSearch(client *clientSession, query SearchQuery) error {
	if !client.loggedIn() {
		// Ignore pre-login searches (return an empty result, do not disconnect).
		return client.send("server.SearchResult", &serverproto.SearchResult{Results: nil, MoreResults: false})
	}
	results := capSearchResults(s.searchAll(query), s.cfg.MaxTCPSearchResults)
	client.noteSearchRequest()
	s.bumpCounter(func(stats *serverCounters) {
		stats.SearchRequests++
		stats.SearchResultEntries += int64(len(results))
	})
	client.mu.Lock()
	client.searchResult = results
	client.searchOffset = 0
	client.mu.Unlock()
	return s.handleSearchMore(client)
}

func (s *Server) handleSearchMore(client *clientSession) error {
	client.mu.Lock()
	if len(client.searchResult) == 0 || client.searchOffset >= len(client.searchResult) {
		client.mu.Unlock()
		s.bumpCounter(func(stats *serverCounters) {
			stats.SearchResultPackets++
		})
		return client.send("server.SearchResult", &serverproto.SearchResult{Results: nil, MoreResults: false})
	}
	end := client.searchOffset + s.cfg.SearchBatchSize
	if end > len(client.searchResult) {
		end = len(client.searchResult)
	}
	packet := &serverproto.SearchResult{
		Results:     append([]serverproto.SharedFileEntry(nil), client.searchResult[client.searchOffset:end]...),
		MoreResults: end < len(client.searchResult),
	}
	client.searchOffset = end
	client.mu.Unlock()
	s.bumpCounter(func(stats *serverCounters) {
		stats.SearchResultPackets++
	})
	return client.send("server.SearchResult", packet)
}

func (s *Server) handleGetSources(client *clientSession, req serverproto.GetFileSources, obfuscatedReply bool) error {
	sources := orderAndCapSources(s.sourcesAll(req.Hash, obfuscatedReply), s.cfg.MaxSourcesPerReply)
	client.noteSourceRequest()
	s.bumpCounter(func(stats *serverCounters) {
		stats.SourceRequests++
	})
	if obfuscatedReply {
		return client.sendFoundSourcesObfuscated(req.Hash, sources)
	}
	endpoints := make([]protocol.Endpoint, 0, len(sources))
	for _, source := range sources {
		endpoints = append(endpoints, protocol.NewEndpoint(source.ClientID, source.Port))
	}
	return client.send("server.FoundFileSources", &serverproto.FoundFileSources{Hash: req.Hash, Sources: endpoints})
}

func (s *Server) handleCallback(client *clientSession, req serverproto.CallbackRequest) error {
	if s.callbackLimiter != nil {
		ip := ""
		if client.remote != nil {
			ip = client.remote.IP.String()
		}
		if !s.callbackLimiter.allow(ip) {
			s.bumpCounter(func(stats *serverCounters) { stats.CallbackRateLimited++ })
			return client.send("server.CallbackRequestFailed", &serverproto.CallbackRequestFailed{})
		}
	}
	client.noteCallbackRequest()
	s.bumpCounter(func(stats *serverCounters) {
		stats.CallbackRequests++
	})
	target := s.findClient(req.ClientID)
	if target == nil {
		return client.send("server.CallbackRequestFailed", &serverproto.CallbackRequestFailed{})
	}
	client.mu.Lock()
	origin := protocol.NewEndpoint(client.assignedID, client.loginPoint.Port())
	client.mu.Unlock()
	if err := target.send("server.CallbackRequestIncoming", &serverproto.CallbackRequestIncoming{Point: origin}); err != nil {
		return client.send("server.CallbackRequestFailed", &serverproto.CallbackRequestFailed{})
	}
	return nil
}

func (s *Server) registerClient(client *clientSession) {
	client.mu.Lock()
	assignedID := client.assignedID
	client.mu.Unlock()
	if assignedID == 0 {
		return
	}
	s.mu.Lock()
	s.clients[assignedID] = client
	s.mu.Unlock()
}

func (s *Server) unregisterClient(client *clientSession) {
	client.mu.Lock()
	assignedID := client.assignedID
	client.mu.Unlock()
	s.bumpCounter(func(stats *serverCounters) {
		stats.TotalDisconnects++
	})
	if assignedID != 0 {
		s.removeClientOfferedFiles(assignedID)
	}
	if assignedID == 0 {
		return
	}
	s.mu.Lock()
	if existing := s.clients[assignedID]; existing == client {
		delete(s.clients, assignedID)
	}
	s.mu.Unlock()
}

func (s *Server) findClient(clientID int32) *clientSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[clientID]
}

func (s *Server) clientCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

func (s *Server) allocateClientID(addr *net.TCPAddr) int32 {
	if clientID := clientIDFromRemote(addr); clientID != 0 {
		s.mu.RLock()
		_, inUse := s.clients[clientID]
		s.mu.RUnlock()
		if !inUse {
			return clientID
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clientID := s.nextID
	for {
		if _, exists := s.clients[clientID]; !exists {
			s.nextID = clientID + 1
			return clientID
		}
		clientID++
	}
}

// serverTCPPort 返回当前 ED2K 监听 TCP 端口，用于 IdChange 中通告混淆端口。
func (s *Server) serverTCPPort() uint16 {
	s.mu.RLock()
	ln := s.listener
	s.mu.RUnlock()
	if ln != nil {
		if ta, ok := ln.Addr().(*net.TCPAddr); ok && ta.Port > 0 {
			return uint16(ta.Port)
		}
	}
	if a, err := net.ResolveTCPAddr("tcp", s.cfg.ListenAddress); err == nil && a.Port > 0 {
		return uint16(a.Port)
	}
	return 4661
}

func (s *Server) currentFilesCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.catalog.Count() + len(s.dynamicFiles)
}

func (s *Server) searchAll(query SearchQuery) []serverproto.SharedFileEntry {
	results := s.catalog.Search(query)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, shared := range s.dynamicFiles {
		record := shared.materialize()
		if !matchesRecord(record, query) {
			continue
		}
		results = append(results, makeSharedFileEntry(record))
	}
	return results
}

type foundSourceEntry struct {
	ClientID           int32
	Port               int
	ObfuscationOptions uint8
	UserHash           *protocol.Hash
}

// capOfferedRecords truncates a client's published file list to max entries.
// A max <= 0 means unlimited (the cap is disabled).
func capOfferedRecords(records []FileRecord, max int) []FileRecord {
	if max > 0 && len(records) > max {
		return records[:max]
	}
	return records
}

// orderAndCapSources orders found sources HighID-first (routable client IDs
// before LowID) so clients receive directly-reachable peers first, then caps the
// list. A max <= 0 or > 255 falls back to the ED2K protocol limit of 255.
func orderAndCapSources(sources []foundSourceEntry, max int) []foundSourceEntry {
	if max <= 0 || max > 255 {
		max = 255
	}
	// Drop duplicate endpoints (same client ID + port) so a file offered by the
	// same peer through several paths is not returned multiple times.
	if len(sources) > 1 {
		seen := make(map[[2]int64]struct{}, len(sources))
		deduped := make([]foundSourceEntry, 0, len(sources))
		for _, src := range sources {
			key := [2]int64{int64(src.ClientID), int64(src.Port)}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			deduped = append(deduped, src)
		}
		sources = deduped
	}
	sort.SliceStable(sources, func(i, j int) bool {
		hi := uint32(sources[i].ClientID) >= 0x1000000
		hj := uint32(sources[j].ClientID) >= 0x1000000
		return hi && !hj
	})
	if len(sources) > max {
		sources = sources[:max]
	}
	return sources
}

func (s *Server) sourcesAll(hash protocol.Hash, obfuscated bool) []foundSourceEntry {
	sources := make([]foundSourceEntry, 0)
	if record, ok := s.catalog.Get(hash); ok {
		for _, source := range record.Endpoints {
			endpoint, err := protocol.EndpointFromString(source.Host, source.Port)
			if err != nil {
				continue
			}
			entry := foundSourceEntry{
				ClientID: endpoint.IP(),
				Port:     endpoint.Port(),
			}
			if obfuscated {
				entry.ObfuscationOptions = source.ObfuscationOptions
				if userHash, ok := parseSourceUserHash(source.UserHash); ok {
					entry.UserHash = &userHash
					entry.ObfuscationOptions |= sourceObfuscationUserHashFlag
				}
			}
			sources = append(sources, entry)
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if shared, ok := s.dynamicFiles[hash.String()]; ok {
		for clientID, source := range shared.byClient {
			endpoint, err := protocol.EndpointFromString(source.Host, source.Port)
			if err != nil {
				continue
			}
			entry := foundSourceEntry{
				ClientID: endpoint.IP(),
				Port:     endpoint.Port(),
			}
			if obfuscated {
				if client := s.clients[clientID]; client != nil {
					entry.ObfuscationOptions, entry.UserHash = client.sourceObfuscationMetadata()
				}
			}
			sources = append(sources, entry)
		}
	}
	return sources
}

// eMule sends OP_OFFERFILES in incremental batches as files finish hashing.
// Preserve earlier batches until the client disconnects; an empty offer clears
// the set. Enforce the per-client cap across all batches, not per packet.
func (s *Server) mergeClientOfferedFiles(clientID int32, records []FileRecord) (int, int) {
	client := s.findClient(clientID)
	if client == nil {
		return 0, 0
	}
	if len(records) == 0 {
		s.removeClientOfferedFiles(clientID)
		return 0, 0
	}
	client.mu.Lock()
	previous := make([]FileRecord, 0, len(records))
	accepted := make([]FileRecord, 0, len(records))
	dropped := 0
	for _, record := range records {
		key := record.Hash.String()
		old, exists := client.offeredFiles[key]
		if !exists && s.cfg.MaxOfferedFilesPerClient > 0 && len(client.offeredFiles) >= s.cfg.MaxOfferedFilesPerClient {
			dropped++
			continue
		}
		if exists {
			previous = append(previous, old)
		}
		client.offeredFiles[key] = record
		accepted = append(accepted, record)
	}
	client.mu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range previous {
		s.removeDynamicLocked(clientID, record.Hash)
	}
	for _, record := range accepted {
		s.addDynamicLocked(clientID, record)
	}
	return len(accepted), dropped
}

func (s *Server) removeClientOfferedFiles(clientID int32) {
	client := s.findClient(clientID)
	if client == nil {
		return
	}
	client.mu.Lock()
	records := make([]FileRecord, 0, len(client.offeredFiles))
	for _, record := range client.offeredFiles {
		records = append(records, record)
	}
	client.offeredFiles = map[string]FileRecord{}
	client.mu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range records {
		s.removeDynamicLocked(clientID, record.Hash)
	}
}

func (s *Server) addDynamicLocked(clientID int32, record FileRecord) {
	key := record.Hash.String()
	shared := s.dynamicFiles[key]
	if shared == nil {
		shared = &dynamicSharedFile{
			record:    record,
			byClient:  make(map[int32]SourceEntry),
			completes: make(map[int32]bool),
		}
		s.dynamicFiles[key] = shared
	}
	base := record
	base.Endpoints = nil
	shared.record = mergeDynamicFileRecord(shared.record, base)
	if len(record.Endpoints) > 0 {
		shared.byClient[clientID] = record.Endpoints[0]
	}
	shared.completes[clientID] = record.CompleteSources > 0
}

func (s *Server) removeDynamicLocked(clientID int32, hash protocol.Hash) {
	key := hash.String()
	shared := s.dynamicFiles[key]
	if shared == nil {
		return
	}
	delete(shared.byClient, clientID)
	delete(shared.completes, clientID)
	if len(shared.byClient) == 0 {
		delete(s.dynamicFiles, key)
	}
}

func (d *dynamicSharedFile) materialize() FileRecord {
	record := d.record
	record.Endpoints = record.Endpoints[:0]
	for _, source := range d.byClient {
		record.Endpoints = append(record.Endpoints, source)
	}
	record.Sources = len(record.Endpoints)
	record.CompleteSources = 0
	for _, complete := range d.completes {
		if complete {
			record.CompleteSources++
		}
	}
	if record.CompleteSources == 0 {
		record.CompleteSources = record.Sources
	}
	return record
}

func mergeDynamicFileRecord(dst, src FileRecord) FileRecord {
	if dst.Hash.IsZero() {
		return src
	}
	if dst.Name == "" {
		dst.Name = src.Name
	}
	if dst.Size == 0 {
		dst.Size = src.Size
	}
	if dst.FileType == "" {
		dst.FileType = src.FileType
	}
	if dst.Extension == "" {
		dst.Extension = src.Extension
	}
	if dst.MediaCodec == "" {
		dst.MediaCodec = src.MediaCodec
	}
	if dst.MediaLength == 0 {
		dst.MediaLength = src.MediaLength
	}
	if dst.MediaBitrate == 0 {
		dst.MediaBitrate = src.MediaBitrate
	}
	return dst
}

func sourceFromSharedEntry(clientID int32, listenPort int, remoteHost string, entry serverproto.SharedFileEntry) (SourceEntry, bool) {
	ip := entry.ClientID
	port := int(entry.Port)
	if ip == 0 || port == 0 || uint32(ip) == 0xfbfbfbfb || uint32(ip) == 0xfcfcfcfc {
		ip = clientID
		port = listenPort
	}
	if ip == 0 || port == 0 {
		return SourceEntry{}, false
	}
	endpoint := protocol.NewEndpoint(ip, port)
	host := endpoint.String()
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	if shouldPreferObservedRemoteSource(host, remoteHost) {
		host = remoteHost
	}
	return SourceEntry{Host: host, Port: port}, true
}

func shouldPreferObservedRemoteSource(host string, remoteHost string) bool {
	if remoteHost == "" || host == "" || host == remoteHost {
		return false
	}
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil || (!remoteIP.IsPrivate() && !remoteIP.IsLoopback()) {
		return false
	}
	sourceIP := net.ParseIP(host)
	return sourceIP != nil && !sourceIP.Equal(remoteIP)
}

func (s *Server) persistCatalog() error {
	if err := s.catalog.Save(); err != nil {
		return err
	}
	s.bumpCounter(func(stats *serverCounters) {
		stats.PersistWrites++
	})
	return nil
}

func (s *Server) bumpCounter(fn func(*serverCounters)) {
	s.mu.Lock()
	fn(&s.stats)
	s.mu.Unlock()
}

func (c *clientSession) send(typeName string, packet protocol.Serializable) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.sendLocked(typeName, packet)
}

func (c *clientSession) sendLocked(typeName string, packet protocol.Serializable) error {
	raw, err := c.server.combiner.Pack(typeName, packet)
	if err != nil {
		return err
	}
	// Trace the logical frame before optional on-the-wire compression.
	if len(raw) >= 6 {
		c.server.tracer.record(traceOut, "tcp", c.conn.RemoteAddr().String(), raw[0], raw[5], len(raw), raw[6:])
	}
	wire := maybePackFrame(raw)
	c.noteOutbound(len(wire))
	c.server.bumpCounter(func(stats *serverCounters) {
		stats.OutboundPackets++
		stats.OutboundBytes += int64(len(wire))
	})
	_, err = c.conn.Write(wire)
	return err
}

// sendFoundSourcesObfuscated 回复 OP_FOUNDSOURCES_OBFU（0x44）：每源在 endpoint 后多 1 字节连接/混淆选项（aMule PartFile::AddSources）。
func (c *clientSession) sendFoundSourcesObfuscated(hash protocol.Hash, sources []foundSourceEntry) error {
	body := &bytes.Buffer{}
	if err := protocol.WriteHash(body, hash); err != nil {
		return err
	}
	if err := body.WriteByte(byte(len(sources))); err != nil {
		return err
	}
	for _, source := range sources {
		if err := protocol.WriteInt32(body, source.ClientID); err != nil {
			return err
		}
		if err := protocol.WriteUInt16(body, uint16(source.Port)); err != nil {
			return err
		}
		if err := body.WriteByte(source.ObfuscationOptions); err != nil {
			return err
		}
		if source.UserHash != nil {
			if _, err := body.Write(source.UserHash.Bytes()); err != nil {
				return err
			}
		}
	}
	return c.sendRawEd2k(opFoundSourcesObfu, body.Bytes())
}

func (c *clientSession) sendRawEd2k(opcode byte, body []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var header protocol.PacketHeader
	header.ResetWithKey(protocol.PK(protocol.EdonkeyHeader, opcode), int32(len(body)+1))
	var frame bytes.Buffer
	if err := header.Put(&frame); err != nil {
		return err
	}
	if _, err := frame.Write(body); err != nil {
		return err
	}
	raw := frame.Bytes()
	c.noteOutbound(len(raw))
	c.server.bumpCounter(func(stats *serverCounters) {
		stats.OutboundPackets++
		stats.OutboundBytes += int64(len(raw))
	})
	c.server.tracer.record(traceOut, "tcp", c.conn.RemoteAddr().String(), protocol.EdonkeyHeader, opcode, len(raw), body)
	_, err := c.conn.Write(raw)
	return err
}

func (c *clientSession) noteInbound(frameBytes int) {
	c.mu.Lock()
	c.lastSeenAt = time.Now()
	c.inboundPackets++
	c.inboundBytes += int64(frameBytes)
	c.mu.Unlock()
}

func (c *clientSession) noteOutbound(frameBytes int) {
	c.mu.Lock()
	c.lastSeenAt = time.Now()
	c.outboundPackets++
	c.outboundBytes += int64(frameBytes)
	c.mu.Unlock()
}

func (c *clientSession) noteSearchRequest() {
	c.mu.Lock()
	c.lastSeenAt = time.Now()
	c.searchRequests++
	c.mu.Unlock()
}

func (c *clientSession) noteSourceRequest() {
	c.mu.Lock()
	c.lastSeenAt = time.Now()
	c.sourceRequests++
	c.mu.Unlock()
}

func (c *clientSession) noteCallbackRequest() {
	c.mu.Lock()
	c.lastSeenAt = time.Now()
	c.callbackRequests++
	c.mu.Unlock()
}

func (c *clientSession) snapshot() ClientSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	remoteAddress := ""
	if c.remote != nil {
		remoteAddress = c.remote.String()
	}
	listenEndpoint := ""
	if c.loginPoint.Defined() {
		listenEndpoint = c.loginPoint.String()
	}
	return ClientSnapshot{
		ClientID:         c.assignedID,
		ClientName:       c.clientName,
		ClientHash:       c.clientHash,
		RemoteAddress:    remoteAddress,
		ListenEndpoint:   listenEndpoint,
		ConnectedAt:      c.connectedAt,
		LastSeenAt:       c.lastSeenAt,
		SearchRequests:   c.searchRequests,
		SourceRequests:   c.sourceRequests,
		CallbackRequests: c.callbackRequests,
		InboundPackets:   c.inboundPackets,
		OutboundPackets:  c.outboundPackets,
		InboundBytes:     c.inboundBytes,
		OutboundBytes:    c.outboundBytes,
	}
}

func readFrame(conn net.Conn) (protocol.PacketHeader, []byte, int, error) {
	headerBuf := make([]byte, protocol.PacketHeaderSize)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return protocol.PacketHeader{}, nil, 0, err
	}
	var header protocol.PacketHeader
	if err := header.Get(bytes.NewReader(headerBuf)); err != nil {
		return protocol.PacketHeader{}, nil, 0, err
	}
	bodySize := int(header.SizePacket())
	if bodySize < 0 {
		return protocol.PacketHeader{}, nil, 0, fmt.Errorf("invalid body size: %d", bodySize)
	}
	body := make([]byte, bodySize)
	if _, err := io.ReadFull(conn, body); err != nil {
		return protocol.PacketHeader{}, nil, 0, err
	}
	frameBytes := protocol.PacketHeaderSize + bodySize
	// Packed (zlib) frames carry a compressed payload after the opcode; inflate it
	// and present the frame to the dispatcher as a normal ED2K packet.
	if header.Protocol == protocol.PackedProt {
		inflated, err := inflatePackedFrame(body)
		if err != nil {
			return protocol.PacketHeader{}, nil, 0, fmt.Errorf("packed frame: %w", err)
		}
		header.Protocol = protocol.EdonkeyHeader
		body = inflated
	}
	return header, body, frameBytes, nil
}

// inflatePackedFrame zlib-decompresses a packed ED2K frame body with a hard cap
// on the decoded size.
func inflatePackedFrame(body []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxDecodedFrameBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxDecodedFrameBytes {
		return nil, fmt.Errorf("decompressed frame exceeds %d bytes", maxDecodedFrameBytes)
	}
	return out, nil
}

func extractClientName(tags protocol.TagList) string {
	for _, tag := range tags {
		if tag.ID == 0x01 {
			return normalizeDisplayText(tag.String)
		}
	}
	return ""
}

func extractClientConnectOptions(tags protocol.TagList) uint8 {
	for _, tag := range tags {
		if tag.ID != ctServerFlags {
			continue
		}
		flags := uint32(tag.UInt64)
		var options uint8
		if flags&srvCapSupportCrypt != 0 {
			options |= 0x01
		}
		if flags&srvCapRequestCrypt != 0 {
			options |= 0x02
		}
		if flags&srvCapRequireCrypt != 0 {
			options |= 0x04
		}
		return options
	}
	return 0
}

func (c *clientSession) sourceObfuscationMetadata() (uint8, *protocol.Hash) {
	c.mu.Lock()
	defer c.mu.Unlock()
	options := c.connectOptions
	if options == 0 || c.clientHash.IsZero() {
		return options, nil
	}
	hash := c.clientHash
	options |= sourceObfuscationUserHashFlag
	return options, &hash
}

func parseSourceUserHash(value string) (protocol.Hash, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return protocol.Hash{}, false
	}
	hash, err := protocol.HashFromString(value)
	if err != nil {
		return protocol.Hash{}, false
	}
	return hash, true
}

// isHTTPMethodStart reports whether b is the first byte of a common HTTP request
// method, used to detect and politely reject HTTP probes on the ED2K port.
func isHTTPMethodStart(b byte) bool {
	switch b {
	case 'G', 'P', 'H', 'O', 'D', 'T', 'C': // GET, POST/PUT, HEAD, OPTIONS, DELETE, TRACE, CONNECT
		return true
	}
	return false
}

func clientIDFromRemote(addr *net.TCPAddr) int32 {
	if addr == nil || addr.IP == nil {
		return 0
	}
	return protocol.EndpointFromInet(addr).IP()
}
