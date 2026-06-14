package ed2ksrv

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// peerRegistry tracks configured peer ED2K servers for active liveness pings
// (OP_GLOBSERVSTATREQ) and records when each last answered.
type peerRegistry struct {
	mu    sync.Mutex
	peers map[string]*peerState
	order []string
}

type peerState struct {
	addr     *net.UDPAddr
	lastSeen time.Time
}

// PeerStatus is the admin-facing view of one peer server.
type PeerStatus struct {
	Address  string    `json:"address"`
	LastSeen time.Time `json:"last_seen"`
}

func newPeerRegistry(specs []string) *peerRegistry {
	r := &peerRegistry{peers: make(map[string]*peerState)}
	for _, spec := range specs {
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(spec))
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		port, perr := strconv.Atoi(portStr)
		if ip == nil || perr != nil || port <= 0 || port > 65535 {
			continue
		}
		key := net.JoinHostPort(host, portStr)
		if _, dup := r.peers[key]; dup {
			continue
		}
		r.peers[key] = &peerState{addr: &net.UDPAddr{IP: ip, Port: port}}
		r.order = append(r.order, key)
	}
	return r
}

func (r *peerRegistry) len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.peers)
}

// addrs returns the peer UDP addresses in configuration order.
func (r *peerRegistry) addrs() []*net.UDPAddr {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*net.UDPAddr, 0, len(r.order))
	for _, key := range r.order {
		out = append(out, r.peers[key].addr)
	}
	return out
}

// markSeen records that a known peer answered. Returns false if addr is not a
// configured peer (so unsolicited status replies cannot spoof peer liveness).
func (r *peerRegistry) markSeen(addr *net.UDPAddr) bool {
	if r == nil || addr == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.peers[addr.String()]
	if !ok {
		return false
	}
	p.lastSeen = time.Now()
	return true
}

// add records a newly-learned peer (e.g. from a peer's server-list reply).
// Returns true if it was not already known.
func (r *peerRegistry) add(addr *net.UDPAddr) bool {
	if r == nil || addr == nil || addr.IP.To4() == nil || addr.Port <= 0 {
		return false
	}
	key := addr.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.peers[key]; ok {
		return false
	}
	r.peers[key] = &peerState{addr: &net.UDPAddr{IP: addr.IP.To4(), Port: addr.Port}}
	r.order = append(r.order, key)
	return true
}

// parseServerListBody decodes an OP_SERVER_LIST_RES body: a 1-byte server count
// followed by that many (4-byte IPv4 + little-endian uint16 port) entries.
func parseServerListBody(body []byte) []*net.UDPAddr {
	if len(body) < 1 {
		return nil
	}
	count := int(body[0])
	out := make([]*net.UDPAddr, 0, count)
	off := 1
	for i := 0; i < count && off+6 <= len(body); i++ {
		ip := net.IPv4(body[off], body[off+1], body[off+2], body[off+3]).To4()
		port := int(binary.LittleEndian.Uint16(body[off+4 : off+6]))
		off += 6
		if ip != nil && port > 0 {
			out = append(out, &net.UDPAddr{IP: ip, Port: port})
		}
	}
	return out
}

func (r *peerRegistry) snapshot() []PeerStatus {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]PeerStatus, 0, len(r.order))
	for _, key := range r.order {
		out = append(out, PeerStatus{Address: key, LastSeen: r.peers[key].lastSeen})
	}
	return out
}
