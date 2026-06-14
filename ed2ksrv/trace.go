package ed2ksrv

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"
)

// traceDirection is the flow direction of a traced ED2K frame.
type traceDirection string

const (
	traceIn  traceDirection = "in"
	traceOut traceDirection = "out"
)

// packetTracer emits a structured record for every ED2K frame the server reads
// or writes, across TCP and UDP. It is intentionally cheap to leave installed:
// when disabled the Server holds a nil *packetTracer and the trace calls return
// immediately.
type packetTracer struct {
	logger   *slog.Logger
	maxBytes int

	mu   sync.Mutex
	file *os.File
}

// packetTraceRecord is the JSON-line shape written to the optional trace file.
type packetTraceRecord struct {
	Time      string `json:"time"`
	Dir       string `json:"dir"`
	Transport string `json:"transport"` // "tcp" | "udp"
	Peer      string `json:"peer"`
	Protocol  string `json:"protocol"`
	Opcode    string `json:"opcode"`
	OpName    string `json:"op_name"`
	Length    int    `json:"length"`
	Hex       string `json:"hex,omitempty"`
}

func newPacketTracer(cfg Config, logger *slog.Logger) (*packetTracer, error) {
	if !cfg.PacketTrace {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	tracer := &packetTracer{logger: logger, maxBytes: cfg.PacketTraceMaxBytes}
	if cfg.PacketTracePath != "" {
		f, err := os.OpenFile(cfg.PacketTracePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		tracer.file = f
	}
	return tracer, nil
}

func (t *packetTracer) close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file != nil {
		_ = t.file.Close()
		t.file = nil
	}
}

// record emits one frame trace. proto/op are the ED2K header bytes; body is the
// frame payload following the opcode (it is never mutated, only hex-sampled).
func (t *packetTracer) record(dir traceDirection, transport, peer string, proto, op byte, length int, body []byte) {
	if t == nil {
		return
	}
	sample := body
	if t.maxBytes > 0 && len(sample) > t.maxBytes {
		sample = sample[:t.maxBytes]
	}
	dump := hex.EncodeToString(sample)
	name := opcodeName(transport, op)
	t.logger.Info("ed2k packet",
		"dir", string(dir),
		"transport", transport,
		"peer", peer,
		"proto", byteHex(proto),
		"op", byteHex(op),
		"op_name", name,
		"len", length,
		"hex", dump,
	)
	if t.file == nil {
		return
	}
	rec := packetTraceRecord{
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
		Dir:       string(dir),
		Transport: transport,
		Peer:      peer,
		Protocol:  byteHex(proto),
		Opcode:    byteHex(op),
		OpName:    name,
		Length:    length,
		Hex:       dump,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	t.mu.Lock()
	_, _ = t.file.Write(append(line, '\n'))
	t.mu.Unlock()
}

func byteHex(b byte) string {
	const digits = "0123456789abcdef"
	return "0x" + string([]byte{digits[b>>4], digits[b&0x0f]})
}

// opcodeName maps known ED2K opcodes to readable names for traces. Unknown
// opcodes return an empty string.
func opcodeName(transport string, op byte) string {
	if transport == "udp" {
		switch op {
		case udpOpGlobSearchReq3:
			return "OP_GLOBSEARCHREQ3"
		case udpOpGlobSearchReq2:
			return "OP_GLOBSEARCHREQ2"
		case udpOpGlobSearchReq:
			return "OP_GLOBSEARCHREQ"
		case udpOpGlobSearchRes:
			return "OP_GLOBSEARCHRES"
		case udpOpGlobGetSources:
			return "OP_GLOBGETSOURCES"
		case udpOpGlobGetSources2:
			return "OP_GLOBGETSOURCES2"
		case udpOpGlobFoundSources:
			return "OP_GLOBFOUNDSOURCES"
		case udpOpServerDescReq:
			return "OP_SERVER_DESC_REQ"
		case udpOpServerDescRes:
			return "OP_SERVER_DESC_RES"
		case udpOpGlobCallbackReq:
			return "OP_GLOBCALLBACKREQUEST"
		case udpOpServerListReq, udpOpServerListReq2:
			return "OP_SERVER_LIST_REQ"
		case udpOpServerListRes:
			return "OP_SERVER_LIST_RES"
		case opGlobServStatReq:
			return "OP_GLOBSERVSTATREQ"
		case opGlobServStatRes:
			return "OP_GLOBSERVSTATRES"
		}
		return ""
	}
	switch op {
	case opLoginRequest:
		return "OP_LOGINREQUEST"
	case opGetServerList:
		return "OP_GETSERVERLIST"
	case opServerList:
		return "OP_SERVERLIST"
	case opOfferFiles:
		return "OP_OFFERFILES"
	case opSearchRequest:
		return "OP_SEARCHREQUEST"
	case opSearchMore:
		return "OP_QUERY_MORE_RESULT"
	case opGetSources:
		return "OP_GETSOURCES"
	case opGetSourcesObfu:
		return "OP_GETSOURCES_OBFU"
	case opCallbackReq:
		return "OP_CALLBACKREQUEST"
	case opDisconnect:
		return "OP_DISCONNECT"
	case opFoundSourcesObfu:
		return "OP_FOUNDSOURCES_OBFU"
	}
	return ""
}
