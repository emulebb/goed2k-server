package ed2ksrv

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	defaultListenAddress      = ":4661"
	defaultAdminListenAddress = ":8080"
	defaultServerName         = "goed2k-server"
	defaultDescription        = "Minimal eD2k/eMule compatible server"
	defaultBatchSize          = 200
	defaultCatalogPath        = "catalog.json"
	defaultDatabaseTable      = "shared_files"
)

// Config describes the runtime settings for the ED2K server.
type Config struct {
	ListenAddress      string `json:"listen_address"`
	AdminListenAddress string `json:"admin_listen_address"`
	AdminToken         string `json:"admin_token"`
	ServerName         string `json:"server_name"`
	ServerDescription  string `json:"server_description"`
	Message            string `json:"message"`
	StorageBackend     string `json:"storage_backend"`
	CatalogPath        string `json:"catalog_path"`
	DatabaseDSN        string `json:"database_dsn"`
	DatabaseTable      string `json:"database_table"`
	SearchBatchSize    int    `json:"search_batch_size"`
	// MaxSourcesPerReply caps how many sources a GetSources reply returns (TCP and
	// UDP). Bounded to the ED2K protocol limit of 255.
	MaxSourcesPerReply int `json:"max_sources_per_reply"`
	// MaxConnsPerIPPerSecond rate-limits new TCP connections per source IP. 0
	// disables the limiter (default); set a positive value to enable abuse control.
	MaxConnsPerIPPerSecond int `json:"max_conns_per_ip_per_second"`
	// MaxOfferedFilesPerClient caps how many shared files one client may publish
	// via OP_OFFERFILES (excess entries are dropped). 0 disables the cap (default).
	MaxOfferedFilesPerClient int `json:"max_offered_files_per_client"`
	// MaxCallbacksPerIPPerSecond rate-limits callback requests (TCP + UDP) per
	// source IP. 0 disables the limiter (default).
	MaxCallbacksPerIPPerSecond int `json:"max_callbacks_per_ip_per_second"`
	// PeerServers lists additional ED2K servers ("ip:port") advertised to clients
	// in the OP_SERVERLIST reply alongside this server. Empty by default.
	PeerServers []string `json:"peer_servers"`
	// MaxTCPSearchResults caps the total number of results a single TCP search may
	// return (across all SearchMore pages). 0 means unlimited (default).
	MaxTCPSearchResults int `json:"max_tcp_search_results"`
	TCPFlags           int32  `json:"tcp_flags"`
	AuxPort            int32  `json:"aux_port"`
	// ProtocolObfuscation enables eMule-style TCP obfuscation (DH + RC4) on the ED2K listener when the client starts with a non-ED2K first byte.
	ProtocolObfuscation bool `json:"protocol_obfuscation"`
	// ServerUDP listens on TCP 端口 + UDPPortOffset（默认 +4），响应 OP_GLOBSERVSTATREQ，向 eMule 通告软性/硬性文件限制等。
	ServerUDP          bool   `json:"server_udp"`
	UDPPortOffset      int    `json:"udp_port_offset"`
	SoftFilesLimit     int32  `json:"soft_files_limit"`
	HardFilesLimit     int32  `json:"hard_files_limit"`
	MaxUsersAdvertised uint32 `json:"max_users_advertised"`
	// UDP holds the UDP search / source-lookup service settings (the high-volume
	// client path: OP_GLOBSEARCHREQ* and OP_GLOBGETSOURCES*).
	UDP UDPConfig `json:"udp"`
	// PacketTrace enables structured per-frame tracing of every ED2K packet
	// (TCP and UDP, both directions). Off by default.
	PacketTrace bool `json:"packet_trace"`
	// PacketTracePath, when set, appends JSON-line packet traces to this file in
	// addition to the logger. Honors the workspace output-root policy.
	PacketTracePath string `json:"packet_trace_path"`
	// PacketTraceMaxBytes bounds how many payload bytes are hex-dumped per frame.
	PacketTraceMaxBytes int `json:"packet_trace_max_bytes"`
}

// UDPConfig configures the ED2K UDP search and source-lookup service.
type UDPConfig struct {
	SearchEnabled         bool `json:"search_enabled"`
	SourcesEnabled        bool `json:"sources_enabled"`
	MaxPayloadBytes       int  `json:"max_payload_bytes"`
	MaxResults            int  `json:"max_results"`
	SearchWorkers         int  `json:"search_workers"`
	SearchQueueSize       int  `json:"search_queue_size"`
	PerIPPacketsPerSecond int  `json:"per_ip_packets_per_second"`
	MaxASTDepth           int  `json:"max_ast_depth"`
}

// DefaultUDPConfig returns the baseline UDP service settings.
func DefaultUDPConfig() UDPConfig {
	return UDPConfig{
		SearchEnabled:         true,
		SourcesEnabled:        true,
		MaxPayloadBytes:       1300,
		MaxResults:            200,
		SearchWorkers:         4,
		SearchQueueSize:       1024,
		PerIPPacketsPerSecond: 20,
		MaxASTDepth:           24,
	}
}

// DefaultConfig returns a working baseline configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddress:       defaultListenAddress,
		AdminListenAddress:  defaultAdminListenAddress,
		ServerName:          defaultServerName,
		ServerDescription:   defaultDescription,
		Message:             "Welcome to goed2k-server",
		StorageBackend:      storageBackendJSON,
		CatalogPath:         defaultCatalogPath,
		DatabaseTable:       defaultDatabaseTable,
		SearchBatchSize:     defaultBatchSize,
		ProtocolObfuscation: true,
		ServerUDP:           true,
		UDPPortOffset:       4,
		SoftFilesLimit:      5000,
		HardFilesLimit:      200000,
		MaxUsersAdvertised:  500000,
		UDP:                 DefaultUDPConfig(),
		PacketTraceMaxBytes: 64,
	}
}

// Normalize applies defaults and validates required fields.
func (c Config) Normalize() (Config, error) {
	if c.ListenAddress == "" {
		c.ListenAddress = defaultListenAddress
	}
	if c.AdminListenAddress == "" {
		c.AdminListenAddress = defaultAdminListenAddress
	}
	if c.ServerName == "" {
		c.ServerName = defaultServerName
	}
	if c.ServerDescription == "" {
		c.ServerDescription = defaultDescription
	}
	if c.SearchBatchSize <= 0 {
		c.SearchBatchSize = defaultBatchSize
	}
	if c.MaxSourcesPerReply <= 0 || c.MaxSourcesPerReply > 255 {
		c.MaxSourcesPerReply = 255
	}
	if c.UDPPortOffset == 0 {
		c.UDPPortOffset = 4
	}
	if c.SoftFilesLimit <= 0 {
		c.SoftFilesLimit = 5000
	}
	if c.HardFilesLimit <= 0 {
		c.HardFilesLimit = 200000
	}
	if c.UDP.MaxPayloadBytes <= 0 {
		c.UDP.MaxPayloadBytes = 1300
	}
	if c.UDP.MaxResults <= 0 {
		c.UDP.MaxResults = 200
	}
	if c.UDP.SearchWorkers <= 0 {
		c.UDP.SearchWorkers = 4
	}
	if c.UDP.SearchQueueSize <= 0 {
		c.UDP.SearchQueueSize = 1024
	}
	if c.UDP.PerIPPacketsPerSecond <= 0 {
		c.UDP.PerIPPacketsPerSecond = 20
	}
	if c.UDP.MaxASTDepth <= 0 {
		c.UDP.MaxASTDepth = 24
	}
	if c.PacketTraceMaxBytes <= 0 {
		c.PacketTraceMaxBytes = 64
	}
	if c.StorageBackend == "" {
		c.StorageBackend = storageBackendJSON
	}
	c.StorageBackend = strings.ToLower(strings.TrimSpace(c.StorageBackend))
	switch c.StorageBackend {
	case storageBackendJSON:
		if c.CatalogPath == "" {
			return Config{}, fmt.Errorf("catalog_path is required")
		}
	case storageBackendMySQL, storageBackendPgSQL:
		if c.DatabaseDSN == "" {
			return Config{}, fmt.Errorf("database_dsn is required when storage_backend is %s", c.StorageBackend)
		}
	default:
		return Config{}, fmt.Errorf("unsupported storage_backend: %s", c.StorageBackend)
	}
	return c, nil
}

// LoadConfig reads a JSON configuration file from disk.
// 若 path 指向的文件不存在，则使用 DefaultConfig 并经 Normalize（与「仅含默认值的配置文件」等价）。
// 第二个返回值为 true 表示因文件不存在而采用了内置默认配置。
func LoadConfig(path string) (Config, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg, err := DefaultConfig().Normalize()
			return cfg, true, err
		}
		return Config{}, false, err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, false, err
	}
	cfg, err = cfg.Normalize()
	return cfg, false, err
}
