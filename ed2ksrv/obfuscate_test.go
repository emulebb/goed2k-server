package ed2ksrv

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"

	"github.com/monkeyWie/goed2k/protocol"
)

func TestServerObfuscatedHandshakeIgnoresPeekedMarkerBeforeDH(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	clientPrivate := big.NewInt(0x12345)
	ga := new(big.Int).Exp(big.NewInt(2), clientPrivate, dh768P)
	gaBuf := encodeFixed96(ga)
	if gaBuf == nil {
		t.Fatal("encode client DH public key")
	}

	type handshakeResult struct {
		conn net.Conn
		err  error
	}
	results := make(chan handshakeResult, 1)
	go func() {
		conn, err := serverObfuscatedHandshake(serverSide, 0x42)
		results <- handshakeResult{conn: conn, err: err}
	}()

	_, clientWriteRC4 := runClientObfuscationHandshake(t, clientSide, clientPrivate, gaBuf)
	writeEncryptedClientFrame(t, clientSide, clientWriteRC4, opGetServerList, nil)

	result := <-results
	if result.err != nil {
		t.Fatalf("server obfuscated handshake failed: %v", result.err)
	}
	defer result.conn.Close()

	header, body, _, err := readFrame(result.conn)
	if err != nil {
		t.Fatalf("read decrypted ED2K frame after handshake: %v", err)
	}
	if header.Protocol != protocol.EdonkeyHeader {
		t.Fatalf("unexpected protocol: 0x%02x", header.Protocol)
	}
	if header.Packet != opGetServerList {
		t.Fatalf("unexpected packet: 0x%02x", header.Packet)
	}
	if len(body) != 0 {
		t.Fatalf("unexpected body length: %d", len(body))
	}
}

func runClientObfuscationHandshake(t *testing.T, conn net.Conn, private *big.Int, remainingGA []byte) (*amuleRC4, *amuleRC4) {
	t.Helper()
	if _, err := conn.Write(remainingGA); err != nil {
		t.Fatalf("write remaining client DH public key: %v", err)
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		t.Fatalf("write client initial padding length: %v", err)
	}

	gbBuf := make([]byte, primeSizeBytes)
	if _, err := io.ReadFull(conn, gbBuf); err != nil {
		t.Fatalf("read server DH public key: %v", err)
	}
	gb := new(big.Int).SetBytes(gbBuf)
	shared := new(big.Int).Exp(gb, private, dh768P)
	s96 := encodeFixed96(shared)
	if s96 == nil {
		t.Fatal("encode shared secret")
	}
	clientReadRC4 := newAmuleRC4(md5Key97(s96, magicValueServer))
	clientWriteRC4 := newAmuleRC4(md5Key97(s96, magicValueRequester))

	serverTail := make([]byte, 7)
	if _, err := io.ReadFull(conn, serverTail); err != nil {
		t.Fatalf("read server handshake tail: %v", err)
	}
	clientReadRC4.xorInPlace(serverTail)
	if binary.LittleEndian.Uint32(serverTail[0:4]) != magicValueSync {
		t.Fatalf("unexpected server magic: 0x%x", binary.LittleEndian.Uint32(serverTail[0:4]))
	}
	padding := int(serverTail[6])
	if padding > 0 {
		pad := make([]byte, padding)
		if _, err := io.ReadFull(conn, pad); err != nil {
			t.Fatalf("read server padding: %v", err)
		}
		clientReadRC4.xorInPlace(pad)
	}

	clientTail := make([]byte, 6)
	binary.LittleEndian.PutUint32(clientTail[0:4], magicValueSync)
	clientTail[4] = enmObfuscation
	clientTail[5] = 0
	clientWriteRC4.xorInPlace(clientTail)
	if _, err := conn.Write(clientTail); err != nil {
		t.Fatalf("write client handshake tail: %v", err)
	}
	return clientReadRC4, clientWriteRC4
}

func writeEncryptedClientFrame(t *testing.T, conn net.Conn, rc4 *amuleRC4, opcode byte, body []byte) {
	t.Helper()
	header := protocol.PacketHeader{
		Protocol: protocol.EdonkeyHeader,
		Size:     int32(len(body) + 1),
		Packet:   opcode,
	}
	var frame bytes.Buffer
	if err := header.Put(&frame); err != nil {
		t.Fatalf("pack ED2K header: %v", err)
	}
	if _, err := frame.Write(body); err != nil {
		t.Fatalf("pack ED2K body: %v", err)
	}
	payload := append([]byte(nil), frame.Bytes()...)
	rc4.xorInPlace(payload)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write encrypted ED2K frame: %v", err)
	}
}
