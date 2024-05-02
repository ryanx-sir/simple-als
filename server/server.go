package server

import (
	"errors"
	"fmt"
	"github.com/ryanx-sir/simple-als/handshake"
	"github.com/ryanx-sir/simple-als/record"
	"github.com/ryanx-sir/simple-als/ticket"
	"github.com/ryanx-sir/simple-als/util"
	"io"
	"time"
)

type server struct {
	reader        io.Reader
	ticketEncoder *ticket.Encoder
}

func NewServer(ticketEncoder *ticket.Encoder) *server {
	return &server{ticketEncoder: ticketEncoder}
}

// Handle
func (s *server) Handle(reader io.Reader) (_ []byte, err error) {
	if reader == nil {
		return nil, errors.New("reader is nil")
	}
	nowTs := time.Now().Unix()
	helloRecord, err := record.ReadNew(reader)
	if err != nil {
		return nil, err
	}
	helloData := helloRecord.GetData()
	clientHello, err := handshake.Unmarshal(helloRecord.GetData(), handshake.TypClientHello)
	if err != nil {
		return nil, err
	}
	s.reader = reader
	switch clientHello.CipherSuite() {
	case util.DHE_SECP256R1_WITH_AES_GCM: // 1-RTT ECDHE
		return s.ecdheAesGcm(clientHello.CipherKey(), uint32(nowTs), helloData)
	case util.DHE_X25519_WITH_XSALSA20_POLY1305: // 1-RTT ECDHE
		return s.ecdheNacl(clientHello.CipherKey(), uint32(nowTs), helloData)
	case util.PSK_WITH_AES_GCM: // 0-RTT PSK
		return s.pskAesGcm(clientHello.CipherKey(), uint32(nowTs), helloData)
	case util.PSK_WITH_XSALSA20_POLY1305:
		// todo
	}
	return nil, fmt.Errorf("cipher(%d) not support", clientHello.CipherSuite())
}
