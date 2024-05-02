package wdals

import (
	"github.com/ryanx-sir/simple-als/client"
	"github.com/ryanx-sir/simple-als/server"
	"github.com/ryanx-sir/simple-als/ticket"
	"github.com/ryanx-sir/simple-als/util"
	"io"
)

const (
	DHE_SECP256R1_WITH_AES_GCM        = util.DHE_SECP256R1_WITH_AES_GCM
	DHE_X25519_WITH_XSALSA20_POLY1305 = util.DHE_X25519_WITH_XSALSA20_POLY1305
	PSK_WITH_AES_GCM                  = util.PSK_WITH_AES_GCM
	PSK_WITH_XSALSA20_POLY1305        = util.PSK_WITH_XSALSA20_POLY1305
)

type Server interface {
	Handle(io.Reader) ([]byte, error)
}

// 应用层client
type AlClient interface {
	Handshake() error
	Request([]byte) ([]byte, error)
}

func NewSimpleServer(ticketEncoder *ticket.Encoder) Server {
	return server.NewServer(ticketEncoder)
}

func NewAesGcmClient(host string) AlClient {
	return client.NewAesGcmClient(host)
}