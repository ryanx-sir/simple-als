package util

const (
	DHE_SECP256R1_WITH_AES_GCM        uint8 = 0xc9
	DHE_X25519_WITH_XSALSA20_POLY1305 uint8 = 0xca
	PSK_WITH_AES_GCM                  uint8 = 0xcb
	PSK_WITH_XSALSA20_POLY1305        uint8 = 0xcc
)

const (
	EarlyKdf  = "the early kdf key"
	MasterKdf = "the master kdf key"
	TicketKdf = "the ticket kdf key"
)
