package handshake

import (
	"bytes"
	"encoding/binary"
	"github.com/ryanx-sir/simple-als/util"
	"io"
)

type handshakeTyp = uint8

const (
	TypHelloRequest     handshakeTyp = 0
	TypClientHello      handshakeTyp = 1
	TypServerHello      handshakeTyp = 2
	TypNewSessionTicket handshakeTyp = 4
)

// handshakeMsg
type handshakeMsg struct {
	nonce       []byte
	ts          uint32
	cipherSuite uint8
	cipherKey   []byte
}

func NewMsg(ts uint32, cipherKey []byte, cipherSuite uint8) *handshakeMsg {
	return &handshakeMsg{
		nonce:       util.Random(32),
		ts:          ts,
		cipherSuite: cipherSuite,
		cipherKey:   cipherKey,
	}
}

func (m *handshakeMsg) CipherSuite() uint8 {
	if m == nil {
		return 0
	}
	return m.cipherSuite
}
func (m *handshakeMsg) CipherKey() []byte {
	if m == nil {
		return nil
	}
	return m.cipherKey
}

func (m *handshakeMsg) Marshal(typ handshakeTyp) []byte {
	hello := make([]byte, 0, 8+len(m.nonce)+len(m.cipherKey))              // total length
	hello = append(hello, typ)                                             // handshake type
	hello = append(hello, m.nonce...)                                      // nonce
	hello = binary.BigEndian.AppendUint32(hello, m.ts)                     // timestamp
	hello = append(hello, m.cipherSuite)                                   // cipher suite type
	hello = binary.BigEndian.AppendUint16(hello, uint16(len(m.cipherKey))) // cipher key
	return append(hello, m.cipherKey...)
}

func Unmarshal(data []byte, typ handshakeTyp) (_ *handshakeMsg, err error) {
	if len(data) < 40 {
		return nil, util.ErrDataCorrupted
	}
	if data[0] != typ {
		return nil, util.ErrDataCorrupted
	}
	r := bytes.NewReader(data)
	if _, err = r.Seek(1, io.SeekCurrent); err != nil { // skip handshake type
		return
	}
	nonce := make([]byte, 32)
	if _, err = r.Read(nonce); err != nil {
		return
	}
	var ts uint32
	if err = binary.Read(r, binary.BigEndian, &ts); err != nil {
		return
	}
	cipherSuite, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	var keyLen uint16
	if err = binary.Read(r, binary.BigEndian, &keyLen); err != nil {
		return
	}
	cipherKey := make([]byte, keyLen)
	if _, err = r.Read(cipherKey); err != nil {
		return
	}
	if r.Len() != 0 {
		return nil, util.ErrDataCorrupted
	}
	return &handshakeMsg{
		nonce:       nonce,
		ts:          ts,
		cipherSuite: cipherSuite,
		cipherKey:   cipherKey,
	}, nil
}
