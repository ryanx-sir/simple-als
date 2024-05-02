package ticket

import (
	"encoding/binary"
	"errors"
	"github.com/ryanx-sir/simple-als/util"
	"golang.org/x/crypto/nacl/secretbox"
)

var ErrTicketIllegal = errors.New("ticket illegal")

// sessionTicket
type sessionTicket struct {
	version   uint16 // 加解密版本
	expireTs  uint32 // 过期时间
	ticketKey []byte
	secret    SecretKey
}

func (t *sessionTicket) Data() (data []byte, err error) {
	ticket, err := t.encrypt()
	if err != nil {
		return nil, err
	}
	data = make([]byte, 4+len(ticket))
	binary.BigEndian.PutUint32(data, t.expireTs)
	copy(data[4:], ticket) // expireTs+ticket
	return
}

// 加密，且只有服务端才能解密
func (t *sessionTicket) encrypt() ([]byte, error) {
	data := make([]byte, 4, 4+len(t.ticketKey))
	binary.BigEndian.PutUint32(data, t.expireTs)
	data = append(data, t.ticketKey...)

	nonce := util.Random(22)
	nonce = binary.BigEndian.AppendUint16(nonce, t.version)
	encrypted := secretbox.Seal(nonce[:], data, (*[24]byte)(nonce), &t.secret)
	return encrypted, nil
}

func (t *sessionTicket) decrypt(data []byte) (err error) {
	if len(data) < 24 {
		return ErrTicketIllegal
	}
	var nonce [24]byte
	copy(nonce[:], data[:24])
	t.version = binary.BigEndian.Uint16(nonce[22:])
	decrypted, ok := secretbox.Open(nil, data[24:], &nonce, &t.secret)
	if !ok {
		return ErrTicketIllegal
	}
	t.expireTs = binary.BigEndian.Uint32(decrypted[:4])
	t.ticketKey = decrypted[4:]
	return
}

func matchTicketVer(data []byte) (t *sessionTicket, err error) {
	if len(data) < 24 {
		return nil, ErrTicketIllegal
	}
	return &sessionTicket{version: binary.BigEndian.Uint16(data[22:24])}, nil
}
