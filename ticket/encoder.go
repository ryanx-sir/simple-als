package ticket

import (
	"errors"
	"time"
)

var ErrTicketVersion = errors.New("ticket version err")
var ErrTicketDecode = errors.New("ticket decode err")

type SecretKey = [32]byte

type Encoder struct {
	version     uint16
	secretKey   map[uint16]SecretKey
	ticketAlive uint32
}

func NewEncoder(ticketAlive time.Duration, secretKey map[uint16]SecretKey) (e *Encoder) {
	if len(secretKey) == 0 {
		panic("ticket secret nil")
	}
	var max uint16
	for version := range secretKey {
		if version > max {
			max = version
		}
	}
	return &Encoder{
		version:     max,
		secretKey:   secretKey,
		ticketAlive: uint32(ticketAlive.Seconds()),
	}
}

func (e Encoder) NewTicket(ticketKey []byte, now uint32) *sessionTicket {
	return &sessionTicket{
		version:   e.version,
		expireTs:  now + e.ticketAlive,
		ticketKey: ticketKey,
		secret:    e.secretKey[e.version],
	}
}

func (e Encoder) Decode(data []byte) (ticketKey []byte, expireTs uint32, err error) {
	ticket, err := matchTicketVer(data)
	if err != nil {
		return nil, 0, errors.Join(ErrTicketVersion, err)
	}
	var verOk bool
	ticket.secret, verOk = e.secretKey[ticket.version]
	if !verOk {
		return nil, 0, ErrTicketVersion
	}
	err = ticket.decrypt(data)
	if err != nil {
		return nil, 0, errors.Join(ErrTicketDecode, err)
	}
	return ticket.ticketKey, ticket.expireTs, nil
}
