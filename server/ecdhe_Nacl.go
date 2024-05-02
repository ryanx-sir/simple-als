package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/ryanx-sir/simple-als/handshake"
	"github.com/ryanx-sir/simple-als/record"
	"github.com/ryanx-sir/simple-als/util"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/pbkdf2"
	"log"
)

/*
** 1-rtt ecdheNacl
** cipherKey: client public key
 */
func (s *server) ecdheNacl(cipherKey []byte, nowTs uint32, clientHello []byte) (_ []byte, err error) {
	if len(cipherKey) != 32 {
		return nil, util.ErrDataCorrupted
	}
	publicKey, privateKey, err := box.GenerateKey(rand.Reader) // 服务端临时生成公、私密钥对
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write(clientHello)

	// todo 1. sendServerHello
	serverHello := handshake.NewMsg(nowTs, publicKey[:], util.DHE_X25519_WITH_XSALSA20_POLY1305)
	record1 := record.NewXsalsa20Poly1305(record.TypeHandshake, serverHello.Marshal(handshake.TypServerHello))
	hasher.Write(record1.GetData())

	// todo 2. keys kdf
	preSharedKey, err := curve25519.X25519(privateKey[:], cipherKey) // pre shared key
	if err != nil {
		return nil, err
	}
	masterKey := pbkdf2.Key(preSharedKey, append([]byte(util.MasterKdf),
		hasher.Sum(nil)...), 1, 24, sha256.New)
	log.Println("server", "masterKey", hex.EncodeToString(masterKey))

	ticketKey := pbkdf2.Key(preSharedKey, append([]byte(util.TicketKdf),
		hasher.Sum(nil)...), 1, 32, sha256.New)
	log.Println("server", "ticketKey", hex.EncodeToString(ticketKey))

	// todo 3. sendNewSessionTicket
	newTicket := s.ticketEncoder.NewTicket(ticketKey, nowTs)
	ticketData, err := newTicket.Data()
	if err != nil {
		return nil, err
	}
	record2 := record.NewXsalsa20Poly1305(record.TypeHandshake, ticketData)
	record2.NaclBox((*[24]byte)(masterKey), (*[32]byte)(cipherKey), privateKey)

	return append(record1.Marshal(), record2.Marshal()...), nil
}
