package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/ryanx-sir/simple-als/handshake"
	"github.com/ryanx-sir/simple-als/record"
	"github.com/ryanx-sir/simple-als/util"
	"golang.org/x/crypto/pbkdf2"
	"log"
)

/*
** 1-rtt EcdheAesGcm
** cipherKey: client public key
 */
func (s *server) ecdheAesGcm(cipherKey []byte, nowTs uint32, clientHello []byte) (_ []byte, err error) {
	cure := ecdh.P256()
	privateKey, err := cure.GenerateKey(rand.Reader) // 服务端临时生成公、私密钥对
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write(clientHello)

	var serverSeq uint32
	// todo 1. sendServerHello
	serverHello := handshake.NewMsg(nowTs, privateKey.PublicKey().Bytes(), util.DHE_SECP256R1_WITH_AES_GCM)
	record1 := record.NewAesGcm(record.TypeHandshake, serverHello.Marshal(handshake.TypServerHello))
	hasher.Write(record1.GetData())
	serverSeq++

	// todo 2. keys kdf
	publicKey, err := cure.NewPublicKey(cipherKey)
	if err != nil {
		return nil, err
	}
	preSharedKey, _ := privateKey.ECDH(publicKey) // pre shared key
	// 主密钥 = kdf(预主密钥+clientNonce+serverNonce)
	masterKey := pbkdf2.Key(preSharedKey, append([]byte(util.MasterKdf),
		hasher.Sum(nil)...), 1, 28, sha256.New) //[key:16+nonce:12]
	log.Println("server", "masterKey", hex.EncodeToString(masterKey))
	ticketKey := pbkdf2.Key(preSharedKey, append([]byte(util.TicketKdf),
		hasher.Sum(nil)...), 1, 32, sha256.New) //[key:16+nonce:12]
	log.Println("server", "ticketKey", hex.EncodeToString(ticketKey))
	keyPair := *(*[28]byte)(masterKey)

	// todo 3. sendNewSessionTicket
	newTicket := s.ticketEncoder.NewTicket(ticketKey, nowTs)
	ticketData, err := newTicket.Data()
	if err != nil {
		return nil, err
	}
	record2 := record.NewAesGcm(record.TypeHandshake, ticketData)
	hasher.Write(record2.GetData())
	err = record2.AesGcmEncrypt(keyPair, serverSeq)
	if err != nil {
		return
	}
	serverSeq++

	return append(record1.Marshal(), record2.Marshal()...), nil
}
