package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/ryanx-sir/simple-als/handshake"
	"github.com/ryanx-sir/simple-als/record"
	"github.com/ryanx-sir/simple-als/util"
	"golang.org/x/crypto/pbkdf2"
	"log"
)

/*
** cipherKey: sessionTicket
 */
func (s *server) pskAesGcm(cipherKey []byte, nowTs uint32, clientHello []byte) (_ []byte, err error) {
	ticketKey, expireTs, err := s.ticketEncoder.Decode(cipherKey)
	if err != nil {
		return nil, err
	}
	if expireTs < nowTs {
		return nil, errors.New("session key expire")
	}
	var clientSeq, serverSeq uint32
	clientSeq++ // incr by clientHello

	hasher := sha256.New()
	hasher.Write(clientHello)

	//earlyKey = kdf(ticketKey+clientNonce)
	earlyKey := pbkdf2.Key(ticketKey, append([]byte(util.EarlyKdf),
		hasher.Sum(nil)...), 1, 28, sha256.New) //[key:16+nonce:12]
	if err != nil {
		return
	}
	log.Println("server", "earlyKey", hex.EncodeToString(earlyKey))
	keyPair := *(*[28]byte)(earlyKey)

	// todo 1. readClientData
	record1, err := record.ReadNew(s.reader)
	if err != nil {
		return nil, err
	}
	err = record1.AesGcmDecrypt(keyPair, clientSeq)
	if err != nil {
		return nil, err
	}
	clientSeq++

	// todo 2. sendServerHello
	serverHello := handshake.NewMsg(nowTs, cipherKey, util.PSK_WITH_AES_GCM)
	record2 := record.NewAesGcm(record.TypeHandshake, serverHello.Marshal(handshake.TypServerHello))
	hasher.Write(record2.GetData())
	serverSeq++

	// todo 3. sendServerData
	masterKey := pbkdf2.Key(ticketKey, append([]byte(util.MasterKdf),
		hasher.Sum(nil)...), 1, 28, sha256.New) //[key:16+nonce:12]
	if err != nil {
		return
	}
	log.Println("server", "masterKey", hex.EncodeToString(masterKey))
	keyPair = *(*[28]byte)(masterKey)

	resp := append([]byte("hi, this is server response!\n "), record1.GetData()...) // todo: replace real resp data
	record3 := record.NewAesGcm(record.TypeApplicationData, resp)
	err = record3.AesGcmEncrypt(keyPair, serverSeq)
	if err != nil {
		return
	}
	return append(record2.Marshal(), record3.Marshal()...), nil
}
