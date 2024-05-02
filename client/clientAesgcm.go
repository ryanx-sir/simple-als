package client

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/ryanx-sir/simple-als/handshake"
	"github.com/ryanx-sir/simple-als/record"
	"github.com/ryanx-sir/simple-als/util"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"log"
	"net/http"
	"time"
)

type aesGcmClient struct {
	host                string
	ticketKey           []byte
	sessionTicket       []byte
	sessionTicketExpire uint32
}

func NewAesGcmClient(host string) *aesGcmClient {
	return &aesGcmClient{host: host}
}

// Handshake
// 1-rtt ecdhe
func (c *aesGcmClient) Handshake() error {
	cure := ecdh.P256()
	privateKey, err := cure.GenerateKey(rand.Reader) // 客户端临时生成公、私密钥对
	if err != nil {
		return err
	}
	nowTs := time.Now().Unix()
	hasher := sha256.New()

	clientHello := handshake.NewMsg(uint32(nowTs), privateKey.PublicKey().Bytes(), util.DHE_SECP256R1_WITH_AES_GCM)
	record0 := record.NewAesGcm(record.TypeHandshake, clientHello.Marshal(handshake.TypClientHello))
	hasher.Write(record0.GetData())

	// todo 0. sendClientHello
	resp, err := http.Get(c.host + "?hello=" + base64.RawURLEncoding.EncodeToString(record0.Marshal()))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	recv_data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	serverRes := bytes.NewReader(recv_data)
	var serverSeq uint32

	// todo 1. readServerHello
	record1, err := record.ReadNew(serverRes)
	if err != nil {
		return err
	}
	if record1.Type() != record.TypeHandshake {
		return util.ErrDataCorrupted
	}
	hasher.Write(record1.GetData())
	serverSeq++
	serverHello, err := handshake.Unmarshal(record1.GetData(), handshake.TypServerHello)
	if err != nil {
		return err
	}
	if serverHello.CipherSuite() != util.DHE_SECP256R1_WITH_AES_GCM {
		return errors.New("cipher not support")
	}
	// todo 2. keys kdf
	publicKey, err := cure.NewPublicKey(serverHello.CipherKey())
	if err != nil {
		return err
	}
	preSharedKey, _ := privateKey.ECDH(publicKey) // pre shared key
	// 主密钥 = kdf(预主密钥+clientNonce+serverNonce)
	masterKey := pbkdf2.Key(preSharedKey, append([]byte(util.MasterKdf),
		hasher.Sum(nil)...), 1, 28, sha256.New) //[key:16+nonce:12]
	log.Println("client", "masterKey", hex.EncodeToString(masterKey))
	ticketKey := pbkdf2.Key(preSharedKey, append([]byte(util.TicketKdf),
		hasher.Sum(nil)...), 1, 32, sha256.New) //[key:16+nonce:12]
	log.Println("client", "ticketKey", hex.EncodeToString(ticketKey))
	keyPair := *(*[28]byte)(masterKey)

	// todo 3. readNewSessionTicket
	record2, err := record.ReadNew(serverRes)
	if err != nil {
		return err
	}
	if err = record2.AesGcmDecrypt(keyPair, serverSeq); err != nil {
		return err
	}
	c.ticketKey = ticketKey
	c.sessionTicketExpire = binary.BigEndian.Uint32(record2.GetData()[:4])
	c.sessionTicket = record2.GetData()[4:]
	return nil
}

// Request
// 0-RTT PSK
func (c *aesGcmClient) Request(data []byte) (_ []byte, err error) {
	nowTs := time.Now().Unix()
	var clientSeq, serverSeq uint32
	hasher := sha256.New()

	clientHello := handshake.NewMsg(uint32(nowTs), c.sessionTicket, util.PSK_WITH_AES_GCM)
	record1 := record.NewAesGcm(record.TypeHandshake, clientHello.Marshal(handshake.TypClientHello))
	hasher.Write(record1.GetData())
	clientSeq++

	//earlyKey = kdf(ticketKey+clientNonce)
	earlyKey := pbkdf2.Key(c.ticketKey, append([]byte(util.EarlyKdf),
		hasher.Sum(nil)...), 1, 28, sha256.New) //[key:16+nonce:12]
	if err != nil {
		return
	}
	log.Println("client", "earlyKey", hex.EncodeToString(earlyKey))
	keyPair := *(*[28]byte)(earlyKey)

	record2 := record.NewAesGcm(record.TypeApplicationData, data)
	err = record2.AesGcmEncrypt(keyPair, clientSeq)
	if err != nil {
		return
	}
	clientSeq++

	//
	payload := append(record1.Marshal(), record2.Marshal()...)
	log.Println("client", "payload", hex.EncodeToString(payload))

	resp, err := http.Post(c.host, "application/x-wdals", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	recv_data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	log.Println("client", "recv_data", hex.EncodeToString(recv_data))

	serverRes := bytes.NewReader(recv_data)

	// todo 1. readServerHello
	record3, err := record.ReadNew(serverRes)
	if err != nil {
		return nil, err
	}
	hasher.Write(record3.GetData())
	serverSeq++

	// todo 2.readServerData
	masterKey := pbkdf2.Key(c.ticketKey, append([]byte(util.MasterKdf),
		hasher.Sum(nil)...), 1, 28, sha256.New) //[key:16+nonce:12]
	if err != nil {
		return
	}
	log.Println("client", "masterKey", hex.EncodeToString(masterKey))
	keyPair = *(*[28]byte)(masterKey)

	dataRecord, err := record.ReadNew(serverRes)
	if err != nil {
		return nil, err
	}
	if err = dataRecord.AesGcmDecrypt(keyPair, serverSeq); err != nil {
		return nil, err
	}
	return dataRecord.GetData(), nil
}
