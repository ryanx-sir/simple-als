package record

import (
	"encoding/binary"
	"errors"
	"github.com/ryanx-sir/simple-als/util"
	"golang.org/x/crypto/nacl/box"
	"io"
)

type recordTyp = uint8

const ProtocolAesGcm uint8 = 0b01
const ProtocolXsalsa20Poly1305 uint8 = 0b10

var ErrRecordVersion = errors.New("record version error")

const (
	TypeChangeCipherSpec uint8 = 0x11 + iota
	TypeAlert
	TypeHandshake
	TypeApplicationData
)

// todo add record interface
type record struct {
	typ     uint8
	version uint8
	length  uint16
	data    []byte
}

func NewAesGcm(typ recordTyp, data []byte) *record {
	return newRecord(typ, ProtocolAesGcm, data)
}

func NewXsalsa20Poly1305(typ recordTyp, data []byte) *record {
	return newRecord(typ, ProtocolXsalsa20Poly1305, data)
}

func newRecord(typ recordTyp, version uint8, data []byte) *record {
	return &record{
		typ:     typ,
		version: version,
		length:  uint16(len(data)),
		data:    data,
	}
}

// ReadNew
// todo change to interface
func ReadNew(buf io.Reader) (*record, error) {
	r := &record{}

	if err := binary.Read(buf, binary.BigEndian, &r.typ); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &r.version); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &r.length); err != nil {
		return nil, err
	}
	r.data = make([]byte, r.length)
	if _, err := buf.Read(r.data); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *record) GetData() []byte {
	if r == nil {
		return nil
	}
	return r.data
}

func (r *record) Type() uint8 {
	if r == nil {
		return 0
	}
	return r.typ
}

func (r *record) Marshal() []byte {
	buf := make([]byte, r.length+4)

	buf[0] = r.typ
	buf[1] = r.version
	binary.BigEndian.PutUint16(buf[2:], r.length)
	copy(buf[4:], r.data)

	return buf
}

func (r *record) AesGcmEncrypt(keyPair [28]byte, seqNum uint32) error {
	if r.version != ProtocolAesGcm {
		return ErrRecordVersion
	}
	nonce := make([]byte, 12)
	copy(nonce, keyPair[16:])
	util.XorNonce(nonce, seqNum)

	addit := make([]byte, 13)
	binary.BigEndian.PutUint64(addit, uint64(seqNum))
	addit[8] = r.typ
	addit[9] = r.version
	// GCM add 16-byte tag
	binary.BigEndian.PutUint16(addit[11:], r.length+16)

	encrypt, err := util.AesGcmEncrypt(keyPair[:16], nonce, r.data, addit)
	if err != nil {
		return err
	}
	r.data = encrypt
	r.length = uint16(len(encrypt))
	return nil
}

func (r *record) AesGcmDecrypt(keyPair [28]byte, seqNum uint32) error {
	if r.version != ProtocolAesGcm {
		return ErrRecordVersion
	}
	nonce := make([]byte, 12)
	copy(nonce, keyPair[16:])
	util.XorNonce(nonce, seqNum)

	addit := make([]byte, 13)
	binary.BigEndian.PutUint64(addit, uint64(seqNum))
	addit[8] = r.typ
	addit[9] = r.version
	binary.BigEndian.PutUint16(addit[11:], r.length)

	decrypt, err := util.AesGcmDecrypt(keyPair[:16], nonce, r.data, addit)
	if err != nil {
		return err
	}
	r.data = decrypt
	r.length = uint16(len(decrypt))
	return nil
}

func (r *record) NaclBox(nonce *[24]byte, peersPublicKey, privateKey *[32]byte) error {
	if r.version != ProtocolXsalsa20Poly1305 {
		return ErrRecordVersion
	}
	nonce[8] = r.typ
	nonce[9] = r.version
	encrypt := box.Seal(nil, r.data, nonce, peersPublicKey, privateKey)
	r.data = encrypt
	r.length = uint16(len(encrypt))
	return nil
}

func (r *record) NaclUnbox(nonce *[24]byte, peersPublicKey, privateKey *[32]byte) error {
	if r.version != ProtocolXsalsa20Poly1305 {
		return ErrRecordVersion
	}
	nonce[8] = r.typ
	nonce[9] = r.version
	decrypt, _ := box.Open(nil, r.data, nonce, peersPublicKey, privateKey)
	r.data = decrypt
	r.length = uint16(len(decrypt))
	return nil
}
