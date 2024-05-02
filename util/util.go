package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

var ErrDataCorrupted = errors.New("data corrupted")

func XorNonce(nonce []byte, seq uint32) {
	seqBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBytes, seq)

	for i := 0; i < 4; i++ {
		pos := len(nonce) - i - 1
		nonce[pos] = nonce[pos] ^ seqBytes[i]
	}
}

func Random(n int) []byte {
	key := make([]byte, n)
	rand.Read(key)
	return key
}

func AesGcmDecrypt(key, nonce, input, additional []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, input, additional)
}

func AesGcmEncrypt(key, nonce, input, additional []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce, input, additional), nil
}
