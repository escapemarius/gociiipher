package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	errEncrypt = errors.New("aead: attempted to encrypt data")
	errDecrypt = errors.New("aead: attempted to decrypt data")
)

func EncryptData(key []byte, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, errEncrypt
	}

	nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, errEncrypt
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, errEncrypt
	}

	ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)

	return
}

func DecryptData(key []byte, nonce []byte, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errDecrypt
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errDecrypt
	}

	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errDecrypt
	}

	return
}
