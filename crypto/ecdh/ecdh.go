package ecdh

import (
	"crypto/ecdh"
	"errors"

	"gociiipher/crypto/ecdsa"
)

var (
	errGenerateSharedKey = errors.New("ecdh: attempted to generate shared key.")
)

type ECDH struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
}

func NewECDH(ecdsa *ecdsa.ECDSA) (ecdh *ECDH) {
	ecdh = new(ECDH)

	privateKey, err := ecdsa.ConvertPrivateKeyToECDH()
	if err != nil {
		panic(err)
	}

	ecdh.privateKey = privateKey
	ecdh.publicKey = privateKey.PublicKey()

	return
}

func (e *ECDH) GenerateSharedKey(remotePublicKey *ecdh.PublicKey) (sharedKey []byte, err error) {
	sharedKey, err = e.privateKey.ECDH(remotePublicKey)
	if err != nil {
		return nil, errGenerateSharedKey
	}

	return
}
