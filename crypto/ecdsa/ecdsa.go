package ecdsa

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

var (
	curve       = elliptic.P256()
	keyFileName = "ecdsa.private_key"
	keyType     = "CURVE NIST P-256 PRIVATE KEY"

	errGenerateKey             = errors.New("ecdsa: attempted to generate key")
	errImportKey               = errors.New("ecdsa: attempted to import private key from file")
	errParseKey                = errors.New("ecdsa: attempted to parse private key")
	errExportKey               = errors.New("ecdsa: attempted to export private key to file")
	errMarshalKey              = errors.New("ecdsa: attempted to marshal private key")
	errSignData                = errors.New("ecdsa: attempted to sign data")
	errVerifyData              = errors.New("ecdsa: attempted to verify data")
	errConvertPrivateKeyToECDH = errors.New("ecdsa: attempted to convert private key to ecdh")
	errConvertPublicKeyToECDH  = errors.New("ecdsa: attempted to convert public key to ecdh")
)

type ECDSA struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func NewECDSA(keyPath string) (ecdsa *ECDSA) {
	ecdsa = new(ECDSA)

	keyPath = filepath.Join(keyPath, keyFileName)

	err := ecdsa.ImportKeyFromFile(keyPath)
	if err != nil {
		err = ecdsa.GenerateKey()
		if err != nil {
			panic(err)
		}
	}

	err = ecdsa.ExportKeyToFile(keyPath)
	if err != nil {
		panic(err)
	}

	return
}

func (e *ECDSA) GenerateKey() (err error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return errGenerateKey
	}

	e.privateKey = privateKey
	e.publicKey = &privateKey.PublicKey

	return
}

func (e *ECDSA) ImportKeyFromFile(keyPath string) (err error) {
	file, err := os.ReadFile(keyPath)
	if err != nil {
		return errImportKey
	}

	pemBlock, _ := pem.Decode(file)

	privateKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		return errParseKey
	}

	e.privateKey = privateKey
	e.publicKey = &privateKey.PublicKey

	return
}

func (e *ECDSA) ExportKeyToFile(keyPath string) (err error) {
	encodedKey, err := x509.MarshalECPrivateKey(e.privateKey)
	if err != nil {
		return errMarshalKey
	}

	pemBlock := &pem.Block{
		Type:  keyType,
		Bytes: encodedKey,
	}

	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	if err != nil {
		return errExportKey
	}

	return
}

func (e *ECDSA) MarshalPublicKey() (publicKeyBytes []byte) {
	publicKeyBytes = elliptic.MarshalCompressed(curve, e.publicKey.X, e.publicKey.Y)

	return
}

func (e *ECDSA) UnmarshalPublicKey(remotePublicKeyBytes []byte) (publicKey *ecdsa.PublicKey) {
	x, y := elliptic.UnmarshalCompressed(curve, remotePublicKeyBytes)
	publicKey = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	return
}

func (e *ECDSA) SignData(data []byte) (signature []byte, err error) {
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	signature, err = ecdsa.SignASN1(rand.Reader, e.privateKey, hash)
	if err != nil {
		return nil, errSignData
	}

	return
}

func (e *ECDSA) VerifyData(publicKey *ecdsa.PublicKey, data []byte, signature []byte) (err error) {
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)

	valid := ecdsa.VerifyASN1(publicKey, hash, signature)
	if valid == false {
		return errVerifyData
	}

	return
}

func (e *ECDSA) ConvertPrivateKeyToECDH() (privateKeyECDH *ecdh.PrivateKey, err error) {
	privateKeyECDH, err = e.privateKey.ECDH()
	if err != nil {
		return nil, errConvertPrivateKeyToECDH
	}

	return
}

func (e *ECDSA) ConvertPublicKeyToECDH(remotePublicKey *ecdsa.PublicKey) (publicKeyECDH *ecdh.PublicKey, err error) {
	publicKeyECDH, err = remotePublicKey.ECDH()
	if err != nil {
		return nil, errConvertPublicKeyToECDH
	}

	return
}
