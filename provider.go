package simpleAuth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"math/big"
)

type Storage interface {
	// set public key, private key and data
	Set(string, string, interface{}) error
	// get public key, private key and data given a public key
	Get(string) (string, string, interface{}, error)
}

func NewProvider(db Storage, publicSize, privateSize int) *Provider {
	return &Provider{db, publicSize, privateSize}
}

type Provider struct {
	Storage
	publicSize  int
	privateSize int
}

// create new api public and private keys and assign them data
func (p *Provider) Create(data interface{}) (string, string, interface{}, error) {
	pubKey, _ := newKey(p.publicSize)
	privKey, _ := newKey(p.privateSize)
	if err := p.Set(pubKey, privKey, data); err != nil {
		return "", "", nil, err
	}
	return pubKey, privKey, data, nil
}

// verify that public key matches with encoded data and return public key, private key and data
// eventually check time
func (p *Provider) Verify(pubKey, reqData, hexMAC string) (interface{}, error) {
	_, privKey, data, err := p.Get(pubKey)
	if err != nil {
		return nil, err
	}

   // get hmac-sha1 hash of provided request data
	mac := hmac.New(sha1.New, []byte(privKey))
	mac.Write([]byte(reqData))
	expectedMAC := mac.Sum(nil)

	// decode hexMAC
	providedMAC, err := hex.DecodeString(hexMAC)
	if err != nil {
		return nil, errors.New("Hex Failure")
	}

	// make sure data is valid
	if hmac.Equal(expectedMAC, []byte(providedMAC)) {
		return data, nil
	}
	return nil, errors.New("Keys don't match")
}

func newKey(size int) (string, error) {
	alphaNumeric := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := ""
	for i := 0; i < size; i++ {
		r, err := rand.Int(rand.Reader, big.NewInt(62))
		if err != nil {
			return "", err
		}
		out += string(alphaNumeric[r.Int64()])
	}
	return out, nil
}
