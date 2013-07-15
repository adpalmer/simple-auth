package simpleAuth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"hash"
)

func NewConsumer(priv string) *Consumer {
	return &Consumer{hmac.New(sha1.New, []byte(priv))}
}

type Consumer struct {
	encoder hash.Hash
}

// Encode String
func (c *Consumer) Encode(data string) string {
	c.encoder.Write([]byte(data))
	encData := c.encoder.Sum(nil)
	defer c.encoder.Reset()
	return hex.EncodeToString(encData)
}
