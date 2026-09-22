package manifest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func (m *Manifest) signingBytes() ([]byte, error) {
	copy := *m
	copy.Signature = ""
	return json.Marshal(copy)
}
func (m *Manifest) Sign(key ed25519.PrivateKey, source, tier string) error {
	if len(key) != ed25519.PrivateKeySize || source == "" || (tier != "config" && tier != "data") {
		return fmt.Errorf("invalid manifest signing configuration")
	}
	m.Source, m.Tier = source, tier
	data, err := m.signingBytes()
	if err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, data))
	return nil
}
func (m *Manifest) Verify(key ed25519.PublicKey, source, tier string) error {
	if len(key) != ed25519.PublicKeySize || m.Source != source || m.Tier != tier {
		return fmt.Errorf("manifest source or tier does not match trusted configuration")
	}
	signature, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return err
	}
	data, err := m.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, data, signature) {
		return fmt.Errorf("manifest signature invalid or missing")
	}
	return nil
}
