package x509_evt

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
)

type seededKeyFormat int

const (
	seededKeySeedOnly seededKeyFormat = iota
	seededKeySeedExpanded
	seededKeyExpandedOnly
)

type seededKey interface {
	seed() []byte
	format() seededKeyFormat
	expanded() []byte
	Public() crypto.PublicKey
}

func toAsn1(m seededKey) ([]byte, error) {
	switch m.format() {
	case seededKeySeedOnly:
		return m.seed(), nil
	case seededKeySeedExpanded:
		attributes := [][]byte{m.seed(), m.expanded()}
		return asn1.Marshal(attributes)
	case seededKeyExpandedOnly:
		return m.expanded(), nil
	}
	return nil, errors.New("unsupported seeded key format when marshalling")
}

func seededKeySeedAndFormat(privateKeyBytes []byte, alg string) ([]byte, seededKeyFormat, error) {
	// Two formats can occur for Seeded Keys: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates-13#name-asn1-module

	var asSeq [][]byte

	seed := privateKeyBytes
	format := seededKeySeedOnly

	_, err := asn1.Unmarshal(seed, &asSeq)
	if err == nil {
		if l := len(asSeq); l < 2 {
			return nil, 0, fmt.Errorf("x509: invalid %s private key sequence length: %d", alg, l)
		}
		seed = asSeq[0]
		format = seededKeySeedExpanded
	}

	return seed, format, nil
}
