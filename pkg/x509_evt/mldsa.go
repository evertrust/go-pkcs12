package x509_evt

import (
	cryptoRand "crypto/rand"
	"fmt"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"io"
)

// MLDSA needs wrapping to save the seed and the format it was created as
type MLDSA44 struct {
	cachedSeed   []byte
	exportFormat seededKeyFormat
	pk           *mldsa44.PublicKey
	*mldsa44.PrivateKey
}

func mldsa44FromBytes(privateKeyBytes []byte) (*MLDSA44, error) {
	alg := "MLDSA-44"

	seed, format, err := seededKeySeedAndFormat(privateKeyBytes, alg)
	if err != nil {
		return nil, err
	}

	if l := len(seed); l != mldsa44.SeedSize {
		return nil, fmt.Errorf("x509: invalid %s private key length: %d", alg, l)
	}

	var seedWithSize [mldsa44.SeedSize]byte

	copy(seedWithSize[:], seed)

	pk, sk := mldsa44.NewKeyFromSeed(&seedWithSize)

	return &MLDSA44{
		cachedSeed:   seed,
		exportFormat: format,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}

func (m *MLDSA44) seed() []byte {
	return m.cachedSeed
}

func (m *MLDSA44) format() seededKeyFormat {
	return m.exportFormat
}

func (m *MLDSA44) expanded() []byte {
	return m.Bytes()
}

func GenerateMLDSA44Key(rand io.Reader) (*MLDSA44, error) {
	var seed [32]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, err
	}
	pk, sk := mldsa44.NewKeyFromSeed(&seed)

	return &MLDSA44{
		cachedSeed:   seed[:],
		exportFormat: seededKeySeedExpanded,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}

type MLDSA65 struct {
	cachedSeed   []byte
	exportFormat seededKeyFormat
	pk           *mldsa65.PublicKey
	*mldsa65.PrivateKey
}

func mldsa65FromBytes(privateKeyBytes []byte) (*MLDSA65, error) {
	alg := "MLDSA-65"

	seed, format, err := seededKeySeedAndFormat(privateKeyBytes, alg)
	if err != nil {
		return nil, err
	}

	if l := len(seed); l != mldsa65.SeedSize {
		return nil, fmt.Errorf("x509: invalid %s private key length: %d", alg, l)
	}

	var seedWithSize [mldsa65.SeedSize]byte

	copy(seedWithSize[:], seed)

	pk, sk := mldsa65.NewKeyFromSeed(&seedWithSize)

	return &MLDSA65{
		cachedSeed:   seed,
		exportFormat: format,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}

func (m *MLDSA65) seed() []byte {
	return m.cachedSeed
}

func (m *MLDSA65) format() seededKeyFormat {
	return m.exportFormat
}

func (m *MLDSA65) expanded() []byte {
	return m.Bytes()
}

func GenerateMLDSA65Key(rand io.Reader) (*MLDSA65, error) {
	var seed [32]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, err
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)

	return &MLDSA65{
		cachedSeed:   seed[:],
		exportFormat: seededKeySeedExpanded,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}

type MLDSA87 struct {
	*mldsa87.PrivateKey
	cachedSeed   []byte
	exportFormat seededKeyFormat
	pk           *mldsa87.PublicKey
}

func mldsa87FromBytes(privateKeyBytes []byte) (*MLDSA87, error) {
	alg := "MLDSA-87"

	seed, format, err := seededKeySeedAndFormat(privateKeyBytes, alg)
	if err != nil {
		return nil, err
	}

	if l := len(seed); l != mldsa87.SeedSize {
		return nil, fmt.Errorf("x509: invalid %s private key length: %d", alg, l)
	}

	var seedWithSize [mldsa87.SeedSize]byte

	copy(seedWithSize[:], seed)

	pk, sk := mldsa87.NewKeyFromSeed(&seedWithSize)

	return &MLDSA87{
		PrivateKey:   sk,
		cachedSeed:   seed,
		exportFormat: format,
		pk:           pk,
	}, nil
}

func (m *MLDSA87) seed() []byte {
	return m.cachedSeed
}

func (m *MLDSA87) format() seededKeyFormat {
	return m.exportFormat
}

func (m *MLDSA87) expanded() []byte {
	return m.Bytes()
}

func GenerateMLDSA87Key(rand io.Reader) (*MLDSA87, error) {
	var seed [32]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, err
	}
	pk, sk := mldsa87.NewKeyFromSeed(&seed)

	return &MLDSA87{
		cachedSeed:   seed[:],
		exportFormat: seededKeySeedExpanded,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}
