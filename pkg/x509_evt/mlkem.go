package x509_evt

import (
	"crypto"
	cryptoRand "crypto/rand"
	"fmt"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"io"
)

// MLKEM needs wrapping to save the seed and the format it was created as
type MLKEM512 struct {
	cachedSeed   []byte
	exportFormat seededKeyFormat
	pk           *mlkem512.PublicKey
	*mlkem512.PrivateKey
}

func mlkem512FromBytes(privateKeyBytes []byte) (*MLKEM512, error) {
	alg := "MLKEM-512"

	seed, format, err := seededKeySeedAndFormat(privateKeyBytes, alg)
	if err != nil {
		return nil, err
	}

	if l := len(seed); l != mlkem512.KeySeedSize {
		return nil, fmt.Errorf("x509: invalid %s private key length: %d", alg, l)
	}

	pk, sk := mlkem512.NewKeyFromSeed(seed)

	return &MLKEM512{
		cachedSeed:   seed,
		exportFormat: format,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}

func (m *MLKEM512) seed() []byte {
	return m.cachedSeed
}

func (m *MLKEM512) format() seededKeyFormat {
	return m.exportFormat
}

func (m *MLKEM512) expanded() []byte {
	var buf [mlkem512.PrivateKeySize]byte
	m.Pack(buf[:])
	return buf[:]
}

func (m *MLKEM512) Public() crypto.PublicKey {
	return m.pk
}

func GenerateMLKEM512Key(rand io.Reader) (*MLKEM512, error) {
	var seed [mlkem512.KeySeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, err
	}
	pk, sk := mlkem512.NewKeyFromSeed(seed[:])
	return &MLKEM512{
		cachedSeed:   seed[:],
		exportFormat: seededKeySeedExpanded,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}

type MLKEM768 struct {
	cachedSeed   []byte
	exportFormat seededKeyFormat
	pk           *mlkem768.PublicKey
	*mlkem768.PrivateKey
}

func mlkem768FromBytes(privateKeyBytes []byte) (*MLKEM768, error) {
	alg := "MLKEM-768"

	seed, format, err := seededKeySeedAndFormat(privateKeyBytes, alg)
	if err != nil {
		return nil, err
	}

	if l := len(seed); l != mlkem768.KeySeedSize {
		return nil, fmt.Errorf("x509: invalid %s private key length: %d", alg, l)
	}

	pk, sk := mlkem768.NewKeyFromSeed(seed)

	return &MLKEM768{
		cachedSeed:   seed,
		exportFormat: format,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}

func (m *MLKEM768) seed() []byte {
	return m.cachedSeed
}

func (m *MLKEM768) format() seededKeyFormat {
	return m.exportFormat
}

func (m *MLKEM768) expanded() []byte {
	var buf [mlkem768.PrivateKeySize]byte
	m.Pack(buf[:])
	return buf[:]
}

func (m *MLKEM768) Public() crypto.PublicKey {
	return m.pk
}

func GenerateMLKEM768Key(rand io.Reader) (*MLKEM768, error) {
	var seed [mlkem768.KeySeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, err
	}
	pk, sk := mlkem768.NewKeyFromSeed(seed[:])
	return &MLKEM768{
		cachedSeed:   seed[:],
		exportFormat: seededKeySeedExpanded,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}

type MLKEM1024 struct {
	cachedSeed   []byte
	exportFormat seededKeyFormat
	pk           *mlkem1024.PublicKey
	*mlkem1024.PrivateKey
}

func mlkem1024FromBytes(privateKeyBytes []byte) (*MLKEM1024, error) {
	alg := "MLKEM-1024"

	seed, format, err := seededKeySeedAndFormat(privateKeyBytes, alg)
	if err != nil {
		return nil, err
	}

	if l := len(seed); l != mlkem1024.KeySeedSize {
		return nil, fmt.Errorf("x509: invalid %s private key length: %d", alg, l)
	}

	pk, sk := mlkem1024.NewKeyFromSeed(seed)

	return &MLKEM1024{
		cachedSeed:   seed,
		exportFormat: format,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}

func (m *MLKEM1024) seed() []byte {
	return m.cachedSeed
}

func (m *MLKEM1024) format() seededKeyFormat {
	return m.exportFormat
}

func (m *MLKEM1024) expanded() []byte {
	var buf [mlkem1024.PrivateKeySize]byte
	m.Pack(buf[:])
	return buf[:]
}

func (m *MLKEM1024) Public() crypto.PublicKey {
	return m.pk
}

func GenerateMLKEM1024Key(rand io.Reader) (*MLKEM1024, error) {
	var seed [mlkem1024.KeySeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, err
	}
	pk, sk := mlkem1024.NewKeyFromSeed(seed[:])
	return &MLKEM1024{
		cachedSeed:   seed[:],
		exportFormat: seededKeySeedExpanded,
		pk:           pk,
		PrivateKey:   sk,
	}, nil
}
