package pkcs12

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"
	"time"
)

// oidTestKey identifies testKey in PKCS#8, an algorithm crypto/x509 does not know.
var oidTestKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// testKey stands for a key type crypto/x509 cannot encode, such as a post-quantum key. It signs
// with Ed25519 so that a certificate can be issued for it.
type testKey struct {
	key ed25519.PrivateKey
}

type testPublicKey struct {
	key ed25519.PublicKey
}

func (k *testKey) Public() crypto.PublicKey {
	return &testPublicKey{key: k.key.Public().(ed25519.PublicKey)}
}

func (k *testKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.key.Sign(random, message, opts)
}

type testPKCS8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// testKeyCodec handles testKey and delegates every other key to crypto/x509.
type testKeyCodec struct{}

func (testKeyCodec) ParsePKCS8PrivateKey(der []byte) (interface{}, error) {
	var envelope testPKCS8
	if _, err := asn1.Unmarshal(der, &envelope); err == nil && envelope.Algo.Algorithm.Equal(oidTestKey) {
		return &testKey{key: ed25519.NewKeyFromSeed(envelope.PrivateKey)}, nil
	}
	return x509.ParsePKCS8PrivateKey(der)
}

func (testKeyCodec) MarshalPKCS8PrivateKey(privateKey interface{}) ([]byte, error) {
	if k, ok := privateKey.(*testKey); ok {
		return asn1.Marshal(testPKCS8{
			Algo:       pkix.AlgorithmIdentifier{Algorithm: oidTestKey},
			PrivateKey: k.key.Seed(),
		})
	}
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

func (testKeyCodec) MarshalPKIXPublicKey(publicKey interface{}) ([]byte, error) {
	if k, ok := publicKey.(*testPublicKey); ok {
		return x509.MarshalPKIXPublicKey(k.key)
	}
	return x509.MarshalPKIXPublicKey(publicKey)
}

func newTestCert(t *testing.T, cn string, isCA bool, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// newTestChain returns a testKey, its certificate and the issuing CA certificate.
func newTestChain(t *testing.T) (*testKey, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCert(t, "test ca", true, caKey.Public(), nil, caKey)
	_, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := newTestCert(t, "test leaf", false, leafKey.Public(), ca, caKey)
	return &testKey{key: leafKey}, leaf, ca
}

func TestKeyCodecRoundTrip(t *testing.T) {
	encoders := map[string]*Encoder{
		"Modern2023":   Modern2023,
		"LegacyRC2":    LegacyRC2,
		"Passwordless": Passwordless,
	}
	for name, encoder := range encoders {
		t.Run(name, func(t *testing.T) {
			password := "password"
			if encoder == Passwordless {
				password = ""
			}
			key, leaf, ca := newTestChain(t)

			pfx, err := encoder.WithKeyCodec(testKeyCodec{}).Encode(key, leaf, []*x509.Certificate{ca}, password)
			if err != nil {
				t.Fatal(err)
			}

			decoded, certificate, caCerts, err := NewDecoder().WithKeyCodec(testKeyCodec{}).DecodeChain(pfx, password)
			if err != nil {
				t.Fatal(err)
			}
			decodedKey, ok := decoded.(*testKey)
			if !ok {
				t.Fatalf("expected *testKey, got %T", decoded)
			}
			if !decodedKey.key.Equal(key.key) {
				t.Error("decoded key differs from the encoded one")
			}
			if !certificate.Equal(leaf) {
				t.Errorf("expected leaf certificate, got %q", certificate.Subject.CommonName)
			}
			if len(caCerts) != 1 || !caCerts[0].Equal(ca) {
				t.Errorf("expected the CA certificate in the chain, got %d certificates", len(caCerts))
			}

			if _, _, _, err := DecodeChain(pfx, password); err == nil {
				t.Error("expected the default decoder to reject a key type crypto/x509 does not know")
			}
		})
	}
}

// The leaf certificate is found by its SubjectPublicKeyInfo even when the private key type does
// not match the type crypto/x509 parsed from the certificate.
func TestKeyCodecFindsLeafCertificate(t *testing.T) {
	key, leaf, ca := newTestChain(t)
	pfx, err := Modern2023.WithKeyCodec(testKeyCodec{}).Encode(key, ca, []*x509.Certificate{leaf}, "password")
	if err != nil {
		t.Fatal(err)
	}

	_, certificate, caCerts, err := NewDecoder().WithKeyCodec(testKeyCodec{}).DecodeChain(pfx, "password")
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.Equal(leaf) {
		t.Errorf("expected leaf certificate, got %q", certificate.Subject.CommonName)
	}
	if len(caCerts) != 1 || !caCerts[0].Equal(ca) {
		t.Errorf("expected the CA certificate in the chain, got %d certificates", len(caCerts))
	}
}

func TestDefaultEncoderRejectsUnknownKeyType(t *testing.T) {
	key, leaf, ca := newTestChain(t)
	if _, err := Modern2023.Encode(key, leaf, []*x509.Certificate{ca}, "password"); err == nil {
		t.Error("expected the default encoder to reject a key type crypto/x509 does not know")
	}
}

func TestWithKeyCodecLeavesSharedEncoderUnchanged(t *testing.T) {
	withCodec := Modern2023.WithKeyCodec(testKeyCodec{})
	if withCodec == Modern2023 {
		t.Fatal("WithKeyCodec must return a new Encoder")
	}
	if Modern2023.keyCodec != nil {
		t.Error("WithKeyCodec must not modify the shared Modern2023 encoder")
	}
}

func TestDecoderMatchesPackageFunctions(t *testing.T) {
	key, leaf, ca := newTestChain(t)
	pfx, err := Modern2023.Encode(key.key, leaf, []*x509.Certificate{ca}, "password")
	if err != nil {
		t.Fatal(err)
	}
	fromPackage, certFromPackage, _, err := DecodeChain(pfx, "password")
	if err != nil {
		t.Fatal(err)
	}
	fromDecoder, certFromDecoder, _, err := NewDecoder().DecodeChain(pfx, "password")
	if err != nil {
		t.Fatal(err)
	}
	if !fromPackage.(ed25519.PrivateKey).Equal(fromDecoder) || !certFromPackage.Equal(certFromDecoder) {
		t.Error("NewDecoder().DecodeChain and DecodeChain must return the same result")
	}
}

// The zero Decoder and a nil codec decode with the default codec instead of panicking.
func TestDecoderZeroValueAndNilCodec(t *testing.T) {
	key, leaf, ca := newTestChain(t)
	pfx, err := Modern2023.Encode(key.key, leaf, []*x509.Certificate{ca}, "password")
	if err != nil {
		t.Fatal(err)
	}
	decoders := map[string]*Decoder{
		"zero value": {},
		"nil codec":  NewDecoder().WithKeyCodec(nil),
	}
	for name, dec := range decoders {
		t.Run(name, func(t *testing.T) {
			decoded, certificate, _, err := dec.DecodeChain(pfx, "password")
			if err != nil {
				t.Fatal(err)
			}
			if !decoded.(ed25519.PrivateKey).Equal(key.key) || !certificate.Equal(leaf) {
				t.Error("unexpected decoding result")
			}
		})
	}

	nilCodecPFX, err := Modern2023.WithKeyCodec(nil).Encode(key.key, leaf, nil, "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(nilCodecPFX, "password"); err != nil {
		t.Fatal(err)
	}
}
