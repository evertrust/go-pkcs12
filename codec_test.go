package pkcs12

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math"
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
		return marshalTestSPKI(k.key)
	}
	return x509.MarshalPKIXPublicKey(publicKey)
}

// marshalTestSPKI encodes a testKey public key with oidTestKey, so that crypto/x509 parses its
// certificate with a nil PublicKey, like a post-quantum certificate.
func marshalTestSPKI(publicKey ed25519.PublicKey) ([]byte, error) {
	return asn1.Marshal(struct {
		Algo      pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algo:      pkix.AlgorithmIdentifier{Algorithm: oidTestKey},
		PublicKey: asn1.BitString{Bytes: publicKey, BitLength: 8 * len(publicKey)},
	})
}

// nonSignerKey is a private key that is not a crypto.Signer, such as a KEM key.
type nonSignerKey struct{}

// nonSignerCodec decodes testKey as a nonSignerKey.
type nonSignerCodec struct {
	testKeyCodec
}

func (c nonSignerCodec) ParsePKCS8PrivateKey(der []byte) (interface{}, error) {
	key, err := c.testKeyCodec.ParsePKCS8PrivateKey(der)
	if _, ok := key.(*testKey); ok {
		return nonSignerKey{}, nil
	}
	return key, err
}

func newTestCert(t *testing.T, cn string, isCA bool, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
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

// newTestChain returns a testKey, its certificate and the issuing CA certificate. The leaf
// certificate carries an oidTestKey SubjectPublicKeyInfo that crypto/x509 does not parse.
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
	spki, err := marshalTestSPKI(leafKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf = replaceSPKI(t, leaf, spki, caKey)
	if leaf.PublicKey != nil {
		t.Fatalf("expected crypto/x509 to leave the test public key unparsed, got %T", leaf.PublicKey)
	}
	return &testKey{key: leafKey}, leaf, ca
}

// tbsCertificate holds the fields of a v3 TBSCertificate as raw elements.
type tbsCertificate struct {
	Version      asn1.RawValue
	SerialNumber asn1.RawValue
	Signature    asn1.RawValue
	Issuer       asn1.RawValue
	Validity     asn1.RawValue
	Subject      asn1.RawValue
	PublicKey    asn1.RawValue
	Extensions   asn1.RawValue
}

type certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

// replaceSPKI returns cert with its SubjectPublicKeyInfo replaced by spki, signed again by the
// Ed25519 CA key.
func replaceSPKI(t *testing.T, cert *x509.Certificate, spki []byte, caKey ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	var tbs tbsCertificate
	if _, err := asn1.Unmarshal(cert.RawTBSCertificate, &tbs); err != nil {
		t.Fatal(err)
	}
	tbs.PublicKey = asn1.RawValue{FullBytes: spki}
	rawTBS, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	var outer certificate
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(caKey, rawTBS)
	der, err := asn1.Marshal(certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: rawTBS},
		SignatureAlgorithm: outer.SignatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	})
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return replaced
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

// A codec may return a private key that is not a crypto.Signer. Leaf matching must not panic on
// the Ed25519 CA certificate in the chain, and the first certificate stays the leaf.
func TestDecodeChainWithNonSignerKey(t *testing.T) {
	key, leaf, ca := newTestChain(t)
	pfx, err := Modern2023.WithKeyCodec(testKeyCodec{}).Encode(key, leaf, []*x509.Certificate{ca}, "password")
	if err != nil {
		t.Fatal(err)
	}

	decoded, certificate, caCerts, err := NewDecoder().WithKeyCodec(nonSignerCodec{}).DecodeChain(pfx, "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded.(nonSignerKey); !ok {
		t.Fatalf("expected nonSignerKey, got %T", decoded)
	}
	if !certificate.Equal(leaf) || len(caCerts) != 1 || !caCerts[0].Equal(ca) {
		t.Error("expected the certificates in their original order")
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

// The zero Decoder and a nil codec decode with the default codec instead of panicking, through
// both the shrouded and the plain key bag.
func TestDecoderZeroValueAndNilCodec(t *testing.T) {
	key, leaf, ca := newTestChain(t)
	encoders := map[string]struct {
		encoder  *Encoder
		password string
	}{
		"shrouded key bag": {Modern2023, "password"},
		"plain key bag":    {Passwordless, ""},
	}
	decoders := map[string]*Decoder{
		"zero value": {},
		"nil codec":  NewDecoder().WithKeyCodec(nil),
	}
	for encoderName, e := range encoders {
		pfx, err := e.encoder.Encode(key.key, leaf, []*x509.Certificate{ca}, e.password)
		if err != nil {
			t.Fatal(err)
		}
		for decoderName, dec := range decoders {
			t.Run(encoderName+"/"+decoderName, func(t *testing.T) {
				decoded, certificate, _, err := dec.DecodeChain(pfx, e.password)
				if err != nil {
					t.Fatal(err)
				}
				if !decoded.(ed25519.PrivateKey).Equal(key.key) || !certificate.Equal(leaf) {
					t.Error("unexpected decoding result")
				}
			})
		}
	}

	nilCodecPFX, err := Modern2023.WithKeyCodec(nil).Encode(key.key, leaf, nil, "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(nilCodecPFX, "password"); err != nil {
		t.Fatal(err)
	}
}

func TestDecoderWithKeyCodecLeavesReceiverUnchanged(t *testing.T) {
	dec := NewDecoder().WithKeyCodec(testKeyCodec{})
	if withNil := dec.WithKeyCodec(nil); withNil == dec {
		t.Fatal("WithKeyCodec must return a new Decoder")
	}
	if _, ok := dec.keyCodec.(testKeyCodec); !ok {
		t.Error("WithKeyCodec must not modify its receiver")
	}
}
