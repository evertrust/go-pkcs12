package pkcs12

import (
	"bytes"
	"crypto"
	"crypto/x509"
)

// KeyCodec converts private keys to and from their PKCS#8 encoding, and public keys to their
// SubjectPublicKeyInfo encoding. Supplying one lets callers handle key types that crypto/x509
// does not know, such as post-quantum keys, without this package depending on them.
type KeyCodec interface {
	ParsePKCS8PrivateKey(der []byte) (privateKey interface{}, err error)
	MarshalPKCS8PrivateKey(privateKey interface{}) (der []byte, err error)
	MarshalPKIXPublicKey(publicKey interface{}) (der []byte, err error)
}

// x509KeyCodec is the default KeyCodec, backed by crypto/x509.
type x509KeyCodec struct{}

func (x509KeyCodec) ParsePKCS8PrivateKey(der []byte) (interface{}, error) {
	return x509.ParsePKCS8PrivateKey(der)
}

func (x509KeyCodec) MarshalPKCS8PrivateKey(privateKey interface{}) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

func (x509KeyCodec) MarshalPKIXPublicKey(publicKey interface{}) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

var defaultKeyCodec KeyCodec = x509KeyCodec{}

// A Decoder contains methods for decoding PKCS#12 files with a given KeyCodec.
// The package-level decoding functions use a Decoder with the default, crypto/x509 based codec.
// The zero value is ready to use and decodes with the default codec.
// A Decoder is safe for concurrent use by multiple goroutines.
type Decoder struct {
	keyCodec KeyCodec
}

// NewDecoder returns a Decoder that uses the default, crypto/x509 based KeyCodec.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// WithKeyCodec returns a new Decoder identical to dec except that it parses private keys with
// the given KeyCodec. A nil codec selects the default one.
func (dec *Decoder) WithKeyCodec(codec KeyCodec) *Decoder {
	d := *dec
	d.keyCodec = codec
	return &d
}

// WithKeyCodec returns a new Encoder identical to enc except that it encodes private keys with
// the given KeyCodec, or the default one when codec is nil. Unlike WithRand and WithIterations, it does not modify enc, so the shared
// package-level Encoders keep using the default codec.
func (enc *Encoder) WithKeyCodec(codec KeyCodec) *Encoder {
	e := *enc
	e.keyCodec = codec
	return &e
}

func (dec *Decoder) codec() KeyCodec {
	if dec.keyCodec == nil {
		return defaultKeyCodec
	}
	return dec.keyCodec
}

func (enc *Encoder) codec() KeyCodec {
	if enc.keyCodec == nil {
		return defaultKeyCodec
	}
	return enc.keyCodec
}

// publicKeyMatches reports whether certificate holds the public key of privateKey, by comparing
// SubjectPublicKeyInfo encodings. It works for key types crypto/x509 leaves unparsed.
func publicKeyMatches(codec KeyCodec, certificate *x509.Certificate, privateKey interface{}) bool {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return false
	}
	spki, err := codec.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return false
	}
	return bytes.Equal(spki, certificate.RawSubjectPublicKeyInfo)
}
