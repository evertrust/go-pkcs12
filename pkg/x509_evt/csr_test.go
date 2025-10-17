package x509_evt

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"reflect"
	"testing"
)

func TestKeyGen(t *testing.T) {
	testCases := []struct {
		name       string
		keyGenFunc func(reader io.Reader) (crypto.PrivateKey, error)
		keyType    reflect.Type
	}{
		{
			name: "ECDH 25519",
			keyGenFunc: func(reader io.Reader) (crypto.PrivateKey, error) {
				return ecdh.X25519().GenerateKey(reader)
			},
			keyType: reflect.TypeOf(&ecdh.PrivateKey{}),
		},
		{
			name: "ML KEM 512",
			keyGenFunc: func(reader io.Reader) (crypto.PrivateKey, error) {
				return GenerateMLKEM512Key(reader)
			},
			keyType: reflect.TypeOf(&MLKEM512{}),
		},
		{
			name: "ML KEM 768",
			keyGenFunc: func(reader io.Reader) (crypto.PrivateKey, error) {
				return GenerateMLKEM768Key(reader)
			},
			keyType: reflect.TypeOf(&MLKEM768{}),
		},
		{
			name: "ML KEM 1024",
			keyGenFunc: func(reader io.Reader) (crypto.PrivateKey, error) {
				return GenerateMLKEM1024Key(reader)
			},
			keyType: reflect.TypeOf(&MLKEM1024{}),
		},
		{
			name: "ML DSA 44",
			keyGenFunc: func(reader io.Reader) (crypto.PrivateKey, error) {
				return GenerateMLDSA44Key(reader)
			},
			keyType: reflect.TypeOf(&MLDSA44{}),
		},
		{
			name: "ML DSA 65",
			keyGenFunc: func(reader io.Reader) (crypto.PrivateKey, error) {
				return GenerateMLDSA65Key(reader)
			},
			keyType: reflect.TypeOf(&MLDSA65{}),
		},
		{
			name: "ML DSA 87",
			keyGenFunc: func(reader io.Reader) (crypto.PrivateKey, error) {
				return GenerateMLDSA87Key(reader)
			},
			keyType: reflect.TypeOf(&MLDSA87{}),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.keyGenFunc(rand.Reader)
			if err != nil {
				t.Fatalf("unexpected error on key generation: %v", err)
			}

			if reflect.TypeOf(key) != tt.keyType {
				t.Fatalf("unexpected key type: %T", key)
			}

			csrBytes, err := CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{
				CommonName: "test",
			}}, key, nil)
			if err != nil {
				t.Fatalf("unexpected error on csr generation: %v", err)
			}

			parsedCsr, err := x509.ParseCertificateRequest(csrBytes)
			if err != nil {
				t.Fatalf("could not parse generated csr: %v", err)
			}

			if parsedCsr.Subject.CommonName != "test" {
				t.Fatalf("invalid CSR contents: %s", parsedCsr.Subject.CommonName)
			}
		})
	}
}
