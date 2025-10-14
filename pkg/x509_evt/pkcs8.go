package x509_evt

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// pkcs8WithAttributes reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8WithAttributes struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes []attribute `asn1:"set,omitempty,tag:0,optional"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.BitString `asn1:"set"`
}

var (
	oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// From x509 package
func marshalKeyUsage(ku x509.KeyUsage) (attribute, error) {
	ext := attribute{Type: oidKeyUsage}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	ext.Values = []asn1.BitString{{Bytes: bitString, BitLength: asn1BitLength(bitString)}}
	return ext, err
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

// Custom encoding function for RSA to handle key attributes
func MarshalPKCS8PrivateKeyWithAttributes(certificate *x509.Certificate, privateKey interface{}) (asn1Data []byte, err error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		var privKeyWithAttr pkcs8WithAttributes
		privKeyWithAttr.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKeyWithAttr.PrivateKey = x509.MarshalPKCS1PrivateKey(k)
		// Compute key usages
		keyUsage := x509.KeyUsage(0)
		if certificate.KeyUsage&(x509.KeyUsageKeyAgreement|x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment) > 0 {
			keyUsage = keyUsage | x509.KeyUsageDataEncipherment
		}
		if certificate.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment|x509.KeyUsageCertSign) > 0 {
			keyUsage = keyUsage | x509.KeyUsageDigitalSignature
		}
		if keyUsage == 0 {
			return asn1.Marshal(privKeyWithAttr)
		}
		attr, err := marshalKeyUsage(keyUsage)
		if err != nil {
			return nil, errors.New("pkcs12: could not marshal key usage: " + err.Error())
		}
		// Marshal attributes for key usage
		privKeyWithAttr.Attributes = []attribute{attr}
		return asn1.Marshal(privKeyWithAttr)
	default:
		return MarshalPKCS8PrivateKey(privateKey)
	}
}

func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	var privKey pkcs8WithAttributes

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKey.PrivateKey = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
		}
		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}
		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}

	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	case *ecdh.PrivateKey:
		if k.Curve() == ecdh.X25519() {
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: oidPublicKeyX25519,
			}
			var err error
			if privKey.PrivateKey, err = asn1.Marshal(k.Bytes()); err != nil {
				return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
			}
		} else {
			oid, ok := oidFromECDHCurve(k.Curve())
			if !ok {
				return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
			}
			oidBytes, err := asn1.Marshal(oid)
			if err != nil {
				return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
			}
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: oidPublicKeyECDSA,
				Parameters: asn1.RawValue{
					FullBytes: oidBytes,
				},
			}
			if privKey.PrivateKey, err = marshalECDHPrivateKey(k); err != nil {
				return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
			}
		}

	case *MLDSA44:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidSignatureMLDSA44,
		}

		curvePrivateKey, err := toAsn1(k)
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	case *MLDSA65:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidSignatureMLDSA65,
		}

		curvePrivateKey, err := toAsn1(k)
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	case *MLDSA87:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidSignatureMLDSA87,
		}

		curvePrivateKey, err := toAsn1(k)
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	default:
		return nil, fmt.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
	}

	return asn1.Marshal(privKey)
}
