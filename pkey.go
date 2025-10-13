package pkcs12

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
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

// Custom encoding function for RSA to handle key attributes
func marshalPKCS8PrivateKey(certificate *x509.Certificate, privateKey interface{}) (asn1Data []byte, err error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		var privKeyWithAttr pkcs8
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
		return x509.MarshalPKCS8PrivateKey(privateKey)
	}
}

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
