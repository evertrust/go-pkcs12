package x509_evt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"math/big"
)

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// RFC 3279, 2.3 Public Key Algorithms
//
//	pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//		rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
//	id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//		x9-57(10040) x9cm(4) 1 }
//
// RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
//	id-ecPublicKey OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
var (
	oidPublicKeyRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA    = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeyX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}
	// FIXME: this is an arbitrary identifier, issued from one of the early drafts
	oidPublicKeyComposite = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 4, 1}
	oidPublicKeyEd25519   = oidSignatureEd25519

	oidPublicKeyMLKEM512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	oidPublicKeyMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	oidPublicKeyMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

// OIDs for signature algorithms
//
//	pkcs-1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
//
// RFC 3279 2.2.1 RSA Signature Algorithms
//
//	md2WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 2 }
//
//	md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
//
//	sha-1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }
//
//	dsaWithSha1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
//
// RFC 3279 2.2.3 ECDSA Signature Algorithm
//
//	ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) ansi-x962(10045)
//		signatures(4) ecdsa-with-SHA1(1)}
//
// RFC 4055 5 PKCS #1 Version 1.5
//
//	sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }
//
//	sha384WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 12 }
//
//	sha512WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 13 }
//
// RFC 5758 3.1 DSA Signature Algorithms
//
//	dsaWithSha256 OBJECT IDENTIFIER ::= {
//		joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
//		csor(3) algorithms(4) id-dsa-with-sha2(3) 2}
//
// RFC 5758 3.2 ECDSA Signature Algorithm
//
//	ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
//
//	ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
//
//	ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//		us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
//
// RFC 8410 3 Curve25519 and Curve448 Algorithm Identifiers
//
//	id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
var (
	oidSignatureMD2WithRSA        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1       = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519           = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidSignatureMLDSA44           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidSignatureMLDSA65           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidSignatureMLDSA87           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
	oidSignatureMLDSA44WithSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 32}
	oidSignatureMLDSA65WithSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 33}
	oidSignatureMLDSA87WithSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 34}
	oidSignatureNoSignature       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 2}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

var (
	OidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

func parsePkcs8(privKey pkcs8WithAttributes) (key, alternateKey any, err error) {
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, nil, errors.New("x509: invalid Ed25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, nil, fmt.Errorf("x509: invalid Ed25519 private key: %v", err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, nil, fmt.Errorf("x509: invalid Ed25519 private key length: %d", l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyX25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, nil, errors.New("x509: invalid X25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, nil, fmt.Errorf("x509: invalid X25519 private key: %v", err)
		}
		key, err = ecdh.X25519().NewPrivateKey(curvePrivateKey)
		return key, nil, err
	case privKey.Algo.Algorithm.Equal(oidPublicKeyMLKEM512):
		mlkem, err := mlkem512FromBytes(privKey.PrivateKey)
		return mlkem, nil, err
	case privKey.Algo.Algorithm.Equal(oidPublicKeyMLKEM768):
		mlkem, err := mlkem768FromBytes(privKey.PrivateKey)
		return mlkem, nil, err
	case privKey.Algo.Algorithm.Equal(oidPublicKeyMLKEM1024):
		mlkem, err := mlkem1024FromBytes(privKey.PrivateKey)
		return mlkem, nil, err
	case privKey.Algo.Algorithm.Equal(oidPublicKeyComposite):
		var compositeKeys []pkcs8WithAttributes

		if _, err := asn1.Unmarshal(privKey.PrivateKey, &compositeKeys); err != nil {
			return nil, nil, fmt.Errorf("x509: invalid composite private key: %v", err)
		}

		if len(compositeKeys) != 2 {
			return nil, nil, fmt.Errorf("x509: invalid composite private key: only composites with length 2 supported")
		}

		key, _, err = parsePkcs8(compositeKeys[0])
		if err != nil {
			return nil, nil, fmt.Errorf("x509: invalid primary key: %v", err)
		}

		alternateKey, _, err = parsePkcs8(compositeKeys[1])
		if err != nil {
			return nil, nil, fmt.Errorf("x509: invalid alternate key: %v", err)
		}

		return key, alternateKey, nil
	case privKey.Algo.Algorithm.Equal(oidSignatureMLDSA44):
		mldsa, err := mldsa44FromBytes(privKey.PrivateKey)
		return mldsa, nil, err
	case privKey.Algo.Algorithm.Equal(oidSignatureMLDSA65):
		mldsa, err := mldsa65FromBytes(privKey.PrivateKey)
		return mldsa, nil, err
	case privKey.Algo.Algorithm.Equal(oidSignatureMLDSA87):
		mldsa, err := mldsa87FromBytes(privKey.PrivateKey)
		return mldsa, nil, err
	default:
		return nil, nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

func ParsePKCS8PrivateKey(der []byte) (key, alternateKey any, err error) {
	var privKey pkcs8WithAttributes
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &ecPrivateKey{}); err == nil {
			return nil, nil, errors.New("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, nil, err
	}
	return parsePkcs8(privKey)
}

// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &pkcs8WithAttributes{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	if namedCurveOID != nil {
		curve = namedCurveFromOID(*namedCurveOID)
	} else {
		curve = namedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}

// RFC 5480, 2.1.1.1. Named Curve
//
//	secp224r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
//	secp256r1 OBJECT IDENTIFIER ::= {
//	  iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//	  prime(1) 7 }
//
//	secp384r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
//	secp521r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
// NB: secp256r1 is equivalent to prime256v1
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

func oidFromECDHCurve(curve ecdh.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case ecdh.X25519():
		return oidPublicKeyX25519, true
	case ecdh.P256():
		return oidNamedCurveP256, true
	case ecdh.P384():
		return oidNamedCurveP384, true
	case ecdh.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

// getPublicKeyAlgorithmFromOID returns the exposed PublicKeyAlgorithm
// identifier for public key types supported in certificates and CSRs. Marshal
// and Parse functions may support a different set of public key types.
func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeyRSA):
		return x509.RSA
	case oid.Equal(oidPublicKeyDSA):
		return x509.DSA
	case oid.Equal(oidPublicKeyECDSA):
		return x509.ECDSA
	case oid.Equal(oidPublicKeyEd25519):
		return x509.Ed25519
	case oid.Equal(oidSignatureMLDSA44):
		return mldsa44PubAlgorithm
	case oid.Equal(oidSignatureMLDSA65):
		return mldsa65PubAlgorithm
	case oid.Equal(oidSignatureMLDSA87):
		return mldsa87PubAlgorithm
	}
	return x509.UnknownPublicKeyAlgorithm
}

var (
	oidExtensionAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidAuthorityInfoAccessOcsp      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

func getSignatureAlgorithmFromAI(ai pkix.AlgorithmIdentifier) x509.SignatureAlgorithm {
	if ai.Algorithm.Equal(oidSignatureEd25519) {
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(ai.Parameters.FullBytes) != 0 {
			return x509.UnknownSignatureAlgorithm
		}
	}

	if !ai.Algorithm.Equal(oidSignatureRSAPSS) {
		for _, details := range signatureAlgorithmDetails {
			if ai.Algorithm.Equal(details.oid) {
				return details.algo
			}
		}
		return x509.UnknownSignatureAlgorithm
	}

	// RSA PSS is special because it encodes important parameters
	// in the Parameters.

	var params pssParameters
	if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
		return x509.UnknownSignatureAlgorithm
	}

	var mgf1HashFunc pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
		return x509.UnknownSignatureAlgorithm
	}

	// PSS is greatly overburdened with options. This code forces them into
	// three buckets by requiring that the MGF1 hash function always match the
	// message hash function (as recommended in RFC 3447, Section 8.1), that the
	// salt length matches the hash length, and that the trailer field has the
	// default value.
	if (len(params.Hash.Parameters.FullBytes) != 0 && !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes)) ||
		!params.MGF.Algorithm.Equal(oidMGF1) ||
		!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
		(len(mgf1HashFunc.Parameters.FullBytes) != 0 && !bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes)) ||
		params.TrailerField != 1 {
		return x509.UnknownSignatureAlgorithm
	}

	switch {
	case params.Hash.Algorithm.Equal(OidSHA256) && params.SaltLength == 32:
		return x509.SHA256WithRSAPSS
	case params.Hash.Algorithm.Equal(OidSHA384) && params.SaltLength == 48:
		return x509.SHA384WithRSAPSS
	case params.Hash.Algorithm.Equal(OidSHA512) && params.SaltLength == 64:
		return x509.SHA512WithRSAPSS
	}

	return x509.UnknownSignatureAlgorithm
}

var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage x509.ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku x509.ExtKeyUsage, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if oid.Equal(pair.oid) {
			return pair.extKeyUsage, true
		}
	}
	return
}
