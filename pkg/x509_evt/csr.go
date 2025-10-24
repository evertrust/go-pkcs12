package x509_evt

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
	"io"
	"net"
	"net/url"
	"unicode"
)

var (
	oidSubjectAltPublicKeyInfo = asn1.ObjectIdentifier{2, 5, 29, 72}
	oidAltSignatureAlgorithm   = asn1.ObjectIdentifier{2, 5, 29, 73}
	oidAltSignatureValue       = asn1.ObjectIdentifier{2, 5, 29, 74}
	oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionRequest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
)

func buildPublicKeyInfo(key hasPublicKey) (*publicKeyInfo, error) {
	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	return &publicKeyInfo{
		Algorithm: publicKeyAlgorithm,
		PublicKey: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: len(publicKeyBytes) * 8,
		},
	}, nil
}

type sigAttributeTypeAndValueSET struct {
	Type  asn1.ObjectIdentifier
	Value []asn1.RawValue `asn1:"set"`
}

func newSigAttr(oid asn1.ObjectIdentifier, value asn1.RawValue) sigAttributeTypeAndValueSET {
	return sigAttributeTypeAndValueSET{
		Type:  oid,
		Value: []asn1.RawValue{value},
	}
}

func buildAttributes(template *x509.CertificateRequest, extensions []pkix.Extension, sigAttrs []sigAttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	// Make a copy of template.Attributes because we may alter it below.
	attributes := make([]pkix.AttributeTypeAndValueSET, 0, len(template.Attributes))
	for _, attr := range template.Attributes {
		values := make([][]pkix.AttributeTypeAndValue, len(attr.Value))
		copy(values, attr.Value)
		attributes = append(attributes, pkix.AttributeTypeAndValueSET{
			Type:  attr.Type,
			Value: values,
		})
	}

	extensionsAppended := false
	if len(extensions) > 0 {
		// Append the extensions to an existing attribute if possible.
		for _, atvSet := range attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) || len(atvSet.Value) == 0 {
				continue
			}

			// specifiedExtensions contains all the extensions that we
			// found specified via template.Attributes.
			specifiedExtensions := make(map[string]bool)

			for _, atvs := range atvSet.Value {
				for _, atv := range atvs {
					specifiedExtensions[atv.Type.String()] = true
				}
			}

			newValue := make([]pkix.AttributeTypeAndValue, 0, len(atvSet.Value[0])+len(extensions))
			newValue = append(newValue, atvSet.Value[0]...)

			for _, e := range extensions {
				if specifiedExtensions[e.Id.String()] {
					// Attributes already contained a value for
					// this extension and it takes priority.
					continue
				}

				newValue = append(newValue, pkix.AttributeTypeAndValue{
					// There is no place for the critical
					// flag in an AttributeTypeAndValue.
					Type:  e.Id,
					Value: e.Value,
				})
			}

			atvSet.Value[0] = newValue
			extensionsAppended = true
			break
		}
	}

	rawAttributes, err := newRawAttributes(attributes)
	if err != nil {
		return nil, err
	}

	// If not included in attributes, add a new attribute for the
	// extensions.
	if len(extensions) > 0 && !extensionsAppended {
		attr := struct {
			Type  asn1.ObjectIdentifier
			Value [][]pkix.Extension `asn1:"set"`
		}{
			Type:  oidExtensionRequest,
			Value: [][]pkix.Extension{extensions},
		}

		b, err := asn1.Marshal(attr)
		if err != nil {
			return nil, errors.New("x509: failed to serialise extensions attribute: " + err.Error())
		}

		var rawValue asn1.RawValue
		if _, err := asn1.Unmarshal(b, &rawValue); err != nil {
			return nil, err
		}

		rawAttributes = append(rawAttributes, rawValue)
	}

	// Append signature attributes

	sigAttributes, err := sigRawAttributes(sigAttrs)
	if err != nil {
		return nil, err
	}

	return append(rawAttributes, sigAttributes...), err
}

func CreateCertificateRequest(rand io.Reader, template *x509.CertificateRequest, primaryKey, alternateKey crypto.PrivateKey) (csr []byte, err error) {
	canPublicKey, ok := primaryKey.(hasPublicKey)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement Public")
	}

	var altKey *crypto.Signer

	if alternateKey != nil {
		alt, ok := alternateKey.(crypto.Signer)
		if !ok {
			return nil, errors.New("x509: certificate alternate key does not implement crypto.Signer")
		}
		altKey = &alt
	}

	signatureAlgorithm, algorithmIdentifier, err := signingParamsForKey(canPublicKey, template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	var altSignatureAlgorithm x509.SignatureAlgorithm
	var sigAttrs []sigAttributeTypeAndValueSET

	if altKey != nil {
		var altAlgorithmIdentifier pkix.AlgorithmIdentifier
		altSignatureAlgorithm, altAlgorithmIdentifier, err = signingParamsForKey(*altKey, template.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}

		altPublicKeyInfo, err := buildPublicKeyInfo(*altKey)
		if err != nil {
			return nil, err
		}

		marshalledAltPublicKeyinfo, err := asn1.Marshal(*altPublicKeyInfo)
		if err != nil {
			return nil, err
		}

		rawAltPublicKeyinfo, err := asRaw(marshalledAltPublicKeyinfo)
		if err != nil {
			return nil, err
		}

		marshalledAltAlgorithmIdentifier, err := asn1.Marshal(altAlgorithmIdentifier)
		if err != nil {
			return nil, err
		}

		rawAltAlgorithmIdentifier, err := asRaw(marshalledAltAlgorithmIdentifier)
		if err != nil {
			return nil, err
		}

		altPublicKeyInfoExt := newSigAttr(oidSubjectAltPublicKeyInfo, rawAltPublicKeyinfo)
		altSignatureAlgorithmExt := newSigAttr(oidAltSignatureAlgorithm, rawAltAlgorithmIdentifier)

		sigAttrs = append(sigAttrs, altSignatureAlgorithmExt, altPublicKeyInfoExt)
	}

	primaryPublicKeyInfo, err := buildPublicKeyInfo(canPublicKey)
	if err != nil {
		return nil, err
	}

	extensions, err := buildCSRExtensions(template)
	if err != nil {
		return nil, err
	}

	rawAttributes, err := buildAttributes(template, extensions, sigAttrs)
	if err != nil {
		return nil, err
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
	}

	tbsCSR := tbsCertificateRequest{
		Version:       0, // PKCS #10, RFC 2986
		Subject:       asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:     *primaryPublicKeyInfo,
		RawAttributes: rawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return nil, err
	}
	tbsCSR.Raw = tbsCSRContents

	if altKey != nil {
		altSignature, err := signTBS(tbsCSRContents, *altKey, altSignatureAlgorithm, rand)
		if err != nil {
			return nil, err
		}

		rawAltSignature := asn1.BitString{Bytes: altSignature, BitLength: len(altSignature) * 8}
		marshalled, err := asn1.Marshal(rawAltSignature)
		if err != nil {
			return nil, err
		}

		raw, err := asRaw(marshalled)
		if err != nil {
			return nil, err
		}

		altSignatureValueExt := newSigAttr(oidAltSignatureValue, raw)

		sigAttrs = append(sigAttrs, altSignatureValueExt)

		rawAttributes, err = buildAttributes(template, extensions, sigAttrs)
		if err != nil {
			return nil, err
		}
	}

	tbsCSR2 := tbsCertificateRequest{
		Version:       0, // PKCS #10, RFC 2986
		Subject:       asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:     *primaryPublicKeyInfo,
		RawAttributes: rawAttributes,
	}

	tbsCSRContents2, err := asn1.Marshal(tbsCSR2)
	if err != nil {
		return nil, err
	}
	tbsCSR2.Raw = tbsCSRContents2

	csrObj := certificateRequest{
		TBSCSR:             tbsCSR2,
		SignatureAlgorithm: algorithmIdentifier,
	}

	if signingKey, ok := primaryKey.(crypto.Signer); ok {
		signature, err := signTBS(tbsCSRContents2, signingKey, signatureAlgorithm, rand)
		if err != nil {
			return nil, err
		}
		csrObj.SignatureValue = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	}

	return asn1.Marshal(csrObj)
}

func asRaw(content []byte) (raw asn1.RawValue, err error) {
	_, err = asn1.Unmarshal(content, &raw)
	if err != nil {
		return asn1.RawValue{}, err
	}
	return raw, nil
}

func signTBS(tbs []byte, key crypto.Signer, sigAlg x509.SignatureAlgorithm, rand io.Reader) ([]byte, error) {
	signed := tbs
	hashFunc := hashFunc(sigAlg)
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	var signerOpts crypto.SignerOpts = hashFunc
	if isRSAPSS(sigAlg) {
		signerOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashFunc,
		}
	}

	signature, err := key.Sign(rand, signed, signerOpts)
	if err != nil {
		return nil, err
	}

	// Check the signature to ensure the crypto.Signer behaved correctly.
	if err := checkSignature(sigAlg, tbs, signature, key.Public(), true); err != nil {
		return nil, fmt.Errorf("x509: signature returned by signer is invalid: %w", err)
	}

	return signature, nil
}

func isRSAPSS(algo x509.SignatureAlgorithm) bool {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			return details.isRSAPSS
		}
	}
	return false
}

func hashFunc(algo x509.SignatureAlgorithm) crypto.Hash {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			return details.hash
		}
	}
	return crypto.Hash(0)
}

func checkSignature(algo x509.SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey, allowSHA1 bool) (err error) {
	var hashType crypto.Hash
	var pubKeyAlgo x509.PublicKeyAlgorithm

	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			hashType = details.hash
			pubKeyAlgo = details.pubKeyAlgo
			break
		}
	}

	switch hashType {
	case crypto.Hash(0):
		switch pubKeyAlgo {
		case x509.Ed25519,
			mldsa44PubAlgorithm,
			mldsa65PubAlgorithm,
			mldsa87PubAlgorithm,
			slhdsa128sPubAlgorithm,
			slhdsa128fPubAlgorithm,
			slhdsa192sPubAlgorithm,
			slhdsa192fPubAlgorithm,
			slhdsa256sPubAlgorithm,
			slhdsa256fPubAlgorithm,
			slhdsa128sShakePubAlgorithm,
			slhdsa128fShakePubAlgorithm,
			slhdsa192sShakePubAlgorithm,
			slhdsa192fShakePubAlgorithm,
			slhdsa256sShakePubAlgorithm,
			slhdsa256fShakePubAlgorithm:
			break
		default:
			return x509.ErrUnsupportedAlgorithm
		}
	case crypto.MD5:
		return x509.InsecureAlgorithmError(algo)
	case crypto.SHA1:
		return x509.InsecureAlgorithmError(algo)
	default:
		if !hashType.Available() {
			return x509.ErrUnsupportedAlgorithm
		}
		h := hashType.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if isRSAPSS(algo) {
			return rsa.VerifyPSS(pub, hashType, signed, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			return rsa.VerifyPKCS1v15(pub, hashType, signed, signature)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, signed, signature) {
			return errors.New("x509: ECDSA verification failure")
		}
		return
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, signed, signature) {
			return errors.New("x509: Ed25519 verification failure")
		}
		return
	case *mldsa44.PublicKey:
		if !mldsa44.Verify(pub, signed, nil, signature) {
			return errors.New("x509: MLDSA-44 verification failure")
		}
		return
	case *mldsa65.PublicKey:
		if !mldsa65.Verify(pub, signed, nil, signature) {
			return errors.New("x509: MLDSA-65 verification failure")
		}
		return
	case *mldsa87.PublicKey:
		if !mldsa87.Verify(pub, signed, nil, signature) {
			return errors.New("x509: MLDSA-87 verification failure")
		}
		return
	case slhdsa.PublicKey:
		if !pub.Scheme().Verify(pub, signed, signature, nil) {
			return errors.New("x509: SLH-DSA verification failure")
		}
		return
	}
	return x509.ErrUnsupportedAlgorithm
}

// newRawAttributes converts AttributeTypeAndValueSETs from a template
// CertificateRequest's Attributes into tbsCertificateRequest RawAttributes.
func newRawAttributes(attributes []pkix.AttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	var rawAttributes []asn1.RawValue
	b, err := asn1.Marshal(attributes)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(b, &rawAttributes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: failed to unmarshal raw CSR Attributes")
	}
	return rawAttributes, nil
}

// newRawAttributes converts AttributeTypeAndValueSETs from a template
// CertificateRequest's Attributes into tbsCertificateRequest RawAttributes.
func sigRawAttributes(attributes []sigAttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	var rawAttributes []asn1.RawValue
	b, err := asn1.Marshal(attributes)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(b, &rawAttributes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: failed to unmarshal raw signature CSR Attributes")
	}
	return rawAttributes, nil
}

// oidInExtensions reports whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		if err := isIA5String(name); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		if err := isIA5String(email); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		uriStr := uri.String()
		if err := isIA5String(uriStr); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uriStr)})
	}
	return asn1.Marshal(rawValues)
}

func isIA5String(s string) error {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

func buildCSRExtensions(template *x509.CertificateRequest) ([]pkix.Extension, error) {
	var ret []pkix.Extension

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		sanBytes, err := marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return nil, err
		}

		ret = append(ret, pkix.Extension{
			Id:    oidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}

	return append(ret, template.ExtraExtensions...), nil
}

var emptyRawValue = asn1.RawValue{}

const (
	noSignatureSigAlgorithm     = x509.SignatureAlgorithm(17)
	mldsa44SigAlgorithm         = x509.SignatureAlgorithm(18)
	mldsa65SigAlgorithm         = x509.SignatureAlgorithm(19)
	mldsa87SigAlgorithm         = x509.SignatureAlgorithm(20)
	slhdsa128sSigAlgorithm      = x509.SignatureAlgorithm(21)
	slhdsa128fSigAlgorithm      = x509.SignatureAlgorithm(22)
	slhdsa192sSigAlgorithm      = x509.SignatureAlgorithm(23)
	slhdsa192fSigAlgorithm      = x509.SignatureAlgorithm(24)
	slhdsa256sSigAlgorithm      = x509.SignatureAlgorithm(25)
	slhdsa256fSigAlgorithm      = x509.SignatureAlgorithm(26)
	slhdsa128sShakeSigAlgorithm = x509.SignatureAlgorithm(27)
	slhdsa128fShakeSigAlgorithm = x509.SignatureAlgorithm(28)
	slhdsa192sShakeSigAlgorithm = x509.SignatureAlgorithm(29)
	slhdsa192fShakeSigAlgorithm = x509.SignatureAlgorithm(30)
	slhdsa256sShakeSigAlgorithm = x509.SignatureAlgorithm(31)
	slhdsa256fShakeSigAlgorithm = x509.SignatureAlgorithm(32)
	noSignaturePubAlgorithm     = x509.PublicKeyAlgorithm(5)
	mldsa44PubAlgorithm         = x509.PublicKeyAlgorithm(6)
	mldsa65PubAlgorithm         = x509.PublicKeyAlgorithm(7)
	mldsa87PubAlgorithm         = x509.PublicKeyAlgorithm(8)
	slhdsa128sPubAlgorithm      = x509.PublicKeyAlgorithm(9)
	slhdsa128fPubAlgorithm      = x509.PublicKeyAlgorithm(10)
	slhdsa192sPubAlgorithm      = x509.PublicKeyAlgorithm(11)
	slhdsa192fPubAlgorithm      = x509.PublicKeyAlgorithm(12)
	slhdsa256sPubAlgorithm      = x509.PublicKeyAlgorithm(13)
	slhdsa256fPubAlgorithm      = x509.PublicKeyAlgorithm(14)
	slhdsa128sShakePubAlgorithm = x509.PublicKeyAlgorithm(15)
	slhdsa128fShakePubAlgorithm = x509.PublicKeyAlgorithm(16)
	slhdsa192sShakePubAlgorithm = x509.PublicKeyAlgorithm(17)
	slhdsa192fShakePubAlgorithm = x509.PublicKeyAlgorithm(18)
	slhdsa256sShakePubAlgorithm = x509.PublicKeyAlgorithm(19)
	slhdsa256fShakePubAlgorithm = x509.PublicKeyAlgorithm(20)
	mlkem512PubAlgorithm        = x509.PublicKeyAlgorithm(21)
	mlkem768PubAlgorithm        = x509.PublicKeyAlgorithm(22)
	mlkem1024PubAlgorithm       = x509.PublicKeyAlgorithm(23)
)

var (
	pssParametersSHA256 = asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 162, 3, 2, 1, 32}}
	pssParametersSHA384 = asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 162, 3, 2, 1, 48}}
	pssParametersSHA512 = asn1.RawValue{FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 162, 3, 2, 1, 64}}
)
var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	params     asn1.RawValue
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
	isRSAPSS   bool
}{
	{x509.MD5WithRSA, "MD5-RSA", oidSignatureMD5WithRSA, asn1.NullRawValue, x509.RSA, crypto.MD5, false},
	{x509.SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA, asn1.NullRawValue, x509.RSA, crypto.SHA1, false},
	{x509.SHA1WithRSA, "SHA1-RSA", oidISOSignatureSHA1WithRSA, asn1.NullRawValue, x509.RSA, crypto.SHA1, false},
	{x509.SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA, asn1.NullRawValue, x509.RSA, crypto.SHA256, false},
	{x509.SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA, asn1.NullRawValue, x509.RSA, crypto.SHA384, false},
	{x509.SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA, asn1.NullRawValue, x509.RSA, crypto.SHA512, false},
	{x509.SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS, pssParametersSHA256, x509.RSA, crypto.SHA256, true},
	{x509.SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS, pssParametersSHA384, x509.RSA, crypto.SHA384, true},
	{x509.SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS, pssParametersSHA512, x509.RSA, crypto.SHA512, true},
	{x509.DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1, emptyRawValue, x509.DSA, crypto.SHA1, false},
	{x509.DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256, emptyRawValue, x509.DSA, crypto.SHA256, false},
	{x509.ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1, emptyRawValue, x509.ECDSA, crypto.SHA1, false},
	{x509.ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256, emptyRawValue, x509.ECDSA, crypto.SHA256, false},
	{x509.ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384, emptyRawValue, x509.ECDSA, crypto.SHA384, false},
	{x509.ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512, emptyRawValue, x509.ECDSA, crypto.SHA512, false},
	{x509.PureEd25519, "Ed25519", oidSignatureEd25519, emptyRawValue, x509.Ed25519, crypto.Hash(0) /* no pre-hashing */, false},
	{mldsa44SigAlgorithm, "MLDSA-44", oidSignatureMLDSA44, emptyRawValue, mldsa44PubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{mldsa65SigAlgorithm, "MLDSA-65", oidSignatureMLDSA65, emptyRawValue, mldsa65PubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{mldsa87SigAlgorithm, "MLDSA-87", oidSignatureMLDSA87, emptyRawValue, mldsa87PubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{mldsa87SigAlgorithm, "MLDSA-87", oidSignatureMLDSA87, emptyRawValue, mldsa87PubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa128sSigAlgorithm, "SLH-DSA-128s", oidSignatureSLHDSA128s, emptyRawValue, slhdsa128sPubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa128fSigAlgorithm, "SLH-DSA-128f", oidSignatureSLHDSA128f, emptyRawValue, slhdsa128fPubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa192sSigAlgorithm, "SLH-DSA-192s", oidSignatureSLHDSA192s, emptyRawValue, slhdsa192sPubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa192fSigAlgorithm, "SLH-DSA-192f", oidSignatureSLHDSA192f, emptyRawValue, slhdsa192fPubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa256sSigAlgorithm, "SLH-DSA-256s", oidSignatureSLHDSA256s, emptyRawValue, slhdsa256sPubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa256fSigAlgorithm, "SLH-DSA-256f", oidSignatureSLHDSA256f, emptyRawValue, slhdsa256fPubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa128sShakeSigAlgorithm, "SLH-DSA-128s-SHAKE", oidSignatureSLHDSAShake128s, emptyRawValue, slhdsa128sShakePubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa128fShakeSigAlgorithm, "SLH-DSA-128f-SHAKE", oidSignatureSLHDSAShake128f, emptyRawValue, slhdsa128fShakePubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa192sShakeSigAlgorithm, "SLH-DSA-192s-SHAKE", oidSignatureSLHDSAShake192s, emptyRawValue, slhdsa192sShakePubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa192fShakeSigAlgorithm, "SLH-DSA-192f-SHAKE", oidSignatureSLHDSAShake192f, emptyRawValue, slhdsa192fShakePubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa256sShakeSigAlgorithm, "SLH-DSA-256s-SHAKE", oidSignatureSLHDSAShake256s, emptyRawValue, slhdsa256sShakePubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{slhdsa256fShakeSigAlgorithm, "SLH-DSA-256f-SHAKE", oidSignatureSLHDSAShake256f, emptyRawValue, slhdsa256fShakePubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
	{noSignatureSigAlgorithm, "SIG-EMPTY", oidSignatureNoSignature, emptyRawValue, noSignaturePubAlgorithm, crypto.Hash(0) /* no pre-hashing */, false},
}

type hasPublicKey interface {
	Public() crypto.PublicKey
}

func signingParamsForKey(key hasPublicKey, sigAlgo x509.SignatureAlgorithm) (x509.SignatureAlgorithm, pkix.AlgorithmIdentifier, error) {
	var ai pkix.AlgorithmIdentifier
	var pubType x509.PublicKeyAlgorithm
	var defaultAlgo x509.SignatureAlgorithm

	switch pub := key.Public().(type) {
	case *ecdh.PublicKey, *mlkem512.PublicKey, *mlkem768.PublicKey, *mlkem1024.PublicKey:
		pubType = noSignaturePubAlgorithm
		defaultAlgo = noSignatureSigAlgorithm
	case *rsa.PublicKey:
		pubType = x509.RSA
		defaultAlgo = x509.SHA256WithRSA

	case *ecdsa.PublicKey:
		pubType = x509.ECDSA
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			defaultAlgo = x509.ECDSAWithSHA256
		case elliptic.P384():
			defaultAlgo = x509.ECDSAWithSHA384
		case elliptic.P521():
			defaultAlgo = x509.ECDSAWithSHA512
		default:
			return 0, ai, errors.New("x509: unsupported elliptic curve")
		}

	case ed25519.PublicKey:
		pubType = x509.Ed25519
		defaultAlgo = x509.PureEd25519

	case *mldsa44.PublicKey:
		pubType = mldsa44PubAlgorithm
		defaultAlgo = mldsa44SigAlgorithm
	case *mldsa65.PublicKey:
		pubType = mldsa65PubAlgorithm
		defaultAlgo = mldsa65SigAlgorithm
	case *mldsa87.PublicKey:
		pubType = mldsa87PubAlgorithm
		defaultAlgo = mldsa87SigAlgorithm
	case slhdsa.PublicKey:
		var err error
		pubType, err = slhdsaIdToPubAlgorithm(pub.ID)
		if err != nil {
			return 0, ai, err
		}
		defaultAlgo, err = slhdsaIdToSigAlgorithm(pub.ID)
		if err != nil {
			return 0, ai, err
		}
	default:
		return 0, ai, errors.New("x509: only RSA, ECDSA, Ed25519, MLDSA and SLHDSA keys supported")
	}

	if sigAlgo == 0 {
		sigAlgo = defaultAlgo
	}

	for _, details := range signatureAlgorithmDetails {
		if details.algo == sigAlgo {
			if details.pubKeyAlgo != pubType {
				return 0, ai, errors.New("x509: requested SignatureAlgorithm does not match private key type")
			}
			if details.hash == crypto.MD5 {
				return 0, ai, errors.New("x509: signing with MD5 is not supported")
			}

			return sigAlgo, pkix.AlgorithmIdentifier{
				Algorithm:  details.oid,
				Parameters: details.params,
			}, nil
		}
	}

	return 0, ai, errors.New("x509: unknown SignatureAlgorithm")
}

func marshalPublicKey(pub any) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is required by
		// RFC 3279, Section 2.3.1.
		publicKeyAlgorithm.Parameters = asn1.NullRawValue
	case *ecdsa.PublicKey:
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: invalid elliptic curve public key")
		}
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case ed25519.PublicKey:
		publicKeyBytes = pub
		publicKeyAlgorithm.Algorithm = oidPublicKeyEd25519
	case *mldsa44.PublicKey:
		publicKeyBytes = pub.Bytes()
		publicKeyAlgorithm.Algorithm = oidSignatureMLDSA44
	case *mldsa65.PublicKey:
		publicKeyBytes = pub.Bytes()
		publicKeyAlgorithm.Algorithm = oidSignatureMLDSA65
	case *mldsa87.PublicKey:
		publicKeyBytes = pub.Bytes()
		publicKeyAlgorithm.Algorithm = oidSignatureMLDSA87
	case *ecdh.PublicKey:
		publicKeyBytes = pub.Bytes()
		publicKeyAlgorithm.Algorithm = oidPublicKeyX25519
	case *mlkem512.PublicKey:
		// err is always nil
		publicKeyBytes, _ = pub.MarshalBinary()
		publicKeyAlgorithm.Algorithm = oidPublicKeyMLKEM512
	case *mlkem768.PublicKey:
		// err is always nil
		publicKeyBytes, _ = pub.MarshalBinary()
		publicKeyAlgorithm.Algorithm = oidPublicKeyMLKEM768
	case *mlkem1024.PublicKey:
		// err is always nil
		publicKeyBytes, _ = pub.MarshalBinary()
		publicKeyAlgorithm.Algorithm = oidPublicKeyMLKEM1024
	case slhdsa.PublicKey:
		publicKeyBytes, _ = pub.MarshalBinary()
		oid, err := slhdsaIdToOid(pub.ID)
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = oid
	default:
		return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

var slhdsaOids = map[slhdsa.ID]asn1.ObjectIdentifier{
	slhdsa.SHA2_128s:  oidSignatureSLHDSA128s,
	slhdsa.SHA2_128f:  oidSignatureSLHDSA128f,
	slhdsa.SHA2_192s:  oidSignatureSLHDSA192s,
	slhdsa.SHA2_192f:  oidSignatureSLHDSA192f,
	slhdsa.SHA2_256s:  oidSignatureSLHDSA256s,
	slhdsa.SHA2_256f:  oidSignatureSLHDSA256f,
	slhdsa.SHAKE_128s: oidSignatureSLHDSAShake128s,
	slhdsa.SHAKE_128f: oidSignatureSLHDSAShake128f,
	slhdsa.SHAKE_192s: oidSignatureSLHDSAShake192s,
	slhdsa.SHAKE_192f: oidSignatureSLHDSAShake192f,
	slhdsa.SHAKE_256s: oidSignatureSLHDSAShake256s,
	slhdsa.SHAKE_256f: oidSignatureSLHDSAShake256f,
}

func oidToSlhdsaId(oid asn1.ObjectIdentifier) (slhdsa.ID, error) {
	for id, storedOid := range slhdsaOids {
		if storedOid.Equal(oid) {
			return id, nil
		}
	}
	return 0, errors.New("unsupported slhdsa.ID")
}

func slhdsaIdToOid(id slhdsa.ID) (asn1.ObjectIdentifier, error) {
	if oid, ok := slhdsaOids[id]; ok {
		return oid, nil
	}
	return nil, errors.New("unsupported slhdsa.ID")
}

func slhdsaIdToPubAlgorithm(id slhdsa.ID) (x509.PublicKeyAlgorithm, error) {
	oid, err := slhdsaIdToOid(id)
	if err != nil {
		return x509.UnknownPublicKeyAlgorithm, err
	}

	for _, details := range signatureAlgorithmDetails {
		if oid.Equal(details.oid) {
			return details.pubKeyAlgo, nil
		}
	}
	return x509.UnknownPublicKeyAlgorithm, errors.New("unsupported slhdsa.ID")
}

func slhdsaIdToSigAlgorithm(id slhdsa.ID) (x509.SignatureAlgorithm, error) {
	oid, err := slhdsaIdToOid(id)
	if err != nil {
		return x509.UnknownSignatureAlgorithm, err
	}
	for _, details := range signatureAlgorithmDetails {
		if oid.Equal(details.oid) {
			return details.algo, nil
		}
	}
	return x509.UnknownSignatureAlgorithm, errors.New("unsupported slhdsa.ID")
}
