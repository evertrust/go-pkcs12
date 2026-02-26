// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/EverTrust/go-pkcs12/pkg/x509_evt"
)

func TestPfx(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, _ := base64.StdEncoding.DecodeString(base64P12)

		priv, _, cert, err := Decode(p12, "")
		if err != nil {
			t.Fatal(err)
		}

		if err := priv.(*rsa.PrivateKey).Validate(); err != nil {
			t.Errorf("error while validating private key: %v", err)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("expected common name to be %q, but found %q", commonName, cert.Subject.CommonName)
		}
	}
}

func TestPEM(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, _ := base64.StdEncoding.DecodeString(base64P12)

		blocks, err := ToPEM(p12, "")
		if err != nil {
			t.Fatalf("error while converting to PEM: %s", err)
		}

		var pemData []byte
		for _, b := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(b)...)
		}

		cert, err := tls.X509KeyPair(pemData, pemData)
		if err != nil {
			t.Errorf("err while converting to key pair: %v", err)
		}
		config := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		config.BuildNameToCertificate()

		if _, exists := config.NameToCertificate[commonName]; !exists {
			t.Errorf("did not find our cert in PEM?: %v", config.NameToCertificate)
		}
	}
}

func TestTrustStore(t *testing.T) {
	for commonName, base64P12 := range testdata {
		p12, _ := base64.StdEncoding.DecodeString(base64P12)

		_, _, cert, err := Decode(p12, "")
		if err != nil {
			t.Fatal(err)
		}

		pfxData, err := EncodeTrustStore(rand.Reader, []*x509.Certificate{cert}, "password")
		if err != nil {
			t.Fatal(err)
		}

		decodedCerts, err := DecodeTrustStore(pfxData, "password")
		if err != nil {
			t.Fatal(err)
		}

		if len(decodedCerts) != 1 {
			t.Fatal("Unexpected number of certs")
		}

		if decodedCerts[0].Subject.CommonName != commonName {
			t.Errorf("expected common name to be %q, but found %q", commonName, decodedCerts[0].Subject.CommonName)
		}
	}
}

func TestPBES2_AES256CBC(t *testing.T) {
	// This P12 PDU is a self-signed certificate exported via Windows certmgr.
	// It is encrypted with the following options (verified via openssl): PBES2, PBKDF2, AES-256-CBC, Iteration 2000, PRF hmacWithSHA256
	commonName := "*.ad.standalone.com"
	base64P12 := `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`
	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, _, cert, caCerts, err := DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if cert.Subject.CommonName != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

func TestPBES2_AES128CBC(t *testing.T) {
	//PKCS7 Encrypted data: PBES2, PBKDF2, AES-128-CBC, Iteration 2048, PRF hmacWithSHA256
	commonName := "example-com"
	base64P12 := `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`

	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, _, cert, caCerts, err := DecodeChain(p12, "rHyQTJsubhfxcpH5JttyilHE6BBsNoZp")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if cert.Subject.CommonName != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

func TestPBES2_AES192CBC(t *testing.T) {
	//PKCS7 Encrypted data: PBES2, PBKDF2, AES-192-CBC, Iteration 2048, PRF hmacWithSHA256
	commonName := "example-com"
	base64P12 := `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`

	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, _, cert, caCerts, err := DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}
	if !rsaPk.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key embedded in private key not equal to public key of certificate")
	}
	if cert.Subject.CommonName != commonName {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
	}
	if len(caCerts) != 0 {
		t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
	}
}

// FIXME: add PQC and hybrid tests

func TestEncode(t *testing.T) {
	base64P12 := `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`
	p12, _ := base64.StdEncoding.DecodeString(base64P12)
	pk, _, cert, _, err := DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}

	rsaPk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Error("could not cast to rsa private key")
	}

	_, err = Encode(rand.Reader, rsaPk, cert, nil, "test")
	if err != nil {
		t.Fatal(err)
	}

	legacy, err := LegacyDES.WithRand(rand.Reader).EncodeWithAttributes(rsaPk, cert, nil, "test", "myName", "Microsoft Software Key Storage Provider")
	if err != nil {
		t.Fatal(err)
	}
	// Try decoding
	_, _, pkcs, err := Decode(legacy, "test")
	if pkcs.Subject.CommonName != "*.ad.standalone.com" {
		t.Fatal("wrong legacy p12 decoded")
	}

	legacy, err = LegacyRC2.WithRand(rand.Reader).EncodeWithAttributes(rsaPk, cert, nil, "test", "myName", "Microsoft Software Key Storage Provider")
	if err != nil {
		t.Fatal(err)
	}
	// Try decoding
	_, _, pkcs, err = Decode(legacy, "test")
	if pkcs.Subject.CommonName != "*.ad.standalone.com" {
		t.Fatal("wrong legacy p12 decoded")
	}

	modern, err := Modern2023.WithRand(rand.Reader).EncodeWithAttributes(rsaPk, cert, nil, "test", "myName", "Microsoft Software Key Storage Provider")
	if err != nil {
		t.Fatal(err)
	}
	// Try decoding
	_, _, pkcs, err = Decode(modern, "test")
	if pkcs.Subject.CommonName != "*.ad.standalone.com" {
		t.Fatal("wrong legacy p12 decoded")
	}
}

func TestDecodeChain(t *testing.T) {

	// entity_issuing_root test case
	p12, _ := base64.StdEncoding.DecodeString(chaintestdata["entity_issuing_root"])
	_, _, cert, chain, err := DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "testing.example.com" {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, "testing.example.com")
	}
	if len(chain) != 2 {
		t.Errorf("unexpected # of caCerts: got %d, want 2", len(chain))
	}
	// check chain order
	if chain[0].Subject.CommonName != "LMO ISSUING CA" {
		t.Errorf("unexpected caCerts[0] common name, got %s, want %s", chain[0].Subject.CommonName, "LMO ISSUING CA")
	}
	if chain[1].Subject.CommonName != "LMO ROOT CA" {
		t.Errorf("unexpected caCerts[1] common name, got %s, want %s", chain[1].Subject.CommonName, "LMO ROOT CA")
	}

	//entity_root_issuing
	p12, _ = base64.StdEncoding.DecodeString(chaintestdata["entity_root_issuing"])
	_, _, cert, chain, err = DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "testing.example.com" {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, "testing.example.com")
	}
	if len(chain) != 2 {
		t.Errorf("unexpected # of caCerts: got %d, want 2", len(chain))
	}
	// check chain order
	if chain[0].Subject.CommonName != "LMO ROOT CA" {
		t.Errorf("unexpected caCerts[0] common name, got %s, want %s", chain[0].Subject.CommonName, "LMO ROOT CA")
	}
	if chain[1].Subject.CommonName != "LMO ISSUING CA" {
		t.Errorf("unexpected caCerts[1] common name, got %s, want %s", chain[1].Subject.CommonName, "LMO ISSUING CA")
	}

	//issuing_entity_root
	p12, _ = base64.StdEncoding.DecodeString(chaintestdata["issuing_entity_root"])
	_, _, cert, chain, err = DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "testing.example.com" {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, "testing.example.com")
	}
	if len(chain) != 2 {
		t.Errorf("unexpected # of caCerts: got %d, want 2", len(chain))
	}
	// check chain order
	if chain[0].Subject.CommonName != "LMO ISSUING CA" {
		t.Errorf("unexpected caCerts[0] common name, got %s, want %s", chain[0].Subject.CommonName, "LMO ISSUING CA")
	}
	if chain[1].Subject.CommonName != "LMO ROOT CA" {
		t.Errorf("unexpected caCerts[1] common name, got %s, want %s", chain[1].Subject.CommonName, "LMO ROOT CA")
	}

	//issuing_root_entity
	p12, _ = base64.StdEncoding.DecodeString(chaintestdata["issuing_root_entity"])
	_, _, cert, chain, err = DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "testing.example.com" {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, "testing.example.com")
	}
	if len(chain) != 2 {
		t.Errorf("unexpected # of caCerts: got %d, want 2", len(chain))
	}
	// check chain order
	if chain[0].Subject.CommonName != "LMO ISSUING CA" {
		t.Errorf("unexpected caCerts[0] common name, got %s, want %s", chain[0].Subject.CommonName, "LMO ISSUING CA")
	}
	if chain[1].Subject.CommonName != "LMO ROOT CA" {
		t.Errorf("unexpected caCerts[1] common name, got %s, want %s", chain[1].Subject.CommonName, "LMO ROOT CA")
	}

	//root_entity_issuing
	p12, _ = base64.StdEncoding.DecodeString(chaintestdata["root_entity_issuing"])
	_, _, cert, chain, err = DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "testing.example.com" {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, "testing.example.com")
	}
	if len(chain) != 2 {
		t.Errorf("unexpected # of caCerts: got %d, want 2", len(chain))
	}
	// check chain order
	if chain[0].Subject.CommonName != "LMO ROOT CA" {
		t.Errorf("unexpected caCerts[0] common name, got %s, want %s", chain[0].Subject.CommonName, "LMO ROOT CA")
	}
	if chain[1].Subject.CommonName != "LMO ISSUING CA" {
		t.Errorf("unexpected caCerts[1] common name, got %s, want %s", chain[1].Subject.CommonName, "LMO ROOT CA")
	}

	//root_issuing_entity
	p12, _ = base64.StdEncoding.DecodeString(chaintestdata["root_issuing_entity"])
	_, _, cert, chain, err = DecodeChain(p12, "password")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "testing.example.com" {
		t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, "testing.example.com")
	}
	if len(chain) != 2 {
		t.Errorf("unexpected # of caCerts: got %d, want 2", len(chain))
	}
	// check chain order
	if chain[0].Subject.CommonName != "LMO ROOT CA" {
		t.Errorf("unexpected caCerts[0] common name, got %s, want %s", chain[0].Subject.CommonName, "LMO ROOT CA")
	}
	if chain[1].Subject.CommonName != "LMO ISSUING CA" {
		t.Errorf("unexpected caCerts[1] common name, got %s, want %s", chain[1].Subject.CommonName, "LMO ISSUING CA")
	}

}

var testdata = map[string]string{
	// 'null' password test case
	"Windows Azure Tools": `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`,
	// empty string password test case
	"testing@example.com": `MIIJzgIBAzCCCZQGCSqGSIb3DQEHAaCCCYUEggmBMIIJfTCCA/cGCSqGSIb3DQEHBqCCA+gwggPk
AgEAMIID3QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIIszfRGqcmPcCAggAgIIDsOZ9Eg1L
s5Wx8JhYoV3HAL4aRnkAWvTYB5NISZOgSgIQTssmt/3A7134dibTmaT/93LikkL3cTKLnQzJ4wDf
YZ1bprpVJvUqz+HFT79m27bP9zYXFrvxWBJbxjYKTSjQMgz+h8LAEpXXGajCmxMJ1oCOtdXkhhzc
LdZN6SAYgtmtyFnCdMEDskSggGuLb3fw84QEJ/Sj6FAULXunW/CPaS7Ce0TMsKmNU/jfFWj3yXXw
ro0kwjKiVLpVFlnBlHo2OoVU7hmkm59YpGhLgS7nxLD3n7nBroQ0ID1+8R01NnV9XLGoGzxMm1te
6UyTCkr5mj+kEQ8EP1Ys7g/TC411uhVWySMt/rcpkx7Vz1r9kYEAzJpONAfr6cuEVkPKrxpq4Fh0
2fzlKBky0i/hrfIEUmngh+ERHUb/Mtv/fkv1j5w9suESbhsMLLiCXAlsP1UWMX+3bNizi3WVMEts
FM2k9byn+p8IUD/A8ULlE4kEaWeoc+2idkCNQkLGuIdGUXUFVm58se0auUkVRoRJx8x4CkMesT8j
b1H831W66YRWoEwwDQp2kK1lA2vQXxdVHWlFevMNxJeromLzj3ayiaFrfByeUXhR2S+Hpm+c0yNR
4UVU9WED2kacsZcpRm9nlEa5sr28mri5JdBrNa/K02OOhvKCxr5ZGmbOVzUQKla2z4w+Ku9k8POm
dfDNU/fGx1b5hcFWtghXe3msWVsSJrQihnN6q1ughzNiYZlJUGcHdZDRtiWwCFI0bR8h/Dmg9uO9
4rawQQrjIRT7B8yF3UbkZyAqs8Ppb1TsMeNPHh1rxEfGVQknh/48ouJYsmtbnzugTUt3mJCXXiL+
XcPMV6bBVAUu4aaVKSmg9+yJtY4/VKv10iw88ktv29fViIdBe3t6l/oPuvQgbQ8dqf4T8w0l/uKZ
9lS1Na9jfT1vCoS7F5TRi+tmyj1vL5kr/amEIW6xKEP6oeAMvCMtbPAzVEj38zdJ1R22FfuIBxkh
f0Zl7pdVbmzRxl/SBx9iIBJSqAvcXItiT0FIj8HxQ+0iZKqMQMiBuNWJf5pYOLWGrIyntCWwHuaQ
wrx0sTGuEL9YXLEAsBDrsvzLkx/56E4INGZFrH8G7HBdW6iGqb22IMI4GHltYSyBRKbB0gadYTyv
abPEoqww8o7/85aPSzOTJ/53ozD438Q+d0u9SyDuOb60SzCD/zPuCEd78YgtXJwBYTuUNRT27FaM
3LGMX8Hz+6yPNRnmnA2XKPn7dx/IlaqAjIs8MIIFfgYJKoZIhvcNAQcBoIIFbwSCBWswggVnMIIF
YwYLKoZIhvcNAQwKAQKgggTuMIIE6jAcBgoqhkiG9w0BDAEDMA4ECJr0cClYqOlcAgIIAASCBMhe
OQSiP2s0/46ONXcNeVAkz2ksW3u/+qorhSiskGZ0b3dFa1hhgBU2Q7JVIkc4Hf7OXaT1eVQ8oqND
uhqsNz83/kqYo70+LS8Hocj49jFgWAKrf/yQkdyP1daHa2yzlEw4mkpqOfnIORQHvYCa8nEApspZ
wVu8y6WVuLHKU67mel7db2xwstQp7PRuSAYqGjTfAylElog8ASdaqqYbYIrCXucF8iF9oVgmb/Qo
xrXshJ9aSLO4MuXlTPELmWgj07AXKSb90FKNihE+y0bWb9LPVFY1Sly3AX9PfrtkSXIZwqW3phpv
MxGxQl/R6mr1z+hlTfY9Wdpb5vlKXPKA0L0Rt8d2pOesylFi6esJoS01QgP1kJILjbrV731kvDc0
Jsd+Oxv4BMwA7ClG8w1EAOInc/GrV1MWFGw/HeEqj3CZ/l/0jv9bwkbVeVCiIhoL6P6lVx9pXq4t
KZ0uKg/tk5TVJmG2vLcMLvezD0Yk3G2ZOMrywtmskrwoF7oAUpO9e87szoH6fEvUZlkDkPVW1NV4
cZk3DBSQiuA3VOOg8qbo/tx/EE3H59P0axZWno2GSB0wFPWd1aj+b//tJEJHaaNR6qPRj4IWj9ru
Qbc8eRAcVWleHg8uAehSvUXlFpyMQREyrnpvMGddpiTC8N4UMrrBRhV7+UbCOWhxPCbItnInBqgl
1JpSZIP7iUtsIMdu3fEC2cdbXMTRul+4rdzUR7F9OaezV3jjvcAbDvgbK1CpyC+MJ1Mxm/iTgk9V
iUArydhlR8OniN84GyGYoYCW9O/KUwb6ASmeFOu/msx8x6kAsSQHIkKqMKv0TUR3kZnkxUvdpBGP
KTl4YCTvNGX4dYALBqrAETRDhua2KVBD/kEttDHwBNVbN2xi81+Mc7ml461aADfk0c66R/m2sjHB
2tN9+wG12OIWFQjL6wF/UfJMYamxx2zOOExiId29Opt57uYiNVLOO4ourPewHPeH0u8Gz35aero7
lkt7cZAe1Q0038JUuE/QGlnK4lESK9UkSIQAjSaAlTsrcfwtQxB2EjoOoLhwH5mvxUEmcNGNnXUc
9xj3M5BD3zBz3Ft7G3YMMDwB1+zC2l+0UG0MGVjMVaeoy32VVNvxgX7jk22OXG1iaOB+PY9kdk+O
X+52BGSf/rD6X0EnqY7XuRPkMGgjtpZeAYxRQnFtCZgDY4wYheuxqSSpdF49yNczSPLkgB3CeCfS
+9NTKN7aC6hBbmW/8yYh6OvSiCEwY0lFS/T+7iaVxr1loE4zI1y/FFp4Pe1qfLlLttVlkygga2UU
SCunTQ8UB/M5IXWKkhMOO11dP4niWwb39Y7pCWpau7mwbXOKfRPX96cgHnQJK5uG+BesDD1oYnX0
6frN7FOnTSHKruRIwuI8KnOQ/I+owmyz71wiv5LMQt+yM47UrEjB/EZa5X8dpEwOZvkdqL7utcyo
l0XH5kWMXdW856LL/FYftAqJIDAmtX1TXF/rbP6mPyN/IlDC0gjP84Uzd/a2UyTIWr+wk49Ek3vQ
/uDamq6QrwAxVmNh5Tset5Vhpc1e1kb7mRMZIzxSP8JcTuYd45oFKi98I8YjvueHVZce1g7OudQP
SbFQoJvdT46iBg1TTatlltpOiH2mFaxWVS0xYjAjBgkqhkiG9w0BCRUxFgQUdA9eVqvETX4an/c8
p8SsTugkit8wOwYJKoZIhvcNAQkUMS4eLABGAHIAaQBlAG4AZABsAHkAIABuAGEAbQBlACAAZgBv
AHIAIABjAGUAcgB0MDEwITAJBgUrDgMCGgUABBRFsNz3Zd1O1GI8GTuFwCWuDOjEEwQIuBEfIcAy
HQ8CAggA`,
}

func TestThatPrivateKeyEncodingAddsAttributeForDigitalSignatureCert(t *testing.T) {
	certString := `-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIQEBA8PccE/bx1uR/v13CfXDANBgkqhkiG9w0BAQsFADAO
MQwwCgYDVQQDDANBQzIwHhcNMjQwMjEzMTQwMzQ1WhcNMjUwMjEyMTQwMzQ1WjAP
MQ0wCwYDVQQDDAR0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
luvPARIaLq2J5FP7oXcQsNq2y6mZ9LMhPWtwz40L+tpO7Cgy+slTFV3tkB7ioMDw
3IY5B1HeWcvy8u3Ss5unywOHghsAqYnaGht85i2LeyjWQDUqN51tabqS27AsGjK6
A7GPk5oZdAWcKLWtyYBAi2XMn910FXIj3j5wx4rvdnsWrMKGk/JSkhaZXu9ZnrfC
yhHg89LdMqYkcAuP6dvB/jlM9FoNPxVaNgSSnGNFfI4RR09nkkhhgIQBYClWEJA2
RDXV5I208Nw+5b48CibgWmpyGi25JlsbAU2kIohE4ZCZT04UKA3ahjOWHEqdbsxS
bn+NqNlZNGuhImJnzLtkxQIDAQABo24wbDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBRO579pF0JvOC/mVIQCJWq548tqKzAfBgNVHSMEGDAWgBQmbdxzWH8HeoFiXE9o
hIBTrs/0MjALBgNVHQ8EBAMCB4AwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0B
AQsFAAOCAQEAGpb/+GpOfiLe3oGwAF9mIIpKNsUvKwwjyDsKB0jDZ/pDmU8LC/GT
iAjdLpPh53wRY9zzRNfgF0GO5gN3g3Eo2ULlLJxgtYlwqhrpbLjqbtFLTtuDyQ/V
waIQpBiZwI3GgzZ2+UZn3CNjgT5Ok7Qx0So4vtyp+JqUGphh7b+xsfWAhKr1vZHO
ZnYlJvPhNbi6sxrnkDT8ER00zhYYT88nl1rvXy5RvGvuLv7toohOp2z1rlRi9Gtt
SQBwvvB1HlA+U57VfqatoqP8zwuLEyiJgHjKzcUqYsS2g2Uid/EvjKnw9mgJ2Jnr
kRZdU0OmPc5ZQAWwKh41MLS8+gHYZOVidQ==
-----END CERTIFICATE-----`
	block, _ := pem.Decode([]byte(certString))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pemString := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCW688BEhourYnk
U/uhdxCw2rbLqZn0syE9a3DPjQv62k7sKDL6yVMVXe2QHuKgwPDchjkHUd5Zy/Ly
7dKzm6fLA4eCGwCpidoaG3zmLYt7KNZANSo3nW1pupLbsCwaMroDsY+Tmhl0BZwo
ta3JgECLZcyf3XQVciPePnDHiu92exaswoaT8lKSFple71met8LKEeDz0t0ypiRw
C4/p28H+OUz0Wg0/FVo2BJKcY0V8jhFHT2eSSGGAhAFgKVYQkDZENdXkjbTw3D7l
vjwKJuBaanIaLbkmWxsBTaQiiEThkJlPThQoDdqGM5YcSp1uzFJuf42o2Vk0a6Ei
YmfMu2TFAgMBAAECggEAHAxvSG+o1gwCmKDTH0sVmwjK+EbpCgVQpC2Xpbs9Ar4X
9OPztZA9FLeEM0jKLb4uBY4cgzO/80hoOqXghuji4mQhhxilotyv4DJDoDPOvHD2
gLBgzD1B3GiEarfvOl87GvyhBnmZSWrRfu9lARII7N9ajEuIC4RPDjrkkvFLV+V3
XLYN4/QiilcveHqgkWZkT6mqUnTeCCntw3gAuGNyUKZzF6SpoLeBX8E14boNOa5n
0kNwLb7tf8F6OM3Y4R2wWB1OXYIKwFiTswIYVDYuP6phIlJuqTw5JnRrkgSY3Auf
Yy3DrldQ9u8Ry7J/8LweshiL3sAYfSNuTtJOIodqgQKBgQDGUcMDhBSs6gs/zSxY
W4xNtSYfefIgMr+cjUvbhcToX3tVNTOEhFUUlPAsN+NBM2qmKK/8R79hYSQeg8Ny
KR8H1l0sJroZk5kKModpVfqf61TSipsdoGHyknKxynvX4FNHS9umzJ3kwgLlEb9F
WgwdcLHi4YMkSYeddgVknsLbTQKBgQDC0Ovz2EBhK2m5lkHumQeFxNe0cTxIXqaY
ayk2GzHy1vhnRD32qsDmjx4zuCdCKyHfoTPW4PWNuldacqI3/4RRs5d0dvHzlwjG
UmjGogtpbCD0y5wAwNjoe1lZR/y6VnqJcTicA9rqHfqIoNv6Grf62dYd+PCp1gre
C7A5TfhDWQKBgCdnBUUEkAsO8S86942SmtyxmiJ02xt0mcdj92dlO4sjtWBnkpXI
qRLOyK0waXGB4rWirdyE8MxLPZ7mdQWQj/7Bo39rLlx4i9aP1YGjOIlfe1ndehY3
0F4epLUYUuTASCuJMdoBG3ng5ixXC1afHnsW8fDu91xVU6GAWm/0byidAoGAXGph
VAaE29ONTtWhpz7+2406SkXhM+96lhlXrmwOMMWbhtlPj6EG6xh/WkeEkBYH9p7x
CYEj2zzHTYfNvkS/D0bjlQML2eMO7Y2QWJHsWfFKXPXtpknVW8uP4hONJxP5AxQr
p48InUDlZUTxtV5RYnVN5l/+QoLgGt9ulHCRUdkCgYEAunNFGBfZXj74t2pDkZIL
L8BwL5x8DEENUajGNIW7rJkwH632rXFnDvTjcQ9VtvgVXWXak83874U3Y6rBIR7C
n2EPOuMaB6Y1ViTzUsW3Ql4FlE/5bF372zbZxwy0DGKGt+Wpqlh980itiSQ+tz6J
rOCwZ+pNzdfXa2rpLwN7uCk=
-----END PRIVATE KEY-----`
	block, _ = pem.Decode([]byte(pemString))
	key, _, err := x509_evt.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := Modern2023.WithRand(rand.Reader).Encode(key, cert, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(pfx))
}

func TestThatPrivateKeyEncodingAddsAttributeForKeyEnciphermentCert(t *testing.T) {
	certString := `-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIQLojxnS/xQX/jQfzXgdvlSjANBgkqhkiG9w0BAQsFADAO
MQwwCgYDVQQDDANBQzIwHhcNMjQwMjEzMTQyMjAxWhcNMjUwMjEyMTQyMjAxWjAP
MQ0wCwYDVQQDDAR0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
luvPARIaLq2J5FP7oXcQsNq2y6mZ9LMhPWtwz40L+tpO7Cgy+slTFV3tkB7ioMDw
3IY5B1HeWcvy8u3Ss5unywOHghsAqYnaGht85i2LeyjWQDUqN51tabqS27AsGjK6
A7GPk5oZdAWcKLWtyYBAi2XMn910FXIj3j5wx4rvdnsWrMKGk/JSkhaZXu9ZnrfC
yhHg89LdMqYkcAuP6dvB/jlM9FoNPxVaNgSSnGNFfI4RR09nkkhhgIQBYClWEJA2
RDXV5I208Nw+5b48CibgWmpyGi25JlsbAU2kIohE4ZCZT04UKA3ahjOWHEqdbsxS
bn+NqNlZNGuhImJnzLtkxQIDAQABo24wbDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBRO579pF0JvOC/mVIQCJWq548tqKzAfBgNVHSMEGDAWgBQmbdxzWH8HeoFiXE9o
hIBTrs/0MjALBgNVHQ8EBAMCBSAwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0B
AQsFAAOCAQEAWmQ5U+BwvCyw7jvrkNsIbyG7tUsYdIzJ3TMzgD7Ts5LsPvQXDn9B
7rcp7O8h8obAW+ThtguzbDONdJrgipTkmLYxKEBDyQGi7PEmLzDGyduG+wS2ddhS
Mtl9Z1hS2MbGbwWwxkdWqj2UH9eop8MMWvcejaIV1ztLT6wVdHHRxzQshcd8nAjU
FVC81e0WPpAKWHfitM2zKy3tj7yQJmCk6/tZgQJC/hLPR/BR2euh1xlJUih2reNR
4LMAe6aCxSQ+3kDGg5Tht5/M4yfdn/JNCQGMQJY/yUuWyizuflInnWAMyjAoH64k
9lD9jGhvOqlvVXOx9mEZwXEZf53y18CSgA==
-----END CERTIFICATE-----`
	block, _ := pem.Decode([]byte(certString))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pemString := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCW688BEhourYnk
U/uhdxCw2rbLqZn0syE9a3DPjQv62k7sKDL6yVMVXe2QHuKgwPDchjkHUd5Zy/Ly
7dKzm6fLA4eCGwCpidoaG3zmLYt7KNZANSo3nW1pupLbsCwaMroDsY+Tmhl0BZwo
ta3JgECLZcyf3XQVciPePnDHiu92exaswoaT8lKSFple71met8LKEeDz0t0ypiRw
C4/p28H+OUz0Wg0/FVo2BJKcY0V8jhFHT2eSSGGAhAFgKVYQkDZENdXkjbTw3D7l
vjwKJuBaanIaLbkmWxsBTaQiiEThkJlPThQoDdqGM5YcSp1uzFJuf42o2Vk0a6Ei
YmfMu2TFAgMBAAECggEAHAxvSG+o1gwCmKDTH0sVmwjK+EbpCgVQpC2Xpbs9Ar4X
9OPztZA9FLeEM0jKLb4uBY4cgzO/80hoOqXghuji4mQhhxilotyv4DJDoDPOvHD2
gLBgzD1B3GiEarfvOl87GvyhBnmZSWrRfu9lARII7N9ajEuIC4RPDjrkkvFLV+V3
XLYN4/QiilcveHqgkWZkT6mqUnTeCCntw3gAuGNyUKZzF6SpoLeBX8E14boNOa5n
0kNwLb7tf8F6OM3Y4R2wWB1OXYIKwFiTswIYVDYuP6phIlJuqTw5JnRrkgSY3Auf
Yy3DrldQ9u8Ry7J/8LweshiL3sAYfSNuTtJOIodqgQKBgQDGUcMDhBSs6gs/zSxY
W4xNtSYfefIgMr+cjUvbhcToX3tVNTOEhFUUlPAsN+NBM2qmKK/8R79hYSQeg8Ny
KR8H1l0sJroZk5kKModpVfqf61TSipsdoGHyknKxynvX4FNHS9umzJ3kwgLlEb9F
WgwdcLHi4YMkSYeddgVknsLbTQKBgQDC0Ovz2EBhK2m5lkHumQeFxNe0cTxIXqaY
ayk2GzHy1vhnRD32qsDmjx4zuCdCKyHfoTPW4PWNuldacqI3/4RRs5d0dvHzlwjG
UmjGogtpbCD0y5wAwNjoe1lZR/y6VnqJcTicA9rqHfqIoNv6Grf62dYd+PCp1gre
C7A5TfhDWQKBgCdnBUUEkAsO8S86942SmtyxmiJ02xt0mcdj92dlO4sjtWBnkpXI
qRLOyK0waXGB4rWirdyE8MxLPZ7mdQWQj/7Bo39rLlx4i9aP1YGjOIlfe1ndehY3
0F4epLUYUuTASCuJMdoBG3ng5ixXC1afHnsW8fDu91xVU6GAWm/0byidAoGAXGph
VAaE29ONTtWhpz7+2406SkXhM+96lhlXrmwOMMWbhtlPj6EG6xh/WkeEkBYH9p7x
CYEj2zzHTYfNvkS/D0bjlQML2eMO7Y2QWJHsWfFKXPXtpknVW8uP4hONJxP5AxQr
p48InUDlZUTxtV5RYnVN5l/+QoLgGt9ulHCRUdkCgYEAunNFGBfZXj74t2pDkZIL
L8BwL5x8DEENUajGNIW7rJkwH632rXFnDvTjcQ9VtvgVXWXak83874U3Y6rBIR7C
n2EPOuMaB6Y1ViTzUsW3Ql4FlE/5bF372zbZxwy0DGKGt+Wpqlh980itiSQ+tz6J
rOCwZ+pNzdfXa2rpLwN7uCk=
-----END PRIVATE KEY-----`
	block, _ = pem.Decode([]byte(pemString))
	key, _, err := x509_evt.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := Modern2023.WithRand(rand.Reader).Encode(key, cert, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(pfx))
}

func TestThatPrivateKeyEncodingAddsAttributesForCertHavingBoth(t *testing.T) {
	certString := `-----BEGIN CERTIFICATE-----
MIIEdjCCAl6gAwIBAgIQfazpyXuiva0/DAJESzOgpzANBgkqhkiG9w0BAQsFADBD
MQswCQYDVQQGEwJGUjESMBAGA1UEChMJRXZlclRydXN0MSAwHgYDVQQDExdFdmVy
VHJ1c3QgUUEgSXNzdWluZyBDQTAeFw0yNDAyMDYwOTE1MDdaFw0yNTAyMDUwOTE1
MDdaMBMxETAPBgNVBAMMCHJhbmRvbWNuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAi7rrjLWC6JJ5UvFYjpMZHy/v5yWVjNOi6KipTepJLSFM+qd+TWEI
W8culVqo0kwN00eEhDbqMPHWhQzn0y72MtjtLMZxGkfMiq1oSVhbjuKyjZoHhvi9
uAvG3RFxgSYlt/E72F5FBy+epl+cj8TWZwtfXZG0SQT7EbV4zKq2RmvvKuo5vjTX
yOUQnPTJRYbt+1bnLidiykflN/PQmTGPFLzml9fT86NUc3bHVvo3j+uqgoIa35yL
HIW+kKb83M3UveqJQ1nRY412dDypzuu2lxYPGq8tfW3lYhgUhUa55JNqBIWL9wc5
hWQ3rcuXs9R4po3ytOnaznjvRjaHGyW1OQIDAQABo4GVMIGSMAwGA1UdEwEB/wQC
MAAwHQYDVR0OBBYEFL+WkjeE64csX65rIklnsZmnKWodMB8GA1UdIwQYMBaAFBQQ
3LAzCfegGprKagjWFldyJcCpMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggr
BgEFBQcDAgYIKwYBBQUHAwEwEwYDVR0RBAwwCoIIa3RvLnRlc3QwDQYJKoZIhvcN
AQELBQADggIBAHLR5xnZUxNohETkK8GvOn+4OZ+4BUz6pdgGF/xj9talMQQiQoEO
4XVIjeaBk4N8caRG4G0hEicDuBup138BhMXyOzE1jjpQ+0QfeeXeFlJ9wCZ0C5Ot
jseQQhV48e8UGHLB8lJKXJnb7VidUY5kjzW3QCszf32Y7kSRCQvQ0sujz9qgi+2F
N0+owprng2T9bRsDGN5CBMvBEz0KAryTrDPy0+W0K5agl0W/NWZ3Wt38sX3tvZiG
tS2ogocl4Lfq3XTlfJ/Mw1B2a9ncIHHwPyY3Lpvqbc6fukZkGXMeoYceBRnvJy3A
qdd+2StUu4JWzUNDD80Dcb1JkZFM7GxeUqphGxdmqQEW39mVydzwK9DZQdKb5vxR
VWE9OlRRyz5prnCEKdwOQu4p27//DJnEVODDZWO4k8h858ejeuOJR9xkP8QKwr1B
hQldRL1RGAmtpXEC9Ysmz5GC7ho1frlArsA+GECTY2Pee00WY40AtU44qZwtRO/W
OwVlvGseGI+1EjFXvZRutx4Tbvi9TP/9hY3NYf5RpFzuXCPJe7HDVyRzNz9ePNB0
ImYunPr0MI5Aj35IwcjItD+K7Roamoek6AmwLE2y5JQxKcHdglmQWpgksftzgZCw
NaMYk5FEuLn9lcMcbjS79RKwPSsZ2HnrKY4CvNnuZMSbsboAubZV7rut
-----END CERTIFICATE-----`
	block, _ := pem.Decode([]byte(certString))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pemString := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCLuuuMtYLoknlS
8ViOkxkfL+/nJZWM06LoqKlN6kktIUz6p35NYQhbxy6VWqjSTA3TR4SENuow8daF
DOfTLvYy2O0sxnEaR8yKrWhJWFuO4rKNmgeG+L24C8bdEXGBJiW38TvYXkUHL56m
X5yPxNZnC19dkbRJBPsRtXjMqrZGa+8q6jm+NNfI5RCc9MlFhu37VucuJ2LKR+U3
89CZMY8UvOaX19Pzo1RzdsdW+jeP66qCghrfnIschb6QpvzczdS96olDWdFjjXZ0
PKnO67aXFg8ary19beViGBSFRrnkk2oEhYv3BzmFZDety5ez1HimjfK06drOeO9G
NocbJbU5AgMBAAECggEAC7qD3Qq7U0RANMsXUNheCnUeoPtRo0F8ciT+GREqVURv
TrbSbjJP3kxIx7aVZxmFK4/cOrDVVYhnJkHgD6Toe3oj5lc91SPjslw93bIx9Tto
G2SrbxPf8NvkNFgre9i038y65j17c8/2dCagYJz4FiwpNBRv2pU1cdYWrq9Bn4V+
CDIAOZvj/Wud1Z8z7p/kzvu0xPvQb3+RFwVeS4mR4fA8EzXuEu2NY1PRXqdDTXO0
uA93JxrVSXoMhiFlWinZGwypZtMKqR4Esyb0smH6QL7u/HjDDWiDw4UCQd8lfOlc
BgaNIjraXl1hbjkh1znSJ7PbeuXbteg7FOi/mdv+gQKBgQDDb6/ftQ7fWN7KiOFW
3kDR82sa55gGtzBts4F20uv1IZSMGnJEbAMKTYH2UkCgZiulAxq8IWzCcGyylgmZ
grxw0zdpiDkEbcNtz0qL9l8gUMfDRdTapN4FATy4oeUQ3FJd/G2f1SRCaThn0/Zf
sB86nCqMMs7zm9l1UfuotUoAaQKBgQC3B/dFt5wxblIp6ZYBADPYymv460YXR0Jw
jlZ11ze2u4pcGRAPGCQRVQrLyM1q05wWQwlm6Cnm6ClVr2osyNEQS2oWHyl7AEZj
nb+hh6LxFMgkfSRuwp3gSJ8mhA4QJ9Ayo6+3+X47OuWwsIdEMMWDN3tnrtuhivPx
CSIKcKx0UQKBgH7G567Vk9U8oCGAE7U3LZNENVlZnJvWn7q59CSxhFEavHL6AN/z
tTEswD6acsPaIzvCvMgHYrbrGQfsHkQPs8/4o/x4WoxN67VC/9e1NVYQMNWyafZ/
dmqGt+4JTz/VvDStuCszp3bRLL7ll+/QnyF1BoC1wNv0YGcjjH2PRHbpAoGAMP5x
43il19mHJu7/F199gW+V/XjFN1/82fJQFJU6tbB39fVDhjbZGMah8DDdQ9ZHNvJU
5vYImWXWArjE/B35UJpPWIKY8PL+5JWKgWu0Y0JD3PieswNnjW0DJSU+Onbd1WBZ
ni6r6qD2cRif7NH9XQWSBAwbgJ+YcxIVyaOlljECgYEAg83pxvFsEKOnyIFBoclz
9LRbAlyxDIoY4RNigXL8gCcwMVWd2cNwOZbLgKanN2uOFXHvOCozrL5f5i6f7bHd
buwfesohD2EsN5FZ4HPsQGWTOBcJb0MXC/tJfUpKMiB8wCEm4CXezSZVNMHO4M9w
PhDP1i21jhMyUUoE2XsXUlU=
-----END PRIVATE KEY-----`
	block, _ = pem.Decode([]byte(pemString))
	key, _, err := x509_evt.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := Modern2023.WithRand(rand.Reader).Encode(key, cert, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(pfx))
}

func TestThatPrivateKeyEncodingAddsNoAttributeForCrlSignCert(t *testing.T) {
	certString := `-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIQI9LdZflGYvyastfzcuwqFTANBgkqhkiG9w0BAQsFADAO
MQwwCgYDVQQDDANBQzIwHhcNMjQwMjEzMTQyMzU0WhcNMjUwMjEyMTQyMzU0WjAP
MQ0wCwYDVQQDDAR0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
luvPARIaLq2J5FP7oXcQsNq2y6mZ9LMhPWtwz40L+tpO7Cgy+slTFV3tkB7ioMDw
3IY5B1HeWcvy8u3Ss5unywOHghsAqYnaGht85i2LeyjWQDUqN51tabqS27AsGjK6
A7GPk5oZdAWcKLWtyYBAi2XMn910FXIj3j5wx4rvdnsWrMKGk/JSkhaZXu9ZnrfC
yhHg89LdMqYkcAuP6dvB/jlM9FoNPxVaNgSSnGNFfI4RR09nkkhhgIQBYClWEJA2
RDXV5I208Nw+5b48CibgWmpyGi25JlsbAU2kIohE4ZCZT04UKA3ahjOWHEqdbsxS
bn+NqNlZNGuhImJnzLtkxQIDAQABo24wbDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBRO579pF0JvOC/mVIQCJWq548tqKzAfBgNVHSMEGDAWgBQmbdxzWH8HeoFiXE9o
hIBTrs/0MjALBgNVHQ8EBAMCAQIwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0B
AQsFAAOCAQEAP1mcf/hnn88Dix30YxEm+nOpCtQ+hi8VDEnw+dCmE0CS9Wn55Czh
ADQcDJDkZfxlTuOqqLc5SnvVQOqiqax3WIQHXJnJTHTgRVzMivg4qaqBZncY67AV
Lpxc0iiDGzt/Om3QR0W/pZx2moZSTUnYpa+BPacjAOQglisoegBA1tbrYpBwDXLB
l0d/RNhnZlEmbF5ZcjH1CEgR41nod7vTPocnQy4VDezqKWoZfppvB3T9c15leUyV
zRkvWx4gjG4IuLqDgUHeFz5leJobNmbuXeTILUYa25H6yZtj1Tg05R8HIi0jyhSf
wsDHGrzWpMGQJx6+8KoWLKUOPrGC+qj9JQ==
-----END CERTIFICATE-----`
	block, _ := pem.Decode([]byte(certString))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pemString := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCLuuuMtYLoknlS
8ViOkxkfL+/nJZWM06LoqKlN6kktIUz6p35NYQhbxy6VWqjSTA3TR4SENuow8daF
DOfTLvYy2O0sxnEaR8yKrWhJWFuO4rKNmgeG+L24C8bdEXGBJiW38TvYXkUHL56m
X5yPxNZnC19dkbRJBPsRtXjMqrZGa+8q6jm+NNfI5RCc9MlFhu37VucuJ2LKR+U3
89CZMY8UvOaX19Pzo1RzdsdW+jeP66qCghrfnIschb6QpvzczdS96olDWdFjjXZ0
PKnO67aXFg8ary19beViGBSFRrnkk2oEhYv3BzmFZDety5ez1HimjfK06drOeO9G
NocbJbU5AgMBAAECggEAC7qD3Qq7U0RANMsXUNheCnUeoPtRo0F8ciT+GREqVURv
TrbSbjJP3kxIx7aVZxmFK4/cOrDVVYhnJkHgD6Toe3oj5lc91SPjslw93bIx9Tto
G2SrbxPf8NvkNFgre9i038y65j17c8/2dCagYJz4FiwpNBRv2pU1cdYWrq9Bn4V+
CDIAOZvj/Wud1Z8z7p/kzvu0xPvQb3+RFwVeS4mR4fA8EzXuEu2NY1PRXqdDTXO0
uA93JxrVSXoMhiFlWinZGwypZtMKqR4Esyb0smH6QL7u/HjDDWiDw4UCQd8lfOlc
BgaNIjraXl1hbjkh1znSJ7PbeuXbteg7FOi/mdv+gQKBgQDDb6/ftQ7fWN7KiOFW
3kDR82sa55gGtzBts4F20uv1IZSMGnJEbAMKTYH2UkCgZiulAxq8IWzCcGyylgmZ
grxw0zdpiDkEbcNtz0qL9l8gUMfDRdTapN4FATy4oeUQ3FJd/G2f1SRCaThn0/Zf
sB86nCqMMs7zm9l1UfuotUoAaQKBgQC3B/dFt5wxblIp6ZYBADPYymv460YXR0Jw
jlZ11ze2u4pcGRAPGCQRVQrLyM1q05wWQwlm6Cnm6ClVr2osyNEQS2oWHyl7AEZj
nb+hh6LxFMgkfSRuwp3gSJ8mhA4QJ9Ayo6+3+X47OuWwsIdEMMWDN3tnrtuhivPx
CSIKcKx0UQKBgH7G567Vk9U8oCGAE7U3LZNENVlZnJvWn7q59CSxhFEavHL6AN/z
tTEswD6acsPaIzvCvMgHYrbrGQfsHkQPs8/4o/x4WoxN67VC/9e1NVYQMNWyafZ/
dmqGt+4JTz/VvDStuCszp3bRLL7ll+/QnyF1BoC1wNv0YGcjjH2PRHbpAoGAMP5x
43il19mHJu7/F199gW+V/XjFN1/82fJQFJU6tbB39fVDhjbZGMah8DDdQ9ZHNvJU
5vYImWXWArjE/B35UJpPWIKY8PL+5JWKgWu0Y0JD3PieswNnjW0DJSU+Onbd1WBZ
ni6r6qD2cRif7NH9XQWSBAwbgJ+YcxIVyaOlljECgYEAg83pxvFsEKOnyIFBoclz
9LRbAlyxDIoY4RNigXL8gCcwMVWd2cNwOZbLgKanN2uOFXHvOCozrL5f5i6f7bHd
buwfesohD2EsN5FZ4HPsQGWTOBcJb0MXC/tJfUpKMiB8wCEm4CXezSZVNMHO4M9w
PhDP1i21jhMyUUoE2XsXUlU=
-----END PRIVATE KEY-----`
	block, _ = pem.Decode([]byte(pemString))
	key, _, err := x509_evt.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pfx, err := Modern2023.WithRand(rand.Reader).Encode(key, cert, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(pfx))
}

func TestHybridParse(t *testing.T) {
	base64P12 := "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"

	p12Bytes, err := base64.StdEncoding.DecodeString(base64P12)
	if err != nil {
		t.Fatalf("could not decode pkcs#12: %v", err)
	}

	pKey, altPkey, cert, chain, err := DecodeChain(p12Bytes, "qWxdsvtM5a5YrfXB")
	if err != nil {
		t.Fatalf("could not parse pkcs#12: %v", err)
	}

	if _, ok := pKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("invalid private key: got %v", reflect.TypeOf(pKey))
	}

	if _, ok := altPkey.(*x509_evt.MLDSA44); !ok {
		t.Fatalf("invalid alternate private key: got %v", reflect.TypeOf(altPkey))
	}

	if cert == nil {
		t.Fatalf("could not parse certificate")
	}

	if cert.Subject.CommonName != "hybrid" {
		t.Fatalf("certificate was not parsed correctly: got cn: %s", cert.Subject.CommonName)
	}

	if chain == nil {
		t.Fatalf("could not parse chain")
	}
}

func TestPQCParse(t *testing.T) {
	base64P12 := "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"

	p12Bytes, err := base64.StdEncoding.DecodeString(base64P12)
	if err != nil {
		t.Fatalf("could not decode pkcs#12: %v", err)
	}

	pKey, altPkey, cert, chain, err := DecodeChain(p12Bytes, "2pyV2xCNKyswupz6")
	if err != nil {
		t.Fatalf("could not parse pkcs#12: %v", err)
	}

	if _, ok := pKey.(*x509_evt.MLDSA44); !ok {
		t.Fatalf("invalid private key: got %v", reflect.TypeOf(pKey))
	}

	if altPkey != nil {
		t.Fatalf("invalid alternate private key: got %v", reflect.TypeOf(altPkey))
	}

	if cert == nil {
		t.Fatalf("could not parse certificate")
	}

	if cert.Subject.CommonName != "pqc" {
		t.Fatalf("certificate was not parsed correctly: got cn: %s", cert.Subject.CommonName)
	}

	if chain == nil {
		t.Fatalf("could not parse chain")
	}
}

var chaintestdata = map[string]string{
	"entity_issuing_root": "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",
	"entity_root_issuing": "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",
	"issuing_entity_root": "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",
	"issuing_root_entity": "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",
	"root_entity_issuing": "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",
	"root_issuing_entity": "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",
}
