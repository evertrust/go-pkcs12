package x509_evt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
)

// Generated using:
//
//	openssl genrsa 1024 | openssl pkcs8WithAttributes -topk8 -nocrypt
var pkcs8RSAPrivateKeyHex = `30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ffa97b4f99df4ff122b70e59ac9b992f3bc2b3dde17d53c1a34928719b02e8fd17839499bfbd515bd6ef99c7a1c47a239718fe36bfd824c0d96060084b5f67f0273443007a24dfaf5634f7772c9346e10eb294c2306671a5a5e719ae24b4de467291bc571014b0e02dec04534d66a9bb171d644b66b091780e8d020301000102818100b595778383c4afdbab95d2bfed12b3f93bb0a73a7ad952f44d7185fd9ec6c34de8f03a48770f2009c8580bcd275e9632714e9a5e3f32f29dc55474b2329ff0ebc08b3ffcb35bc96e6516b483df80a4a59cceb71918cbabf91564e64a39d7e35dce21cb3031824fdbc845dba6458852ec16af5dddf51a8397a8797ae0337b1439024100ea0eb1b914158c70db39031dd8904d6f18f408c85fbbc592d7d20dee7986969efbda081fdf8bc40e1b1336d6b638110c836bfdc3f314560d2e49cd4fbde1e20b024100e32a4e793b574c9c4a94c8803db5152141e72d03de64e54ef2c8ed104988ca780cd11397bc359630d01b97ebd87067c5451ba777cf045ca23f5912f1031308c702406dfcdbbd5a57c9f85abc4edf9e9e29153507b07ce0a7ef6f52e60dcfebe1b8341babd8b789a837485da6c8d55b29bbb142ace3c24a1f5b54b454d01b51e2ad03024100bd6a2b60dee01e1b3bfcef6a2f09ed027c273cdbbaf6ba55a80f6dcc64e4509ee560f84b4f3e076bd03b11e42fe71a3fdd2dffe7e0902c8584f8cad877cdc945024100aa512fa4ada69881f1d8bb8ad6614f192b83200aef5edf4811313d5ef30a86cbd0a90f7b025c71ea06ec6b34db6306c86b1040670fd8654ad7291d066d06d031`

// Generated using:
//
//	openssl ecparam -genkey -name secp224r1 | openssl pkcs8WithAttributes -topk8 -nocrypt
var pkcs8P224PrivateKeyHex = `3078020100301006072a8648ce3d020106052b810400210461305f020101041cca3d72b3e88fed2684576dad9b80a9180363a5424986900e3abcab3fa13c033a0004f8f2a6372872a4e61263ed893afb919576a4cacfecd6c081a2cbc76873cf4ba8530703c6042b3a00e2205087e87d2435d2e339e25702fae1`

// Generated using:
//
//	openssl ecparam -genkey -name secp256r1 | openssl pkcs8WithAttributes -topk8 -nocrypt
var pkcs8P256PrivateKeyHex = `308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420dad6b2f49ca774c36d8ae9517e935226f667c929498f0343d2424d0b9b591b43a14403420004b9c9b90095476afe7b860d8bd43568cab7bcb2eed7b8bf2fa0ce1762dd20b04193f859d2d782b1e4cbfd48492f1f533113a6804903f292258513837f07fda735`

// Generated using:
//
//	openssl ecparam -genkey -name secp384r1 | openssl pkcs8WithAttributes -topk8 -nocrypt
var pkcs8P384PrivateKeyHex = `3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104309bf832f6aaaeacb78ce47ffb15e6fd0fd48683ae79df6eca39bfb8e33829ac94aa29d08911568684c2264a08a4ceb679a164036200049070ad4ed993c7770d700e9f6dc2baa83f63dd165b5507f98e8ff29b5d2e78ccbe05c8ddc955dbf0f7497e8222cfa49314fe4e269459f8e880147f70d785e530f2939e4bf9f838325bb1a80ad4cf59272ae0e5efe9a9dc33d874492596304bd3`

// Generated using:
//
//	openssl ecparam -genkey -name secp521r1 | openssl pkcs8WithAttributes -topk8 -nocrypt
//
// Note that OpenSSL will truncate the private key if it can (i.e. it emits it
// like an integer, even though it's an OCTET STRING field). Thus if you
// regenerate this you may, randomly, find that it's a byte shorter than
// expected and the Go test will fail to recreate it exactly.
var pkcs8P521PrivateKeyHex = `3081ee020100301006072a8648ce3d020106052b810400230481d63081d3020101044200cfe0b87113a205cf291bb9a8cd1a74ac6c7b2ebb8199aaa9a5010d8b8012276fa3c22ac913369fa61beec2a3b8b4516bc049bde4fb3b745ac11b56ab23ac52e361a1818903818600040138f75acdd03fbafa4f047a8e4b272ba9d555c667962b76f6f232911a5786a0964e5edea6bd21a6f8725720958de049c6e3e6661c1c91b227cebee916c0319ed6ca003db0a3206d372229baf9dd25d868bf81140a518114803ce40c1855074d68c4e9dab9e65efba7064c703b400f1767f217dac82715ac1f6d88c74baf47a7971de4ea`

// From RFC 8410, Section 7.
var pkcs8Ed25519PrivateKeyHex = `302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842`

// Generated using:
//
//	openssl genpkey -algorithm x25519
var pkcs8X25519PrivateKeyHex = `302e020100300506032b656e0422042068ff93a73c5adefd6d498b24e588fd4daa10924d992afed01b43ca5725025a6b`

// FIXME: add composite key
func TestPKCS8(t *testing.T) {
	tests := []struct {
		name       string
		keyHex     string
		keyType    reflect.Type
		altKeyType reflect.Type
		curve      elliptic.Curve
	}{
		{
			name:    "RSA private key",
			keyHex:  pkcs8RSAPrivateKeyHex,
			keyType: reflect.TypeOf(&rsa.PrivateKey{}),
		},
		{
			name:    "P-224 private key",
			keyHex:  pkcs8P224PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P224(),
		},
		{
			name:    "P-256 private key",
			keyHex:  pkcs8P256PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P256(),
		},
		{
			name:    "P-384 private key",
			keyHex:  pkcs8P384PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P384(),
		},
		{
			name:    "P-521 private key",
			keyHex:  pkcs8P521PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P521(),
		},
		{
			name:    "Ed25519 private key",
			keyHex:  pkcs8Ed25519PrivateKeyHex,
			keyType: reflect.TypeOf(ed25519.PrivateKey{}),
		},
		{
			name:    "X25519 private key",
			keyHex:  pkcs8X25519PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdh.PrivateKey{}),
		},
	}

	for _, test := range tests {
		derBytes, err := hex.DecodeString(test.keyHex)
		if err != nil {
			t.Errorf("%s: failed to decode hex: %s", test.name, err)
			continue
		}
		privKey, altPKey, err := ParsePKCS8PrivateKey(derBytes)
		if err != nil {
			t.Errorf("%s: failed to decode PKCS#8: %s", test.name, err)
			continue
		}
		if reflect.TypeOf(privKey) != test.keyType {
			t.Errorf("%s: decoded PKCS#8 returned unexpected key type: %T", test.name, privKey)
			continue
		}
		if ecKey, isEC := privKey.(*ecdsa.PrivateKey); isEC && ecKey.Curve != test.curve {
			t.Errorf("%s: decoded PKCS#8 returned unexpected curve %#v", test.name, ecKey.Curve)
			continue
		}
		if test.altKeyType != nil && reflect.TypeOf(altPKey) != test.altKeyType {
			t.Errorf("%s: decoded PKCS#8 returned unexpected alternate key type: %T", test.name, privKey)
			continue
		}
		// FIXME: marshal should probably marshal both ?
		reserialised, err := MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			t.Errorf("%s: failed to marshal into PKCS#8: %s", test.name, err)
			continue
		}
		if !bytes.Equal(derBytes, reserialised) {
			t.Errorf("%s: marshaled PKCS#8 didn't match original: got %x, want %x", test.name, reserialised, derBytes)
			continue
		}

		if ecKey, isEC := privKey.(*ecdsa.PrivateKey); isEC {
			ecdhKey, err := ecKey.ECDH()
			if err != nil {
				if ecKey.Curve != elliptic.P224() {
					t.Errorf("%s: failed to convert to ecdh: %s", test.name, err)
				}
				continue
			}
			reserialised, err := MarshalPKCS8PrivateKey(ecdhKey)
			if err != nil {
				t.Errorf("%s: failed to marshal into PKCS#8: %s", test.name, err)
				continue
			}
			if !bytes.Equal(derBytes, reserialised) {
				t.Errorf("%s: marshaled PKCS#8 didn't match original: got %x, want %x", test.name, reserialised, derBytes)
				continue
			}
		}
	}
}

const hexPKCS8TestPKCS1Key = "3082025c02010002818100b1a1e0945b9289c4d3f1329f8a982c4a2dcd59bfd372fb8085a9c517554607ebd2f7990eef216ac9f4605f71a03b04f42a5255b158cf8e0844191f5119348baa44c35056e20609bcf9510f30ead4b481c81d7865fb27b8e0090e112b717f3ee08cdfc4012da1f1f7cf2a1bc34c73a54a12b06372d09714742dd7895eadde4aa5020301000102818062b7fa1db93e993e40237de4d89b7591cc1ea1d04fed4904c643f17ae4334557b4295270d0491c161cb02a9af557978b32b20b59c267a721c4e6c956c2d147046e9ae5f2da36db0106d70021fa9343455f8f973a4b355a26fd19e6b39dee0405ea2b32deddf0f4817759ef705d02b34faab9ca93c6766e9f722290f119f34449024100d9c29a4a013a90e35fd1be14a3f747c589fac613a695282d61812a711906b8a0876c6181f0333ca1066596f57bff47e7cfcabf19c0fc69d9cd76df743038b3cb024100d0d3546fecf879b5551f2bd2c05e6385f2718a08a6face3d2aecc9d7e03645a480a46c81662c12ad6bd6901e3bd4f38029462de7290859567cdf371c79088d4f024100c254150657e460ea58573fcf01a82a4791e3d6223135c8bdfed69afe84fbe7857274f8eb5165180507455f9b4105c6b08b51fe8a481bb986a202245576b713530240045700003b7a867d0041df9547ae2e7f50248febd21c9040b12dae9c2feab0d3d4609668b208e4727a3541557f84d372ac68eaf74ce1018a4c9a0ef92682c8fd02405769731480bb3a4570abf422527c5f34bf732fa6c1e08cc322753c511ce055fac20fc770025663ad3165324314df907f1f1942f0448a7e9cdbf87ecd98b92156"
const hexPKCS8TestECKey = "3081a40201010430bdb9839c08ee793d1157886a7a758a3c8b2a17a4df48f17ace57c72c56b4723cf21dcda21d4e1ad57ff034f19fcfd98ea00706052b81040022a16403620004feea808b5ee2429cfcce13c32160e1c960990bd050bb0fdf7222f3decd0a55008e32a6aa3c9062051c4cba92a7a3b178b24567412d43cdd2f882fa5addddd726fe3e208d2c26d733a773a597abb749714df7256ead5105fa6e7b3650de236b50"

var pkcs8MismatchKeyTests = []struct {
	hexKey        string
	errorContains string
}{
	{hexKey: hexPKCS8TestECKey, errorContains: "use ParseECPrivateKey instead"},
	{hexKey: hexPKCS8TestPKCS1Key, errorContains: "use ParsePKCS1PrivateKey instead"},
}

func TestPKCS8MismatchKeyFormat(t *testing.T) {
	for i, test := range pkcs8MismatchKeyTests {
		derBytes, _ := hex.DecodeString(test.hexKey)
		_, _, err := ParsePKCS8PrivateKey(derBytes)
		if !strings.Contains(err.Error(), test.errorContains) {
			t.Errorf("#%d: expected error containing %q, got %s", i, test.errorContains, err)
		}
	}
}

func TestEncoding(t *testing.T) {
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
MIIEzQIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3LXzP7mmV17xk
BDxvy1quDEVhmtAlWN5r494KMSxzJ4+vG1p6EqXXng8iDtRzAps+J0qqSSwwrctX
4p0YuHlNZTN6g4tT+Fujug8g31D6nF1Kw4gDcNY2o0ksABQxHDlZrzrrbkHcLfQ8
nyAAGICtpMNfWR30qEfulYD0xNqUHho2KaNhMjSLkq3cCrNx792XJpRdHv6Er1Kw
iKlJ+nknQpuubTDTb8RPK8tOE6RtA4+ymCQ1Et1++CEeqhvq1P/desDzVRmeePHf
lTjmRJACyFlRrXTteKmURkv32QPTP51xOE5om9KmIxnxZxpwoAiJSVz/vl18G7qm
kbtRXNs9AgMBAAECggEAGGV6CJWHwXm8sRNxWzBZ0PF4ciH00+yMnxD3uyLGeUXN
GLTLbZO7O8bk3BPejrzLoVEJXDmnpYoYGYnog2jaWwj9/LS1Y0ciKWG37xhfCCm4
MSNuo4qtNRS1Q6N1DP9l0gCJF98U7Xa/Xy2QTQL2bGoTzUiouTOKdQe7Z54qQGyy
GHb4VUQkSchmqAMopJRyIuZ0aICxr5TRKlu4I2DU+MTceA2u50fWfeiJ7xJ2GbBm
u19Jus2Efch4DO2bWbSLMtyJJaxj+yQyPFFV5VPRT0YtWyH1VLdwDOxicMbhWQEn
r616dEOJ1ptBqaTfdqIbcWnBZ0n/VMUKx8YJUpumQQKBgQDpPz1jwWvPcslFOObV
MY+yTVxOjOmd2vB41n6xtQVzB0sSik/4pT8OQ0iHHOGtXZiPfw728Y3stmZr9eAO
LSkVN7rmcE5GkT7FmlmYT8+sXBWSJsmJ+dYie8UsyChkRGkt+T21Mszs4rOIT1Zk
KFr4QUf5znbAACNpuYRqEL1r4QKBgQDJC+QsnKMywWUTRvL8iqJ2IFDifb8WXTX6
nzj7YIv02NV2fX2NcQZDhfg9y47Q+MpaNGLEaL7Xqzn5ZZHHBN8ODPO41fQyItKw
PJ9p5gzAe5W1fNOvZMOw89wEXCiEdg3rsotkliPj/BjZY9AgP6FYgPx67uVfm0DY
hTPh6h363QKBgH7ySWJCwn+stLi1KIU+LTxY+HVUIk4k/B54d4oWwPmDLavQlYf5
wCDuI8pNwNJPj5oCCE4E2D7OY148+w4cLDD9HP8QfrnPkX+Q61SHk7r2f1MFQ0mS
LaalAILICZvQ1AIOljRJitke5aG5tIZcpG5bcWYXpfAH4z5Glzf3FnFhAoGBAI9D
fwRfVlg7wff7rflSHTUKEDllm/6my2ldfvB6uyDuRybZg9d/vBPv6pa2cH3vW9rt
y5fkgGIVLQnQXBIzIXPUvPRw2kPD1tkpSfvfqCSdrHAYlIw+xMha7eTZezHxIjhc
EcLKzqaOpXJ8Evp3/VShDcnYZPE9I/dm7DLHbzetAoGBAI3cXMLQ0EtYiLzne2Ed
rz1OsdEENYa4tcnLgDeCb3CIfzd7JSS/e4rhrKtkPinFn5PACyoGcL3DcBxR4Smb
EKr/kSWhA3QCCI3VvDk9ig+v/sBGYXzKrubtniDqcHGskFZ70w15uFA+95II0pjH
ayzhr3Fk02N0kDKS6Uz58HBCoA0wCwYDVR0PMQQDAgeA
-----END PRIVATE KEY-----`
	block, _ = pem.Decode([]byte(pemString))
	key, _, err := ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	asn1Data, err := MarshalPKCS8PrivateKeyWithAttributes(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(asn1Data))
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
	key, _, err := ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	asn1val, err := MarshalPKCS8PrivateKeyWithAttributes(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(asn1val))
	var privateKeyWithAttr pkcs8WithAttributes
	_, err = asn1.Unmarshal(asn1val, &privateKeyWithAttr)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyWithAttr.Attributes) != 1 || len(privateKeyWithAttr.Attributes[0].Values) != 1 || int(privateKeyWithAttr.Attributes[0].Values[0].Bytes[0]) != 0b10000000 {
		t.Fatal("key should have digitalsignature only")
	}
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
	key, _, err := ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	asn1val, err := MarshalPKCS8PrivateKeyWithAttributes(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(asn1val))
	var privateKeyWithAttr pkcs8WithAttributes
	_, err = asn1.Unmarshal(asn1val, &privateKeyWithAttr)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyWithAttr.Attributes) != 1 || len(privateKeyWithAttr.Attributes[0].Values) != 1 || int(privateKeyWithAttr.Attributes[0].Values[0].Bytes[0]) != 0b00010000 {
		t.Fatal("key should have dataencipherment only")
	}
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
	key, _, err := ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	asn1val, err := MarshalPKCS8PrivateKeyWithAttributes(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(asn1val))
	var privateKeyWithAttr pkcs8WithAttributes
	_, err = asn1.Unmarshal(asn1val, &privateKeyWithAttr)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyWithAttr.Attributes) != 1 || len(privateKeyWithAttr.Attributes[0].Values) != 1 || int(privateKeyWithAttr.Attributes[0].Values[0].Bytes[0]) != 0b10010000 {
		t.Fatal("key should have digitalsignature and dataencipherment")
	}
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
	key, _, err := ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	asn1val, err := MarshalPKCS8PrivateKeyWithAttributes(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(asn1val))
	var privateKeyWithAttr pkcs8WithAttributes
	_, err = asn1.Unmarshal(asn1val, &privateKeyWithAttr)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyWithAttr.Attributes) != 0 {
		t.Fatal("key should have no attributes")
	}
}
