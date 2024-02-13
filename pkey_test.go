package pkcs12

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

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
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	asn1Data, err := marshalPKCS8PrivateKey(cert, key)
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
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	asn1val, err := marshalPKCS8PrivateKey(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(asn1val))
	var privateKeyWithAttr pkcs8
	_, err = asn1.Unmarshal(asn1val, &privateKeyWithAttr)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyWithAttr.Attributes) != 1 || len(privateKeyWithAttr.Attributes[0].Values) != 1 || int(privateKeyWithAttr.Attributes[0].Values[0].Bytes[0]) != 0b10000000 {
		t.Fatal("key should have digitalsignature only")
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
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	asn1val, err := marshalPKCS8PrivateKey(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(asn1val))
	var privateKeyWithAttr pkcs8
	_, err = asn1.Unmarshal(asn1val, &privateKeyWithAttr)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyWithAttr.Attributes) != 1 || len(privateKeyWithAttr.Attributes[0].Values) != 1 || int(privateKeyWithAttr.Attributes[0].Values[0].Bytes[0]) != 0b00010000 {
		t.Fatal("key should have dataencipherment only")
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
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	asn1val, err := marshalPKCS8PrivateKey(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(asn1val))
	var privateKeyWithAttr pkcs8
	_, err = asn1.Unmarshal(asn1val, &privateKeyWithAttr)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyWithAttr.Attributes) != 1 || len(privateKeyWithAttr.Attributes[0].Values) != 1 || int(privateKeyWithAttr.Attributes[0].Values[0].Bytes[0]) != 0b10010000 {
		t.Fatal("key should have digitalsignature and dataencipherment")
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
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	asn1val, err := marshalPKCS8PrivateKey(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(asn1val))
	pfx, err := Modern2023.WithRand(rand.Reader).Encode(key, cert, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(pfx))
	var privateKeyWithAttr pkcs8
	_, err = asn1.Unmarshal(asn1val, &privateKeyWithAttr)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyWithAttr.Attributes) != 0 {
		t.Fatal("key should have no attributes")
	}
}
