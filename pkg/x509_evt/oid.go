package x509_evt

import (
	"crypto/x509"
	"encoding/asn1"
	"reflect"
	"unsafe"
)

func newOIDFromDER(der []byte) (x509.OID, bool) {
	if len(der) == 0 || der[len(der)-1]&0x80 != 0 {
		return x509.OID{}, false
	}

	start := 0
	for i, v := range der {
		// ITU-T X.690, section 8.19.2:
		// The subidentifier shall be encoded in the fewest possible octets,
		// that is, the leading octet of the subidentifier shall not have the value 0x80.
		if i == start && v == 0x80 {
			return x509.OID{}, false
		}
		if v&0x80 == 0 {
			start = i + 1
		}
	}

	// FIXME: ugly trick to allow modification of der
	var final x509.OID

	v := reflect.ValueOf(&final).Elem()
	f := v.FieldByName("der")

	ptr := unsafe.Pointer(f.UnsafeAddr())
	realPtr := (*[]byte)(ptr)
	*realPtr = der

	return final, true
}

func toASN1OID(oid x509.OID) (asn1.ObjectIdentifier, bool) {

	v := reflect.ValueOf(oid)
	f := v.FieldByName("der")

	oidDer := f.Bytes()

	out := make([]int, 0, len(oidDer)+1)

	const (
		valSize         = 31 // amount of usable bits of val for OIDs.
		bitsPerByte     = 7
		maxValSafeShift = (1 << (valSize - bitsPerByte)) - 1
	)

	val := 0

	for _, v := range oidDer {
		if val > maxValSafeShift {
			return nil, false
		}

		val <<= bitsPerByte
		val |= int(v & 0x7F)

		if v&0x80 == 0 {
			if len(out) == 0 {
				if val < 80 {
					out = append(out, val/40)
					out = append(out, val%40)
				} else {
					out = append(out, 2)
					out = append(out, val-80)
				}
				val = 0
				continue
			}
			out = append(out, val)
			val = 0
		}
	}

	return out, true
}
