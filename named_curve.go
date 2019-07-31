package dtls

import (
	"crypto/elliptic"
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type namedCurve uint16

type namedCurveKeypair struct {
	curve      namedCurve
	publicKey  []byte
	privateKey []byte
}

const (
	namedCurveP256   namedCurve = 0x0017 // 23
	namedCurveP384   namedCurve = 0x0018 // 24
	namedCurveP521   namedCurve = 0x0019 // 25
	namedCurveX25519 namedCurve = 0x001d // 29
)

var namedCurves = map[namedCurve]bool{
	namedCurveX25519: true,
	namedCurveP256:   true,
	namedCurveP384:   true,
	namedCurveP521:   true,
}

func generateKeypair(c namedCurve) (*namedCurveKeypair, error) {
	switch c {
	case namedCurveX25519:
		tmp := make([]byte, 32)
		if _, err := rand.Read(tmp); err != nil {
			return nil, err
		}

		var public, private [32]byte
		copy(private[:], tmp)

		curve25519.ScalarBaseMult(&public, &private)
		return &namedCurveKeypair{namedCurveX25519, public[:], private[:]}, nil
	case namedCurveP256:
		privateKey, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		return &namedCurveKeypair{namedCurveP256, elliptic.Marshal(elliptic.P256(), x, y), privateKey}, nil
	case namedCurveP384:
		privateKey, x, y, err := elliptic.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}

		return &namedCurveKeypair{namedCurveP256, elliptic.Marshal(elliptic.P384(), x, y), privateKey}, nil
	case namedCurveP521:
		privateKey, x, y, err := elliptic.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}

		return &namedCurveKeypair{namedCurveP256, elliptic.Marshal(elliptic.P521(), x, y), privateKey}, nil
	}
	return nil, errInvalidNamedCurve
}
