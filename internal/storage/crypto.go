package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256 and SHA-224 for crypto.Hash.New
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for crypto.Hash.New
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// MaxMessageSize is the largest Message AWS KMS accepts in Sign and Verify.
const MaxMessageSize = 4096

// material is the private key material of one KMS key, with the operations
// the emulator needs from it.
type material struct {
	spec KeySpec
	priv crypto.PrivateKey // *ecdsa.PrivateKey, ed25519.PrivateKey, *rsa.PrivateKey or *secp256k1.PrivateKey
}

// oidSecp256k1 and oidECPublicKey build the SPKI of a secp256k1 key, which
// crypto/x509 cannot marshal.
var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

func generateMaterial(spec KeySpec) (*material, error) {
	var (
		priv crypto.PrivateKey
		err  error
	)
	switch spec {
	case SpecECCNISTP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case SpecECCNISTP384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case SpecECCNISTP521:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case SpecECCSECGP256K1:
		priv, err = secp256k1.GeneratePrivateKey()
	case SpecEd25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case SpecRSA2048:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case SpecRSA3072:
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	case SpecRSA4096:
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("no key material for key spec %s", spec)
	}
	if err != nil {
		return nil, err
	}
	return &material{spec: spec, priv: priv}, nil
}

// publicKeyDER returns the key's public key as a DER-encoded X.509
// SubjectPublicKeyInfo, which is what GetPublicKey returns.
func (m *material) publicKeyDER() ([]byte, error) {
	switch k := m.priv.(type) {
	case *ecdsa.PrivateKey:
		return x509.MarshalPKIXPublicKey(&k.PublicKey)
	case ed25519.PrivateKey:
		return x509.MarshalPKIXPublicKey(k.Public())
	case *rsa.PrivateKey:
		return x509.MarshalPKIXPublicKey(&k.PublicKey)
	case *secp256k1.PrivateKey:
		curve, err := asn1.Marshal(oidSecp256k1)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidECPublicKey, Parameters: asn1.RawValue{FullBytes: curve}},
			PublicKey: asn1.BitString{Bytes: k.PubKey().SerializeUncompressed()},
		})
	}
	return nil, errors.New("unsupported key type")
}

// marshalPrivate serializes the private key for the state file: PKCS #8 for
// the key types crypto/x509 handles, the raw 32-byte scalar for secp256k1.
func (m *material) marshalPrivate() ([]byte, error) {
	if k, ok := m.priv.(*secp256k1.PrivateKey); ok {
		return k.Serialize(), nil
	}
	return x509.MarshalPKCS8PrivateKey(m.priv)
}

func unmarshalMaterial(spec KeySpec, der []byte) (*material, error) {
	if spec == SpecECCSECGP256K1 {
		if len(der) != 32 {
			return nil, fmt.Errorf("secp256k1 private key is %d bytes, want 32", len(der))
		}
		return &material{spec: spec, priv: secp256k1.PrivKeyFromBytes(der)}, nil
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	return &material{spec: spec, priv: priv}, nil
}

// sign signs msg, which has already been validated against alg and mt. For a
// RAW message it hashes first; for a DIGEST it signs the digest as given.
func (m *material) sign(alg SigningAlgorithm, mt MessageType, msg []byte) ([]byte, error) {
	if alg == AlgEd25519 {
		// Pure Ed25519 signs the message itself; KMS requires RAW for it.
		return m.priv.(ed25519.PrivateKey).Sign(nil, msg, &ed25519.Options{})
	}
	if alg == AlgEd25519ph {
		// KMS requires DIGEST and still applies the Ed25519ph SHA-512
		// prehash to it ("hashed twice: once by you and once by KMS").
		ph := sha512Sum(msg)
		return m.priv.(ed25519.PrivateKey).Sign(nil, ph, &ed25519.Options{Hash: crypto.SHA512})
	}
	h := algHash(alg)
	digest := msg
	if mt != MessageDigest {
		digest = hashBytes(h, msg)
	}
	switch k := m.priv.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, digest)
	case *secp256k1.PrivateKey:
		return secpecdsa.Sign(k, digest).Serialize(), nil
	case *rsa.PrivateKey:
		if isPSS(alg) {
			return rsa.SignPSS(rand.Reader, k, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.SignPKCS1v15(rand.Reader, k, h, digest)
	}
	return nil, errors.New("unsupported key type")
}

// verify reports whether sig is a valid signature of msg under alg. It never
// returns an error for a malformed signature: that is simply not valid.
func (m *material) verify(alg SigningAlgorithm, mt MessageType, msg, sig []byte) bool {
	if alg == AlgEd25519 {
		pub := m.priv.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
		return ed25519.VerifyWithOptions(pub, msg, sig, &ed25519.Options{}) == nil
	}
	if alg == AlgEd25519ph {
		pub := m.priv.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
		return ed25519.VerifyWithOptions(pub, sha512Sum(msg), sig, &ed25519.Options{Hash: crypto.SHA512}) == nil
	}
	h := algHash(alg)
	digest := msg
	if mt != MessageDigest {
		digest = hashBytes(h, msg)
	}
	switch k := m.priv.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.VerifyASN1(&k.PublicKey, digest, sig)
	case *secp256k1.PrivateKey:
		parsed, err := secpecdsa.ParseDERSignature(sig)
		return err == nil && parsed.Verify(digest, k.PubKey())
	case *rsa.PrivateKey:
		if isPSS(alg) {
			return rsa.VerifyPSS(&k.PublicKey, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
		return rsa.VerifyPKCS1v15(&k.PublicKey, h, digest, sig) == nil
	}
	return false
}

func isPSS(alg SigningAlgorithm) bool {
	return alg == AlgRSAPSSSHA256 || alg == AlgRSAPSSSHA384 || alg == AlgRSAPSSSHA512
}

func hashBytes(h crypto.Hash, msg []byte) []byte {
	hh := h.New()
	hh.Write(msg)
	return hh.Sum(nil)
}

func sha512Sum(msg []byte) []byte { return hashBytes(crypto.SHA512, msg) }
