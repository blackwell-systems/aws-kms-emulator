package awskmsemulator_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type signCase struct {
	spec types.KeySpec
	alg  types.SigningAlgorithmSpec
	hash crypto.Hash
	slow bool
}

var signCases = []signCase{
	{spec: types.KeySpecEccNistP256, alg: types.SigningAlgorithmSpecEcdsaSha256, hash: crypto.SHA256},
	{spec: types.KeySpecEccNistP384, alg: types.SigningAlgorithmSpecEcdsaSha384, hash: crypto.SHA384},
	{spec: types.KeySpecEccNistP521, alg: types.SigningAlgorithmSpecEcdsaSha512, hash: crypto.SHA512},
	{spec: types.KeySpecEccSecgP256k1, alg: types.SigningAlgorithmSpecEcdsaSha256, hash: crypto.SHA256},
	{spec: types.KeySpecRsa2048, alg: types.SigningAlgorithmSpecRsassaPssSha256, hash: crypto.SHA256},
	{spec: types.KeySpecRsa2048, alg: types.SigningAlgorithmSpecRsassaPssSha384, hash: crypto.SHA384},
	{spec: types.KeySpecRsa2048, alg: types.SigningAlgorithmSpecRsassaPssSha512, hash: crypto.SHA512},
	{spec: types.KeySpecRsa2048, alg: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, hash: crypto.SHA256},
	{spec: types.KeySpecRsa2048, alg: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, hash: crypto.SHA384},
	{spec: types.KeySpecRsa2048, alg: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, hash: crypto.SHA512},
	{spec: types.KeySpecRsa3072, alg: types.SigningAlgorithmSpecRsassaPssSha256, hash: crypto.SHA256, slow: true},
	{spec: types.KeySpecRsa4096, alg: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, hash: crypto.SHA256, slow: true},
}

func sum(h crypto.Hash, msg []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(msg)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(msg)
		return d[:]
	}
	d := sha512.Sum512(msg)
	return d[:]
}

// verifyExternally checks sig against the public key from GetPublicKey with
// nothing but the standard library (and dcrd for secp256k1, which the standard
// library lacks), the way a consumer of a KMS signature would.
func verifyExternally(t *testing.T, pubDER []byte, c signCase, digest, sig []byte) bool {
	t.Helper()
	if c.spec == types.KeySpecEccSecgP256k1 {
		var spki struct {
			Algorithm struct {
				ID    asn1.ObjectIdentifier
				Curve asn1.ObjectIdentifier
			}
			PublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(pubDER, &spki); err != nil {
			t.Fatalf("secp256k1 SPKI: %v", err)
		}
		if !spki.Algorithm.ID.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}) || !spki.Algorithm.Curve.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 10}) {
			t.Fatalf("secp256k1 SPKI algorithm = %v", spki.Algorithm)
		}
		pub, err := secp256k1.ParsePubKey(spki.PublicKey.Bytes)
		if err != nil {
			t.Fatalf("secp256k1 point: %v", err)
		}
		parsed, err := secpecdsa.ParseDERSignature(sig)
		if err != nil {
			t.Fatalf("secp256k1 signature is not DER: %v", err)
		}
		return parsed.Verify(digest, pub)
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest, sig) // also proves the signature is DER
	case *rsa.PublicKey:
		switch c.alg {
		case types.SigningAlgorithmSpecRsassaPssSha256, types.SigningAlgorithmSpecRsassaPssSha384, types.SigningAlgorithmSpecRsassaPssSha512:
			return rsa.VerifyPSS(k, c.hash, digest, sig, &rsa.PSSOptions{SaltLength: c.hash.Size()}) == nil
		}
		return rsa.VerifyPKCS1v15(k, c.hash, digest, sig) == nil
	}
	t.Fatalf("unexpected public key type %T", pub)
	return false
}

func TestSign_AllSpecsVerifyExternally(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	for _, tc := range signCases {
		t.Run(fmt.Sprintf("%s/%s", tc.spec, tc.alg), func(t *testing.T) {
			if tc.slow && testing.Short() {
				t.Skip("slow RSA key generation")
			}
			key := createKey(t, c, tc.spec)
			pk, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyId})
			if err != nil {
				t.Fatalf("GetPublicKey: %v", err)
			}
			if pk.KeySpec != tc.spec || pk.KeyUsage != types.KeyUsageTypeSignVerify {
				t.Fatalf("GetPublicKey KeySpec/KeyUsage = %s/%s", pk.KeySpec, pk.KeyUsage)
			}
			found := false
			for _, a := range pk.SigningAlgorithms {
				found = found || a == tc.alg
			}
			if !found {
				t.Fatalf("SigningAlgorithms %v lacks %s", pk.SigningAlgorithms, tc.alg)
			}

			msg := []byte("the quick brown fox")
			digest := sum(tc.hash, msg)

			for _, mt := range []struct {
				name string
				typ  types.MessageType
				in   []byte
			}{{"RAW", types.MessageTypeRaw, msg}, {"DIGEST", types.MessageTypeDigest, digest}} {
				signed, err := c.Sign(ctx, &kms.SignInput{
					KeyId: key.KeyId, Message: mt.in, MessageType: mt.typ, SigningAlgorithm: tc.alg,
				})
				if err != nil {
					t.Fatalf("Sign %s: %v", mt.name, err)
				}
				if !verifyExternally(t, pk.PublicKey, tc, digest, signed.Signature) {
					t.Fatalf("%s signature did not verify against the public key", mt.name)
				}
				// A message and its digest are the same message to Verify.
				for _, vt := range []struct {
					typ types.MessageType
					in  []byte
				}{{types.MessageTypeRaw, msg}, {types.MessageTypeDigest, digest}} {
					res, err := c.Verify(ctx, &kms.VerifyInput{
						KeyId: key.KeyId, Message: vt.in, MessageType: vt.typ,
						Signature: signed.Signature, SigningAlgorithm: tc.alg,
					})
					if err != nil || !res.SignatureValid {
						t.Fatalf("Verify(%s) of a %s signature = %+v, %v", vt.typ, mt.name, res, err)
					}
				}
			}
		})
	}
}

func TestSign_P256CurveMatchesSpec(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	for spec, curve := range map[types.KeySpec]elliptic.Curve{
		types.KeySpecEccNistP256: elliptic.P256(),
		types.KeySpecEccNistP384: elliptic.P384(),
		types.KeySpecEccNistP521: elliptic.P521(),
	} {
		key := createKey(t, c, spec)
		pk, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyId})
		if err != nil {
			t.Fatalf("GetPublicKey(%s): %v", spec, err)
		}
		pub, err := x509.ParsePKIXPublicKey(pk.PublicKey)
		if err != nil {
			t.Fatalf("ParsePKIXPublicKey(%s): %v", spec, err)
		}
		if got := pub.(*ecdsa.PublicKey).Curve; got != curve {
			t.Fatalf("%s key is on curve %v, want %v", spec, got.Params().Name, curve.Params().Name)
		}
	}
}

func TestVerify_TamperedInputsFail(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	msg := []byte("payload")
	signed, err := c.Sign(ctx, &kms.SignInput{KeyId: key.KeyId, Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	flipped := append([]byte(nil), signed.Signature...)
	flipped[len(flipped)-1] ^= 1
	for name, in := range map[string]*kms.VerifyInput{
		"changed message":   {KeyId: key.KeyId, Message: []byte("payloaD"), Signature: signed.Signature, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256},
		"changed signature": {KeyId: key.KeyId, Message: msg, Signature: flipped, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256},
		"not DER":           {KeyId: key.KeyId, Message: msg, Signature: []byte{1, 2, 3}, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256},
		// A RAW message hashed once is not the same as a digest hashed again.
		"digest signed as raw": {KeyId: key.KeyId, Message: sum(crypto.SHA256, msg), MessageType: types.MessageTypeRaw, Signature: signed.Signature, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256},
	} {
		_, err := c.Verify(ctx, in)
		if errCode(err) != "KMSInvalidSignatureException" {
			t.Errorf("%s: error = %v, want KMSInvalidSignatureException", name, err)
		}
	}
	other := createKey(t, c, types.KeySpecEccNistP256)
	_, err = c.Verify(ctx, &kms.VerifyInput{KeyId: other.KeyId, Message: msg, Signature: signed.Signature, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
	wantCode(t, err, "KMSInvalidSignatureException")
}

func TestEd25519_SignatureIsDeterministic(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistEdwards25519)
	var sigs [][]byte
	for i := 0; i < 2; i++ {
		out, err := c.Sign(ctx, &kms.SignInput{KeyId: key.KeyId, Message: []byte("m"), SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512})
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, out.Signature)
	}
	if string(sigs[0]) != string(sigs[1]) {
		t.Fatal("Ed25519 signatures of one message differ; Ed25519 is deterministic")
	}
}

func TestSign_ByAliasKeyARNAndAliasARN(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistEdwards25519)
	if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/signer"), TargetKeyId: key.KeyId}); err != nil {
		t.Fatalf("CreateAlias: %v", err)
	}
	aliasARN := "arn:aws:kms:us-east-1:111122223333:alias/signer"
	for _, id := range []string{*key.KeyId, *key.Arn, "alias/signer", aliasARN} {
		out, err := c.Sign(ctx, &kms.SignInput{KeyId: aws.String(id), Message: []byte("m"), SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512})
		if err != nil {
			t.Fatalf("Sign with KeyId %q: %v", id, err)
		}
		if *out.KeyId != *key.Arn {
			t.Fatalf("Sign with KeyId %q returned KeyId %q, want the key ARN %q", id, *out.KeyId, *key.Arn)
		}
	}
}
