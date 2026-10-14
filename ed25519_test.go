package awskmsemulator_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func ed25519Public(t *testing.T, c *kms.Client, keyID string) ed25519.PublicKey {
	t.Helper()
	out, err := c.GetPublicKey(context.Background(), &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if out.KeySpec != types.KeySpecEccNistEdwards25519 || out.KeyUsage != types.KeyUsageTypeSignVerify {
		t.Fatalf("KeySpec/KeyUsage = %s/%s", out.KeySpec, out.KeyUsage)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		t.Fatalf("PublicKey is not an SPKI: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want ed25519.PublicKey", pub)
	}
	return edPub
}

func TestEd25519_SignRaw_VerifiesWithStdlib(t *testing.T) {
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistEdwards25519)
	pub := ed25519Public(t, c, *key.KeyId)

	for _, size := range []int{1, 32, 4096} {
		msg := make([]byte, size)
		for i := range msg {
			msg[i] = byte(i)
		}
		out, err := c.Sign(context.Background(), &kms.SignInput{
			KeyId: key.KeyId, Message: msg, MessageType: types.MessageTypeRaw,
			SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
		})
		if err != nil {
			t.Fatalf("Sign(%d bytes): %v", size, err)
		}
		if len(out.Signature) != ed25519.SignatureSize {
			t.Fatalf("signature is %d bytes, want raw %d", len(out.Signature), ed25519.SignatureSize)
		}
		if !ed25519.Verify(pub, msg, out.Signature) {
			t.Fatalf("ed25519.Verify rejected the KMS signature (%d bytes)", size)
		}
		if *out.KeyId != *key.Arn || out.SigningAlgorithm != types.SigningAlgorithmSpecEd25519Sha512 {
			t.Fatalf("response KeyId/SigningAlgorithm = %s/%s", *out.KeyId, out.SigningAlgorithm)
		}
	}
}

func TestEd25519_SignRaw_MessageTypeDefaultsToRaw(t *testing.T) {
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistEdwards25519)
	pub := ed25519Public(t, c, *key.KeyId)
	out, err := c.Sign(context.Background(), &kms.SignInput{
		KeyId: key.KeyId, Message: []byte("hello"), SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(pub, []byte("hello"), out.Signature) {
		t.Fatal("signature without MessageType did not verify as a RAW signature")
	}
}

// ED25519_PH_SHA_512 with DIGEST: the caller supplies a 64-byte SHA-512 digest
// and KMS prehashes it again, so the signature is Ed25519ph over SHA-512(digest).
func TestEd25519ph_SignDigest_VerifiesWithStdlib(t *testing.T) {
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistEdwards25519)
	pub := ed25519Public(t, c, *key.KeyId)

	digest := sha512.Sum512([]byte("a message too large to send, or not"))
	out, err := c.Sign(context.Background(), &kms.SignInput{
		KeyId: key.KeyId, Message: digest[:], MessageType: types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519PhSha512,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	prehash := sha512.Sum512(digest[:])
	if err := ed25519.VerifyWithOptions(pub, prehash[:], out.Signature, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
		t.Fatalf("Ed25519ph verification of the KMS signature failed: %v", err)
	}
	// A pure Ed25519 verifier must not accept an Ed25519ph signature.
	if ed25519.Verify(pub, digest[:], out.Signature) {
		t.Fatal("Ed25519ph signature verified as pure Ed25519")
	}
}

func TestEd25519_VerifyThroughKMS(t *testing.T) {
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistEdwards25519)
	ctx := context.Background()
	msg := []byte("verify me")
	signed, err := c.Sign(ctx, &kms.SignInput{
		KeyId: key.KeyId, Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := c.Verify(ctx, &kms.VerifyInput{
		KeyId: key.KeyId, Message: msg, Signature: signed.Signature,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil || !ok.SignatureValid {
		t.Fatalf("Verify = %+v, %v; want SignatureValid", ok, err)
	}
	_, err = c.Verify(ctx, &kms.VerifyInput{
		KeyId: key.KeyId, Message: []byte("other"), Signature: signed.Signature,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	wantCode(t, err, "KMSInvalidSignatureException")
}
