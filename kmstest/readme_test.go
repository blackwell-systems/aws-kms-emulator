package kmstest_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/blackwell-systems/aws-kms-emulator/kmstest"
)

// TestReadmeExample is the example in the README: sign with an Ed25519 KMS key
// and verify the signature outside KMS, with the public key from GetPublicKey.
func TestReadmeExample(t *testing.T) {
	ctx := context.Background()

	srv := kmstest.NewServer(t)
	client := srv.Client()

	key, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  types.KeySpecEccNistEdwards25519,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("release v1.2.3")
	signed, err := client.Sign(ctx, &kms.SignInput{
		KeyId:            key.KeyMetadata.KeyId,
		Message:          message,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		t.Fatal(err)
	}

	pub, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyMetadata.KeyId})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(pub.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(parsed.(ed25519.PublicKey), message, signed.Signature) {
		t.Fatal("signature does not verify")
	}
}
