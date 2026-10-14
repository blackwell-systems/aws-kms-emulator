package awskmsemulator_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Verify must reject a changed message and a damaged signature for every
// algorithm, including the Ed25519 pair and both RSA paddings.
func TestVerify_TamperRejectedForEveryAlgorithm(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	cases := append([]signCase{}, signCases...)
	cases = append(cases,
		signCase{spec: types.KeySpecEccNistEdwards25519, alg: types.SigningAlgorithmSpecEd25519Sha512},
		signCase{spec: types.KeySpecEccNistEdwards25519, alg: types.SigningAlgorithmSpecEd25519PhSha512, hash: 0})
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s", tc.spec, tc.alg), func(t *testing.T) {
			if tc.slow && testing.Short() {
				t.Skip("slow RSA key generation")
			}
			key := createKey(t, c, tc.spec)
			ph := tc.alg == types.SigningAlgorithmSpecEd25519PhSha512
			mt := types.MessageTypeRaw
			msg, other := []byte("original"), []byte("0riginal")
			if ph {
				mt = types.MessageTypeDigest
				msg, other = make([]byte, 64), make([]byte, 64)
				other[0] = 1
			}
			signed, err := c.Sign(ctx, &kms.SignInput{KeyId: key.KeyId, Message: msg, MessageType: mt, SigningAlgorithm: tc.alg})
			if err != nil {
				t.Fatal(err)
			}
			in := func(m, sig []byte) *kms.VerifyInput {
				return &kms.VerifyInput{KeyId: key.KeyId, Message: m, MessageType: mt, Signature: sig, SigningAlgorithm: tc.alg}
			}
			if res, err := c.Verify(ctx, in(msg, signed.Signature)); err != nil || !res.SignatureValid {
				t.Fatalf("the genuine signature was rejected: %v", err)
			}
			_, err = c.Verify(ctx, in(other, signed.Signature))
			wantCode(t, err, "KMSInvalidSignatureException")
			flipped := append([]byte(nil), signed.Signature...)
			flipped[len(flipped)/2] ^= 0x80
			_, err = c.Verify(ctx, in(msg, flipped))
			wantCode(t, err, "KMSInvalidSignatureException")
		})
	}
}

// Ed25519ph is not the same function as pure Ed25519: a PH signature does not
// verify as ED25519_SHA_512, so Verify must apply the right one.
func TestEd25519_PureAndPrehashSignaturesAreNotInterchangeable(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistEdwards25519)
	digest := make([]byte, 64)
	ph, err := c.Sign(ctx, &kms.SignInput{KeyId: key.KeyId, Message: digest, MessageType: types.MessageTypeDigest, SigningAlgorithm: types.SigningAlgorithmSpecEd25519PhSha512})
	if err != nil {
		t.Fatal(err)
	}
	pure, err := c.Sign(ctx, &kms.SignInput{KeyId: key.KeyId, Message: digest, SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Verify(ctx, &kms.VerifyInput{KeyId: key.KeyId, Message: digest, Signature: ph.Signature, SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512})
	wantCode(t, err, "KMSInvalidSignatureException")
	_, err = c.Verify(ctx, &kms.VerifyInput{KeyId: key.KeyId, Message: digest, MessageType: types.MessageTypeDigest, Signature: pure.Signature, SigningAlgorithm: types.SigningAlgorithmSpecEd25519PhSha512})
	wantCode(t, err, "KMSInvalidSignatureException")
}

// A page that ends exactly at the end of the list is not truncated.
func TestPagination_ExactMultipleIsNotTruncated(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	createKey(t, c, types.KeySpecEccNistP256)
	var tags []types.Tag
	for i := 0; i < 2; i++ {
		tags = append(tags, types.Tag{TagKey: aws.String(fmt.Sprintf("t%d", i)), TagValue: aws.String("v")})
		if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(fmt.Sprintf("alias/e%d", i)), TargetKeyId: key.KeyId}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: key.KeyId, Tags: tags}); err != nil {
		t.Fatal(err)
	}

	keys, err := c.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(2)})
	if err != nil || len(keys.Keys) != 2 || keys.Truncated || keys.NextMarker != nil {
		t.Errorf("ListKeys 2 of 2: %d keys, Truncated=%v, NextMarker=%v, %v", len(keys.Keys), keys.Truncated, keys.NextMarker, err)
	}
	al, err := c.ListAliases(ctx, &kms.ListAliasesInput{Limit: aws.Int32(2)})
	if err != nil || len(al.Aliases) != 2 || al.Truncated || al.NextMarker != nil {
		t.Errorf("ListAliases 2 of 2: %d, Truncated=%v, %v", len(al.Aliases), al.Truncated, err)
	}
	tg, err := c.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: key.KeyId, Limit: aws.Int32(2)})
	if err != nil || len(tg.Tags) != 2 || tg.Truncated || tg.NextMarker != nil {
		t.Errorf("ListResourceTags 2 of 2: %d, Truncated=%v, %v", len(tg.Tags), tg.Truncated, err)
	}
	// One fewer than the list is truncated, with a marker.
	one, err := c.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(1)})
	if err != nil || !one.Truncated || one.NextMarker == nil {
		t.Errorf("ListKeys 1 of 2: Truncated=%v, NextMarker=%v, %v", one.Truncated, one.NextMarker, err)
	}
}

func TestKeyID_LengthBoundaryAndARNService(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	// 2048 characters is within the limit, so this is a lookup miss, not a validation error.
	_, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(strings.Repeat("a", 2048))})
	wantCode(t, err, "NotFoundException")
	_, err = c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(strings.Repeat("a", 2049))})
	wantCode(t, err, "ValidationException")

	// An ARN for another service is invalid even when the rest looks like a KMS key ARN.
	key := createKey(t, c, types.KeySpecEccNistP256)
	_, err = c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("arn:aws:s3:us-east-1:111122223333:key/" + *key.KeyId)})
	wantCode(t, err, "InvalidArnException")
}

func TestCreateKey_AsymmetricWithoutUsageSaysWhy(t *testing.T) {
	c, _ := newClient(t)
	_, err := c.CreateKey(context.Background(), &kms.CreateKeyInput{KeySpec: types.KeySpecEccNistP256})
	wantCode(t, err, "ValidationException")
	if !strings.Contains(err.Error(), "must specify a KeyUsage") {
		t.Fatalf("message = %v", err)
	}
}
