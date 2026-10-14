package awskmsemulator_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// The conformance tests encode behaviour that AWS documents. Each cites its
// source; docs/AWS-BEHAVIOUR.md lists every source and marks what the
// documentation does not settle.

const (
	docKeyStates = "https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html"
	docSign      = "https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html"
	docKeySpecs  = "https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html"
)

// TestConformance_KeyStateTable runs every operation in the key-state table
// against a key in each state and compares with the table (docKeyStates).
// Where the table lists two possible exceptions for a pending-deletion key
// ("[2] or [3]": DisabledException or KMSInvalidStateException), the emulator
// returns KMSInvalidStateException; the table does not say which, and this is
// the one the Floci emulator reports observing from AWS (see AWS-BEHAVIOUR.md).
func TestConformance_KeyStateTable(t *testing.T) {
	ctx := context.Background()
	alg := types.SigningAlgorithmSpecEcdsaSha256

	type operation struct {
		name string
		run  func(c *kms.Client, key, aliasName string) error
	}
	ops := []operation{
		{"Sign", func(c *kms.Client, k, _ string) error {
			_, err := c.Sign(ctx, &kms.SignInput{KeyId: aws.String(k), Message: []byte("m"), SigningAlgorithm: alg})
			return err
		}},
		{"Verify", func(c *kms.Client, k, _ string) error {
			_, err := c.Verify(ctx, &kms.VerifyInput{KeyId: aws.String(k), Message: []byte("m"), Signature: []byte{0x30, 0x00}, SigningAlgorithm: alg})
			if errCode(err) == "KMSInvalidSignatureException" {
				return nil // the key state allowed the call; the dummy signature is just wrong
			}
			return err
		}},
		{"GetPublicKey", func(c *kms.Client, k, _ string) error {
			_, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(k)})
			return err
		}},
		{"DescribeKey", func(c *kms.Client, k, _ string) error {
			_, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(k)})
			return err
		}},
		{"ListResourceTags", func(c *kms.Client, k, _ string) error {
			_, err := c.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: aws.String(k)})
			return err
		}},
		{"TagResource", func(c *kms.Client, k, _ string) error {
			_, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: aws.String(k), Tags: []types.Tag{{TagKey: aws.String("a"), TagValue: aws.String("b")}}})
			return err
		}},
		{"CreateAlias", func(c *kms.Client, k, name string) error {
			_, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(name), TargetKeyId: aws.String(k)})
			return err
		}},
		{"EnableKey", func(c *kms.Client, k, _ string) error {
			_, err := c.EnableKey(ctx, &kms.EnableKeyInput{KeyId: aws.String(k)})
			return err
		}},
		{"DisableKey", func(c *kms.Client, k, _ string) error {
			_, err := c.DisableKey(ctx, &kms.DisableKeyInput{KeyId: aws.String(k)})
			return err
		}},
		{"ScheduleKeyDeletion", func(c *kms.Client, k, _ string) error {
			_, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String(k)})
			return err
		}},
		{"CancelKeyDeletion", func(c *kms.Client, k, _ string) error {
			_, err := c.CancelKeyDeletion(ctx, &kms.CancelKeyDeletionInput{KeyId: aws.String(k)})
			return err
		}},
	}

	// "" means the operation succeeds in that state.
	want := map[string][3]string{ // Enabled, Disabled, PendingDeletion
		"Sign":                {"", "DisabledException", "KMSInvalidStateException"},
		"Verify":              {"", "DisabledException", "KMSInvalidStateException"},
		"GetPublicKey":        {"", "", "KMSInvalidStateException"},
		"DescribeKey":         {"", "", ""},
		"ListResourceTags":    {"", "", ""},
		"TagResource":         {"", "", "KMSInvalidStateException"},
		"CreateAlias":         {"", "", "KMSInvalidStateException"},
		"EnableKey":           {"", "", "KMSInvalidStateException"},
		"DisableKey":          {"", "", "KMSInvalidStateException"},
		"ScheduleKeyDeletion": {"", "", "KMSInvalidStateException"},
		"CancelKeyDeletion":   {"KMSInvalidStateException", "KMSInvalidStateException", ""},
	}

	states := []string{"Enabled", "Disabled", "PendingDeletion"}
	for _, op := range ops {
		for i, state := range states {
			t.Run(op.name+"/"+state, func(t *testing.T) {
				c, _ := newClient(t)
				key := createKey(t, c, types.KeySpecEccNistP256)
				switch state {
				case "Disabled":
					if _, err := c.DisableKey(ctx, &kms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
						t.Fatal(err)
					}
				case "PendingDeletion":
					if _, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: key.KeyId}); err != nil {
						t.Fatal(err)
					}
				}
				err := op.run(c, *key.KeyId, "alias/conformance")
				if wantCode := want[op.name][i]; wantCode == "" {
					if err != nil {
						t.Fatalf("%s on a %s key (%s): %v, want success", op.name, state, docKeyStates, err)
					}
				} else if errCode(err) != wantCode {
					t.Fatalf("%s on a %s key (%s): %v, want %s", op.name, state, docKeyStates, err, wantCode)
				}
			})
		}
	}
}

// TestConformance_AliasesOfPendingKeys: UpdateAlias succeeds when the source
// key is pending deletion and fails when the destination is (docKeyStates, [10]);
// DeleteAlias works on a key in every state.
func TestConformance_AliasesOfPendingKeys(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	src := createKey(t, c, types.KeySpecEccNistP256)
	dst := createKey(t, c, types.KeySpecEccNistP256)
	if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/mv"), TargetKeyId: src.KeyId}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: src.KeyId}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/mv"), TargetKeyId: dst.KeyId}); err != nil {
		t.Fatalf("UpdateAlias away from a pending key: %v", err)
	}
	if _, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: dst.KeyId}); err != nil {
		t.Fatal(err)
	}
	_, err := c.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/mv"), TargetKeyId: dst.KeyId})
	wantCode(t, err, "KMSInvalidStateException")
	if _, err := c.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: aws.String("alias/mv")}); err != nil {
		t.Fatalf("DeleteAlias of an alias on a pending key: %v", err)
	}
}

// TestConformance_SigningAlgorithmsPerKeySpec compares the SigningAlgorithms
// that DescribeKey and GetPublicKey report with the table in docKeySpecs.
func TestConformance_SigningAlgorithmsPerKeySpec(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	rsa := []types.SigningAlgorithmSpec{
		types.SigningAlgorithmSpecRsassaPssSha256, types.SigningAlgorithmSpecRsassaPssSha384, types.SigningAlgorithmSpecRsassaPssSha512,
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	}
	want := map[types.KeySpec][]types.SigningAlgorithmSpec{
		types.KeySpecEccNistP256:         {types.SigningAlgorithmSpecEcdsaSha256},
		types.KeySpecEccNistP384:         {types.SigningAlgorithmSpecEcdsaSha384},
		types.KeySpecEccNistP521:         {types.SigningAlgorithmSpecEcdsaSha512},
		types.KeySpecEccSecgP256k1:       {types.SigningAlgorithmSpecEcdsaSha256},
		types.KeySpecEccNistEdwards25519: {types.SigningAlgorithmSpecEd25519Sha512, types.SigningAlgorithmSpecEd25519PhSha512},
		types.KeySpecRsa2048:             rsa,
	}
	for spec, algs := range want {
		key := createKey(t, c, spec)
		check := func(where string, got []types.SigningAlgorithmSpec) {
			if len(got) != len(algs) {
				t.Errorf("%s %s: SigningAlgorithms = %v, want %v (%s)", spec, where, got, algs, docKeySpecs)
				return
			}
			for i := range algs {
				if got[i] != algs[i] {
					t.Errorf("%s %s: SigningAlgorithms = %v, want %v (%s)", spec, where, got, algs, docKeySpecs)
				}
			}
		}
		check("DescribeKey", key.SigningAlgorithms)
		pk, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: key.KeyId})
		if err != nil {
			t.Fatal(err)
		}
		check("GetPublicKey", pk.SigningAlgorithms)
	}
}

// TestConformance_EveryAlgorithmOnEveryKeySpec signs with every (key spec,
// algorithm) pair and expects success only for the pairs in docKeySpecs.
func TestConformance_EveryAlgorithmOnEveryKeySpec(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	algs := []types.SigningAlgorithmSpec{
		types.SigningAlgorithmSpecRsassaPssSha256, types.SigningAlgorithmSpecRsassaPssSha384, types.SigningAlgorithmSpecRsassaPssSha512,
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		types.SigningAlgorithmSpecEcdsaSha256, types.SigningAlgorithmSpecEcdsaSha384, types.SigningAlgorithmSpecEcdsaSha512,
		types.SigningAlgorithmSpecEd25519Sha512, types.SigningAlgorithmSpecEd25519PhSha512,
	}
	allowed := map[types.KeySpec]map[types.SigningAlgorithmSpec]bool{
		types.KeySpecEccNistP256:         {types.SigningAlgorithmSpecEcdsaSha256: true},
		types.KeySpecEccNistP384:         {types.SigningAlgorithmSpecEcdsaSha384: true},
		types.KeySpecEccNistP521:         {types.SigningAlgorithmSpecEcdsaSha512: true},
		types.KeySpecEccSecgP256k1:       {types.SigningAlgorithmSpecEcdsaSha256: true},
		types.KeySpecEccNistEdwards25519: {types.SigningAlgorithmSpecEd25519Sha512: true, types.SigningAlgorithmSpecEd25519PhSha512: true},
		types.KeySpecRsa2048: {
			types.SigningAlgorithmSpecRsassaPssSha256: true, types.SigningAlgorithmSpecRsassaPssSha384: true, types.SigningAlgorithmSpecRsassaPssSha512: true,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256: true, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384: true, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512: true,
		},
	}
	for spec, ok := range allowed {
		key := createKey(t, c, spec)
		for _, alg := range algs {
			// A 64-byte digest is the right length for SHA-512 only, so RAW is
			// the type that is valid for all but Ed25519ph.
			mt := types.MessageTypeRaw
			msg := make([]byte, 64)
			if alg == types.SigningAlgorithmSpecEd25519PhSha512 {
				mt = types.MessageTypeDigest
			}
			_, err := c.Sign(ctx, &kms.SignInput{KeyId: key.KeyId, Message: msg, MessageType: mt, SigningAlgorithm: alg})
			switch {
			case ok[alg] && err != nil:
				t.Errorf("%s with %s: %v, want success (%s)", spec, alg, err, docKeySpecs)
			case !ok[alg] && errCode(err) != "InvalidKeyUsageException":
				t.Errorf("%s with %s: %v, want InvalidKeyUsageException (%s)", spec, alg, err, docSign)
			}
		}
	}
}

// TestConformance_DigestLengths: a DIGEST must be exactly as long as the hash
// of the signing algorithm (docSign, MessageType).
func TestConformance_DigestLengths(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	for _, tc := range []struct {
		spec types.KeySpec
		alg  types.SigningAlgorithmSpec
		size int
	}{
		{types.KeySpecEccNistP256, types.SigningAlgorithmSpecEcdsaSha256, 32},
		{types.KeySpecEccNistP384, types.SigningAlgorithmSpecEcdsaSha384, 48},
		{types.KeySpecEccNistP521, types.SigningAlgorithmSpecEcdsaSha512, 64},
		{types.KeySpecEccSecgP256k1, types.SigningAlgorithmSpecEcdsaSha256, 32},
		{types.KeySpecEccNistEdwards25519, types.SigningAlgorithmSpecEd25519PhSha512, 64},
		{types.KeySpecRsa2048, types.SigningAlgorithmSpecRsassaPssSha384, 48},
		{types.KeySpecRsa2048, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, 64},
	} {
		key := createKey(t, c, tc.spec)
		for _, size := range []int{tc.size - 1, tc.size, tc.size + 1} {
			_, err := c.Sign(ctx, &kms.SignInput{KeyId: key.KeyId, Message: make([]byte, size), MessageType: types.MessageTypeDigest, SigningAlgorithm: tc.alg})
			if size == tc.size && err != nil {
				t.Errorf("%s %s: a %d-byte digest was rejected: %v", tc.spec, tc.alg, size, err)
			}
			if size != tc.size && errCode(err) != "ValidationException" {
				t.Errorf("%s %s: a %d-byte digest: %v, want ValidationException", tc.spec, tc.alg, size, err)
			}
		}
	}
}
