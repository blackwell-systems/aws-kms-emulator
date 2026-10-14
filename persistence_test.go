package awskmsemulator_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	awskmsemulator "github.com/blackwell-systems/aws-kms-emulator"
	"github.com/blackwell-systems/aws-kms-emulator/internal/storage"
	"github.com/blackwell-systems/aws-kms-emulator/kmstest"
)

func TestPersistence_KeysSurviveARestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	msg := []byte("signed before the restart")

	first := kmstest.NewServer(t, awskmsemulator.WithDataDir(dir))
	c := first.Client()
	specs := []types.KeySpec{
		types.KeySpecEccNistEdwards25519, types.KeySpecEccNistP256, types.KeySpecEccSecgP256k1, types.KeySpecRsa2048,
	}
	type saved struct {
		id, arn string
		pub     []byte
	}
	keys := map[types.KeySpec]saved{}
	for _, spec := range specs {
		k := createKey(t, c, spec)
		pk, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: k.KeyId})
		if err != nil {
			t.Fatal(err)
		}
		keys[spec] = saved{*k.KeyId, *k.Arn, pk.PublicKey}
	}
	ed := keys[types.KeySpecEccNistEdwards25519]
	if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/release"), TargetKeyId: aws.String(ed.id)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: aws.String(ed.id), Tags: []types.Tag{{TagKey: aws.String("env"), TagValue: aws.String("ci")}}}); err != nil {
		t.Fatal(err)
	}
	p256 := keys[types.KeySpecEccNistP256]
	if _, err := c.DisableKey(ctx, &kms.DisableKeyInput{KeyId: aws.String(p256.id)}); err != nil {
		t.Fatal(err)
	}
	k1 := keys[types.KeySpecEccSecgP256k1]
	sched, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String(k1.id), PendingWindowInDays: aws.Int32(9)})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := c.Sign(ctx, &kms.SignInput{KeyId: aws.String("alias/release"), Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512})
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, storage.StateFileName))
		if err != nil {
			t.Fatalf("state file: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("state file mode = %v, want 0600 (it holds private keys)", info.Mode().Perm())
		}
	}

	c2 := kmstest.NewServer(t, awskmsemulator.WithDataDir(dir)).Client()

	// Same key IDs, same public keys.
	for spec, want := range keys {
		d, err := c2.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(want.id)})
		if err != nil {
			t.Fatalf("DescribeKey(%s) after restart: %v", spec, err)
		}
		if *d.KeyMetadata.Arn != want.arn || d.KeyMetadata.KeySpec != spec {
			t.Errorf("%s: metadata changed across the restart: %+v", spec, d.KeyMetadata)
		}
		pk, err := c2.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(want.id)})
		if err != nil {
			if spec == types.KeySpecEccSecgP256k1 {
				continue // pending deletion
			}
			t.Fatal(err)
		}
		if string(pk.PublicKey) != string(want.pub) {
			t.Errorf("%s: the public key changed across the restart", spec)
		}
	}

	// The restored private key is the same: a new signature verifies under the old public key,
	// and the old signature still verifies through KMS.
	again, err := c2.Sign(ctx, &kms.SignInput{KeyId: aws.String(ed.id), Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512})
	if err != nil {
		t.Fatalf("Sign after restart: %v", err)
	}
	pub, _ := x509.ParsePKIXPublicKey(ed.pub)
	if !ed25519.Verify(pub.(ed25519.PublicKey), msg, again.Signature) {
		t.Error("a signature made after the restart does not verify under the pre-restart public key")
	}
	if res, err := c2.Verify(ctx, &kms.VerifyInput{KeyId: aws.String(ed.id), Message: msg, Signature: signed.Signature, SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512}); err != nil || !res.SignatureValid {
		t.Errorf("pre-restart signature no longer verifies: %v", err)
	}

	// Aliases, tags and states are restored.
	if d, err := c2.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("alias/release")}); err != nil || *d.KeyMetadata.KeyId != ed.id {
		t.Errorf("alias after restart: %+v, %v", d, err)
	}
	if l, err := c2.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: aws.String(ed.id)}); err != nil || len(l.Tags) != 1 || *l.Tags[0].TagValue != "ci" {
		t.Errorf("tags after restart: %+v, %v", l, err)
	}
	_, err = c2.Sign(ctx, &kms.SignInput{KeyId: aws.String(p256.id), Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
	wantCode(t, err, "DisabledException")
	d, err := c2.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(k1.id)})
	if err != nil || d.KeyMetadata.KeyState != types.KeyStatePendingDeletion || *d.KeyMetadata.PendingDeletionWindowInDays != 9 {
		t.Fatalf("pending key after restart: %+v, %v", d, err)
	}
	if got := d.KeyMetadata.DeletionDate.Sub(*sched.DeletionDate).Abs(); got > time.Second {
		t.Errorf("DeletionDate moved by %v across the restart", got)
	}
	// RSA keys restore too.
	rsaKey := keys[types.KeySpecRsa2048]
	if _, err := c2.Sign(ctx, &kms.SignInput{KeyId: aws.String(rsaKey.id), Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256}); err != nil {
		t.Errorf("RSA Sign after restart: %v", err)
	}
}

func TestPersistence_DeletionAcrossRestartAndClock(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Now()
	clock := awskmsemulator.WithClock(func() time.Time { return now })

	first := kmstest.NewServer(t, awskmsemulator.WithDataDir(dir), clock)
	key := createKey(t, first.Client(), types.KeySpecEccNistP256)
	if _, err := first.Client().ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: key.KeyId, PendingWindowInDays: aws.Int32(7)}); err != nil {
		t.Fatal(err)
	}
	first.Close()

	now = now.Add(8 * 24 * time.Hour)
	c := kmstest.NewServer(t, awskmsemulator.WithDataDir(dir), clock).Client()
	_, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
	wantCode(t, err, "NotFoundException")
	if out, _ := c.ListKeys(ctx, &kms.ListKeysInput{}); len(out.Keys) != 0 {
		t.Fatalf("expired key listed: %v", out.Keys)
	}
}

func TestPersistence_NewDirectoryIsCreatedAndEveryChangeIsWritten(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "nested", "state")
	c := kmstest.NewServer(t, awskmsemulator.WithDataDir(dir)).Client()
	state := filepath.Join(dir, storage.StateFileName)
	size := func() int {
		b, _ := os.ReadFile(state)
		return len(b)
	}
	key := createKey(t, c, types.KeySpecEccNistP256)
	afterCreate := size()
	if afterCreate == 0 {
		t.Fatal("CreateKey did not write the state file")
	}
	if _, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: key.KeyId, Tags: []types.Tag{{TagKey: aws.String("a-long-tag-name"), TagValue: aws.String("a-long-tag-value")}}}); err != nil {
		t.Fatal(err)
	}
	if size() <= afterCreate {
		t.Error("TagResource did not rewrite the state file")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func TestPersistence_DamagedStateIsNeverOverwritten(t *testing.T) {
	for name, content := range map[string]string{
		"not JSON":              `{"formatVersion":`,
		"future format version": `{"formatVersion":99,"keys":[],"aliases":[]}`,
		"corrupt key material":  `{"formatVersion":1,"keys":[{"id":"x","spec":"ECC_NIST_P256","usage":"SIGN_VERIFY","state":"Enabled","creationDate":"2026-01-01T00:00:00Z","privateKey":"AAAA"}],"aliases":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, storage.StateFileName)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := awskmsemulator.New(awskmsemulator.WithDataDir(dir)); err == nil {
				t.Fatal("New succeeded on a state file it cannot read")
			}
			if got, _ := os.ReadFile(path); string(got) != content {
				t.Fatalf("the unreadable state file was modified: %s", got)
			}
		})
	}
}

func TestPersistence_OffByDefault(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	c, _ := newClient(t)
	createKey(t, c, types.KeySpecEccNistP256)
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("an emulator without a data directory wrote files: %v", entries)
	}
}
