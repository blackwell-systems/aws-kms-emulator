package awskmsemulator_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	awskmsemulator "github.com/blackwell-systems/aws-kms-emulator"
)

var uuidShape = func(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return false
	}
	for i, n := range []int{8, 4, 4, 4, 12} {
		if len(parts[i]) != n {
			return false
		}
	}
	return len(s) == 36 && s[14] == '4' && strings.ContainsRune("89ab", rune(s[19]))
}

func TestCreateKey_Metadata(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t, awskmsemulator.WithRegion("eu-west-2"), awskmsemulator.WithAccountID("123456789012"))
	before := time.Now().Add(-time.Second)
	out, err := c.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec: types.KeySpecEccNistEdwards25519, KeyUsage: types.KeyUsageTypeSignVerify,
		Description: aws.String("release signer"),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	m := out.KeyMetadata
	if !uuidShape(*m.KeyId) {
		t.Errorf("KeyId %q is not a version 4 UUID", *m.KeyId)
	}
	if want := "arn:aws:kms:eu-west-2:123456789012:key/" + *m.KeyId; *m.Arn != want {
		t.Errorf("Arn = %q, want %q", *m.Arn, want)
	}
	if *m.AWSAccountId != "123456789012" {
		t.Errorf("AWSAccountId = %q", *m.AWSAccountId)
	}
	if m.KeySpec != types.KeySpecEccNistEdwards25519 || string(m.CustomerMasterKeySpec) != "ECC_NIST_EDWARDS25519" {
		t.Errorf("KeySpec/CustomerMasterKeySpec = %s/%s", m.KeySpec, m.CustomerMasterKeySpec)
	}
	if m.KeyUsage != types.KeyUsageTypeSignVerify || m.KeyState != types.KeyStateEnabled || !m.Enabled {
		t.Errorf("KeyUsage/KeyState/Enabled = %s/%s/%v", m.KeyUsage, m.KeyState, m.Enabled)
	}
	if m.KeyManager != types.KeyManagerTypeCustomer || m.Origin != types.OriginTypeAwsKms || m.MultiRegion == nil || *m.MultiRegion {
		t.Errorf("KeyManager/Origin/MultiRegion = %s/%s/%v", m.KeyManager, m.Origin, m.MultiRegion)
	}
	if *m.Description != "release signer" {
		t.Errorf("Description = %q", *m.Description)
	}
	if m.CreationDate == nil || m.CreationDate.Before(before) || m.CreationDate.After(time.Now().Add(time.Second)) {
		t.Errorf("CreationDate = %v", m.CreationDate)
	}
	if len(m.SigningAlgorithms) != 2 || m.SigningAlgorithms[0] != types.SigningAlgorithmSpecEd25519Sha512 || m.SigningAlgorithms[1] != types.SigningAlgorithmSpecEd25519PhSha512 {
		t.Errorf("SigningAlgorithms = %v", m.SigningAlgorithms)
	}
	if len(m.EncryptionAlgorithms) != 0 {
		t.Errorf("EncryptionAlgorithms = %v on a signing key", m.EncryptionAlgorithms)
	}
	if m.DeletionDate != nil {
		t.Errorf("DeletionDate = %v on an enabled key", m.DeletionDate)
	}

	d, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: m.Arn})
	if err != nil {
		t.Fatalf("DescribeKey: %v", err)
	}
	if *d.KeyMetadata.KeyId != *m.KeyId || *d.KeyMetadata.Arn != *m.Arn {
		t.Errorf("DescribeKey returned a different key: %+v", d.KeyMetadata)
	}
}

func TestCreateKey_Defaults(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	out, err := c.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	m := out.KeyMetadata
	if m.KeySpec != types.KeySpecSymmetricDefault || m.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		t.Errorf("default KeySpec/KeyUsage = %s/%s, want SYMMETRIC_DEFAULT/ENCRYPT_DECRYPT", m.KeySpec, m.KeyUsage)
	}
	if len(m.EncryptionAlgorithms) != 1 || m.EncryptionAlgorithms[0] != types.EncryptionAlgorithmSpecSymmetricDefault {
		t.Errorf("EncryptionAlgorithms = %v", m.EncryptionAlgorithms)
	}
	if len(m.SigningAlgorithms) != 0 {
		t.Errorf("SigningAlgorithms = %v on an encryption key", m.SigningAlgorithms)
	}
	if *m.Description != "" {
		t.Errorf("default Description = %q, want empty", *m.Description)
	}
}

func TestCreateKey_ErrorTypes(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	cases := map[string]struct {
		in   *kms.CreateKeyInput
		code string
	}{
		"asymmetric key without KeyUsage": {&kms.CreateKeyInput{KeySpec: types.KeySpecEccNistP256}, "ValidationException"},
		"unknown KeySpec":                 {&kms.CreateKeyInput{KeySpec: "ECC_NIST_P999", KeyUsage: types.KeyUsageTypeSignVerify}, "ValidationException"},
		"unknown KeyUsage":                {&kms.CreateKeyInput{KeySpec: types.KeySpecEccNistP256, KeyUsage: "SIGNING"}, "ValidationException"},
		"symmetric key for SIGN_VERIFY":   {&kms.CreateKeyInput{KeyUsage: types.KeyUsageTypeSignVerify}, "ValidationException"},
		"secp256k1 for ENCRYPT_DECRYPT":   {&kms.CreateKeyInput{KeySpec: types.KeySpecEccSecgP256k1, KeyUsage: types.KeyUsageTypeEncryptDecrypt}, "ValidationException"},
		"Ed25519 for KEY_AGREEMENT":       {&kms.CreateKeyInput{KeySpec: types.KeySpecEccNistEdwards25519, KeyUsage: types.KeyUsageTypeKeyAgreement}, "ValidationException"},
		"Description over 8192":           {&kms.CreateKeyInput{Description: aws.String(strings.Repeat("d", 8193))}, "ValidationException"},
		"KeySpec and CustomerMasterKeySpec differ": {&kms.CreateKeyInput{
			KeySpec: types.KeySpecEccNistP256, CustomerMasterKeySpec: types.CustomerMasterKeySpecEccNistP384, KeyUsage: types.KeyUsageTypeSignVerify}, "ValidationException"},
		"multi-Region":          {&kms.CreateKeyInput{MultiRegion: aws.Bool(true)}, "UnsupportedOperationException"},
		"imported key material": {&kms.CreateKeyInput{Origin: types.OriginTypeExternal}, "UnsupportedOperationException"},
		"HMAC key":              {&kms.CreateKeyInput{KeySpec: types.KeySpecHmac256, KeyUsage: types.KeyUsageTypeGenerateVerifyMac}, "UnsupportedOperationException"},
		"ML-DSA key":            {&kms.CreateKeyInput{KeySpec: types.KeySpecMlDsa65, KeyUsage: types.KeyUsageTypeSignVerify}, "UnsupportedOperationException"},
		"RSA encryption key":    {&kms.CreateKeyInput{KeySpec: types.KeySpecRsa2048, KeyUsage: types.KeyUsageTypeEncryptDecrypt}, "UnsupportedOperationException"},
		"ECC key agreement":     {&kms.CreateKeyInput{KeySpec: types.KeySpecEccNistP256, KeyUsage: types.KeyUsageTypeKeyAgreement}, "UnsupportedOperationException"},
		"custom key store":      {&kms.CreateKeyInput{CustomKeyStoreId: aws.String("cks-1234")}, "UnsupportedOperationException"},
		"aws: tag":              {&kms.CreateKeyInput{Tags: []types.Tag{{TagKey: aws.String("aws:x"), TagValue: aws.String("v")}}}, "TagException"},
		"duplicate tag keys":    {&kms.CreateKeyInput{Tags: []types.Tag{{TagKey: aws.String("a"), TagValue: aws.String("1")}, {TagKey: aws.String("a"), TagValue: aws.String("2")}}}, "TagException"},
		"empty tag key":         {&kms.CreateKeyInput{Tags: []types.Tag{{TagKey: aws.String(""), TagValue: aws.String("v")}}}, "ValidationException"},
		"tag value over 256":    {&kms.CreateKeyInput{Tags: []types.Tag{{TagKey: aws.String("k"), TagValue: aws.String(strings.Repeat("v", 257))}}}, "ValidationException"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.CreateKey(ctx, tc.in)
			wantCode(t, err, tc.code)
		})
	}
	if out, err := c.ListKeys(ctx, &kms.ListKeysInput{}); err != nil || len(out.Keys) != 0 {
		t.Fatalf("rejected CreateKey calls left keys behind: %v, %v", out, err)
	}
}

func TestCreateKey_TagLimit(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	var tags []types.Tag
	for i := 0; i < 51; i++ {
		tags = append(tags, types.Tag{TagKey: aws.String(fmt.Sprintf("k%02d", i)), TagValue: aws.String("v")})
	}
	_, err := c.CreateKey(ctx, &kms.CreateKeyInput{Tags: tags})
	wantCode(t, err, "LimitExceededException")
	if _, err := c.CreateKey(ctx, &kms.CreateKeyInput{Tags: tags[:50]}); err != nil {
		t.Fatalf("50 tags must be accepted: %v", err)
	}
}

func TestDescribeKey_ErrorTypes(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	for id, code := range map[string]string{
		"1234abcd-12ab-34cd-56ef-1234567890ab": "NotFoundException",
		"alias/missing":                        "NotFoundException",
		"arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab": "NotFoundException",
		"arn:aws:kms:us-east-1:111122223333":                                          "InvalidArnException",
		"arn:aws:kms:us-east-1:111122223333:key":                                      "InvalidArnException",
	} {
		_, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(id)})
		if errCode(err) != code {
			t.Errorf("DescribeKey(%q): %v, want %s", id, err, code)
		}
	}
}

func TestGetPublicKey_ErrorTypes(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	sym, _ := c.CreateKey(ctx, &kms.CreateKeyInput{})
	_, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: sym.KeyMetadata.KeyId})
	wantCode(t, err, "UnsupportedOperationException")
	_, err = c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String("alias/none")})
	wantCode(t, err, "NotFoundException")
}

func TestKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	state := func() *types.KeyMetadata {
		t.Helper()
		d, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
		if err != nil {
			t.Fatalf("DescribeKey: %v", err)
		}
		return d.KeyMetadata
	}

	// Disable and Enable are idempotent.
	for i := 0; i < 2; i++ {
		if _, err := c.DisableKey(ctx, &kms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
			t.Fatalf("DisableKey #%d: %v", i+1, err)
		}
	}
	if m := state(); m.KeyState != types.KeyStateDisabled || m.Enabled {
		t.Fatalf("after DisableKey: %s, Enabled=%v", m.KeyState, m.Enabled)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.EnableKey(ctx, &kms.EnableKeyInput{KeyId: key.KeyId}); err != nil {
			t.Fatalf("EnableKey #%d: %v", i+1, err)
		}
	}
	if m := state(); m.KeyState != types.KeyStateEnabled || !m.Enabled {
		t.Fatalf("after EnableKey: %s, Enabled=%v", m.KeyState, m.Enabled)
	}

	// Cancel on a key that is not pending deletion fails.
	_, err := c.CancelKeyDeletion(ctx, &kms.CancelKeyDeletionInput{KeyId: key.KeyId})
	wantCode(t, err, "KMSInvalidStateException")

	before := time.Now()
	sched, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: key.KeyId, PendingWindowInDays: aws.Int32(7)})
	if err != nil {
		t.Fatalf("ScheduleKeyDeletion: %v", err)
	}
	if *sched.KeyId != *key.Arn || sched.KeyState != types.KeyStatePendingDeletion || *sched.PendingWindowInDays != 7 {
		t.Fatalf("ScheduleKeyDeletion = KeyId %s, state %s, window %d", *sched.KeyId, sched.KeyState, *sched.PendingWindowInDays)
	}
	if got := sched.DeletionDate.Sub(before); got < 7*24*time.Hour-time.Minute || got > 7*24*time.Hour+time.Minute {
		t.Fatalf("DeletionDate is %v after the call, want 7 days", got)
	}
	m := state()
	if m.KeyState != types.KeyStatePendingDeletion || m.Enabled || m.DeletionDate == nil || m.PendingDeletionWindowInDays == nil || *m.PendingDeletionWindowInDays != 7 {
		t.Fatalf("pending key metadata = %+v", m)
	}

	// A key pending deletion rejects state changes, scheduling again and tagging.
	_, err = c.EnableKey(ctx, &kms.EnableKeyInput{KeyId: key.KeyId})
	wantCode(t, err, "KMSInvalidStateException")
	_, err = c.DisableKey(ctx, &kms.DisableKeyInput{KeyId: key.KeyId})
	wantCode(t, err, "KMSInvalidStateException")
	_, err = c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: key.KeyId})
	wantCode(t, err, "KMSInvalidStateException")
	_, err = c.TagResource(ctx, &kms.TagResourceInput{KeyId: key.KeyId, Tags: []types.Tag{{TagKey: aws.String("a"), TagValue: aws.String("b")}}})
	wantCode(t, err, "KMSInvalidStateException")
	_, err = c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/late"), TargetKeyId: key.KeyId})
	wantCode(t, err, "KMSInvalidStateException")
	// Describe and ListResourceTags still work on it.
	if _, err := c.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: key.KeyId}); err != nil {
		t.Fatalf("ListResourceTags on a pending key: %v", err)
	}

	canc, err := c.CancelKeyDeletion(ctx, &kms.CancelKeyDeletionInput{KeyId: key.KeyId})
	if err != nil || *canc.KeyId != *key.Arn {
		t.Fatalf("CancelKeyDeletion = %+v, %v", canc, err)
	}
	if m := state(); m.KeyState != types.KeyStateDisabled || m.DeletionDate != nil {
		t.Fatalf("after CancelKeyDeletion: %s, DeletionDate=%v; want Disabled and none", m.KeyState, m.DeletionDate)
	}
}

func TestScheduleKeyDeletion_Window(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	for _, days := range []int32{0, 6, 31, -1} {
		key := createKey(t, c, types.KeySpecEccNistP256)
		_, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: key.KeyId, PendingWindowInDays: aws.Int32(days)})
		if errCode(err) != "ValidationException" {
			t.Errorf("PendingWindowInDays=%d: %v, want ValidationException", days, err)
		}
	}
	for _, days := range []int32{7, 30} {
		key := createKey(t, c, types.KeySpecEccNistP256)
		out, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: key.KeyId, PendingWindowInDays: aws.Int32(days)})
		if err != nil || *out.PendingWindowInDays != days {
			t.Errorf("PendingWindowInDays=%d: %+v, %v", days, out, err)
		}
	}
	key := createKey(t, c, types.KeySpecEccNistP256)
	out, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: key.KeyId})
	if err != nil || *out.PendingWindowInDays != 30 {
		t.Errorf("default window = %+v, %v; want 30", out, err)
	}
}

// Lifecycle operations that take a key ID or key ARN do not take an alias.
func TestKeyOnlyOperationsRejectAliases(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/k"), TargetKeyId: key.KeyId}); err != nil {
		t.Fatal(err)
	}
	_, err := c.DisableKey(ctx, &kms.DisableKeyInput{KeyId: aws.String("alias/k")})
	wantCode(t, err, "NotFoundException")
	_, err = c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String("alias/k")})
	wantCode(t, err, "NotFoundException")
	_, err = c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/k2"), TargetKeyId: aws.String("alias/k")})
	wantCode(t, err, "NotFoundException")
}

func TestDeletionDateElapsed_KeyAndAliasesAreGone(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	c, _ := newClient(t, awskmsemulator.WithClock(func() time.Time { return now }))
	key := createKey(t, c, types.KeySpecEccNistP256)
	if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/doomed"), TargetKeyId: key.KeyId}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: key.KeyId, PendingWindowInDays: aws.Int32(7)}); err != nil {
		t.Fatal(err)
	}

	now = now.Add(7*24*time.Hour - time.Second)
	if _, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId}); err != nil {
		t.Fatalf("a second before the deletion date the key must still exist: %v", err)
	}
	now = now.Add(time.Second)
	_, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
	wantCode(t, err, "NotFoundException")
	_, err = c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("alias/doomed")})
	wantCode(t, err, "NotFoundException")
	if out, _ := c.ListKeys(ctx, &kms.ListKeysInput{}); len(out.Keys) != 0 {
		t.Fatalf("ListKeys after deletion = %v", out.Keys)
	}
	if out, _ := c.ListAliases(ctx, &kms.ListAliasesInput{}); len(out.Aliases) != 0 {
		t.Fatalf("ListAliases after deletion = %v", out.Aliases)
	}
}

func TestListKeys_Pagination(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	want := map[string]bool{}
	for i := 0; i < 5; i++ {
		want[*createKey(t, c, types.KeySpecEccNistP256).KeyId] = true
	}
	// Pending-deletion keys are listed too.
	for id := range want {
		if _, err := c.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: aws.String(id)}); err != nil {
			t.Fatal(err)
		}
		break
	}

	got := map[string]bool{}
	var marker *string
	pages := 0
	for {
		out, err := c.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(2), Marker: marker})
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		pages++
		for _, k := range out.Keys {
			if got[*k.KeyId] {
				t.Fatalf("key %s listed twice", *k.KeyId)
			}
			got[*k.KeyId] = true
			if *k.KeyArn != "arn:aws:kms:us-east-1:111122223333:key/"+*k.KeyId {
				t.Fatalf("KeyArn = %s", *k.KeyArn)
			}
		}
		if out.Truncated != (out.NextMarker != nil) {
			t.Fatalf("Truncated=%v with NextMarker=%v", out.Truncated, out.NextMarker)
		}
		if !out.Truncated {
			break
		}
		marker = out.NextMarker
	}
	if pages != 3 || len(got) != 5 {
		t.Fatalf("pages=%d keys=%d, want 3 pages and 5 keys", pages, len(got))
	}
	for id := range want {
		if !got[id] {
			t.Errorf("key %s missing from ListKeys", id)
		}
	}
}

func TestList_PagingErrorTypes(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	for name, err := range map[string]error{
		"ListKeys Limit 0":            second(c.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(0)})),
		"ListKeys Limit 1001":         second(c.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(1001)})),
		"ListAliases Limit 101":       second(c.ListAliases(ctx, &kms.ListAliasesInput{Limit: aws.Int32(101)})),
		"ListAliases Limit -1":        second(c.ListAliases(ctx, &kms.ListAliasesInput{Limit: aws.Int32(-1)})),
		"ListResourceTags Limit 1001": second(c.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: key.KeyId, Limit: aws.Int32(1001)})),
	} {
		if errCode(err) != "ValidationException" {
			t.Errorf("%s: %v, want ValidationException", name, err)
		}
	}
	for name, err := range map[string]error{
		"ListKeys":         second(c.ListKeys(ctx, &kms.ListKeysInput{Marker: aws.String("!!not-a-marker")})),
		"ListAliases":      second(c.ListAliases(ctx, &kms.ListAliasesInput{Marker: aws.String("!!not-a-marker")})),
		"ListResourceTags": second(c.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: key.KeyId, Marker: aws.String("!!not-a-marker")})),
	} {
		if errCode(err) != "InvalidMarkerException" {
			t.Errorf("%s: %v, want InvalidMarkerException", name, err)
		}
	}
	// Limit at both ends is accepted.
	if _, err := c.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(1)}); err != nil {
		t.Errorf("ListKeys Limit 1: %v", err)
	}
	if _, err := c.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(1000)}); err != nil {
		t.Errorf("ListKeys Limit 1000: %v", err)
	}
	if _, err := c.ListAliases(ctx, &kms.ListAliasesInput{Limit: aws.Int32(100)}); err != nil {
		t.Errorf("ListAliases Limit 100: %v", err)
	}
}

func second[T any](_ T, err error) error { return err }
