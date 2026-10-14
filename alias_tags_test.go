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

func TestAlias_CreateListUpdateDelete(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	a := createKey(t, c, types.KeySpecEccNistP256)
	b := createKey(t, c, types.KeySpecEccNistEdwards25519)

	for _, name := range []string{"alias/zeta", "alias/alpha", "alias/team/mid_1-x"} {
		if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(name), TargetKeyId: a.KeyId}); err != nil {
			t.Fatalf("CreateAlias(%s): %v", name, err)
		}
	}
	// A key ARN is accepted as the target.
	if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/by-arn"), TargetKeyId: b.Arn}); err != nil {
		t.Fatalf("CreateAlias with a key ARN target: %v", err)
	}

	all, err := c.ListAliases(ctx, &kms.ListAliasesInput{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, al := range all.Aliases {
		names = append(names, *al.AliasName)
		if *al.AliasArn != "arn:aws:kms:us-east-1:111122223333:"+*al.AliasName {
			t.Errorf("AliasArn = %s", *al.AliasArn)
		}
		if al.CreationDate == nil || al.LastUpdatedDate == nil {
			t.Errorf("alias %s lacks dates", *al.AliasName)
		}
	}
	if got, want := strings.Join(names, ","), "alias/alpha,alias/by-arn,alias/team/mid_1-x,alias/zeta"; got != want {
		t.Fatalf("ListAliases = %s, want %s (sorted by name)", got, want)
	}

	onlyB, err := c.ListAliases(ctx, &kms.ListAliasesInput{KeyId: b.Arn})
	if err != nil || len(onlyB.Aliases) != 1 || *onlyB.Aliases[0].AliasName != "alias/by-arn" || *onlyB.Aliases[0].TargetKeyId != *b.KeyId {
		t.Fatalf("ListAliases(KeyId=b) = %+v, %v", onlyB, err)
	}

	// UpdateAlias retargets and bumps LastUpdatedDate.
	if _, err := c.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/alpha"), TargetKeyId: b.KeyId}); err != nil {
		t.Fatalf("UpdateAlias: %v", err)
	}
	d, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("alias/alpha")})
	if err != nil || *d.KeyMetadata.KeyId != *b.KeyId {
		t.Fatalf("alias/alpha resolves to %+v, %v; want key b", d, err)
	}

	if _, err := c.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: aws.String("alias/alpha")}); err != nil {
		t.Fatalf("DeleteAlias: %v", err)
	}
	_, err = c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("alias/alpha")})
	wantCode(t, err, "NotFoundException")
	// Deleting an alias leaves the key alone.
	if _, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: b.KeyId}); err != nil {
		t.Fatalf("key vanished with its alias: %v", err)
	}
}

func TestAlias_ErrorTypes(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/taken"), TargetKeyId: key.KeyId}); err != nil {
		t.Fatal(err)
	}
	create := func(name, target string) error {
		_, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(name), TargetKeyId: aws.String(target)})
		return err
	}
	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"duplicate name":              {create("alias/taken", *key.KeyId), "AlreadyExistsException"},
		"no alias/ prefix":            {create("plain", *key.KeyId), "InvalidAliasNameException"},
		"alias/ alone":                {create("alias/", *key.KeyId), "InvalidAliasNameException"},
		"reserved alias/aws/ prefix":  {create("alias/aws/mine", *key.KeyId), "InvalidAliasNameException"},
		"space in name":               {create("alias/has space", *key.KeyId), "InvalidAliasNameException"},
		"dot in name":                 {create("alias/has.dot", *key.KeyId), "InvalidAliasNameException"},
		"name over 256":               {create("alias/"+strings.Repeat("a", 251), *key.KeyId), "ValidationException"},
		"empty name":                  {create("", *key.KeyId), "ValidationException"},
		"empty target":                {create("alias/x", ""), "ValidationException"},
		"unknown target":              {create("alias/x", "1234abcd-12ab-34cd-56ef-1234567890ab"), "NotFoundException"},
		"malformed target ARN":        {create("alias/x", "arn:aws:kms:bad"), "InvalidArnException"},
		"UpdateAlias unknown alias":   {second(c.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/none"), TargetKeyId: key.KeyId})), "NotFoundException"},
		"UpdateAlias unknown target":  {second(c.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/taken"), TargetKeyId: aws.String("1234abcd-12ab-34cd-56ef-1234567890ab")})), "NotFoundException"},
		"DeleteAlias unknown alias":   {second(c.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: aws.String("alias/none")})), "NotFoundException"},
		"ListAliases unknown KeyId":   {second(c.ListAliases(ctx, &kms.ListAliasesInput{KeyId: aws.String("1234abcd-12ab-34cd-56ef-1234567890ab")})), "NotFoundException"},
		"ListAliases malformed KeyId": {second(c.ListAliases(ctx, &kms.ListAliasesInput{KeyId: aws.String("arn:aws:kms:x")})), "InvalidArnException"},
	} {
		if errCode(tc.err) != tc.code {
			t.Errorf("%s: %v, want %s", name, tc.err, tc.code)
		}
	}
}

func TestAlias_LimitPerKey(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	other := createKey(t, c, types.KeySpecEccNistP256)
	for i := 0; i < 50; i++ {
		if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(fmt.Sprintf("alias/a%02d", i)), TargetKeyId: key.KeyId}); err != nil {
			t.Fatalf("alias %d: %v", i, err)
		}
	}
	_, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/a50"), TargetKeyId: key.KeyId})
	wantCode(t, err, "LimitExceededException")
	// The quota is per key: another key is unaffected, and so is moving one alias to it.
	if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/other"), TargetKeyId: other.KeyId}); err != nil {
		t.Fatalf("alias on another key: %v", err)
	}
	// Updating an alias to the key it already has does not count it twice.
	if _, err := c.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/a00"), TargetKeyId: key.KeyId}); err != nil {
		t.Fatalf("UpdateAlias to the same key at the limit: %v", err)
	}
	_, err = c.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/other"), TargetKeyId: key.KeyId})
	wantCode(t, err, "LimitExceededException")
}

func TestAlias_Pagination(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	for i := 0; i < 5; i++ {
		if _, err := c.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(fmt.Sprintf("alias/p%d", i)), TargetKeyId: key.KeyId}); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	var marker *string
	for {
		out, err := c.ListAliases(ctx, &kms.ListAliasesInput{Limit: aws.Int32(2), Marker: marker})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range out.Aliases {
			got = append(got, *a.AliasName)
		}
		if !out.Truncated {
			break
		}
		marker = out.NextMarker
	}
	if want := "alias/p0,alias/p1,alias/p2,alias/p3,alias/p4"; strings.Join(got, ",") != want {
		t.Fatalf("paged aliases = %v, want %s", got, want)
	}
}

func TestTags_TagUntagList(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	out, err := c.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec: types.KeySpecEccNistP256, KeyUsage: types.KeyUsageTypeSignVerify,
		Tags: []types.Tag{{TagKey: aws.String("env"), TagValue: aws.String("dev")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := out.KeyMetadata.KeyId

	if _, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: id, Tags: []types.Tag{
		{TagKey: aws.String("owner"), TagValue: aws.String("team-a")},
		{TagKey: aws.String("env"), TagValue: aws.String("prod")}, // replaces
		{TagKey: aws.String("empty"), TagValue: aws.String("")},
	}}); err != nil {
		t.Fatalf("TagResource: %v", err)
	}
	list := func() string {
		t.Helper()
		l, err := c.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: id})
		if err != nil {
			t.Fatalf("ListResourceTags: %v", err)
		}
		var parts []string
		for _, tg := range l.Tags {
			parts = append(parts, *tg.TagKey+"="+*tg.TagValue)
		}
		return strings.Join(parts, ",")
	}
	if got, want := list(), "empty=,env=prod,owner=team-a"; got != want {
		t.Fatalf("tags = %q, want %q", got, want)
	}
	if _, err := c.UntagResource(ctx, &kms.UntagResourceInput{KeyId: id, TagKeys: []string{"env", "never-existed"}}); err != nil {
		t.Fatalf("UntagResource: %v", err)
	}
	if got, want := list(), "empty=,owner=team-a"; got != want {
		t.Fatalf("tags after untag = %q, want %q", got, want)
	}
}

func TestTags_ErrorTypes(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	tg := func(k, v string) []types.Tag { return []types.Tag{{TagKey: aws.String(k), TagValue: aws.String(v)}} }
	tag := func(tags []types.Tag) error {
		_, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: key.KeyId, Tags: tags})
		return err
	}
	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"aws: prefix":               {tag(tg("aws:cost", "x")), "TagException"},
		"AWS: prefix, any case":     {tag(tg("AWS:cost", "x")), "TagException"},
		"duplicate keys in request": {tag(append(tg("a", "1"), tg("a", "2")...)), "TagException"},
		"empty key":                 {tag(tg("", "x")), "ValidationException"},
		"key over 128":              {tag(tg(strings.Repeat("k", 129), "x")), "ValidationException"},
		"value over 256":            {tag(tg("k", strings.Repeat("v", 257))), "ValidationException"},
		"unknown key":               {second(c.TagResource(ctx, &kms.TagResourceInput{KeyId: aws.String("1234abcd-12ab-34cd-56ef-1234567890ab"), Tags: tg("a", "b")})), "NotFoundException"},
		"Untag unknown key":         {second(c.UntagResource(ctx, &kms.UntagResourceInput{KeyId: aws.String("1234abcd-12ab-34cd-56ef-1234567890ab"), TagKeys: []string{"a"}})), "NotFoundException"},
		"ListResourceTags unknown":  {second(c.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: aws.String("alias/none")})), "NotFoundException"},
		"TagResource malformed ARN": {second(c.TagResource(ctx, &kms.TagResourceInput{KeyId: aws.String("arn:bad"), Tags: tg("a", "b")})), "InvalidArnException"},
	} {
		if errCode(tc.err) != tc.code {
			t.Errorf("%s: %v, want %s", name, tc.err, tc.code)
		}
	}
}

func TestTags_LimitOf50(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	key := createKey(t, c, types.KeySpecEccNistP256)
	var tags []types.Tag
	for i := 0; i < 50; i++ {
		tags = append(tags, types.Tag{TagKey: aws.String(fmt.Sprintf("k%02d", i)), TagValue: aws.String("v")})
	}
	if _, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: key.KeyId, Tags: tags}); err != nil {
		t.Fatalf("50 tags: %v", err)
	}
	// Replacing the value of an existing tag at the limit is fine; adding a 51st is not.
	if _, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: key.KeyId, Tags: tags[:1]}); err != nil {
		t.Fatalf("re-tagging at the limit: %v", err)
	}
	_, err := c.TagResource(ctx, &kms.TagResourceInput{KeyId: key.KeyId, Tags: []types.Tag{{TagKey: aws.String("extra"), TagValue: aws.String("v")}}})
	wantCode(t, err, "LimitExceededException")

	// Paging through them.
	seen := 0
	var marker *string
	for {
		out, err := c.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: key.KeyId, Limit: aws.Int32(20), Marker: marker})
		if err != nil {
			t.Fatal(err)
		}
		seen += len(out.Tags)
		if !out.Truncated {
			break
		}
		marker = out.NextMarker
	}
	if seen != 50 {
		t.Fatalf("paged %d tags, want 50", seen)
	}
}
