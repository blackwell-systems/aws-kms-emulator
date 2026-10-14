//go:build crosscheck

// Package crosscheck runs one set of SDK-level scenarios against any KMS
// endpoint and records the outcome of each, so two emulators can be compared.
//
//	KMS_ENDPOINT=http://localhost:4566 KMS_OUT=floci.json go test -tags crosscheck ./crosscheck
//
// With KMS_ENDPOINT unset it runs against an in-process aws-kms-emulator.
// A scenario's outcome is the error code, or "ok" plus the observable facts.
package crosscheck

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"github.com/blackwell-systems/aws-kms-emulator/kmstest"
)

var (
	ctx     = context.Background()
	results = map[string]string{}
	client  *kms.Client
)

func rec(name, outcome string) { results[name] = outcome }

func code(err error) string {
	if err == nil {
		return "ok"
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return "non-api-error:" + strings.SplitN(err.Error(), "\n", 2)[0]
}

func TestMain(m *testing.M) {
	// client is created in TestScenarios, which has a *testing.T for kmstest.
	os.Exit(m.Run())
}

func sum(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(b)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(b)
		return d[:]
	}
	d := sha512.Sum512(b)
	return d[:]
}

type keyInfo struct {
	id   string
	spec types.KeySpec
}

func newKey(spec types.KeySpec) (keyInfo, string) {
	out, err := client.CreateKey(ctx, &kms.CreateKeyInput{KeySpec: spec, KeyUsage: types.KeyUsageTypeSignVerify})
	if err != nil {
		return keyInfo{}, code(err)
	}
	return keyInfo{*out.KeyMetadata.KeyId, spec}, "ok"
}

func algs(a ...types.SigningAlgorithmSpec) []types.SigningAlgorithmSpec { return a }

var allAlgs = algs(
	types.SigningAlgorithmSpecRsassaPssSha256, types.SigningAlgorithmSpecRsassaPssSha384, types.SigningAlgorithmSpecRsassaPssSha512,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	types.SigningAlgorithmSpecEcdsaSha256, types.SigningAlgorithmSpecEcdsaSha384, types.SigningAlgorithmSpecEcdsaSha512,
	types.SigningAlgorithmSpecEd25519Sha512, types.SigningAlgorithmSpecEd25519PhSha512)

var specs = []types.KeySpec{
	types.KeySpecEccNistP256, types.KeySpecEccNistP384, types.KeySpecEccNistP521, types.KeySpecEccSecgP256k1,
	types.KeySpecEccNistEdwards25519, types.KeySpecRsa2048,
}

func hashOf(alg types.SigningAlgorithmSpec) crypto.Hash {
	s := string(alg)
	switch {
	case strings.HasSuffix(s, "SHA_256"):
		return crypto.SHA256
	case strings.HasSuffix(s, "SHA_384"):
		return crypto.SHA384
	}
	return crypto.SHA512
}

func isEd(alg types.SigningAlgorithmSpec) bool { return strings.HasPrefix(string(alg), "ED25519") }

func extVerify(pubDER []byte, alg types.SigningAlgorithmSpec, msg []byte, sig []byte) string {
	if len(pubDER) == 0 {
		return "no-pubkey"
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		// secp256k1 is not parseable by crypto/x509; check the structure only.
		var spki struct {
			Alg struct {
				ID, Curve asn1.ObjectIdentifier
			}
			Key asn1.BitString
		}
		if _, e := asn1.Unmarshal(pubDER, &spki); e == nil && spki.Alg.Curve.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 10}) {
			return "k1-spki-ok(sig unchecked)"
		}
		return "pubkey-unparseable"
	}
	h := hashOf(alg)
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if alg == types.SigningAlgorithmSpecEd25519PhSha512 {
			ph := sha512.Sum512(msg)
			return fmt.Sprint(ed25519.VerifyWithOptions(k, ph[:], sig, &ed25519.Options{Hash: crypto.SHA512}) == nil)
		}
		return fmt.Sprint(ed25519.Verify(k, msg, sig))
	case *ecdsa.PublicKey:
		return fmt.Sprint(ecdsa.VerifyASN1(k, sum(h, msg), sig))
	case *rsa.PublicKey:
		if strings.Contains(string(alg), "PSS") {
			return fmt.Sprint(rsa.VerifyPSS(k, h, sum(h, msg), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil)
		}
		return fmt.Sprint(rsa.VerifyPKCS1v15(k, h, sum(h, msg), sig) == nil)
	}
	return "unknown-pubkey-type"
}

func TestScenarios(t *testing.T) {
	if ep := os.Getenv("KMS_ENDPOINT"); ep != "" {
		client = kms.New(kms.Options{
			Region: "us-east-1", BaseEndpoint: aws.String(ep), RetryMaxAttempts: 1,
			Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		})
	} else {
		client = kmstest.NewServer(t).Client()
	}
	defer func() {
		out := os.Getenv("KMS_OUT")
		if out == "" {
			return
		}
		b, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Error(err)
		}
	}()

	// 1. Key creation and GetPublicKey fields, per spec.
	keys := map[types.KeySpec]keyInfo{}
	for _, spec := range specs {
		k, c := newKey(spec)
		rec("create/"+string(spec), c)
		if c != "ok" {
			continue
		}
		keys[spec] = k
		d, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &k.id})
		if err != nil {
			rec("describe/"+string(spec), code(err))
		} else {
			m := d.KeyMetadata
			var a []string
			for _, x := range m.SigningAlgorithms {
				a = append(a, string(x))
			}
			rec("describe/"+string(spec), fmt.Sprintf("spec=%s usage=%s state=%s enabled=%v algs=%v origin=%s mgr=%s encAlgs=%d idUUID=%v arnShape=%v",
				m.KeySpec, m.KeyUsage, m.KeyState, m.Enabled, a, m.Origin, m.KeyManager, len(m.EncryptionAlgorithms),
				len(*m.KeyId) == 36, strings.HasPrefix(*m.Arn, "arn:aws:kms:") && strings.HasSuffix(*m.Arn, ":key/"+*m.KeyId)))
		}
		pk, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &k.id})
		if err != nil {
			rec("getpublickey/"+string(spec), code(err))
			continue
		}
		var a []string
		for _, x := range pk.SigningAlgorithms {
			a = append(a, string(x))
		}
		_, perr := x509.ParsePKIXPublicKey(pk.PublicKey)
		rec("getpublickey/"+string(spec), fmt.Sprintf("spec=%s usage=%s algs=%v spkiParses=%v keyIdIsArn=%v", pk.KeySpec, pk.KeyUsage, a, perr == nil, strings.HasPrefix(str(pk.KeyId), "arn:")))
	}

	// 2. Sign (RAW and DIGEST) and Verify for every spec x algorithm.
	msg := []byte("cross-check message")
	for _, spec := range specs {
		k, ok := keys[spec]
		if !ok {
			continue
		}
		pk, _ := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &k.id})
		var pub []byte
		if pk != nil {
			pub = pk.PublicKey
		}
		for _, alg := range allAlgs {
			for _, mt := range []types.MessageType{types.MessageTypeRaw, types.MessageTypeDigest, ""} {
				in := msg
				if mt == types.MessageTypeDigest {
					if alg == types.SigningAlgorithmSpecEd25519PhSha512 {
						d := sha512.Sum512(msg)
						in = d[:]
					} else if !isEd(alg) {
						in = sum(hashOf(alg), msg)
					} else {
						in = make([]byte, 64)
					}
				}
				if alg == types.SigningAlgorithmSpecEd25519PhSha512 && mt != types.MessageTypeDigest {
					in = make([]byte, 64)
				}
				name := fmt.Sprintf("sign/%s/%s/%s", spec, alg, mtName(mt))
				out, err := client.Sign(ctx, &kms.SignInput{KeyId: &k.id, Message: in, MessageType: mt, SigningAlgorithm: alg})
				if err != nil {
					rec(name, code(err))
					continue
				}
				ext := "n/a"
				if mt != types.MessageTypeDigest || alg == types.SigningAlgorithmSpecEd25519PhSha512 {
					orig := msg
					if alg == types.SigningAlgorithmSpecEd25519PhSha512 {
						orig = in // the digest the caller supplied
					}
					ext = extVerify(pub, alg, orig, out.Signature)
				} else {
					ext = extVerifyDigest(pub, alg, in, out.Signature)
				}
				v, verr := client.Verify(ctx, &kms.VerifyInput{KeyId: &k.id, Message: in, MessageType: mt, Signature: out.Signature, SigningAlgorithm: alg})
				vr := code(verr)
				if verr == nil {
					vr = fmt.Sprint("valid=", v.SignatureValid)
				}
				rec(name, fmt.Sprintf("ok sigLen>0=%v externalVerify=%s kmsVerify=%s respAlg=%s respKeyIsArn=%v", len(out.Signature) > 0, ext, vr, out.SigningAlgorithm, strings.HasPrefix(str(out.KeyId), "arn:")))
			}
		}
	}

	// 3. Cross-type verify: sign RAW, verify as DIGEST of the hash, and tampering.
	for _, spec := range []types.KeySpec{types.KeySpecEccNistP256, types.KeySpecEccNistEdwards25519, types.KeySpecRsa2048} {
		k, ok := keys[spec]
		if !ok {
			continue
		}
		alg := map[types.KeySpec]types.SigningAlgorithmSpec{
			types.KeySpecEccNistP256: types.SigningAlgorithmSpecEcdsaSha256, types.KeySpecEccNistEdwards25519: types.SigningAlgorithmSpecEd25519Sha512,
			types.KeySpecRsa2048: types.SigningAlgorithmSpecRsassaPssSha256}[spec]
		s, err := client.Sign(ctx, &kms.SignInput{KeyId: &k.id, Message: msg, SigningAlgorithm: alg})
		if err != nil {
			continue
		}
		dig := msg
		if !isEd(alg) {
			dig = sum(crypto.SHA256, msg)
		}
		_, e1 := client.Verify(ctx, &kms.VerifyInput{KeyId: &k.id, Message: dig, MessageType: types.MessageTypeDigest, Signature: s.Signature, SigningAlgorithm: alg})
		rec("verify-crosstype/"+string(spec), "rawSigAsDigest="+code(e1))
		_, e2 := client.Verify(ctx, &kms.VerifyInput{KeyId: &k.id, Message: []byte("changed"), Signature: s.Signature, SigningAlgorithm: alg})
		rec("verify-tampered-msg/"+string(spec), code(e2))
		bad := append([]byte(nil), s.Signature...)
		bad[len(bad)/2] ^= 1
		_, e3 := client.Verify(ctx, &kms.VerifyInput{KeyId: &k.id, Message: msg, Signature: bad, SigningAlgorithm: alg})
		rec("verify-tampered-sig/"+string(spec), code(e3))
		_, e4 := client.Verify(ctx, &kms.VerifyInput{KeyId: &k.id, Message: msg, Signature: []byte{1, 2, 3}, SigningAlgorithm: alg})
		rec("verify-garbage-sig/"+string(spec), code(e4))
		other, _ := newKey(spec)
		_, e5 := client.Verify(ctx, &kms.VerifyInput{KeyId: &other.id, Message: msg, Signature: s.Signature, SigningAlgorithm: alg})
		rec("verify-other-key/"+string(spec), code(e5))
	}

	// 4. Digest length rules, size-1/size/size+1.
	for _, tc := range []struct {
		spec types.KeySpec
		alg  types.SigningAlgorithmSpec
		n    int
	}{
		{types.KeySpecEccNistP256, types.SigningAlgorithmSpecEcdsaSha256, 32},
		{types.KeySpecEccNistP384, types.SigningAlgorithmSpecEcdsaSha384, 48},
		{types.KeySpecEccNistP521, types.SigningAlgorithmSpecEcdsaSha512, 64},
		{types.KeySpecEccNistEdwards25519, types.SigningAlgorithmSpecEd25519PhSha512, 64},
		{types.KeySpecRsa2048, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, 48},
	} {
		k, ok := keys[tc.spec]
		if !ok {
			continue
		}
		for _, d := range []int{tc.n - 1, tc.n, tc.n + 1} {
			_, err := client.Sign(ctx, &kms.SignInput{KeyId: &k.id, Message: make([]byte, d), MessageType: types.MessageTypeDigest, SigningAlgorithm: tc.alg})
			rec(fmt.Sprintf("digestlen/%s/%s/%d", tc.spec, tc.alg, d), code(err))
		}
	}

	// 5. Message size limits.
	for _, tc := range []struct {
		spec types.KeySpec
		alg  types.SigningAlgorithmSpec
	}{
		{types.KeySpecEccNistP256, types.SigningAlgorithmSpecEcdsaSha256},
		{types.KeySpecEccNistEdwards25519, types.SigningAlgorithmSpecEd25519Sha512},
		{types.KeySpecRsa2048, types.SigningAlgorithmSpecRsassaPssSha256},
	} {
		k, ok := keys[tc.spec]
		if !ok {
			continue
		}
		for _, n := range []int{0, 1, 4096, 4097, 10000} {
			_, err := client.Sign(ctx, &kms.SignInput{KeyId: &k.id, Message: make([]byte, n), SigningAlgorithm: tc.alg})
			rec(fmt.Sprintf("msgsize/sign/%s/%d", tc.spec, n), code(err))
			_, err = client.Verify(ctx, &kms.VerifyInput{KeyId: &k.id, Message: make([]byte, n), Signature: []byte{1}, SigningAlgorithm: tc.alg})
			rec(fmt.Sprintf("msgsize/verify/%s/%d", tc.spec, n), code(err))
		}
	}

	// 6. Message type rules.
	if k, ok := keys[types.KeySpecEccNistEdwards25519]; ok {
		for _, mt := range []types.MessageType{"", types.MessageTypeRaw, types.MessageTypeDigest, types.MessageTypeExternalMu, "BOGUS"} {
			for _, alg := range algs(types.SigningAlgorithmSpecEd25519Sha512, types.SigningAlgorithmSpecEd25519PhSha512) {
				_, err := client.Sign(ctx, &kms.SignInput{KeyId: &k.id, Message: make([]byte, 64), MessageType: mt, SigningAlgorithm: alg})
				rec(fmt.Sprintf("ed-msgtype/%s/%s", alg, mtName(mt)), code(err))
			}
		}
	}
	if k, ok := keys[types.KeySpecEccNistP256]; ok {
		for _, mt := range []types.MessageType{types.MessageTypeExternalMu, "BOGUS"} {
			_, err := client.Sign(ctx, &kms.SignInput{KeyId: &k.id, Message: make([]byte, 64), MessageType: mt, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
			rec("p256-msgtype/"+mtName(mt), code(err))
		}
		_, err := client.Sign(ctx, &kms.SignInput{KeyId: &k.id, Message: msg, SigningAlgorithm: "ECDSA_SHA_999"})
		rec("sign/unknown-alg", code(err))
		for _, a := range algs(types.SigningAlgorithmSpecSm2dsa, types.SigningAlgorithmSpecMlDsaShake256) {
			_, err = client.Sign(ctx, &kms.SignInput{KeyId: &k.id, Message: msg, SigningAlgorithm: a})
			rec("sign/other-alg/"+string(a), code(err))
		}
	}

	// 7. Lookup and ARN errors.
	k := keys[types.KeySpecEccNistP256]
	look := func(name, id string) {
		_, err := client.Sign(ctx, &kms.SignInput{KeyId: aws.String(id), Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
		rec("lookup/sign/"+name, code(err))
		_, err = client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(id)})
		rec("lookup/describe/"+name, code(err))
	}
	look("unknown-uuid", "1234abcd-12ab-34cd-56ef-1234567890ab")
	look("garbage", "not-a-key")
	look("missing-alias", "alias/nope")
	look("missing-alias-arn", "arn:aws:kms:us-east-1:000000000000:alias/nope")
	look("bad-arn", "arn:aws:kms:us-east-1")
	look("other-service-arn", "arn:aws:s3:::bucket/key")
	look("other-region-arn", "arn:aws:kms:eu-west-1:111122223333:key/"+k.id)
	look("alias-without-prefix", "plainalias")
	_, err := client.Sign(ctx, &kms.SignInput{KeyId: aws.String(strings.Repeat("a", 2049)), Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
	rec("lookup/sign/keyid-2049", code(err))

	// 8. Aliases.
	if k.id != "" {
		_, err = client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/xc"), TargetKeyId: &k.id})
		rec("alias/create", code(err))
		s, err := client.Sign(ctx, &kms.SignInput{KeyId: aws.String("alias/xc"), Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
		if err == nil {
			rec("alias/sign-by-alias", fmt.Sprintf("ok respKeyIsArn=%v", strings.HasPrefix(str(s.KeyId), "arn:")))
		} else {
			rec("alias/sign-by-alias", code(err))
		}
		d, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String("alias/xc")})
		rec("alias/describe-by-alias", fmt.Sprintf("%s same=%v", code(err), err == nil && str(d.KeyMetadata.KeyId) == k.id))
		_, err = client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/xc"), TargetKeyId: &k.id})
		rec("alias/duplicate", code(err))
		for name, an := range map[string]string{"noprefix": "xc2", "aws-prefix": "alias/aws/x", "space": "alias/a b", "dot": "alias/a.b", "slash-only": "alias/", "too-long": "alias/" + strings.Repeat("a", 251), "empty": "", "uppercase-ok": "alias/UPPER_ok-1/x"} {
			_, err = client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String(an), TargetKeyId: &k.id})
			rec("alias/name/"+name, code(err))
		}
		_, err = client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/tgt-alias"), TargetKeyId: aws.String("alias/xc")})
		rec("alias/target-is-alias", code(err))
		_, err = client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/tgt-arn"), TargetKeyId: aws.String("arn:aws:kms:us-east-1:000000000000:key/" + k.id)})
		rec("alias/target-key-arn(other account)", code(err))
		_, err = client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/tgt-missing"), TargetKeyId: aws.String("1234abcd-12ab-34cd-56ef-1234567890ab")})
		rec("alias/target-missing", code(err))
		la, err := client.ListAliases(ctx, &kms.ListAliasesInput{})
		if err == nil {
			var names []string
			for _, a := range la.Aliases {
				names = append(names, *a.AliasName)
			}
			sort.Strings(names)
			rec("alias/list-all", fmt.Sprint(names))
		} else {
			rec("alias/list-all", code(err))
		}
		_, err = client.UpdateAlias(ctx, &kms.UpdateAliasInput{AliasName: aws.String("alias/nope"), TargetKeyId: &k.id})
		rec("alias/update-missing", code(err))
		_, err = client.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: aws.String("alias/nope")})
		rec("alias/delete-missing", code(err))
		for _, n := range []int32{0, 101} {
			_, err = client.ListAliases(ctx, &kms.ListAliasesInput{Limit: aws.Int32(n)})
			rec(fmt.Sprintf("alias/list-limit-%d", n), code(err))
		}
		_, err = client.ListAliases(ctx, &kms.ListAliasesInput{Marker: aws.String("!!bad")})
		rec("alias/list-bad-marker", code(err))
	}

	// 9. CreateKey validation.
	ck := func(name string, in *kms.CreateKeyInput) {
		out, err := client.CreateKey(ctx, in)
		if err != nil {
			rec("createkey/"+name, code(err))
			return
		}
		m := out.KeyMetadata
		rec("createkey/"+name, fmt.Sprintf("ok spec=%s usage=%s", m.KeySpec, m.KeyUsage))
	}
	ck("default", &kms.CreateKeyInput{})
	ck("asym-no-usage", &kms.CreateKeyInput{KeySpec: types.KeySpecEccNistP256})
	ck("unknown-spec", &kms.CreateKeyInput{KeySpec: "ECC_NIST_P999", KeyUsage: types.KeyUsageTypeSignVerify})
	ck("unknown-usage", &kms.CreateKeyInput{KeySpec: types.KeySpecEccNistP256, KeyUsage: "SIGNING"})
	ck("sym-sign-verify", &kms.CreateKeyInput{KeyUsage: types.KeyUsageTypeSignVerify})
	ck("k1-encrypt", &kms.CreateKeyInput{KeySpec: types.KeySpecEccSecgP256k1, KeyUsage: types.KeyUsageTypeEncryptDecrypt})
	ck("ed-encrypt", &kms.CreateKeyInput{KeySpec: types.KeySpecEccNistEdwards25519, KeyUsage: types.KeyUsageTypeEncryptDecrypt})
	ck("ed-key-agreement", &kms.CreateKeyInput{KeySpec: types.KeySpecEccNistEdwards25519, KeyUsage: types.KeyUsageTypeKeyAgreement})
	ck("rsa-sign-3072", &kms.CreateKeyInput{KeySpec: types.KeySpecRsa3072, KeyUsage: types.KeyUsageTypeSignVerify})
	ck("rsa-encrypt", &kms.CreateKeyInput{KeySpec: types.KeySpecRsa2048, KeyUsage: types.KeyUsageTypeEncryptDecrypt})
	ck("hmac", &kms.CreateKeyInput{KeySpec: types.KeySpecHmac256, KeyUsage: types.KeyUsageTypeGenerateVerifyMac})
	ck("mldsa", &kms.CreateKeyInput{KeySpec: types.KeySpecMlDsa65, KeyUsage: types.KeyUsageTypeSignVerify})
	ck("multiregion", &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
	ck("desc-8192", &kms.CreateKeyInput{Description: aws.String(strings.Repeat("d", 8192))})
	ck("desc-8193", &kms.CreateKeyInput{Description: aws.String(strings.Repeat("d", 8193))})
	ck("tag-aws-prefix", &kms.CreateKeyInput{Tags: []types.Tag{{TagKey: aws.String("aws:x"), TagValue: aws.String("v")}}})
	ck("tag-dup", &kms.CreateKeyInput{Tags: []types.Tag{{TagKey: aws.String("a"), TagValue: aws.String("1")}, {TagKey: aws.String("a"), TagValue: aws.String("2")}}})
	ck("cmk-spec-alias", &kms.CreateKeyInput{CustomerMasterKeySpec: types.CustomerMasterKeySpecEccNistP256, KeyUsage: types.KeyUsageTypeSignVerify})
	// symmetric key behaviours
	if out, err := client.CreateKey(ctx, &kms.CreateKeyInput{}); err == nil {
		id := out.KeyMetadata.KeyId
		_, e := client.Sign(ctx, &kms.SignInput{KeyId: id, Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
		rec("symmetric/sign", code(e))
		_, e = client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: id})
		rec("symmetric/getpublickey", code(e))
		_, e = client.Verify(ctx, &kms.VerifyInput{KeyId: id, Message: msg, Signature: []byte{1}, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
		rec("symmetric/verify", code(e))
	}

	// 10. Key state matrix, on a fresh key per cell.
	type opfn func(id *string) error
	ops := map[string]opfn{
		"sign": func(id *string) error {
			_, e := client.Sign(ctx, &kms.SignInput{KeyId: id, Message: msg, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
			return e
		},
		"verify": func(id *string) error {
			_, e := client.Verify(ctx, &kms.VerifyInput{KeyId: id, Message: msg, Signature: []byte{0x30, 0}, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256})
			if code(e) == "KMSInvalidSignatureException" {
				return nil
			}
			return e
		},
		"getpublickey": func(id *string) error { _, e := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: id}); return e },
		"describe":     func(id *string) error { _, e := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: id}); return e },
		"enable":       func(id *string) error { _, e := client.EnableKey(ctx, &kms.EnableKeyInput{KeyId: id}); return e },
		"disable":      func(id *string) error { _, e := client.DisableKey(ctx, &kms.DisableKeyInput{KeyId: id}); return e },
		"schedule": func(id *string) error {
			_, e := client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: id})
			return e
		},
		"cancel": func(id *string) error {
			_, e := client.CancelKeyDeletion(ctx, &kms.CancelKeyDeletionInput{KeyId: id})
			return e
		},
		"tag": func(id *string) error {
			_, e := client.TagResource(ctx, &kms.TagResourceInput{KeyId: id, Tags: []types.Tag{{TagKey: aws.String("a"), TagValue: aws.String("b")}}})
			return e
		},
		"listtags": func(id *string) error {
			_, e := client.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: id})
			return e
		},
		"createalias": func(id *string) error {
			_, e := client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/st-" + *id), TargetKeyId: id})
			return e
		},
	}
	names := make([]string, 0, len(ops))
	for n := range ops {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, state := range []string{"enabled", "disabled", "pending"} {
		for _, n := range names {
			kk, c := newKey(types.KeySpecEccNistP256)
			if c != "ok" {
				continue
			}
			switch state {
			case "disabled":
				_, _ = client.DisableKey(ctx, &kms.DisableKeyInput{KeyId: &kk.id})
			case "pending":
				_, _ = client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: &kk.id, PendingWindowInDays: aws.Int32(7)})
			}
			rec(fmt.Sprintf("state/%s/%s", state, n), code(ops[n](&kk.id)))
		}
	}
	// Lifecycle details.
	if kk, c := newKey(types.KeySpecEccNistP256); c == "ok" {
		s, err := client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: &kk.id, PendingWindowInDays: aws.Int32(7)})
		if err == nil {
			rec("lifecycle/schedule-response", fmt.Sprintf("state=%s window=%s keyIdIsArn=%v hasDate=%v", s.KeyState, i32(s.PendingWindowInDays), strings.HasPrefix(str(s.KeyId), "arn:"), s.DeletionDate != nil))
		} else {
			rec("lifecycle/schedule-response", code(err))
		}
		d, _ := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &kk.id})
		if d != nil {
			m := d.KeyMetadata
			rec("lifecycle/describe-pending", fmt.Sprintf("state=%s enabled=%v hasDeletionDate=%v window=%v", m.KeyState, m.Enabled, m.DeletionDate != nil, m.PendingDeletionWindowInDays != nil))
		}
		cr, err := client.CancelKeyDeletion(ctx, &kms.CancelKeyDeletionInput{KeyId: &kk.id})
		if err == nil {
			d, _ = client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &kk.id})
			if d == nil {
				rec("lifecycle/cancel", "ok describe-failed")
			} else {
				rec("lifecycle/cancel", fmt.Sprintf("ok keyIdIsArn=%v stateAfter=%s enabledAfter=%v", strings.HasPrefix(str(cr.KeyId), "arn:"), d.KeyMetadata.KeyState, d.KeyMetadata.Enabled))
			}
		} else {
			rec("lifecycle/cancel", code(err))
		}
	}
	for _, w := range []int32{0, 6, 7, 30, 31} {
		kk, _ := newKey(types.KeySpecEccNistP256)
		_, err := client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: &kk.id, PendingWindowInDays: aws.Int32(w)})
		rec(fmt.Sprintf("lifecycle/window-%d", w), code(err))
	}
	if kk, c := newKey(types.KeySpecEccNistP256); c == "ok" {
		s, err := client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: &kk.id})
		if err == nil {
			rec("lifecycle/default-window", i32(s.PendingWindowInDays))
		}
	}

	// 11. Lists, tags, paging.
	lk, err := client.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(1)})
	if err == nil {
		rec("list/keys-limit-1", fmt.Sprintf("n=%d truncated=%v marker=%v", len(lk.Keys), lk.Truncated, lk.NextMarker != nil))
	} else {
		rec("list/keys-limit-1", code(err))
	}
	for _, n := range []int32{0, 1001} {
		_, err = client.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(n)})
		rec(fmt.Sprintf("list/keys-limit-%d", n), code(err))
	}
	_, err = client.ListKeys(ctx, &kms.ListKeysInput{Marker: aws.String("!!bad")})
	rec("list/keys-bad-marker", code(err))
	if kk, c := newKey(types.KeySpecEccNistP256); c == "ok" {
		tg := func(k, v string) []types.Tag { return []types.Tag{{TagKey: aws.String(k), TagValue: aws.String(v)}} }
		for name, tags := range map[string][]types.Tag{"aws-prefix": tg("aws:x", "v"), "empty-key": tg("", "v"), "empty-value": tg("k", ""), "key-129": tg(strings.Repeat("k", 129), "v"), "value-257": tg("k", strings.Repeat("v", 257))} {
			_, err = client.TagResource(ctx, &kms.TagResourceInput{KeyId: &kk.id, Tags: tags})
			rec("tags/"+name, code(err))
		}
		var many []types.Tag
		for i := 0; i < 51; i++ {
			many = append(many, types.Tag{TagKey: aws.String(fmt.Sprintf("k%02d", i)), TagValue: aws.String("v")})
		}
		kk, _ = newKey(types.KeySpecEccNistP256) // a key with no other tags
		_, err = client.TagResource(ctx, &kms.TagResourceInput{KeyId: &kk.id, Tags: many[:50]})
		rec("tags/50", code(err))
		_, err = client.TagResource(ctx, &kms.TagResourceInput{KeyId: &kk.id, Tags: many[50:]})
		rec("tags/51st", code(err))
		_, err = client.UntagResource(ctx, &kms.UntagResourceInput{KeyId: &kk.id, TagKeys: []string{"k00", "nonexistent"}})
		rec("tags/untag", code(err))
	}

	// 12. Disabled/enable idempotence and unsupported ops.
	if kk, c := newKey(types.KeySpecEccNistP256); c == "ok" {
		_, e1 := client.DisableKey(ctx, &kms.DisableKeyInput{KeyId: &kk.id})
		_, e2 := client.DisableKey(ctx, &kms.DisableKeyInput{KeyId: &kk.id})
		rec("idempotent/disable-twice", code(e1)+","+code(e2))
		_, e1 = client.EnableKey(ctx, &kms.EnableKeyInput{KeyId: &kk.id})
		_, e2 = client.EnableKey(ctx, &kms.EnableKeyInput{KeyId: &kk.id})
		rec("idempotent/enable-twice", code(e1)+","+code(e2))
		_, e := client.DisableKey(ctx, &kms.DisableKeyInput{KeyId: aws.String("alias/xc")})
		rec("keyonly/disable-by-alias", code(e))
	}
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func i32(p *int32) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprint(*p)
}

func mtName(m types.MessageType) string {
	if m == "" {
		return "default"
	}
	return string(m)
}

func extVerifyDigest(pubDER []byte, alg types.SigningAlgorithmSpec, digest, sig []byte) string {
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return "pubkey-unparseable-or-k1"
	}
	h := hashOf(alg)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprint(ecdsa.VerifyASN1(k, digest, sig))
	case *rsa.PublicKey:
		if strings.Contains(string(alg), "PSS") {
			return fmt.Sprint(rsa.VerifyPSS(k, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil)
		}
		return fmt.Sprint(rsa.VerifyPKCS1v15(k, h, digest, sig) == nil)
	}
	return "n/a"
}
