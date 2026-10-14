// Package awskmsemulator is a local emulator of the AWS KMS signing API.
//
// It speaks the AWS JSON 1.1 protocol over HTTP, the protocol the AWS SDKs use
// for KMS, so the official clients (aws-sdk-go-v2 and the others, and the AWS
// CLI) reach it when pointed at a custom endpoint. It needs no AWS account and
// no network.
//
// # Use in tests
//
// New returns an http.Handler with its own empty key store, and Register mounts
// one on a ServeMux. The kmstest subpackage starts an httptest server and
// builds an aws-sdk-go-v2 client for it:
//
//	srv := kmstest.NewServer(t)
//	client := srv.Client()
//	key, _ := client.CreateKey(ctx, &kms.CreateKeyInput{
//	    KeySpec:  types.KeySpecEccNistEdwards25519,
//	    KeyUsage: types.KeyUsageTypeSignVerify,
//	})
//
// # Operations
//
// CreateKey, DescribeKey, GetPublicKey, Sign, Verify, ListKeys, EnableKey,
// DisableKey, ScheduleKeyDeletion, CancelKeyDeletion, CreateAlias,
// UpdateAlias, DeleteAlias, ListAliases, TagResource, UntagResource and
// ListResourceTags. Signing works with ECC_NIST_P256, ECC_NIST_P384,
// ECC_NIST_P521, ECC_SECG_P256K1, ECC_NIST_EDWARDS25519 and RSA_2048,
// RSA_3072 and RSA_4096 keys. Other KMS operations return a
// NotImplementedException. See docs/FEATURES.md for the full list.
//
// # Authentication
//
// SigV4 signatures are never validated. By default the emulator does not
// look at the Authorization header; WithStrictAuth makes it require a
// well-formed one.
//
// # Persistence
//
// WithDataDir (or the AWS_KMS_DATA_DIR environment variable of the standalone
// server) keeps keys across restarts in a state file that holds private keys
// in plaintext. Use it for development keys only.
//
// # License
//
// Apache 2.0. See the LICENSE file.
//
// # Links
//
// Repository: https://github.com/blackwell-systems/aws-kms-emulator
// Documentation: https://pkg.go.dev/github.com/blackwell-systems/aws-kms-emulator
// Issues: https://github.com/blackwell-systems/aws-kms-emulator/issues
package awskmsemulator
