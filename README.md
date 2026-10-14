# AWS KMS Emulator

[![Blackwell Systems](https://raw.githubusercontent.com/blackwell-systems/blackwell-docs-theme/main/badge-trademark.svg)](https://github.com/blackwell-systems)
[![Go Reference](https://pkg.go.dev/badge/github.com/blackwell-systems/aws-kms-emulator.svg)](https://pkg.go.dev/github.com/blackwell-systems/aws-kms-emulator)
[![Go Version](https://img.shields.io/badge/go-1.27+-blue.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> **A local AWS KMS signing API** - Test Ed25519, ECDSA and RSA signing with the real AWS SDKs, no AWS account.

An emulator of the AWS KMS API, scoped to asymmetric signing. It speaks the same wire protocol as AWS (AWS JSON 1.1), so `aws-sdk-go-v2` and the other official clients reach it when you point them at a custom endpoint. Keys are real: signatures come from real key material and verify with `crypto/ecdsa`, `crypto/ed25519` and `crypto/rsa` against the public key from `GetPublicKey`.

Validation and errors follow AWS's documentation: the same exception types, the 4096-byte message limit, the digest length rules, the key-state table. [docs/AWS-BEHAVIOUR.md](docs/AWS-BEHAVIOUR.md) cites the page behind every rule and says which ones the documentation leaves open.

**Three ways to run it**: a Go library for in-process tests, a standalone server binary, and a Docker image. No AWS credentials required.

## Why This Emulator Exists

Code that signs with KMS is hard to test locally. The usual choices are the real service (credentials, cost, latency, a network in CI) or a mock that returns canned bytes and cannot catch a wrong algorithm, a wrong message type or a signature that does not verify.

Ed25519 makes it worse. AWS KMS added the `ECC_NIST_EDWARDS25519` key spec in November 2025, and support for it in local emulators is recent and uneven. This emulator covers it from the start: the pure `ED25519_SHA_512` algorithm (RAW messages) and the `ED25519_PH_SHA_512` prehash algorithm (DIGEST messages), with the two message-type rules AWS enforces.

What this emulator offers:

| | |
|---|---|
| **Real signatures** | ECDSA (P-256, P-384, P-521, secp256k1), Ed25519, RSA-PSS and RSA PKCS #1 v1.5. Not mocked. |
| **AWS's own validation** | `ValidationException`, `NotFoundException`, `DisabledException`, `KMSInvalidStateException`, `InvalidKeyUsageException`, `KMSInvalidSignatureException` and the rest, from the API reference. |
| **In-process or standalone** | `kmstest.NewServer(t)` for Go tests, `cmd/server` for everything else. |
| **Persistence** | Set `AWS_KMS_DATA_DIR` and keys survive restarts, so a public key you pinned in a config stays valid. |
| **Tested through the real SDK** | The test suite drives `aws-sdk-go-v2` against the emulator and verifies every signature with the standard library. |

## Quick Start

### In a Go test

```go
func TestSigning(t *testing.T) {
	ctx := context.Background()

	srv := kmstest.NewServer(t) // starts an in-process emulator, closed when the test ends
	client := srv.Client()      // an aws-sdk-go-v2 KMS client pointed at it

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

	// Verify outside KMS, with the public key (an X.509 SubjectPublicKeyInfo).
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
```

This is `kmstest/readme_test.go`, so it compiles and runs with the suite. Each `kmstest.NewServer` call is an independent emulator with its own keys.

Prefer to mount the handler yourself? `awskmsemulator.New(opts...)` returns an `http.Handler`, and `awskmsemulator.Register(mux, opts...)` mounts it on a `ServeMux`:

```go
h, err := awskmsemulator.New()
srv := httptest.NewServer(h)
```

Options: `WithDataDir`, `WithRegion`, `WithAccountID`, `WithStrictAuth`, `WithClock`, `WithLogf`.

### Standalone server

```bash
go install github.com/blackwell-systems/aws-kms-emulator/cmd/server@latest

server                  # listens on :8080
server --port 4599
```

Point any AWS client at it. With the AWS CLI:

```bash
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1

aws kms create-key --endpoint-url http://localhost:8080 \
  --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY

aws kms sign --endpoint-url http://localhost:8080 \
  --key-id <KeyId> --message "$(echo -n hello | base64)" --message-type RAW \
  --signing-algorithm ED25519_SHA_512
```

In `aws-sdk-go-v2` set the endpoint on the client:

```go
cfg, _ := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"),
	config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
client := kms.NewFromConfig(cfg, func(o *kms.Options) {
	o.BaseEndpoint = aws.String("http://localhost:8080")
})
```

Other SDKs use their own setting for the same thing (`endpoint_url`, `endpointOverride`, and so on).

The server stops cleanly on SIGINT and SIGTERM. `GET /health` returns 200, for container health checks.

### Docker

```bash
docker build -t aws-kms-emulator .
docker run -p 8080:8080 aws-kms-emulator
```

To keep keys across restarts, mount a volume on `/data`:

```bash
docker run -p 8080:8080 \
  -e AWS_KMS_DATA_DIR=/data -v kms-data:/data \
  aws-kms-emulator
```

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `AWS_KMS_PORT` | `8080` | HTTP port (or `--port`) |
| `AWS_KMS_LOG_LEVEL` | `info` | `debug` logs one line per request |
| `AWS_KMS_DATA_DIR` | unset | Directory to persist state in. Unset means in-memory only |
| `AWS_KMS_REGION` | `us-east-1` | Region in ARNs |
| `AWS_KMS_ACCOUNT_ID` | `111122223333` | Account ID in ARNs |
| `AWS_KMS_STRICT_AUTH` | off | `true` requires a well-formed SigV4 `Authorization` header |

### Authentication

By default the emulator accepts any request, signed or not, and never validates signatures. A client that sends SigV4 headers works; a `curl` without them works too.

With `AWS_KMS_STRICT_AUTH=true` (or `WithStrictAuth(true)`) the request must carry an `Authorization: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...` header whose credential scope names the `kms` service, plus an `X-Amz-Date` or `Date` header. A missing header is `MissingAuthenticationToken` (403), a malformed one is `IncompleteSignature` (403). That catches a client that forgot to sign. It does not check the signature, the access key or the date, so it does not prove the credentials are right.

### Persistence

By default keys live in memory and are gone when the process stops. Set `AWS_KMS_DATA_DIR` and the emulator restores keys, aliases, tags and key states from `state.json` in that directory on startup, and rewrites it after every change (atomically, through a temp file and a rename). Keys scheduled for deletion keep their deletion date; one whose date passed while the emulator was stopped is gone when it starts.

`state.json` holds private keys in plaintext, with mode `0600`. Use it for development keys only. If the file exists but cannot be read, the emulator refuses to start rather than overwrite it. Delete the file to start from scratch.

## Supported Operations

| Operation | Notes |
|-----------|-------|
| `CreateKey` | `SIGN_VERIFY` keys: `ECC_NIST_P256`, `ECC_NIST_P384`, `ECC_NIST_P521`, `ECC_SECG_P256K1`, `ECC_NIST_EDWARDS25519`, `RSA_2048`, `RSA_3072`, `RSA_4096`. Also `SYMMETRIC_DEFAULT` keys as metadata only (no `Encrypt` or `Decrypt`), so key-usage errors can be tested. Description and tags |
| `DescribeKey` | By key ID, key ARN, alias name or alias ARN |
| `GetPublicKey` | DER SubjectPublicKeyInfo, `KeySpec`, `KeyUsage`, `SigningAlgorithms` |
| `Sign`, `Verify` | `ECDSA_SHA_256/384/512`, `ED25519_SHA_512` (RAW), `ED25519_PH_SHA_512` (DIGEST), `RSASSA_PSS_SHA_256/384/512`, `RSASSA_PKCS1_V1_5_SHA_256/384/512`. Message types RAW and DIGEST |
| `ListKeys` | Paginated |
| `EnableKey`, `DisableKey` | |
| `ScheduleKeyDeletion`, `CancelKeyDeletion` | 7 to 30 day window; the key and its aliases are gone when it passes |
| `CreateAlias`, `UpdateAlias`, `DeleteAlias`, `ListAliases` | Paginated, filter by key |
| `TagResource`, `UntagResource`, `ListResourceTags` | |

Every other KMS operation returns HTTP 501 `NotImplementedException`; an operation AWS does not have returns 404 `UnknownOperationException`. [docs/FEATURES.md](docs/FEATURES.md) has the full supported / not supported list.

### Errors

Errors are the AWS JSON 1.1 shape: HTTP 400 (500 for `KMSInternalException`), `x-amzn-ErrorType` header, and `{"__type": "...", "message": "..."}`. The SDKs turn them into their modelled exception types:

```go
var disabled *types.DisabledException
if errors.As(err, &disabled) { ... }
```

`ValidationException` is not a modelled type in the KMS SDKs, so check it by code:

```go
var apiErr smithy.APIError
if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ValidationException" { ... }
```

Match on the exception type, not on the message text: messages are written to be readable and differ from AWS's in places.

## Not Supported

- Encryption, decryption, data keys, MACs, key agreement, and RSA encryption keys
- Key policies, grants, IAM: the emulator authorizes nothing
- Key rotation, imported key material, multi-Region keys, custom key stores
- AWS-managed keys and aliases (`alias/aws/...`)
- SM2 and ML-DSA keys, `EXTERNAL_MU`
- More than one account or Region per emulator

## Roadmap

- **IAM enforcement mode.** The GCP counterpart, [gcp-kms-emulator](https://github.com/blackwell-systems/gcp-kms-emulator), can deny requests using production-style IAM policies. An equivalent here would check key policies and IAM policies before a signing call, so permission bugs fail in CI the way they fail in AWS. Not started.
- More of the KMS API as real use asks for it (encryption, data keys, key policies).

## Use Cases

- **Unit and integration tests** for code that signs with KMS: release signing, JWT and token signing, certificate and CSR builders, blockchain transaction signers
- **CI pipelines** with no AWS credentials and no network
- **Local development** against the same SDK calls production makes
- **Testing key lifecycle handling**: a disabled key, a key scheduled for deletion, an alias that moves

## Development

```bash
make test       # go test ./...
make build      # builds bin/server
```

Tests drive everything through `aws-sdk-go-v2`, verify signatures with the standard library, and check every error type. `go vet` runs for Linux and Windows.

## Maintained By

Dayna Blackwell, [Blackwell Systems](https://github.com/blackwell-systems).

If you use this emulator, I'd like to hear what you test with it and what is missing. Open an issue or a discussion, or write to dayna@blackwell-systems.com.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
